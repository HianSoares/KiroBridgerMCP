"""Second review round of the persistent case flow: evidence preservation, activity-level QRadar<->Trend
links, coverage of records beyond presentation caps, behavior-level authorization and the global deadline.

All data is synthetic. No QRadar or Vision One is contacted; Trend results are mocked. The first
assertion of each scenario checks the observable behavior (disposition, link level, closure readiness,
scope acceptance or budget state), so the tests fail on the earlier implementation by behavior.
"""

import asyncio
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from soc_bridge import closure_assessment, process_chain
from soc_bridge.ariel_collection import Budget, BudgetExhausted
from soc_bridge.case_investigation import bridge_findings, investigate_offense_case, reassess_case
from soc_bridge.case_store import CaseStore
from soc_bridge.closure_scope import validate_scope
from soc_bridge.offense_evidence import collect_offense_evidence
from soc_bridge.windows_events import extract

from synthetic_lab import G_PARENT, G_PS, HOST, IP, MS, NOW, SHA, Lab, offense, row, sysmon

OTHER_HOST = "ws-demo-02.example.test"
PARENT_SHA = "CD" * 32
TOOL = "C:\\Tools\\synthetic.exe"
WINDOW = {"window_start": "2026-10-09T15:00:00+00:00", "window_end": "2026-10-09T17:00:00+00:00"}
PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
BACKUP = "powershell.exe -NoProfile -File C:\\ops\\backup.ps1"
ENCODED = "powershell.exe -NoProfile -EncodedCommand SQBFAFgA"


def run(coro):
    return asyncio.run(coro)


def tp_report(host=HOST, pid=4321, launch="2026-10-09T16:00:01Z", sha=SHA, observables=None,
              parent=None, classification="True Positive", uuid="ev-synth-1", with_records=True):
    """Alert-first report whose True Positive rests on a linked executed process with a sandbox verdict."""
    process = {"filePath": TOOL, "cmd": "synthetic.exe --run", "pid": pid, "hashId": "inst-synth-1",
               "launchTime": launch, "fileHashSha256": sha.lower()}
    record = {"tool": "search_endpoint_activities_list", "uuid": uuid, "event_time_utc": "2026-10-09T16:00:02.000Z",
              "endpoint_host": host, "endpoint_guid": f"guid-{host}", "process": process,
              "parent": parent or {"filePath": "C:\\Windows\\explorer.exe", "pid": 1000, "hashId": "inst-parent",
                                   "launchTime": "2026-10-09T15:00:00Z", "fileHashSha256": PARENT_SHA.lower()},
              "cut_by_bridge": []}
    verdict = {f"sandbox:{sha.lower()[:12]}": {"state": "collected", "queried_hash": sha.lower(),
                                               "items": [{"riskLevel": "high", "digest": {"sha256": sha.lower()}}]}}
    return {"alert": {"createdDateTime": "2026-10-09T16:30:00Z"},
            "assessment": {"classification": classification, "facts": ["synthetic linked execution + verdict"]},
            "extraction": {"observables": observables if observables is not None else {
                "hash": [{"value": sha.lower(), "role": "process", "sources": ["indicators[0]"], "cut_by_bridge": False}],
                "host": [{"value": host, "role": "endpoint", "sources": ["impactScope[0]"], "cut_by_bridge": False}],
                "command": [{"value": "synthetic.exe --run", "role": "process", "sources": ["indicators[1]"],
                             "cut_by_bridge": False}]}},
            "auto_pivots": {"records": {"linked": [record] if with_records else []}},
            "enrichment": verdict if with_records else {}}


def overview(report, alert_id="WB-SYNTH-2", state="collected"):
    item = {"alert_id": alert_id, "state": state,
            "association": {"temporal_check": "within window", "match_fields": ["impactScopeEntityValue"]}}
    if state == "collected":
        item["report"] = report
    else:
        item["error"] = "TimeoutError"
    return {"alerts": [{"alert_id": alert_id}],
            "deepened_alerts": {"state": "collected", "not_deepened": [], "investigations": [item]}}


def inconclusive_report():
    return {"alert": {}, "assessment": {"classification": "Inconclusive", "facts": []},
            "extraction": {"observables": {}}, "auto_pivots": {"records": {"linked": []}}, "enrichment": {}}


def process_lab():
    rows = [row(sysmon(G_PS, 4321, TOOL, "synthetic.exe --run", parent_pid=1000, hashes=f"SHA256={SHA}"),
                name="Process Create")]
    return Lab({"FROM events WHERE INOFFENSE(12345)": ("events", rows, None)})


def authorization(**scope):
    return {"requirement": "authorization", "source": "Change system", "reference": "CHG-SYNTH-41",
            "scope": {"activity": "process_execution", "entities": [HOST], **WINDOW, **scope}}


class EvidencePreservationTests(unittest.TestCase):
    """Item 1: an inconclusive or failed re-collection must not erase earlier facts."""

    def investigate(self, store, value=None, side_effect=None, include_trend=True):
        patch = mock.AsyncMock(return_value=value, side_effect=side_effect)
        with mock.patch("soc_bridge.core.investigate", patch):
            return run(investigate_offense_case(process_lab(), object() if include_trend else None, 12345,
                                                store=store, include_trend=include_trend, now=NOW))

    def test_inconclusive_recollection_keeps_the_sustained_malicious_facts(self):
        with tempfile.TemporaryDirectory() as root:
            store = CaseStore(Path(root))
            first = self.investigate(store, overview(tp_report()))
            self.assertEqual(first["decision"]["disposition"]["category"], "malicious_confirmed")
            second = self.investigate(store, overview(inconclusive_report()))
            self.assertEqual(second["decision"]["disposition"]["category"], "malicious_confirmed")
            reassessed = reassess_case("offense-12345", [], store)
            self.assertEqual(reassessed["decision"]["disposition"]["category"], "malicious_confirmed")
            alert = store.load("offense-12345")["trend"]["alerts"]["WB-SYNTH-2"]
            self.assertEqual([a["classification"] for a in alert["attempts"]], ["True Positive", "Inconclusive"])
            self.assertTrue(alert["facts"])
            self.assertTrue(all(f["status"] == "sustained" for f in alert["facts"].values()))
            self.assertEqual(alert["current"]["classification"], "True Positive")
            self.assertIn("not observed again", alert["current"]["basis"])

    def test_timeout_and_trend_failure_are_recorded_without_dropping_facts(self):
        with tempfile.TemporaryDirectory() as root:
            store = CaseStore(Path(root))
            self.investigate(store, overview(tp_report()))
            timed_out = self.investigate(store, overview(None, state="failed"))
            self.assertEqual(timed_out["decision"]["disposition"]["category"], "malicious_confirmed")
            failing = self.investigate(store, side_effect=RuntimeError("synthetic Trend failure"))
            self.assertEqual(failing["decision"]["disposition"]["category"], "malicious_confirmed")
            alert = store.load("offense-12345")["trend"]["alerts"]["WB-SYNTH-2"]
            self.assertEqual([a["state"] for a in alert["attempts"]], ["collected", "failed"])
            runs = store.load("offense-12345")["trend"]["runs"]
            self.assertEqual(runs[-1]["state"], "unavailable")

    def test_explicit_refutation_supported_by_evidence_revises_the_conclusion(self):
        with tempfile.TemporaryDirectory() as root:
            store = CaseStore(Path(root))
            self.investigate(store, overview(tp_report()))
            refuting = dict(inconclusive_report(), assessment={
                "classification": "False Positive", "facts": ["linked record shows the behavior did not occur"],
                "why": "behavior_absent confirmed by linked records"})
            revised = self.investigate(store, overview(refuting))
            self.assertNotEqual(revised["decision"]["disposition"]["category"], "malicious_confirmed")
            alert = store.load("offense-12345")["trend"]["alerts"]["WB-SYNTH-2"]
            refuted = [f for f in alert["facts"].values() if f["status"] == "refuted"]
            self.assertTrue(refuted)
            self.assertIn("False Positive", refuted[0]["refuted_by"]["basis"])
            self.assertEqual(alert["revisions"][-1]["replaced_facts"], sorted(alert["facts"]))

    def test_analyst_refutation_in_reassessment_is_recorded_as_external(self):
        with tempfile.TemporaryDirectory() as root:
            store = CaseStore(Path(root))
            self.investigate(store, overview(tp_report()))
            record = {"requirement": "trend_finding_refuted", "alert_id": "WB-SYNTH-2", "source": "IR ticket",
                      "reference": "IR-SYNTH-9", "summary": "sandbox re-analysis of the same hash: benign test file"}
            report = reassess_case("offense-12345", [record], store)
            self.assertNotEqual(report["decision"]["disposition"]["category"], "malicious_confirmed")
            alert = store.load("offense-12345")["trend"]["alerts"]["WB-SYNTH-2"]
            revision = alert["revisions"][-1]
            self.assertEqual(revision["source"], "analyst-supplied record (not verified by the bridge): IR ticket IR-SYNTH-9")
            self.assertTrue(revision["replaced_facts"])


class ActivityLinkTests(unittest.TestCase):
    """Item 2: the link must demonstrate the malicious activity itself, not a shared artifact or host."""

    def result(self, host=HOST, pid="4321", utc="2026-10-09 16:00:01.000", sha=SHA, image=TOOL,
               command="synthetic.exe --run", parent_pid="1000"):
        record = extract(row(sysmon(G_PS, int(pid), image, command, parent_pid=int(parent_pid), host=host,
                                    hashes=f"SHA256={sha}", utc=utc)), {}, [])
        record["provenance"] = {"query": "events", "scope": "offense_linked", "search_id": "s1", "result_row_index": 0,
                                "starttime_utc": "2026-10-09T16:00:05+00:00",
                                "devicetime_utc": "2026-10-09T16:00:01+00:00"}
        return {"queries": {"events": {"returned_rows": 1}}, "processes": process_chain.analyze([record])}

    def trend(self, report):
        return overview(report)["deepened_alerts"]

    def level(self, result, report):
        trend = self.trend(report)
        findings, _ = bridge_findings(result, trend)
        return trend["investigations"][0]["link"]["level"], findings

    def test_shared_parent_hash_does_not_attribute_the_malice(self):
        observables = {"hash": [{"value": PARENT_SHA.lower(), "role": "parent", "sources": ["x"], "cut_by_bridge": False}],
                       "host": [{"value": HOST, "role": "endpoint", "sources": ["y"], "cut_by_bridge": False}]}
        qradar = self.result(pid="999", sha=PARENT_SHA, image="C:\\Tools\\helper.exe", command="helper.exe")
        level, findings = self.level(qradar, tp_report(observables=observables))
        self.assertEqual(level, "candidate")
        self.assertNotIn("malicious_activity_confirmed", findings)
        self.assertFalse(findings["corroborated"])

    def test_common_binary_in_distinct_executions_is_not_the_same_activity(self):
        level, findings = self.level(self.result(pid="7777", utc="2026-10-09 16:40:00.000"), tp_report())
        self.assertEqual(level, "candidate")
        self.assertNotIn("malicious_activity_confirmed", findings)

    def test_incompatible_execution_times_stay_candidate(self):
        level, _ = self.level(self.result(utc="2026-10-09 15:05:00.000"), tp_report())
        self.assertEqual(level, "candidate")

    def test_alert_creation_time_is_not_used_as_execution_time(self):
        report = tp_report(launch=None)
        level, _ = self.level(self.result(), report)
        self.assertEqual(level, "candidate")

    def test_multi_endpoint_alert_does_not_mix_hosts_and_hashes(self):
        observables = {"hash": [{"value": SHA.lower(), "role": "process", "sources": ["a"], "cut_by_bridge": False}],
                       "host": [{"value": HOST, "role": "endpoint", "sources": ["b"], "cut_by_bridge": False},
                                {"value": OTHER_HOST, "role": "endpoint", "sources": ["c"], "cut_by_bridge": False}]}
        # The malicious execution happened on OTHER_HOST; QRadar saw the same file on HOST.
        level, findings = self.level(self.result(host=HOST), tp_report(host=OTHER_HOST, observables=observables))
        self.assertEqual(level, "candidate")
        self.assertNotIn("malicious_activity_confirmed", findings)

    def test_case_or_spacing_changes_are_not_an_exact_command(self):
        level, _ = self.level(self.result(pid="5555", command="SYNTHETIC.exe  --run"), tp_report())
        self.assertEqual(level, "candidate")

    def test_same_instance_on_the_same_host_is_demonstrated(self):
        level, findings = self.level(self.result(), tp_report())
        self.assertEqual(level, "demonstrated")
        self.assertTrue(findings["corroborated"])
        match = findings["malicious_activity_confirmed"]["link"]["matches"][0]
        self.assertEqual(match["relation"], "same_process_instance")
        self.assertEqual(match["trend_record"]["uuid"], "ev-synth-1")

    def test_demonstrated_parent_chain_is_described_explicitly(self):
        qradar = self.result(pid="1000", sha=PARENT_SHA, image="C:\\Windows\\explorer.exe", command="explorer.exe",
                             utc="2026-10-09 15:00:00.000", parent_pid="4")
        level, findings = self.level(qradar, tp_report())
        self.assertEqual(level, "demonstrated")
        match = findings["malicious_activity_confirmed"]["link"]["matches"][0]
        self.assertEqual(match["relation"], "parent_of_malicious_instance")
        self.assertIn("parent", match["description"])


def creation_records(commands):
    out = []
    for index, command in enumerate(commands):
        guid = "{%08d-1111-4111-8111-111111111111}" % index
        record = extract(row(sysmon(guid, 5000 + index, PS, command, parent_guid=G_PARENT), offset_ms=index * 10), {}, [])
        record["provenance"] = {"query": "events", "scope": "offense_linked", "search_id": "s1",
                                "result_row_index": index, "starttime_utc": "2026-10-09T16:00:01+00:00"}
        out.append(record)
    return out


def decision_result(analysis):
    return {"offense_id": 12345, "assessment": {}, "linux": {}, "gap_details": [],
            "queries": {"events": {"result_set_complete": True, "search_id": "s1", "outcome": "complete_in_window",
                                   "returned_rows": 150, "scope": "offense_linked"},
                        "flows": {"result_set_complete": True, "search_id": "s2", "outcome": "empty",
                                  "returned_rows": 0, "scope": "offense_linked"}},
            "metadata": {"status": "OPEN", "offense_source": IP},
            "events": {"observed_interval": {"start": "2026-10-09T16:00:00+00:00", "end": "2026-10-09T16:02:00+00:00"}},
            "processes": analysis,
            "closing_reasons": {"state": "collected", "reasons": [{"id": 1, "text": "Non-Issue"}]}}


class OmittedRecordsTests(unittest.TestCase):
    """Item 3: records beyond the presentation cap must be evaluated or declared not evaluated."""

    def test_unauthorized_activity_after_the_first_100_records_blocks_benign_closure(self):
        commands = [BACKUP] * 120 + [ENCODED] + [BACKUP] * 29
        analysis = process_chain.analyze(creation_records(commands))
        self.assertEqual(analysis["process_creations_omitted"], 50)
        result = closure_assessment.propose(decision_result(analysis), [authorization(processes=["powershell.exe"],
                                                                                      command_lines=[BACKUP])])
        self.assertFalse(result["ready_to_close"])
        evidence = result["requirements"]["authorization"]["evidence"]
        self.assertEqual(result["requirements"]["authorization"]["status"], "compatible")
        self.assertEqual(evidence["uncovered_count"], 1)
        self.assertIn("EncodedCommand", evidence["uncovered_instances"][0]["process"]["command_line"])
        self.assertEqual(len(evidence["covered_instances"]), 149)

    def test_population_above_the_analysis_cap_is_declared_not_evaluated(self):
        commands = [BACKUP] * 30
        with mock.patch("soc_bridge.process_chain.ANALYSIS_CAP", 20):
            analysis = process_chain.analyze(creation_records(commands))
        result = closure_assessment.propose(decision_result(analysis), [authorization(processes=["powershell.exe"],
                                                                                      command_lines=[BACKUP])])
        self.assertFalse(result["ready_to_close"])
        evidence = result["requirements"]["authorization"]["evidence"]
        self.assertEqual(evidence["instances_not_evaluated"]["process_execution"]["count"], 10)
        self.assertIn("analysis cap", evidence["instances_not_evaluated"]["process_execution"]["reason"])
        self.assertTrue(evidence["instances_not_evaluated"]["process_execution"]["next_action"])

    def test_assess_closure_path_uses_all_rows_not_witness_samples(self):
        flows = [{"firstpackettime": MS + i, "sourceip": IP, "destinationip": f"198.51.100.{i + 1}",
                  "destinationport": 443, "protocolid": 6} for i in range(20)]
        lab = Lab({"FROM flows WHERE INOFFENSE(12345)": ("flows", flows, None)})
        evidence = run(collect_offense_evidence(lab, offense(), now=NOW, budget=Budget(max_seconds=30)))
        instances = evidence["closure_assessment"]["observed_activity"]["instances"]
        destinations = {e for i in instances if i["activity"] == "network_traffic" for e in i["entities"]}
        self.assertEqual(len(destinations - {IP}), 20)


class BehaviorAuthorizationTests(unittest.TestCase):
    """Item 4: an authorization names a behavior, not only an executable."""

    def analysis(self, commands):
        return process_chain.analyze(creation_records(commands))

    def test_interpreter_name_alone_is_not_an_authorization(self):
        with self.assertRaisesRegex(ValueError, "behavior"):
            validate_scope({"activity": "process_execution", "entities": [HOST], "processes": ["powershell.exe"], **WINDOW})
        with self.assertRaisesRegex(ValueError, "interpreter"):
            validate_scope({"activity": "process_execution", "entities": [HOST], "processes": ["powershell.exe"],
                            "artifact_hashes": [SHA], **WINDOW})

    def test_backup_authorization_does_not_cover_another_command_of_the_same_interpreter(self):
        result = closure_assessment.propose(decision_result(self.analysis([BACKUP, ENCODED])),
                                            [authorization(processes=["powershell.exe"], script_paths=["C:\\ops\\backup.ps1"])])
        evidence = result["requirements"]["authorization"]["evidence"]
        self.assertFalse(result["ready_to_close"])
        self.assertEqual(evidence["uncovered_count"], 1)
        self.assertIn("EncodedCommand", evidence["uncovered_instances"][0]["process"]["command_line"])

    def test_different_scripts_and_significant_arguments_are_not_covered(self):
        commands = [BACKUP, "powershell.exe -NoProfile -File C:\\ops\\wipe.ps1",
                    "powershell.exe -NoProfile -File C:\\ops\\backup.ps1 -Target \\\\other\\share",
                    "powershell.exe -NoProfile -file c:\\ops\\backup.ps1"]
        result = closure_assessment.propose(decision_result(self.analysis(commands)),
                                            [authorization(processes=["powershell.exe"], command_lines=[BACKUP])])
        evidence = result["requirements"]["authorization"]["evidence"]
        self.assertEqual(evidence["uncovered_count"], 3)
        scripted = closure_assessment.propose(decision_result(self.analysis(commands)),
                                              [authorization(processes=["powershell.exe"],
                                                             script_paths=["C:\\ops\\backup.ps1"])])
        uncovered = [u["process"]["command_line"] for u in scripted["requirements"]["authorization"]["evidence"]["uncovered_instances"]]
        self.assertEqual(sorted(uncovered), sorted(commands[1:3]))

    def test_explicit_broad_authorization_is_declared_in_the_report(self):
        broad = authorization(processes=["powershell.exe"], breadth="any_behavior_of_named_processes",
                              breadth_basis="CHG-SYNTH-41 authorizes any PowerShell use by the patching team on this host")
        result = closure_assessment.propose(decision_result(self.analysis([BACKUP, ENCODED])), [broad])
        self.assertEqual(result["requirements"]["authorization"]["status"], "confirmed")
        self.assertIn("broad", " ".join(result["requirements"]["authorization"]["evidence"]["broad_authorizations"][0]["declared"]))
        self.assertIn("autorização abrangente", result["suggested_note"])

    def test_sudo_check_does_not_authorize_other_privileged_commands(self):
        def sudo(command, offset):
            return {"starttime": MS + offset, "devicetime": MS + offset, "sourceip": IP, "log_source": "Synthetic Linux",
                    "event_name": "sudo", "raw_payload": f"db-01 sudo: oracle : TTY=pts/0 ; PWD=/home/oracle ; "
                                                          f"USER=root ; COMMAND={command}"}
        rows = [sudo("/usr/bin/systemctl status oracle-db", 0), sudo("/bin/bash", 1000)]
        lab = Lab({"FROM events WHERE INOFFENSE(12345)": ("events", rows, None)})
        record = {"requirement": "authorization", "source": "Change system", "reference": "CHG-SYNTH-42",
                  "scope": {"activity": "privilege_use", "entities": ["db-01", "oracle"], **WINDOW,
                            "commands": ["/usr/bin/systemctl status oracle-db"], "run_as": ["root"]}}
        evidence = run(collect_offense_evidence(lab, offense(), now=NOW, budget=Budget(max_seconds=30),
                                                confirmations=[record]))
        requirement = evidence["closure_assessment"]["requirements"]["authorization"]
        self.assertNotEqual(requirement["status"], "confirmed")
        uncovered = [u["process"]["command"] for u in requirement["evidence"]["uncovered_instances"]
                     if u["activity"] == "privilege_use"]
        self.assertEqual(uncovered, ["/bin/bash"])


class FrozenClock:
    def __call__(self):
        return 0.0


class DeadlineTests(unittest.IsolatedAsyncioTestCase):
    """Item 5: once a call was cut at the deadline, no new upstream call may start."""

    async def test_a_deadline_cut_closes_the_budget_even_if_the_budget_clock_lags(self):
        budget = Budget(max_seconds=0.05, clock=FrozenClock())  # asyncio fires; the budget clock never advances

        async def forever():
            await asyncio.Event().wait()
        with self.assertRaises(BudgetExhausted):
            await budget.run(forever, "slow read")
        self.assertIsNotNone(budget.blocked("query"))
        self.assertLessEqual(budget.remaining_seconds(), 0)
        with self.assertRaises(BudgetExhausted) as caught:
            await budget.run(forever, "next read")
        self.assertFalse(caught.exception.started)

    async def test_lagging_clock_starts_no_validation_creation_or_rule_read(self):
        class SlowCatalog(Lab):
            async def read_aql_resource(self, resource):
                await asyncio.sleep(5)

        lab = SlowCatalog({"FROM events": ("events", [], None)}, catalog={})
        await collect_offense_evidence(lab, offense(), now=NOW, budget=Budget(max_seconds=0.05, clock=FrozenClock()))
        names = [name for name, _ in lab.calls]
        self.assertFalse({"validate_aql", "create_ariel_search", "get_rule"} & set(names), names)

    async def test_floating_point_residue_after_a_cut_starts_no_call(self):
        # With these clock readings, start + allowed - elapsed leaves ~9e-14 s "remaining" after the cut
        # (the CI failure on windows-latest): the cut must close the budget as state, not arithmetic.
        class Readings:
            def __init__(self):
                self.values = iter([1323.833])

            def __call__(self):
                return next(self.values, 1323.855)

        budget = Budget(max_seconds=0.1, clock=Readings())

        async def forever():
            await asyncio.Event().wait()
        with self.assertRaises(BudgetExhausted):
            await budget.run(forever, "slow read")
        self.assertEqual(budget.remaining_seconds(), 0)
        self.assertEqual(budget.blocked("query"), "time budget exhausted")

        class SlowCatalog(Lab):
            async def read_aql_resource(self, resource):
                await asyncio.sleep(5)

        lab = SlowCatalog({"FROM events": ("events", [], None)}, catalog={})
        await collect_offense_evidence(lab, offense(), now=NOW, budget=Budget(max_seconds=0.1, clock=Readings()))
        names = [name for name, _ in lab.calls]
        self.assertFalse({"validate_aql", "create_ariel_search", "get_rule"} & set(names), names)

    async def test_reserved_phase_time_is_released_when_the_phase_is_entered(self):
        budget = Budget(max_seconds=0.4, clock=FrozenClock())
        budget.reserve("correlation", seconds=0.3)

        async def forever():
            await asyncio.Event().wait()
        with self.assertRaises(BudgetExhausted):
            await budget.run(forever, "primary read")
        self.assertIsNotNone(budget.blocked("call"))  # the primary phase used its share
        budget.enter("correlation")
        self.assertIsNone(budget.blocked("call"))  # the reserved later phase still has its time
        began = time.perf_counter()
        with self.assertRaises(BudgetExhausted):
            await budget.run(forever, "correlation read")
        self.assertGreater(time.perf_counter() - began, 0.2)
