"""Regression tests for the review of the persistent case flow (one class per finding).

All data is synthetic. No QRadar or Vision One is contacted; Trend results are mocked.
"""

import asyncio
import multiprocessing
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from soc_bridge import closure_assessment
from soc_bridge.ariel_collection import Budget
from soc_bridge.case_investigation import bridge_findings, investigate_offense_case, reassess_case
from soc_bridge.case_store import CaseConflict, CaseStore, merge_query
from soc_bridge.closure_scope import validate_scope
from soc_bridge.offense_evidence import collect_offense_evidence, resume_mismatch

from synthetic_lab import G_OTHER, G_PS, HOST, IP, MS, NOW, SHA, Lab, offense, row, sysmon
from test_case_review_round2 import tp_report

OTHER_HOST = "ws-demo-02.example.test"
WINDOW = {"window_start": "2026-10-09T15:00:00+00:00", "window_end": "2026-10-09T17:00:00+00:00"}


def run(coro):
    return asyncio.run(coro)


def plain_rows(count=7):
    return [{"starttime": MS + i * 1000, "devicetime": MS + i * 1000, "sourceip": IP, "event_name": f"Synthetic {i}",
             "log_source": "Synthetic WinCollect", "raw_payload": f"synthetic payload {i}", "qid": 100 + i}
            for i in range(count)]


def process_rows():
    return [row(sysmon(G_PS, 4321, "C:\\Tools\\synthetic.exe", "synthetic.exe --run", parent_pid=1000,
                       hashes=f"SHA256={SHA}"), name="Process Create")]


def trend_overview(alert_id="WB-SYNTH-2", host=HOST, classification="True Positive", with_ids=True):
    # The True Positive rests on a linked executed instance with a sandbox verdict (see test_case_review_round2).
    report = tp_report(host=host, classification=classification, with_records=with_ids,
                       observables=None if with_ids else {})
    return {"alerts": [{"alert_id": alert_id}], "deepened_alerts": {
        "state": "collected", "not_deepened": [], "investigations": [
            {"alert_id": alert_id, "state": "collected", "report": report,
             "association": {"temporal_check": "within window", "match_fields": ["impactScopeEntityValue"]}}]}}


def authorization(reference="CHG-SYNTH-21", entities=(HOST,), processes=("synthetic.exe",),
                  command_lines=("synthetic.exe --run",), **extra):
    extra.setdefault("command_lines", list(command_lines))
    return {"requirement": "authorization", "source": "Change system", "reference": reference,
            "scope": {"activity": "process_execution", "entities": list(entities), "processes": list(processes),
                      **WINDOW, **extra}}


class ReassessmentKeepsTrendEvidenceTests(unittest.TestCase):
    """Finding 1: a reassessment reused only QRadar and could drop Trend evidence of malice."""

    def test_reassessment_and_later_runs_keep_the_linked_true_positive(self):
        lab = Lab({"INOFFENSE(12345)": ("events", process_rows(), None)})
        with tempfile.TemporaryDirectory() as root:
            store = CaseStore(Path(root))
            with mock.patch("soc_bridge.core.investigate", mock.AsyncMock(return_value=trend_overview())):
                first = run(investigate_offense_case(lab, object(), 12345, store=store, now=NOW))
            self.assertEqual(first["decision"]["disposition"]["category"], "malicious_confirmed")
            self.assertEqual(first["related_alerts"][0]["link"], "demonstrated")
            self.assertEqual(first["confidence"]["level"], "high")
            calls = len(lab.calls)
            reassessed = reassess_case("offense-12345", [authorization()], store)
            self.assertEqual(len(lab.calls), calls)
            self.assertEqual(reassessed["reassessment"]["trend_results_reused"], ["WB-SYNTH-2"])
            self.assertEqual(reassessed["decision"]["disposition"]["category"], "malicious_confirmed")
            self.assertFalse(reassessed["decision"]["ready_to_close"])
            self.assertIsNone(reassessed["decision"]["recommended_reason"])
            authorized = next(d for d in reassessed["closure"]["disposition_matrix"] if d["id"] == "authorized_activity")
            self.assertEqual(authorized["sufficiency"], "contradicted")
            # A later run without Trend, or with Trend failing, keeps the stored alert result.
            later = run(investigate_offense_case(lab, None, 12345, store=store, include_trend=False, now=NOW))
            self.assertEqual(later["decision"]["disposition"]["category"], "malicious_confirmed")
            with mock.patch("soc_bridge.core.investigate", mock.AsyncMock(side_effect=RuntimeError("synthetic"))):
                failing = run(investigate_offense_case(lab, object(), 12345, store=store, now=NOW))
            self.assertEqual(failing["decision"]["disposition"]["category"], "malicious_confirmed")
            trend = store.load("offense-12345")["trend"]
            self.assertEqual(trend["alerts"]["WB-SYNTH-2"]["current"]["classification"], "True Positive")
            self.assertEqual([r["state"] for r in trend["runs"]], ["collected", "not_requested", "unavailable"])


class OffenseIsolationTests(unittest.TestCase):
    """Finding 2: a case_id reused for another offense resumed the first offense's jobs."""

    def test_case_bound_to_another_offense_is_rejected_before_any_call(self):
        lab = Lab({"INOFFENSE(12345)": ("events", plain_rows(), None)}, offenses={12345: offense(), 777: offense(777)})
        with tempfile.TemporaryDirectory() as root:
            store = CaseStore(Path(root))
            run(investigate_offense_case(lab, None, 12345, case_id="shared-case", store=store, include_trend=False,
                                         budget=Budget(max_seconds=30, page_size=2, max_pages=1), now=NOW))
            calls = len(lab.calls)
            with self.assertRaisesRegex(ValueError, "belongs to offense 12345"):
                run(investigate_offense_case(lab, None, 777, case_id="shared-case", store=store, include_trend=False,
                                             now=NOW))
            self.assertEqual(len(lab.calls), calls)
            self.assertEqual(store.load("shared-case")["offense_id"], 12345)

    def test_saved_job_of_another_offense_or_query_is_never_continued(self):
        lab = Lab({"INOFFENSE(777)": ("events", plain_rows(2), None)}, offenses={777: offense(777)})
        saved = {"offense_id": 12345, "database": "events", "scope": "offense_linked", "search_id": "job-of-12345",
                 "aql": "SELECT * FROM events WHERE INOFFENSE(12345)", "outcome": "partial", "state": "COMPLETED",
                 "next_start": 2, "rows": plain_rows(2)}
        result = run(collect_offense_evidence(lab, offense(777), now=NOW, resume={"events": saved}))
        touched = [a for n, a in lab.calls if isinstance(a, dict) and a.get("search_id") == "job-of-12345"]
        self.assertEqual(touched, [])
        resume = result["queries"]["events"]["resume"]
        self.assertEqual(resume["action"], "not_resumed_state_mismatch")
        self.assertIn("offense_id", resume["mismatched"])
        self.assertEqual(result["queries"]["events"]["offense_id"], 777)
        self.assertEqual(resume_mismatch({**saved, "offense_id": 777, "aql": "q"}, 777, "q", None, "events",
                                         "offense_linked"), [])
        self.assertEqual(resume_mismatch({**saved, "offense_id": 777, "aql": "q"}, 777, "q", None, "flows",
                                         "offense_linked"), ["database"])
        self.assertEqual(resume_mismatch({**saved, "offense_id": 777}, 777, "q", "q2", "events", "context"),
                         ["scope", "aql"])


class BlockingLab(Lab):
    """Blocks forever on the first call matching ``block_at`` until the task is cancelled."""

    def __init__(self, routes, block_at, **kw):
        super().__init__(routes, **kw)
        self.block_at = block_at
        self.blocking = True
        self.reached = None

    async def call(self, name, args):
        if self.blocking and self.block_at(name, args):
            self.calls.append((name, args))
            self.reached.set()
            await asyncio.Event().wait()
        return await super().call(name, args)


def events_jobs(lab):
    return [a for n, a in lab.calls if n == "create_ariel_search" and "INOFFENSE(12345)" in a["query_expression"]
            and "FROM events" in a["query_expression"]]


class CheckpointCancellationTests(unittest.TestCase):
    """Finding 3: progress was saved only after the whole QRadar collection."""

    def cancel_when_blocked(self, lab, store, **kw):
        async def scenario():
            lab.reached = asyncio.Event()
            task = asyncio.create_task(investigate_offense_case(lab, None, 12345, store=store, include_trend=False,
                                                                now=NOW, **kw))
            await asyncio.wait_for(lab.reached.wait(), 20)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        run(scenario())

    def test_cancelling_during_pagination_keeps_job_cursor_and_rows_and_resumes_without_new_job(self):
        lab = BlockingLab({"INOFFENSE(12345)": ("events", plain_rows(7), None)},
                          lambda n, a: n == "get_ariel_search_results" and a["search_id"] == "synthetic-job-0"
                          and a["start"] >= 4)
        with tempfile.TemporaryDirectory() as root:
            budget = lambda: Budget(max_seconds=30, page_size=2, max_pages=20)  # noqa: E731
            self.cancel_when_blocked(lab, CaseStore(Path(root)), budget=budget())
            case = CaseStore(Path(root)).load("offense-12345")
            saved = case["queries"]["events"]
            self.assertEqual(saved["search_id"], "synthetic-job-0")
            self.assertEqual(saved["next_start"], 4)
            self.assertEqual(saved["rows_stored"], 4)
            self.assertEqual(saved["outcome"], "partial")
            self.assertEqual(saved["checkpoint"], "page")
            self.assertIn("cancelled", case["runs"][-1]["stage"])
            self.assertEqual(len(events_jobs(lab)), 1)
            lab.blocking = False
            report = run(investigate_offense_case(lab, None, 12345, store=CaseStore(Path(root)), include_trend=False,
                                                  budget=budget(), now=NOW))
            self.assertEqual(len(events_jobs(lab)), 1)  # same job, never recreated
            events = report["coverage"]["events"]
            self.assertEqual((events["search_id"], events["resume"], events["outcome"], events["rows"]),
                             ("synthetic-job-0", "continued_same_search", "complete_in_window", 7))
            reads = [a["start"] for n, a in lab.calls if n == "get_ariel_search_results"
                     and a["search_id"] == "synthetic-job-0"]
            self.assertEqual(reads[-2:], [4, 6])  # continued from the saved cursor
            case = CaseStore(Path(root)).load("offense-12345")
            linked = [e for e in case["evidence"].values() if e["tier"] == "offense_associated"]
            self.assertEqual(len(linked), 7)
            self.assertTrue(all(len(e["seen_in"]) == 1 for e in linked))

    def test_cancelling_during_creation_keeps_creation_uncertain_and_never_recreates(self):
        lab = BlockingLab({"INOFFENSE(12345)": ("events", plain_rows(3), None)},
                          lambda n, a: n == "create_ariel_search" and "INOFFENSE(12345)" in a["query_expression"]
                          and "FROM events" in a["query_expression"])
        with tempfile.TemporaryDirectory() as root:
            self.cancel_when_blocked(lab, CaseStore(Path(root)))
            saved = CaseStore(Path(root)).load("offense-12345")["queries"]["events"]
            self.assertEqual((saved["outcome"], saved["checkpoint"], saved.get("search_id")),
                             ("creation_uncertain", "creating", None))
            lab.blocking = False
            report = run(investigate_offense_case(lab, None, 12345, store=CaseStore(Path(root)), include_trend=False,
                                                  now=NOW))
            self.assertEqual(len(events_jobs(lab)), 1)  # only the cancelled attempt
            self.assertEqual(report["coverage"]["events"]["resume"], "requires_resolution")

    def test_case_is_saved_before_the_first_upstream_call(self):
        lab = BlockingLab({}, lambda n, a: n == "get_offense")
        with tempfile.TemporaryDirectory() as root:
            self.cancel_when_blocked(lab, CaseStore(Path(root)))
            case = CaseStore(Path(root)).load("offense-12345")
            self.assertEqual(case["offense_id"], 12345)
            self.assertIn("cancelled", case["runs"][0]["stage"])
            self.assertEqual(case["queries"], {})


class CorrelationTests(unittest.TestCase):
    """Finding 4: a True Positive related only by IP/time confirmed malice and raised confidence."""

    def result(self, host=HOST, scope="offense_linked"):
        return {"queries": {"events": {"returned_rows": 25}}, "processes": {"process_instances": [{
            "host_norm": host, "command_line": "synthetic.exe --run", "image": "C:\\Tools\\synthetic.exe",
            "pid": "4321", "utc_time": "2026-10-09 16:00:01.000", "hashes": {"SHA256": SHA},
            "provenance": {"query": "events", "scope": scope, "search_id": "s1", "result_row_index": 0}}]}}

    def trend(self, **kw):
        trend = trend_overview(**kw)["deepened_alerts"]
        for item in trend["investigations"]:
            item["report"]["identifiers"] = None
        return trend

    def test_ip_time_only_true_positive_neither_confirms_nor_corroborates(self):
        for label, result, trend in (
                ("no identifiers", self.result(), self.trend(with_ids=False)),
                ("same hash on another host", self.result(host=OTHER_HOST), self.trend()),
                ("match only in host context", self.result(scope="host_ip_time_context"), self.trend())):
            with self.subTest(label):
                findings, contradictions = bridge_findings(result, trend)
                self.assertNotIn("malicious_activity_confirmed", findings)
                self.assertFalse(findings["corroborated"])  # QRadar rows exist but do not corroborate
                self.assertEqual(contradictions[0]["status"], "unresolved")
                self.assertEqual(trend["investigations"][0]["link"]["level"], "candidate")

    def test_shared_identifier_on_the_same_host_demonstrates_the_link(self):
        findings, contradictions = bridge_findings(self.result(), self.trend())
        self.assertTrue(findings["corroborated"])
        self.assertEqual(contradictions, [])
        link = findings["malicious_activity_confirmed"]["link"]
        self.assertEqual(link["level"], "demonstrated")
        self.assertEqual(set(link["matches"][0]["shared_identifiers"]),
                         {"file hash (sha256)", "identical image path", "process ID",
                          "identical command line (original string)", "compatible execution time"})

    def test_uncorroborated_analyst_malice_record_is_not_high_confidence(self):
        base = ScopeTests().result()
        record = {"requirement": "malicious_activity_confirmed", "source": "IR ticket", "reference": "IR-SYNTH-3",
                  "scope": {"activity": "process_execution", "entities": [HOST], "processes": ["powershell.exe"],
                            "command_lines": ["powershell.exe -File C:\\ops\\backup.ps1"], **WINDOW}}
        result = closure_assessment.propose(base, [record], [], {"corroborated": False})
        self.assertEqual(result["disposition"]["category"], "malicious_confirmed")
        self.assertEqual(result["confidence_detail"]["level"], "moderate")


class ScopeTests(unittest.TestCase):
    """Finding 5: authorizing process_execution on one host covered other hosts and commands."""

    def creation(self, host, image, command, index, parent="C:\\Windows\\explorer.exe"):
        return {"host_norm": host, "guid_norm": f"g{index}", "image": image, "command_line": command,
                "fields": {"ParentImage": {"value": parent, "source": "payload"}},
                "provenance": {"query": "events", "scope": "offense_linked", "search_id": "s1",
                               "result_row_index": index, "starttime_utc": "2026-10-09T16:00:01+00:00"}}

    def result(self):
        ps = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        return {"offense_id": 12345, "assessment": {}, "linux": {}, "gap_details": [],
                "queries": {"events": {"result_set_complete": True, "search_id": "s1", "outcome": "complete_in_window",
                                       "returned_rows": 3, "scope": "offense_linked"},
                            "flows": {"result_set_complete": True, "search_id": "s2", "outcome": "empty",
                                      "returned_rows": 0, "scope": "offense_linked"}},
                "metadata": {"status": "OPEN", "offense_source": IP},
                "events": {"observed_interval": {"start": "2026-10-09T16:00:00+00:00", "end": "2026-10-09T16:02:00+00:00"}},
                "processes": {"process_creations": [
                    self.creation(HOST, ps, "powershell.exe -File C:\\ops\\backup.ps1", 0),
                    self.creation(OTHER_HOST, ps, "powershell.exe -File C:\\ops\\backup.ps1", 1),
                    self.creation(HOST, "C:\\Windows\\System32\\cmd.exe", "cmd.exe /c whoami", 2)]},
                "closing_reasons": {"state": "collected", "reasons": [{"id": 1, "text": "Non-Issue"}]}}

    def test_each_instance_needs_its_own_entity_process_and_window(self):
        record = authorization(processes=("powershell.exe",), command_lines=("powershell.exe -File C:\\ops\\backup.ps1",))
        result = closure_assessment.propose(self.result(), [record])
        evidence = result["requirements"]["authorization"]["evidence"]
        self.assertFalse(result["ready_to_close"])
        self.assertEqual(result["requirements"]["authorization"]["status"], "compatible")
        self.assertEqual(list(evidence["covered_instances"].values()), ["CHG-SYNTH-21"])
        uncovered = {u["id"]: u["reason"] for u in evidence["uncovered_instances"]}
        self.assertEqual(len(uncovered), 2)
        self.assertTrue(any(OTHER_HOST in k and "entity" in v for k, v in uncovered.items()))
        self.assertTrue(any("process cmd.exe not named" in v for v in uncovered.values()))
        self.assertTrue(all(u["process"]["command_line"] for u in evidence["uncovered_instances"]))
        self.assertIn("2 uncovered instance(s)", result["requirements"]["authorization"]["next_check"])

    def test_command_line_and_parent_restrictions_are_enforced(self):
        narrow = authorization(entities=(HOST, OTHER_HOST), processes=("powershell.exe", "cmd.exe"),
                               command_lines=("powershell.exe -File C:\\ops\\backup.ps1",))
        evidence = closure_assessment.propose(self.result(), [narrow])["requirements"]["authorization"]["evidence"]
        self.assertEqual(len(evidence["covered_instances"]), 2)
        self.assertIn("command line not identical", evidence["uncovered_instances"][0]["reason"])
        both = ("powershell.exe -File C:\\ops\\backup.ps1", "cmd.exe /c whoami")
        parent = authorization(entities=(HOST, OTHER_HOST), processes=("powershell.exe", "cmd.exe"),
                               command_lines=both, parent_processes=["services.exe"])
        evidence = closure_assessment.propose(self.result(), [parent])["requirements"]["authorization"]["evidence"]
        self.assertEqual(evidence["covered_instances"], {})
        full = authorization(entities=(HOST, OTHER_HOST), processes=("powershell.exe", "cmd.exe"), command_lines=both)
        result = closure_assessment.propose(self.result(), [full])
        self.assertEqual(result["requirements"]["authorization"]["status"], "confirmed")
        self.assertTrue(result["ready_to_close"])

    def test_process_scope_requires_named_processes(self):
        with self.assertRaisesRegex(ValueError, "scope.processes is required"):
            validate_scope({"activity": "process_execution", "entities": [HOST], **WINDOW})
        with self.assertRaisesRegex(ValueError, "script_block_ids is required"):
            validate_scope({"activity": "script_execution", "entities": [HOST], **WINDOW})
        with self.assertRaisesRegex(ValueError, "do not apply to a network_traffic scope"):
            validate_scope({"activity": "network_traffic", "entities": [IP], "processes": ["x.exe"], **WINDOW})


class SlowStore(CaseStore):
    """Widens the gap between the revision check and the replace to expose lost updates."""

    def _before_write(self):
        time.sleep(0.4)


def _concurrent_writer(root, label, barrier, results):
    store = SlowStore(Path(root))
    case = store.load("offense-12345")
    barrier.wait()
    try:
        store.save({**case, "pending": [label]}, case["revision"])
        results.put((label, "saved"))
    except CaseConflict:
        results.put((label, "conflict"))


class ConcurrencyTests(unittest.TestCase):
    """Finding 6: read/compare/write of the revision was not atomic across processes."""

    def test_two_processes_writing_the_same_revision_cannot_both_succeed(self):
        with tempfile.TemporaryDirectory() as root:
            CaseStore(Path(root)).save(CaseStore.new("offense-12345", offenses=[12345]), 0)
            context = multiprocessing.get_context("spawn")
            barrier, results = context.Barrier(2), context.Queue()
            workers = [context.Process(target=_concurrent_writer, args=(root, label, barrier, results))
                       for label in ("writer-a", "writer-b")]
            for worker in workers:
                worker.start()
            outcomes = dict(results.get(timeout=60) for _ in workers)
            for worker in workers:
                worker.join(30)
            self.assertEqual(sorted(outcomes.values()), ["conflict", "saved"])
            final = CaseStore(Path(root)).load("offense-12345")
            winner = next(label for label, outcome in outcomes.items() if outcome == "saved")
            self.assertEqual((final["revision"], final["pending"]), (2, [winner]))

    def test_threads_in_one_process_are_serialized_too(self):
        with tempfile.TemporaryDirectory() as root:
            store = SlowStore(Path(root))
            store.save(CaseStore.new("offense-12345", offenses=[12345]), 0)
            case = store.load("offense-12345")

            async def both():
                async def write(label):
                    try:
                        await asyncio.to_thread(store.save, {**case, "pending": [label]}, case["revision"])
                        return "saved"
                    except CaseConflict:
                        return "conflict"
                return sorted(await asyncio.gather(write("a"), write("b")))
            self.assertEqual(run(both()), ["conflict", "saved"])


class DeduplicationTests(unittest.TestCase):
    """Finding 7: payload-less records with different properties were merged."""

    def test_records_without_enough_identity_are_never_merged(self):
        case = CaseStore.new("c1")
        base = {"starttime": MS, "log_source": "Synthetic Sysmon", "qid": 1, "Computer": HOST}
        merge_query(case, "events", {"database": "events", "scope": "offense_linked", "search_id": "s1"},
                    [dict(base, ProcessGuid=G_PS), dict(base, ProcessGuid=G_OTHER)], "run-1")
        self.assertEqual(len(case["evidence"]), 2)
        merge_query(case, "host_context", {"database": "events", "scope": "host_ip_time_context", "search_id": "s2"},
                    [dict(base, ProcessGuid=G_PS)], "run-1")
        self.assertEqual(len(case["evidence"]), 3)  # identical payload-less row from another query: not merged
        self.assertTrue(all("insufficient identity" in e["identity"] for e in case["evidence"].values()))
        self.assertEqual(sorted(r["query"] for e in case["evidence"].values() for r in e["seen_in"]),
                         ["events", "events", "host_context"])

    def test_same_payload_with_different_properties_stays_separate(self):
        case = CaseStore.new("c1")
        base = {"starttime": MS, "devicetime": MS, "log_source": "Synthetic Sysmon", "qid": 1, "raw_payload": "p"}
        merge_query(case, "events", {"database": "events", "scope": "offense_linked", "search_id": "s1"},
                    [dict(base, ProcessGuid=G_PS)], "run-1")
        result = merge_query(case, "parent_lookup_1", {"database": "events", "scope": "parent_process_lookup",
                                                       "search_id": "s2"}, [dict(base, ProcessGuid=G_OTHER)], "run-1")
        self.assertEqual((len(case["evidence"]), result["kept_apart_by_properties"]), (2, 1))
        merge_query(case, "host_context", {"database": "events", "scope": "host_ip_time_context", "search_id": "s3"},
                    [dict(base, ProcessGuid=G_PS)], "run-1")
        shared = next(e for e in case["evidence"].values() if e["properties"].get("ProcessGuid") == G_PS)
        self.assertEqual([r["query"] for r in shared["seen_in"]], ["events", "host_context"])

    def test_replaced_jobs_keep_their_provenance_in_history(self):
        case = CaseStore.new("c1")
        merge_query(case, "events", {"database": "events", "scope": "offense_linked", "search_id": "s1", "aql": "a1",
                                     "outcome": "partial"}, plain_rows(1), "run-1", 12345)
        merge_query(case, "events", {"database": "events", "scope": "offense_linked", "search_id": "s2", "aql": "a2",
                                     "outcome": "complete_in_window"}, plain_rows(1), "run-2", 12345)
        history = case["queries"]["events"]["history"]
        self.assertEqual((history[0]["search_id"], history[0]["aql"], history[0]["offense_id"]), ("s1", "a1", 12345))
        evidence = next(iter(case["evidence"].values()))
        self.assertEqual([r["search_id"] for r in evidence["seen_in"]], ["s1", "s2"])


class TimezoneTests(unittest.TestCase):
    """Finding 8: confirmation dates without a timezone were silently read as UTC."""

    def test_local_or_ambiguous_times_are_rejected(self):
        for value in ("2026-10-09T14:00:00", "2026-10-09 14:00:00", "2026-10-09", 1791561600000, "14:00", None):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "explicit timezone"):
                validate_scope({"activity": "offense_activity", "entities": [IP], "window_start": value,
                                "window_end": "2026-10-09T17:00:00Z"})

    def test_explicit_offsets_are_converted_to_utc(self):
        scope = validate_scope({"activity": "offense_activity", "entities": [IP],
                                "window_start": "2026-10-09T13:00:00-03:00", "window_end": "2026-10-09T17:00:00Z"})
        self.assertEqual((scope["window_start"], scope["window_end"]),
                         ("2026-10-09T16:00:00+00:00", "2026-10-09T17:00:00+00:00"))
        with self.assertRaisesRegex(ValueError, "explicit timezone"):
            closure_assessment.validate_confirmations([{
                "requirement": "authorization", "source": "Change system", "reference": "CHG-SYNTH-30",
                "scope": {"activity": "offense_activity", "entities": [IP], "window_start": "2026-10-09T13:00:00",
                          "window_end": "2026-10-09T17:00:00"}}], 12345)


if __name__ == "__main__":
    unittest.main()
