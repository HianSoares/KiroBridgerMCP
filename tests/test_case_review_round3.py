"""Third review round: conflicting hashes, PID reuse in process chains, and refutations of a single link.

All data is synthetic. No QRadar or Vision One is contacted; Trend results are mocked. The first
assertion of each scenario checks the observable behavior (link level, disposition, fact status),
so the tests fail on the earlier implementation by behavior.
"""

import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from soc_bridge import process_chain
from soc_bridge.case_investigation import bridge_findings, investigate_offense_case, reassess_case
from soc_bridge.case_store import CaseStore
from soc_bridge.windows_events import extract

from synthetic_lab import HOST, NOW, SHA, Lab, row, sysmon
from test_case_review_round2 import overview, tp_report

OTHER_HOST = "ws-demo-02.example.test"
MAL = "C:\\Tools\\synthetic.exe"
CMD = "synthetic.exe --run"
OTHER_SHA = "EF" * 32
PARENT_SHA = "CD" * 32
LAUNCHER = "C:\\Tools\\launcher.exe"
LAUNCHER_SHA = "12" * 32
GUID_A = "{aaaaaaaa-1111-4111-8111-111111111111}"
GUID_B = "{bbbbbbbb-2222-4222-8222-222222222222}"
GUID_C = "{cccccccc-3333-4333-8333-333333333333}"


def run(coro):
    return asyncio.run(coro)


def group(pid, launch, image=MAL, cmd=CMD, sha=SHA, instance="inst-mal", key="hashId", **extra):
    out = {"filePath": image, "cmd": cmd, "pid": pid, key: instance, "launchTime": launch, **extra}
    if sha:
        out["fileHashSha256"] = sha.lower()
    return out


def trend_raw(process, parent=None, obj=None, host=HOST, verdict=SHA, alert="WB-SYNTH-3",
              event_time="2026-10-09T16:00:02.000Z"):
    record = {"tool": "search_endpoint_activities_list", "uuid": "ev-r3-1", "event_time_utc": event_time,
              "endpoint_host": host, "endpoint_guid": f"guid-{host}", "process": process, "cut_by_bridge": []}
    if parent:
        record["parent"] = parent
    if obj:
        record["object"] = obj
    report = {"alert": {"createdDateTime": "2026-10-09T16:30:00Z"},
              "assessment": {"classification": "True Positive", "facts": ["synthetic execution + verdict"]},
              "extraction": {"observables": {}}, "auto_pivots": {"records": {"linked": [record]}},
              "enrichment": {"sandbox:r3": {"state": "collected", "queried_hash": verdict.lower(),
                                            "items": [{"riskLevel": "high", "digest": {"sha256": verdict.lower()}}]}}}
    return {"state": "collected", "not_deepened": [], "investigations": [{
        "alert_id": alert, "state": "collected", "report": report,
        "association": {"temporal_check": "within window", "match_fields": ["impactScopeEntityValue"]}}]}


def qrec(guid, pid, image, cmd, utc, scope="offense_linked", host=HOST, hashes=f"SHA256={SHA}", parent_guid=None,
         parent_pid=None, parent_image="C:\\Windows\\explorer.exe", index=0):
    record = extract(row(sysmon(guid, pid, image, cmd, parent_guid=parent_guid, parent_pid=parent_pid, host=host,
                                hashes=hashes, utc=utc, parent_image=parent_image), offset_ms=index), {}, [])
    record["provenance"] = {"query": "events" if scope == "offense_linked" else "host_context", "scope": scope,
                            "search_id": "s1" if scope == "offense_linked" else "s9", "result_row_index": index,
                            "starttime_utc": "2026-10-09T16:00:05+00:00"}
    return record


def result(*records):
    return {"queries": {"events": {"returned_rows": len(records)}}, "processes": process_chain.analyze(list(records))}


def evaluate(qradar, raw):
    findings, contradictions = bridge_findings(qradar, raw)
    return raw["investigations"][0]["link"], findings, contradictions


SAME = "2026-10-09 16:00:01.000"
LAUNCH = "2026-10-09T16:00:01Z"


class HashConflictTests(unittest.TestCase):
    """Problem 1: conflicting full hashes must not be outweighed by path, PID or command."""

    def test_divergent_sha256_with_same_path_pid_command_and_time_is_not_a_link(self):
        qradar = result(qrec(GUID_A, 4321, MAL, CMD, SAME, hashes=f"SHA256={OTHER_SHA}"))
        link, findings, contradictions = evaluate(qradar, trend_raw(group(4321, LAUNCH)))
        self.assertEqual(link["level"], "candidate")
        self.assertNotIn("malicious_activity_confirmed", findings)
        self.assertFalse(findings["corroborated"])
        conflict = next(c for c in contradictions if c["id"].startswith("link_conflict:"))
        self.assertIn("sha256", conflict["summary"])
        self.assertEqual(conflict["evidence"]["conflicts"][0]["hashes"]["sha256"]["state"], "conflict")

    def test_equal_sha256_with_the_execution_identity_is_a_link(self):
        link, findings, _ = evaluate(result(qrec(GUID_A, 4321, MAL, CMD, SAME)), trend_raw(group(4321, LAUNCH)))
        self.assertEqual(link["level"], "demonstrated")
        self.assertEqual(link["matches"][0]["relation"], "same_process_instance")
        self.assertEqual(link["matches"][0]["artifact"]["state"], "equal")
        self.assertTrue(findings["corroborated"])

    def test_absent_hash_needs_path_pid_and_time_and_a_conflicting_pid_is_not_ignored(self):
        absent = result(qrec(GUID_A, 4321, MAL, CMD, SAME, hashes=None))
        link, _, _ = evaluate(absent, trend_raw(group(4321, LAUNCH)))
        self.assertEqual(link["level"], "demonstrated")
        self.assertEqual(link["matches"][0]["artifact"]["state"], "absent")
        other_pid = result(qrec(GUID_A, 5555, MAL, CMD, SAME, hashes=None))
        link, findings, _ = evaluate(other_pid, trend_raw(group(4321, LAUNCH)))
        self.assertEqual(link["level"], "candidate")  # identical command, but the known PIDs differ
        self.assertIn("process ID", link["why_not_demonstrated"])

    def test_different_algorithms_do_not_invent_a_conflict(self):
        qradar = result(qrec(GUID_A, 4321, MAL, CMD, SAME, hashes="MD5=" + "AB" * 16))
        link, _, contradictions = evaluate(qradar, trend_raw(group(4321, LAUNCH)))
        self.assertEqual(link["level"], "demonstrated")
        self.assertEqual(link["matches"][0]["artifact"]["state"], "not_comparable")
        self.assertFalse([c for c in contradictions if c["id"].startswith("link_conflict:")])

    def test_truncated_hash_is_not_a_complete_equality(self):
        qradar = result(qrec(GUID_A, 4321, "C:\\Other\\synthetic.exe", CMD, SAME, hashes="SHA256=" + SHA[:20]))
        link, findings, _ = evaluate(qradar, trend_raw(group(4321, LAUNCH)))
        self.assertEqual(link["level"], "candidate")
        self.assertNotIn("malicious_activity_confirmed", findings)
        self.assertIn("incomplete", link["why_not_demonstrated"])

    def test_conflict_is_reported_in_the_case_report_and_note(self):
        rows = [row(sysmon("{dddddddd-4444-4444-8444-444444444444}", 4321, MAL, CMD, hashes=f"SHA256={OTHER_SHA}"),
                    name="Process Create")]
        lab = Lab({"FROM events WHERE INOFFENSE(12345)": ("events", rows, None)})
        with tempfile.TemporaryDirectory() as root, \
                mock.patch("soc_bridge.core.investigate", mock.AsyncMock(return_value=overview(tp_report()))):
            report = run(investigate_offense_case(lab, object(), 12345, store=CaseStore(Path(root)), now=NOW))
        self.assertNotEqual(report["decision"]["disposition"]["category"], "malicious_confirmed")
        conflict = next(c for c in report["contradictions"] if c["id"].startswith("link_conflict:"))
        self.assertIn(conflict["summary"], report["note_pt"])


class ProcessChainIdentityTests(unittest.TestCase):
    """Problem 2: PID reuse must not produce a false parent/child chain."""

    def child(self, parent_guid=None, host=HOST, utc="2026-10-09 16:50:00.000"):
        return qrec(GUID_C, 6000, "C:\\Windows\\System32\\cmd.exe", "cmd.exe /c whoami", utc, host=host,
                    hashes=f"SHA256={'34' * 32}", parent_guid=parent_guid, parent_pid=4321, parent_image=MAL, index=1)

    def test_reused_pid_with_parent_guid_of_the_new_instance_is_not_the_malicious_parent(self):
        reused = qrec(GUID_B, 4321, MAL, CMD, "2026-10-09 16:49:00.000", scope="host_ip_time_context", index=2)
        link, findings, _ = evaluate(result(self.child(GUID_B), reused), trend_raw(group(4321, LAUNCH)))
        self.assertEqual(link["level"], "candidate")
        self.assertNotIn("malicious_activity_confirmed", findings)
        self.assertIn("PID reuse", link["why_not_demonstrated"])

    def test_parent_demonstrated_by_guid_and_instance_is_a_link(self):
        parent = qrec(GUID_A, 4321, MAL, CMD, SAME, scope="host_ip_time_context", index=2)
        link, findings, _ = evaluate(result(self.child(GUID_A), parent), trend_raw(group(4321, LAUNCH)))
        self.assertEqual(link["level"], "demonstrated")
        match = link["matches"][0]
        self.assertEqual(match["relation"], "child_of_malicious_instance")
        self.assertEqual(match["chain"]["parent_record_scope"], "host_ip_time_context")
        self.assertIn("not an INOFFENSE record", match["description"])

    def test_long_lived_parent_with_a_demonstrated_chain_stays_valid(self):
        parent = qrec(GUID_A, 4321, MAL, CMD, "2026-10-09 10:00:00.000", scope="host_ip_time_context", index=2)
        link, _, _ = evaluate(result(self.child(GUID_A), parent),
                              trend_raw(group(4321, "2026-10-09T10:00:00Z"), event_time="2026-10-09T10:00:01.000Z"))
        self.assertEqual(link["level"], "demonstrated")
        self.assertEqual(link["matches"][0]["relation"], "child_of_malicious_instance")

    def test_same_pid_and_path_without_instance_data_stays_candidate(self):
        link, findings, _ = evaluate(result(self.child(None)), trend_raw(group(4321, LAUNCH)))
        self.assertEqual(link["level"], "candidate")
        self.assertNotIn("malicious_activity_confirmed", findings)
        self.assertIn("ParentProcessGuid", link["why_not_demonstrated"])

    def test_parent_record_of_another_endpoint_is_not_combined(self):
        elsewhere = qrec(GUID_A, 4321, MAL, CMD, SAME, scope="host_ip_time_context", host=OTHER_HOST, index=2)
        link, _, _ = evaluate(result(self.child(GUID_A), elsewhere), trend_raw(group(4321, LAUNCH)))
        self.assertEqual(link["level"], "candidate")

    def test_parent_of_a_launched_object_is_the_actor_not_the_actors_parent(self):
        actor = group(3000, "2026-10-09T15:59:59Z", image=LAUNCHER, cmd="launcher.exe", sha=LAUNCHER_SHA,
                      instance="inst-actor")
        obj = group(4321, LAUNCH, key="processHashId")
        actors_parent = group(1000, "2026-10-09T09:00:00Z", image="C:\\Windows\\explorer.exe", cmd="explorer.exe",
                              sha=PARENT_SHA, instance="inst-explorer")
        raw = lambda: trend_raw(actor, parent=actors_parent, obj=obj)  # noqa: E731
        explorer = result(qrec(GUID_B, 1000, "C:\\Windows\\explorer.exe", "explorer.exe", "2026-10-09 09:00:00.000",
                               hashes=f"SHA256={PARENT_SHA}"))
        link, findings, _ = evaluate(explorer, raw())
        self.assertEqual(link["level"], "candidate")  # the actor's parent did not launch the malicious object
        self.assertNotIn("malicious_activity_confirmed", findings)
        launcher = result(qrec(GUID_A, 3000, LAUNCHER, "launcher.exe", "2026-10-09 15:59:59.000",
                               hashes=f"SHA256={LAUNCHER_SHA}"))
        link, _, _ = evaluate(launcher, raw())
        self.assertEqual(link["level"], "demonstrated")
        self.assertEqual(link["matches"][0]["relation"], "parent_of_malicious_instance")


GUID_E = "{eeeeeeee-5555-4555-8555-555555555555}"


def malicious_row():
    return row(sysmon(GUID_E, 4321, MAL, CMD, parent_pid=1000, hashes=f"SHA256={SHA}"), name="Process Create")


def child_row():
    return row(sysmon("{ffffffff-6666-4666-8666-666666666666}", 6000, "C:\Windows\System32\cmd.exe",
                      "cmd.exe /c whoami", parent_guid=GUID_E, parent_pid=4321, parent_image=MAL,
                      hashes=f"SHA256={'34' * 32}", utc="2026-10-09 16:05:00.000"), offset_ms=1000, name="Process Create")


def process_lab(with_child=False):
    rows = [malicious_row()] + ([child_row()] if with_child else [])
    return Lab({"FROM events WHERE INOFFENSE(12345)": ("events", rows, None)})


class RefutationTests(unittest.TestCase):
    """Problem 3: a refutation of one link must not be undone by the same old data."""

    def investigate(self, store, lab, report=None, rerun=None):
        with mock.patch("soc_bridge.core.investigate", mock.AsyncMock(return_value=overview(report or tp_report()))):
            return run(investigate_offense_case(lab, object(), 12345, store=store, now=NOW, rerun_queries=rerun))

    def alert(self, store):
        return store.load("offense-12345")["trend"]["alerts"]["WB-SYNTH-2"]

    def refute(self, fact_ids, summary="IR review: this QRadar process is a different execution"):
        return {"requirement": "trend_finding_refuted", "alert_id": "WB-SYNTH-2", "source": "IR ticket",
                "reference": "IR-SYNTH-31", "summary": summary, "facts": fact_ids}

    def test_refuting_only_the_link_survives_reassessments_and_recollection(self):
        lab = process_lab()
        with tempfile.TemporaryDirectory() as root:
            store = CaseStore(Path(root))
            first = self.investigate(store, lab)
            self.assertEqual(first["decision"]["disposition"]["category"], "malicious_confirmed")
            links = [f for f, x in self.alert(store)["facts"].items() if x["kind"] == "qradar_link"]
            self.assertEqual(len(links), 1)
            calls = len(lab.calls)
            report = reassess_case("offense-12345", [self.refute(links)], store)
            self.assertNotEqual(report["decision"]["disposition"]["category"], "malicious_confirmed")
            self.assertEqual(len(lab.calls), calls)
            self.assertEqual(report["related_alerts"][0]["classification"], "True Positive")
            self.assertEqual(self.alert(store)["facts"][links[0]]["status"], "refuted")
            again = reassess_case("offense-12345", [], store)
            self.assertNotEqual(again["decision"]["disposition"]["category"], "malicious_confirmed")
            self.assertEqual(self.alert(store)["facts"][links[0]]["status"], "refuted")
            recollected = self.investigate(store, lab, rerun=["events"])  # same records, new Ariel job
            self.assertNotEqual(recollected["decision"]["disposition"]["category"], "malicious_confirmed")
            alert = self.alert(store)
            self.assertEqual(alert["facts"][links[0]]["status"], "refuted")
            self.assertTrue(alert["facts"][links[0]]["rematched_after_refutation"])
            conflict = next(c for c in recollected["contradictions"] if c["id"].startswith("refuted_link_still_matched:"))
            self.assertIn("IR-SYNTH-31", conflict["summary"])

    def test_explicit_reasoned_reinstatement_and_new_evidence_allow_revision(self):
        with tempfile.TemporaryDirectory() as root:
            store = CaseStore(Path(root))
            self.investigate(store, process_lab())
            links = [f for f, x in self.alert(store)["facts"].items() if x["kind"] == "qradar_link"]
            reassess_case("offense-12345", [self.refute(links)], store)
            reinstated = reassess_case("offense-12345", [{
                "requirement": "trend_finding_reinstated", "alert_id": "WB-SYNTH-2", "source": "IR ticket",
                "reference": "IR-SYNTH-32", "summary": "IR-SYNTH-31 cited the wrong host; same execution confirmed",
                "facts": links}], store)
            self.assertEqual(reinstated["decision"]["disposition"]["category"], "malicious_confirmed")
            revision = self.alert(store)["revisions"][-1]
            self.assertEqual(revision["reestablished_facts"], links)
            self.assertIn("IR-SYNTH-32", revision["source"])
        with tempfile.TemporaryDirectory() as root:
            store = CaseStore(Path(root))
            self.investigate(store, process_lab())
            links = [f for f, x in self.alert(store)["facts"].items() if x["kind"] == "qradar_link"]
            reassess_case("offense-12345", [self.refute(links)], store)
            # A new record pertinent to the chain (the child launched by the malicious instance) is new evidence.
            renewed = self.investigate(store, process_lab(with_child=True), rerun=["events"])
            self.assertEqual(renewed["decision"]["disposition"]["category"], "malicious_confirmed")
            alert = self.alert(store)
            self.assertEqual(alert["facts"][links[0]]["status"], "refuted")

    def test_refuting_one_link_keeps_an_independent_link(self):
        with tempfile.TemporaryDirectory() as root:
            store = CaseStore(Path(root))
            self.investigate(store, process_lab(with_child=True))
            facts = self.alert(store)["facts"]
            links = {x["data"]["relation"]: f for f, x in facts.items() if x["kind"] == "qradar_link"}
            self.assertEqual(sorted(links), ["child_of_malicious_instance", "same_process_instance"])
            report = reassess_case("offense-12345", [self.refute([links["child_of_malicious_instance"]])], store)
            self.assertEqual(report["decision"]["disposition"]["category"], "malicious_confirmed")
            facts = self.alert(store)["facts"]
            self.assertEqual([facts[links[r]]["status"] for r in ("child_of_malicious_instance", "same_process_instance")],
                             ["refuted", "sustained"])

    def test_refuting_the_whole_alert_still_works(self):
        with tempfile.TemporaryDirectory() as root:
            store = CaseStore(Path(root))
            self.investigate(store, process_lab())
            report = reassess_case("offense-12345", [self.refute(None, "sandbox re-analysis: benign test file")], store)
            self.assertNotEqual(report["decision"]["disposition"]["category"], "malicious_confirmed")
            self.assertEqual(report["related_alerts"][0]["classification"], "Refuted")

    def test_stored_link_from_earlier_criteria_is_not_resurrected(self):
        rows = [row(sysmon("{dddddddd-4444-4444-8444-444444444444}", 4321, MAL, CMD, parent_pid=1000,
                           hashes=f"SHA256={OTHER_SHA}"), name="Process Create")]
        lab = Lab({"FROM events WHERE INOFFENSE(12345)": ("events", rows, None)})
        with tempfile.TemporaryDirectory() as root:
            store = CaseStore(Path(root))
            self.investigate(store, lab)
            case = store.load("offense-12345")
            entry = case["trend"]["alerts"]["WB-SYNTH-2"]
            instance = next(f for f, x in entry["facts"].items() if x["kind"] == "malicious_instance")
            legacy = {"fact_id": instance, "relation": "same_process_instance", "host": HOST,
                      "qradar_record": {"query": "events", "search_id": "synthetic-job-0", "result_row_index": 0},
                      "shared_identifiers": ["identical image path", "process ID"]}
            entry["facts"]["link:legacy"] = {"kind": "qradar_link", "status": "sustained", "first_run": "run-0",
                                             "last_observed_run": "run-0", "source": "earlier criteria", "data": legacy}
            store.save(case, case["revision"])
            report = reassess_case("offense-12345", [], store)
            self.assertNotEqual(report["decision"]["disposition"]["category"], "malicious_confirmed")
            fact = self.alert(store)["facts"]["link:legacy"]
            self.assertEqual(fact["status"], "needs_revalidation")
            self.assertEqual(fact["data"], legacy)  # history preserved
