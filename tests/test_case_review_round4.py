"""Fourth review round: stored links against contradicting evidence, and refutations against irrelevant changes.

All data is synthetic. No QRadar or Vision One is contacted; Trend results are mocked. Each scenario
goes through investigate_offense_case / reassess_case and checks disposition, confidence and the
persisted fact state first, so the tests fail on the earlier implementation by behavior.
"""

import asyncio
import copy
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from soc_bridge.ariel_collection import Budget
from soc_bridge.case_investigation import investigate_offense_case, reassess_case
from soc_bridge.case_store import CaseStore

from synthetic_lab import MS, NOW, SHA, Lab, row, sysmon
from test_case_review_round2 import inconclusive_report, overview, tp_report
from test_case_review_round3 import malicious_row

OTHER_SHA = "EF" * 32
SECOND_SHA = "56" * 32
ALERT = "WB-SYNTH-2"


def run(coro):
    return asyncio.run(coro)


def filler(index):
    return {"starttime": MS + 5000 + index, "devicetime": MS + 5000 + index, "sourceip": "192.0.2.10",
            "event_name": f"Synthetic filler {index}", "log_source": "Synthetic WinCollect",
            "raw_payload": f"synthetic filler {index}", "qid": 900 + index}


def second_row():
    return row(sysmon("{abababab-7777-4777-8777-777777777777}", 7000, "C:\\Tools\\second.exe", "second.exe --go",
                      parent_pid=1000, hashes=f"SHA256={SECOND_SHA}"), offset_ms=10, name="Process Create")


def lab(*extra):
    return Lab({"FROM events WHERE INOFFENSE(12345)": ("events", [malicious_row(), *extra], None)})


def report(sha=SHA, md5=None, sha1=None, second=False):
    out = tp_report(sha=sha)
    process = out["auto_pivots"]["records"]["linked"][0]["process"]
    if md5:
        process["fileHashMd5"] = md5
    if sha1:
        process["fileHashSha1"] = sha1
    if second:
        record = copy.deepcopy(out["auto_pivots"]["records"]["linked"][0])
        record.update(uuid="ev-synth-2")
        record["process"] = {"filePath": "C:\\Tools\\second.exe", "cmd": "second.exe --go", "pid": 7000,
                             "hashId": "inst-synth-2", "launchTime": "2026-10-09T16:00:01Z",
                             "fileHashSha256": SECOND_SHA.lower()}
        out["auto_pivots"]["records"]["linked"].append(record)
        out["enrichment"]["sandbox:second"] = {"state": "collected", "queried_hash": SECOND_SHA.lower(),
                                               "items": [{"riskLevel": "high", "digest": {"sha256": SECOND_SHA.lower()}}]}
    return out


class Flow:
    def investigate(self, store, qradar, trend=None, include_trend=True, rerun=None, budget=None, side_effect=None):
        patch = mock.AsyncMock(return_value=trend, side_effect=side_effect)
        with mock.patch("soc_bridge.core.investigate", patch):
            return run(investigate_offense_case(qradar, object() if include_trend else None, 12345, store=store,
                                                include_trend=include_trend, rerun_queries=rerun, now=NOW,
                                                budget=budget))

    def links(self, store):
        facts = store.load("offense-12345")["trend"]["alerts"][ALERT]["facts"]
        return {f: x for f, x in facts.items() if x["kind"] == "qradar_link"}

    def assertMalicious(self, report, malicious=True):
        if malicious:
            self.assertEqual(report["decision"]["disposition"]["category"], "malicious_confirmed")
            self.assertEqual(report["confidence"]["level"], "high")
        else:
            self.assertNotEqual(report["decision"]["disposition"]["category"], "malicious_confirmed")
            self.assertNotEqual(report["confidence"]["level"], "high")


class StoredLinkContradictionTests(Flow, unittest.TestCase):
    """Problem 1: a stored link must not confirm the association when current evidence contradicts it."""

    def test_conflicting_trend_hash_withdraws_the_stored_link_across_flows(self):
        with tempfile.TemporaryDirectory() as root:
            store = CaseStore(Path(root))
            qradar = lab()
            self.assertMalicious(self.investigate(store, qradar, overview(report())))
            conflicting = self.investigate(store, qradar, overview(report(sha=OTHER_SHA)))
            self.assertMalicious(conflicting, malicious=False)
            [(link_id, link)] = self.links(store).items()
            self.assertEqual(link["status"], "contradicted")
            self.assertIn("sha256", " ".join(link["contradicted_by"]["conflicts"]))
            self.assertEqual(link["data"]["trend_instance"]["hashes"], [SHA.lower()])  # history preserved
            self.assertTrue(any(c["id"].startswith("link_contradicted:") for c in conflicting["contradictions"]))
            self.assertTrue(any(c["id"].startswith("link_conflict:") for c in conflicting["contradictions"]))
            self.assertMalicious(reassess_case("offense-12345", [], store), malicious=False)
            self.assertMalicious(self.investigate(store, qradar, overview(report(sha=OTHER_SHA)), rerun=["events"]),
                                 malicious=False)  # new Ariel job
            self.assertMalicious(self.investigate(store, qradar, include_trend=False), malicious=False)
            instance = next(x for x in store.load("offense-12345")["trend"]["alerts"][ALERT]["facts"].values()
                            if x["kind"] == "malicious_instance")
            self.assertEqual(instance["history"][0]["probative"]["instance"]["hashes"], {"sha256": SHA.lower()})

    def test_conflict_after_a_resumed_collection(self):
        with tempfile.TemporaryDirectory() as root:
            store = CaseStore(Path(root))
            qradar = lab(filler(1), filler(2))
            partial = self.investigate(store, qradar, overview(report()), budget=Budget(max_seconds=30, page_size=1,
                                                                                         max_pages=1))
            self.assertEqual(partial["coverage"]["events"]["outcome"], "partial")
            self.assertEqual(partial["decision"]["disposition"]["category"], "malicious_confirmed")
            resumed = self.investigate(store, qradar, overview(report(sha=OTHER_SHA)))
            self.assertEqual(resumed["coverage"]["events"]["resume"], "continued_same_search")
            self.assertMalicious(resumed, malicious=False)

    def test_absent_observations_keep_the_valid_link(self):
        with tempfile.TemporaryDirectory() as root:
            store = CaseStore(Path(root))
            qradar = lab()
            self.assertMalicious(self.investigate(store, qradar, overview(report())))
            self.assertMalicious(self.investigate(store, qradar, overview(None, state="failed")))  # timeout
            self.assertMalicious(self.investigate(store, qradar, overview(inconclusive_report())))
            self.assertMalicious(self.investigate(store, qradar, side_effect=RuntimeError("synthetic Trend failure")))
            self.assertMalicious(self.investigate(store, qradar, include_trend=False))
            self.assertEqual([x["status"] for x in self.links(store).values()], ["sustained"])

    def test_an_independent_valid_link_still_counts(self):
        with tempfile.TemporaryDirectory() as root:
            store = CaseStore(Path(root))
            qradar = lab(second_row())
            self.assertMalicious(self.investigate(store, qradar, overview(report(second=True))))
            self.assertEqual(len(self.links(store)), 2)
            changed = self.investigate(store, qradar, overview(report(sha=OTHER_SHA, second=True)))
            self.assertMalicious(changed)
            states = {x["data"]["trend_record"]["uuid"]: x["status"] for x in self.links(store).values()}
            self.assertEqual(states, {"ev-synth-1": "contradicted", "ev-synth-2": "sustained"})


class RefutationPertinenceTests(Flow, unittest.TestCase):
    """Problem 2: an irrelevant change must not re-establish a refuted link."""

    def refute_link(self, store):
        [link_id] = list(self.links(store))
        reassess_case("offense-12345", [{
            "requirement": "trend_finding_refuted", "alert_id": ALERT, "source": "IR ticket", "reference": "IR-SYNTH-41",
            "summary": "IR review: the offense process is a different execution", "facts": [link_id]}], store)
        return link_id

    def test_incomplete_hash_and_metadata_do_not_undo_the_refutation(self):
        with tempfile.TemporaryDirectory() as root:
            store = CaseStore(Path(root))
            qradar = lab()
            self.investigate(store, qradar, overview(report()))
            link_id = self.refute_link(store)
            self.assertMalicious(self.investigate(store, qradar, overview(report()), rerun=["events"]), malicious=False)
            changed = self.investigate(store, qradar, overview(report(md5="AB12")), rerun=["events"])
            self.assertMalicious(changed, malicious=False)
            link = self.links(store)[link_id]
            self.assertEqual(link["status"], "refuted")
            self.assertFalse(link["observations_after_refutation"][-1]["probative_change"])
            self.assertMalicious(reassess_case("offense-12345", [], store), malicious=False)
            self.assertMalicious(self.investigate(store, qradar, overview(report(md5="AB12"))), malicious=False)

    def test_a_probative_change_is_recorded_for_review_but_does_not_reinstate(self):
        with tempfile.TemporaryDirectory() as root:
            store = CaseStore(Path(root))
            qradar = lab()
            self.investigate(store, qradar, overview(report()))
            link_id = self.refute_link(store)
            changed = self.investigate(store, qradar, overview(report(sha1="12" * 20)))
            self.assertMalicious(changed, malicious=False)
            link = self.links(store)[link_id]
            self.assertEqual(link["status"], "refuted")
            observation = link["observations_after_refutation"][-1]
            self.assertTrue(observation["probative_change"])
            self.assertIn("sha1", " ".join(observation["changes"]))
            review = next(c for c in changed["contradictions"] if c["id"].startswith("refuted_link_still_matched:"))
            self.assertIn("review", review["summary"])

    def test_refutation_survives_a_resumed_collection(self):
        with tempfile.TemporaryDirectory() as root:
            store = CaseStore(Path(root))
            qradar = lab(filler(1), filler(2))
            self.investigate(store, qradar, overview(report()), budget=Budget(max_seconds=30, page_size=1, max_pages=1))
            link_id = self.refute_link(store)
            resumed = self.investigate(store, qradar, overview(report(md5="AB12")))
            self.assertEqual(resumed["coverage"]["events"]["resume"], "continued_same_search")
            self.assertMalicious(resumed, malicious=False)
            self.assertEqual(self.links(store)[link_id]["status"], "refuted")

    def test_explicit_reasoned_reinstatement_still_restores(self):
        with tempfile.TemporaryDirectory() as root:
            store = CaseStore(Path(root))
            qradar = lab()
            self.investigate(store, qradar, overview(report()))
            link_id = self.refute_link(store)
            restored = reassess_case("offense-12345", [{
                "requirement": "trend_finding_reinstated", "alert_id": ALERT, "source": "IR ticket",
                "reference": "IR-SYNTH-42", "summary": "IR-SYNTH-41 reviewed the wrong host", "facts": [link_id]}], store)
            self.assertMalicious(restored)
            self.assertEqual(self.links(store)[link_id]["status"], "sustained")
