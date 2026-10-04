"""Full-flow regressions: contradictory instance records and telemetry UUID aliases.

Only synthetic QRadar responses and mocked Trend reports are used.
"""

import copy
import tempfile
import unittest
from pathlib import Path

from soc_bridge.case_investigation import reassess_case
from soc_bridge.case_store import CaseStore

from synthetic_lab import Lab, SHA, row, sysmon
from test_case_review_round2 import overview, tp_report
from test_case_review_round3 import CMD, GUID_E, MAL, malicious_row
from test_case_review_round4 import Flow, report as trend_report, second_row


class CaseFlow(Flow):
    def qradar(self, *rows):
        return Lab({"FROM events WHERE INOFFENSE(12345)": ("events", list(rows), None)})

    def changed(self, utc="2026-10-09 16:00:01.000", hashes="EF" * 32, **extra):
        return row(sysmon(GUID_E, 4321, MAL, CMD, parent_pid=1000,
                          hashes="SHA256=" + hashes, utc=utc, **extra), name="Process Create")

    def assertWithdrawn(self, result, store):
        self.assertMalicious(result, malicious=False)
        self.assertEqual([f["status"] for f in self.links(store).values()], ["contradicted"])
        self.assertTrue(any(c["id"].startswith("link_contradicted:") for c in result["contradictions"]))
        self.assertMalicious(reassess_case("offense-12345", [], store), malicious=False)


class InstanceContradictionTests(CaseFlow, unittest.TestCase):
    def test_changed_qradar_hash_and_start_of_same_guid_withdraw_stored_link(self):
        with tempfile.TemporaryDirectory() as root:
            store = CaseStore(Path(root))
            self.investigate(store, self.qradar(malicious_row()), overview(tp_report()))
            result = self.investigate(store, self.qradar(self.changed("2026-10-09 16:00:10.000")),
                                      include_trend=False, rerun=["events"])
            self.assertWithdrawn(result, store)

    def test_changed_qradar_start_alone_is_positive_contradiction(self):
        with tempfile.TemporaryDirectory() as root:
            store = CaseStore(Path(root))
            self.investigate(store, self.qradar(malicious_row()), overview(tp_report()))
            result = self.investigate(store, self.qradar(self.changed("2026-10-09 16:00:10.000", SHA)),
                                      include_trend=False, rerun=["events"])
            self.assertWithdrawn(result, store)

    def test_matching_and_conflicting_rows_of_same_guid_never_sustain_link(self):
        for reverse in (False, True):
            with self.subTest(reverse=reverse), tempfile.TemporaryDirectory() as root:
                store = CaseStore(Path(root))
                self.investigate(store, self.qradar(malicious_row()), overview(tp_report()))
                records = [malicious_row(), self.changed()]
                if reverse:
                    records.reverse()
                result = self.investigate(store, self.qradar(*records), include_trend=False, rerun=["events"])
                self.assertWithdrawn(result, store)
                self.assertMalicious(self.investigate(store, self.qradar(*records), include_trend=False), malicious=False)

    def test_initial_collection_of_conflicting_instance_rows_is_not_malicious_confirmed(self):
        with tempfile.TemporaryDirectory() as root:
            store = CaseStore(Path(root))
            result = self.investigate(store, self.qradar(malicious_row(), self.changed()), overview(tp_report()))
            self.assertWithdrawn(result, store)

    def test_conflict_does_not_remove_an_independent_execution(self):
        with tempfile.TemporaryDirectory() as root:
            store = CaseStore(Path(root))
            self.investigate(store, self.qradar(malicious_row(), second_row()), overview(trend_report(second=True)))
            result = self.investigate(store, self.qradar(malicious_row(), self.changed(), second_row()),
                                      include_trend=False, rerun=["events"])
            self.assertMalicious(result)
            self.assertEqual(sorted(f["status"] for f in self.links(store).values()), ["contradicted", "sustained"])

    def test_conflict_free_recollection_revalidates_contradicted_link(self):
        with tempfile.TemporaryDirectory() as root:
            store = CaseStore(Path(root))
            self.investigate(store, self.qradar(malicious_row()), overview(tp_report()))
            bad = self.investigate(store, self.qradar(self.changed()), include_trend=False, rerun=["events"])
            self.assertWithdrawn(bad, store)
            restored = self.investigate(store, self.qradar(malicious_row()), include_trend=False, rerun=["events"])
            self.assertMalicious(restored)


class ExecutionRefutationTests(CaseFlow, unittest.TestCase):
    def refute_link(self, store, all_facts=False):
        links = list(self.links(store))
        result = reassess_case("offense-12345", [{
            "requirement": "trend_finding_refuted", "alert_id": "WB-SYNTH-2", "source": "IR ticket",
            "reference": "IR-SYNTH-51", "summary": "This execution is not the activity involved in this offense",
            **({} if all_facts else {"facts": links})}], store)
        self.assertMalicious(result, malicious=False)
        return links

    def test_another_record_uuid_of_same_execution_cannot_bypass_link_refutation(self):
        with tempfile.TemporaryDirectory() as root:
            store = CaseStore(Path(root))
            initial = tp_report()
            qradar = self.qradar(malicious_row())
            self.investigate(store, qradar, overview(initial))
            links = self.refute_link(store)
            recollected = copy.deepcopy(initial)
            recollected["auto_pivots"]["records"]["linked"][0]["uuid"] = "ev-synth-another-record"
            result = self.investigate(store, qradar, overview(recollected), rerun=["events"])
            self.assertMalicious(result, malicious=False)
            self.assertEqual(list(self.links(store)), links)
            self.assertEqual(self.links(store)[links[0]]["status"], "refuted")
            self.assertMalicious(reassess_case("offense-12345", [], store), malicious=False)

    def test_another_uuid_cannot_bypass_whole_alert_refutation(self):
        with tempfile.TemporaryDirectory() as root:
            store = CaseStore(Path(root))
            qradar = self.qradar(malicious_row())
            self.investigate(store, qradar, overview(tp_report()))
            self.refute_link(store, all_facts=True)
            result = self.investigate(store, qradar, overview(tp_report(uuid="ev-synth-another-record")))
            self.assertMalicious(result, malicious=False)
            self.assertEqual(result["related_alerts"][0]["classification"], "Refuted")

    def test_changed_trend_id_cannot_make_same_qradar_execution_an_independent_link(self):
        with tempfile.TemporaryDirectory() as root:
            store = CaseStore(Path(root))
            qradar = self.qradar(malicious_row())
            self.investigate(store, qradar, overview(tp_report()))
            links = self.refute_link(store)
            changed = tp_report(uuid="ev-synth-new-record")
            changed["auto_pivots"]["records"]["linked"][0]["process"]["hashId"] = "inst-synth-other-label"
            result = self.investigate(store, qradar, overview(changed))
            self.assertMalicious(result, malicious=False)
            self.assertEqual(list(self.links(store)), links)
            self.assertEqual(self.links(store)[links[0]]["status"], "refuted")

    def test_independent_execution_remains_new_evidence_after_refutation(self):
        with tempfile.TemporaryDirectory() as root:
            store = CaseStore(Path(root))
            self.investigate(store, self.qradar(malicious_row()), overview(tp_report()))
            self.refute_link(store)
            result = self.investigate(store, self.qradar(malicious_row(), second_row()),
                                      overview(trend_report(second=True)), rerun=["events"])
            self.assertMalicious(result)
            self.assertEqual(sorted(f["status"] for f in self.links(store).values()), ["refuted", "sustained"])

    def test_legacy_uuid_fact_ids_and_missing_instance_id_keep_refutation(self):
        with tempfile.TemporaryDirectory() as root:
            store = CaseStore(Path(root))
            qradar = self.qradar(malicious_row())
            self.investigate(store, qradar, overview(tp_report()))
            case = store.load("offense-12345")
            facts = case["trend"]["alerts"]["WB-SYNTH-2"]["facts"]
            instance_id = next(k for k, f in facts.items() if f["kind"] == "malicious_instance")
            legacy_id = "malicious_instance:legacy-uuid:process"
            facts[legacy_id] = facts.pop(instance_id)
            facts[legacy_id]["data"]["fact_id"] = legacy_id
            facts[legacy_id]["data"]["instance"].pop("instance_id")
            old_link_id = next(k for k, f in facts.items() if f["kind"] == "qradar_link")
            legacy_link = "link:" + legacy_id + ":same_process_instance:" + facts[old_link_id]["data"]["qradar_instance_key"]
            facts[legacy_link] = facts.pop(old_link_id)
            facts[legacy_link]["data"]["fact_id"] = legacy_id
            facts[legacy_link]["data"]["trend_instance"].pop("instance_id")
            store.save(case, case["revision"])
            self.refute_link(store)
            new = self.investigate(store, qradar, overview(tp_report(uuid="ev-synth-new-uuid")))
            self.assertMalicious(new, malicious=False)
            self.assertEqual(list(self.links(store)), [legacy_link])
            entry = store.load("offense-12345")["trend"]["alerts"]["WB-SYNTH-2"]
            self.assertIn(legacy_id, entry["facts"])
            refs = entry["facts"][legacy_id]["provenance"]
            self.assertTrue(any((r.get("trend_record") or {}).get("uuid") == "ev-synth-new-uuid" for r in refs))

    def test_existing_uuid_alias_of_refuted_link_is_not_an_independent_link(self):
        with tempfile.TemporaryDirectory() as root:
            store = CaseStore(Path(root))
            qradar = self.qradar(malicious_row())
            self.investigate(store, qradar, overview(tp_report()))
            [link_id] = self.refute_link(store)
            case = store.load("offense-12345")
            facts = case["trend"]["alerts"]["WB-SYNTH-2"]["facts"]
            alias = copy.deepcopy(facts[link_id])
            alias.update(status="sustained")
            alias["data"]["trend_record"]["uuid"] = "ev-synth-legacy-alias"
            alias["data"]["fact_id"] = "malicious_instance:legacy-alias:process"
            facts["link:legacy-alias"] = alias
            store.save(case, case["revision"])
            result = reassess_case("offense-12345", [], store)
            self.assertMalicious(result, malicious=False)
            self.assertEqual(self.links(store)["link:legacy-alias"]["status"], "refuted")
