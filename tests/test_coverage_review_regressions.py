"""Review regressions using synthetic records and bounded in-process clients only."""
import asyncio
import unittest
from unittest.mock import patch

from soc_bridge.alert_assessment import assess
from soc_bridge.alert_investigation import investigate_vision_alert
from soc_bridge.ariel_collection import Budget
from soc_bridge.closure_assessment import propose, validate_confirmations
from soc_bridge.deepening import deepen
from soc_bridge.qradar_context import lookup, read
from soc_bridge.trend_enrichment import optional_read
from trend_fixtures import ALERT_ID, NOW, SHA, T0, FakeVision, z


def run(operation):
    return asyncio.run(operation)


class ContextReviewTests(unittest.TestCase):
    def test_budget_stop_preserves_unread_offset(self):
        class Q:
            calls = []
            async def call(self, tool, args):
                self.calls.append(args)
                return [{"name": f"rule-{i}"} for i in range(100)]
        q = Q()
        got = run(read(q, Budget(max_calls=1), "list_rules", {}, "p", "t", page_size=100, max_pages=3))
        self.assertEqual(len(q.calls), 1)
        self.assertEqual(got["count"], 100)
        self.assertEqual(got["continuation"]["args"]["offset"], 100)
        self.assertFalse(got["result_set_complete"])

    def test_timeout_preserves_unread_offset_and_rows(self):
        class Q:
            async def call(self, tool, args):
                if args["offset"]:
                    await asyncio.sleep(1)
                return [{"name": f"rule-{i}"} for i in range(100)]
        got = run(read(Q(), Budget(max_seconds=.03), "list_rules", {}, "p", "t", page_size=100, max_pages=3))
        self.assertEqual(got["count"], 100)
        self.assertEqual(got["continuation"]["args"]["offset"], 100)

    def test_non_json_is_format_failure_not_empty(self):
        class Q:
            async def call(self, tool, args):
                return "unexpected upstream text"
        self.assertEqual(run(read(Q(), Budget(), "list_rules", {}, "p", "t"))["state"], "format")

    def test_failed_name_scan_does_not_claim_all_items_scanned(self):
        class Q:
            available = set()
        got = run(lookup(Q(), Budget(), "rules", "Synthetic"))["result"]
        self.assertEqual(got["state"], "tool_absent")
        self.assertNotEqual(got["coverage"], "all items scanned")

    def test_reference_match_happens_before_display_key_cuts(self):
        class Q:
            async def call(self, tool, args):
                return {"number_of_elements": 200, "data": {f"key-{i}": f"value-{i}" for i in range(200)}}
        got = run(lookup(Q(), Budget(), "reference_lookup", "value-150", "Synthetic"))["result"]
        self.assertEqual(got["get_reference_map"]["matches"], ["data.key-150"])

    def test_single_page_limit_is_not_exhaustive(self):
        class Q:
            async def call(self, tool, args):
                return [{"id": i} for i in range(10)]
        got = run(read(Q(), Budget(), "list_assets", {"limit": 10}, "p", "t"))
        self.assertFalse(got["result_set_complete"])
        self.assertTrue(got["more_available"])


class TrendFormatReviewTests(unittest.TestCase):
    def test_unstructured_response_is_not_a_negative_result(self):
        class V:
            async def call(self, tool, args):
                return "unexpected upstream text"
        got = run(optional_read(V(), Budget(), "workbench_insights_list", {}, "p", "t"))
        self.assertEqual(got["state"], "format")

    def test_invalid_list_envelope_is_format_failure(self):
        class V:
            async def call(self, tool, args):
                return {"items": "not a list"}
        got = run(optional_read(V(), Budget(), "workbench_insights_list", {}, "p", "t"))
        self.assertEqual(got["state"], "format")


class DecisionReviewTests(unittest.TestCase):
    def report(self, role="process", hash_value=SHA, launched=True):
        group = {"fileHashSha256": hash_value, "filePath": "C:\\synthetic.exe", "pid": 7,
                 "hashId" if role == "process" else "processHashId": "instance-7"}
        if launched:
            group["launchTime"] = z(T0)
        return {"alert_id": ALERT_ID, "clocks": {"anchor": {"provisional": False}},
                "auto_pivots": {"record_counts": {"linked": 1}, "continuation": [],
                    "pivots": [{"state": "complete_in_window"}],
                    "records": {"linked": [{"uuid": "synthetic-linked", "time_utc": z(T0), role: group}]}},
                "hypothesis_checks": {f"sandbox:{SHA[:12]}": {"state": "collected", "queried_hash": SHA,
                    "items": [{"riskLevel": "high", "digest": {"sha256": SHA}}]}}}

    def test_parent_hash_is_not_malicious_execution(self):
        got = assess(self.report(role="parent"))
        self.assertEqual(got["classification"], "Inconclusive")

    def test_file_access_target_hash_is_not_execution(self):
        self.assertEqual(assess(self.report(role="object", launched=False))["classification"], "Inconclusive")

    def test_prefix_collision_is_not_full_hash_equality(self):
        different = SHA[:12] + ("0" if SHA[12] != "0" else "1") + SHA[13:]
        self.assertEqual(assess(self.report(hash_value=different))["classification"], "Inconclusive")

    def test_filter_without_returned_digest_is_not_a_verdict_for_that_hash(self):
        report = self.report()
        report["hypothesis_checks"][f"sandbox:{SHA[:12]}"]["items"] = [{"riskLevel": "high"}]
        self.assertEqual(assess(report)["classification"], "Inconclusive")

    def test_executed_actor_and_exact_returned_hash_can_sustain_true_positive(self):
        self.assertEqual(assess(self.report())["classification"], "True Positive")

    def test_newly_launched_object_can_sustain_true_positive(self):
        self.assertEqual(assess(self.report(role="object"))["classification"], "True Positive")

    def test_linked_uuid_alone_does_not_confirm_execution(self):
        report = self.report()
        report["auto_pivots"]["records"]["linked"] = [{"uuid": "synthetic-linked"}]
        got = assess(report)
        self.assertNotEqual(got["requirements"]["execution_observed"]["status"], "confirmed")

    def test_missing_queries_cannot_satisfy_collection_requirement(self):
        report = {"offense_id": 71, "assessment": {}, "queries": {}, "metadata": {"status": "OPEN"},
                  "closing_reasons": {"state": "collected", "reasons": [{"id": 1, "text": "Non-Issue"}]}}
        got = propose(report, [{"requirement": "authorization", "source": "synthetic change", "reference": "CHG-1"}])
        self.assertFalse(got["ready_to_close"])
        self.assertNotEqual(got["requirements"]["relevant_collection_complete"]["status"], "confirmed")

    def test_zero_is_not_a_primary_offense_reference(self):
        with self.assertRaises(ValueError):
            validate_confirmations([{"requirement": "primary_offense", "source": "synthetic", "reference": "0"}], 71)

    def test_duplicate_retains_collection_gaps_as_limits_not_blockers(self):
        report = {"offense_id": 71, "assessment": {}, "queries": {}, "metadata": {"status": "OPEN"},
                  "closing_reasons": {"state": "collected", "reasons": [{"id": 3, "text": "Duplicate"}]}}
        got = propose(report, [{"requirement": "primary_offense", "source": "analyst", "reference": "70"}])
        self.assertTrue(got["ready_to_close"])
        self.assertEqual(got["blocking_requirements"], [])
        self.assertTrue(got["other_unresolved_requirements"])
        self.assertIn("não bloqueiam", got["suggested_note"])


class BudgetReviewTests(unittest.TestCase):
    def test_ariel_correlation_precedes_offense_lead_scan(self):
        order = []
        async def correlation(*args, **kwargs):
            order.append("ariel")
            return {"notes": []}
        class Q:
            async def call(self, tool, args):
                order.append(tool)
                return []
        with patch("soc_bridge.trend_qradar.correlate", side_effect=correlation):
            run(investigate_vision_alert(Q(), FakeVision(), ALERT_ID, ariel_offset_hours=-3, now=NOW))
        self.assertEqual(order[0], "ariel")
        self.assertIn("list_source_addresses", order)

    def test_deepening_partitions_share_one_global_cap(self):
        assigned = []
        async def alert(*args, budget, **kwargs):
            assigned.append(budget.max_partitions)
            budget.partitions_used = budget.max_partitions
            return {}
        alerts = [{"alert_id": f"WB-SYNTH-{i}", "temporal_check": "within window",
                   "match_fields": ["impactScopeEntityValue"]} for i in range(2)]
        with patch("soc_bridge.alert_investigation.investigate_vision_alert", side_effect=alert):
            got = run(deepen(FakeVision(), alerts, 71, now=NOW))
        self.assertEqual(sum(assigned), 24)
        self.assertEqual(got["budget"]["partitions_used"], 24)
