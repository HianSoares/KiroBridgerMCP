"""Synthetic regression cases for offense scope, time, coverage and conclusions."""

import base64
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from mcp.types import CallToolResult, TextContent

from soc_bridge.core import window
from soc_bridge.offense_evidence import (Budget, collect_offense_evidence, collect_query,
    event_summary, flow_summary, host_summary, query_tail, render_evidence, utc, verify_offense)
from soc_bridge.transports import QRADAR_TOOLS, RestrictedMCP

NOW = datetime(2026, 10, 9, 18, 0, tzinfo=timezone.utc)
START = NOW - timedelta(hours=2)
MS = int(START.timestamp() * 1000)
OFFENSE = {"id": 12345, "description": "Synthetic DHCP detector", "status": "CLOSED",
    "magnitude": 5, "severity": 3, "offense_source": "192.0.2.10",
    "start_time": MS, "last_updated_time": MS + 120000, "event_count": 2,
    "flow_count": 3, "rules": [{"id": 12, "type": "CRE_RULE"}]}


class QRadar:
    def __init__(self, metadata=None, pending=False, flow_count=None):
        self.metadata = dict(OFFENSE if metadata is None else metadata)
        self.pending = pending
        self.flow_count = flow_count
        self.calls, self.jobs = [], {}

    async def read_aql_resource(self, resource):
        self.calls.append(("resource", resource))
        return {"fields": []}

    async def call(self, name, args):
        self.calls.append((name, args))
        if name == "get_offense":
            return self.metadata
        if name == "get_rule":
            return {"id": args["rule_id"], "name": "Synthetic DHCP rule", "enabled": True}
        if name == "validate_aql":
            return {"valid": True}
        if name == "create_ariel_search":
            query = args["query_expression"]
            sid = f"synthetic-job-{len(self.jobs)}"
            if "UNIQUECOUNT" in query:
                database, rows = "flows", [{"total_rows": self.flow_count or 3, "distinct_destinations": 2}]
            elif "FROM flows" in query:
                database, rows = "flows", [
                    {"sourceip": "192.0.2.10", "destinationip": "198.51.100.1", "protocolid": 17,
                     "sourceport": 67, "destinationport": 68, "firstpackettime": MS, "sourcebytes": 100, "destinationbytes": 0},
                    {"sourceip": "192.0.2.10", "destinationip": "198.51.100.1", "protocolid": 17,
                     "sourceport": 67, "destinationport": 67, "firstpackettime": MS, "sourcebytes": 100, "destinationbytes": 0},
                    {"sourceip": "192.0.2.10", "destinationip": "203.0.113.1", "protocolid": 17,
                     "sourceport": 67, "destinationport": 67, "firstpackettime": MS, "sourcebytes": 100, "destinationbytes": 0}]
            elif "INOFFENSE" in query:
                database, rows = "events", [{"starttime": MS, "event_name": "Firewall Drop", "log_source": "Synthetic firewall"},
                    {"starttime": MS + 120000, "event_name": "Synthetic DHCP Scanner", "log_source": "Synthetic CRE"}]
            else:
                database, rows = "events", [{"starttime": MS, "event_name": "Success using explicit credentials",
                    "username": "synthetic_service", "raw_payload": "EventID=4648 ProcessName=svchost.exe"}]
            self.jobs[sid] = (database, rows)
            return {"search_id": sid}
        if name == "get_ariel_search_status":
            return {"status": "EXECUTE" if self.pending else "COMPLETED", "record_count": len(self.jobs[args["search_id"]][1])}
        if name == "get_ariel_search_results":
            database, rows = self.jobs[args["search_id"]]
            return {database: rows[args["start"]:args["start"] + args["limit"]]}
        raise AssertionError(name)


class Pages:
    """One synthetic job whose rows are served page by page."""
    def __init__(self, rows, total="rows", database="events"):
        self.rows, self.database = rows, database
        self.total = len(rows) if total == "rows" else total
        self.created, self.result_starts = 0, []

    async def call(self, name, args):
        if name == "validate_aql":
            return {"valid": True}
        if name == "create_ariel_search":
            self.created += 1
            return {"search_id": "synthetic-job-1", "status": "WAIT"}
        if name == "get_ariel_search_status":
            return {"status": "COMPLETED", "record_count": self.total}
        if name == "get_ariel_search_results":
            self.result_starts.append(args["start"])
            return {self.database: self.rows[args["start"]:args["start"] + args["limit"]]}
        raise AssertionError(name)


class OffenseEvidenceTests(unittest.IsolatedAsyncioTestCase):
    async def test_linked_queries_have_no_ip_substitute_and_never_confirm_false_positive(self):
        qr = QRadar()
        evidence = await collect_offense_evidence(qr, OFFENSE, now=NOW)
        for name in ("events", "flows", "flow_census"):
            query = evidence["queries"][name]
            self.assertIn("WHERE INOFFENSE(12345)", query["aql"])
            self.assertNotIn("sourceip =", query["aql"])
            self.assertTrue(query["result_set_complete"])
            self.assertEqual(query["scope"], "offense_linked")
        self.assertIn("sourceport, destinationip, destinationport", evidence["queries"]["flows"]["aql"])
        self.assertEqual(evidence["flows"]["distinct_destinations_in_collected_rows"], 2)
        self.assertEqual(evidence["flows"]["distinct_destinations_in_search"], 2)
        # One destination belongs to both port groups: summing distinct counts would give three.
        self.assertEqual(sum(g["distinct_destinations"] for g in evidence["flows"]["port_groups"]), 3)
        self.assertFalse(evidence["assessment"]["final_benign_verdict_permitted"])
        self.assertIn("compatible with DHCP", evidence["assessment"]["statement"])
        self.assertEqual(evidence["rules"][0]["metadata"]["name"], "Synthetic DHCP rule")
        rendered = "\n".join(render_evidence(evidence))
        self.assertIn("Metadata interval without padding", rendered)
        self.assertIn(utc(MS), rendered)
        self.assertIn("Status: preliminary", rendered)
        self.assertEqual(evidence["host"]["explicit_credential_attempts"][0]["event_id"], 4648)

    async def test_host_window_uses_observed_epochs_not_padded_metadata(self):
        evidence = await collect_offense_evidence(QRadar(), OFFENSE, now=NOW)
        query = evidence["queries"]["host_context"]["aql"]
        self.assertIn(f"starttime >= {MS - 15 * 60000}", query)
        self.assertIn(f"starttime <= {MS + 120000 + 15 * 60000}", query)
        self.assertEqual(evidence["metadata_interval"]["padding_seconds"], 0)
        self.assertEqual(evidence["metadata_interval"]["start"], utc(MS))
        self.assertEqual(window(OFFENSE)[0], START - timedelta(hours=1))

    async def test_count_mismatch_and_census_mismatch_are_gaps_not_explanations(self):
        offense = {**OFFENSE, "event_count": 1}
        evidence = await collect_offense_evidence(QRadar(flow_count=4), offense, now=NOW)
        self.assertEqual(evidence["count_comparison"]["events"]["status"], "unresolved")
        self.assertTrue(any("census" in gap for gap in evidence["gaps"]))
        self.assertTrue(any("count reconciliation" in gap for gap in evidence["gaps"]))

    async def test_pending_is_not_empty_completed_and_keeps_search_id(self):
        evidence = await collect_offense_evidence(QRadar(pending=True), OFFENSE, now=NOW)
        query = evidence["queries"]["events"]
        self.assertEqual(query["state"], "EXECUTE")
        self.assertFalse(query["result_set_complete"])
        self.assertTrue(query["search_id"])
        self.assertEqual(evidence["assessment"]["confidence_in_port_pattern"], "insufficient")

    async def test_historical_case_does_not_silently_use_default_timezone(self):
        qr = QRadar()
        evidence = await collect_offense_evidence(qr, OFFENSE, now=NOW + timedelta(days=2))
        self.assertEqual(evidence["queries"], {})
        self.assertTrue(any("verified QRadar timezone" in gap for gap in evidence["gaps"]))
        self.assertFalse(any(name == "create_ariel_search" for name, _ in qr.calls))

    async def test_explicit_verified_historical_offset_is_visible(self):
        evidence = await collect_offense_evidence(QRadar(), OFFENSE, -3, True, now=NOW + timedelta(days=2))
        query = evidence["queries"]["events"]["aql"]
        self.assertIn("START '2026-10-09 12:59:00'", query)
        self.assertTrue(evidence["linked_window"]["timezone_verified"])

    async def test_fresh_host_pivot_collects_past_without_claiming_future_margin(self):
        evidence = await collect_offense_evidence(QRadar(), OFFENSE, now=START + timedelta(minutes=3))
        self.assertIn("host_context", evidence["queries"])
        self.assertTrue(evidence["host_window"]["future_margin_not_observable"])
        self.assertEqual(evidence["host_window"]["end_utc"], utc(START + timedelta(minutes=3)))

    def test_overlong_historical_raw_window_requires_partition(self):
        tail, scope = query_tail(START, START + timedelta(days=2), -3, True, NOW + timedelta(days=3))
        self.assertIsNone(tail)
        self.assertIn("partition", scope["reason"])

    async def test_raw_payload_cut_is_explicit_and_does_not_attribute_collector(self):
        class LongPayload(QRadar):
            async def call(self, name, args):
                result = await super().call(name, args)
                if name == "get_ariel_search_results" and "events" in result:
                    result["events"][0]["raw_payload"] = "x" * 33000
                return result
        evidence = await collect_offense_evidence(LongPayload(), OFFENSE, now=NOW)
        self.assertTrue(evidence["queries"]["events"]["truncated_fields"])
        self.assertTrue(evidence["queries"]["events"]["samples"][0]["sample_preview_truncated"])
        self.assertTrue(any("bridge truncated" in gap for gap in evidence["gaps"]))
        self.assertIn("Unknown", evidence["host"]["payload_limit_component"])

    async def test_metadata_ids_are_validated_before_any_query(self):
        with self.assertRaises(ValueError):
            await verify_offense(QRadar(metadata={"id": 9}), 12345)
        for bad in (True, 0, "12345"):
            with self.assertRaises(ValueError):
                await verify_offense(QRadar(), bad)

    async def test_optional_rule_failure_does_not_stop_linked_collection(self):
        class NoRule(QRadar):
            async def call(self, name, args):
                if name == "get_rule":
                    raise RuntimeError("unavailable")
                return await super().call(name, args)
        evidence = await collect_offense_evidence(NoRule(), OFFENSE, now=NOW)
        self.assertTrue(evidence["queries"]["events"]["result_set_complete"])
        self.assertEqual(evidence["rules"][0]["state"], "unavailable")

    async def test_follows_one_search_and_records_budget_or_limit(self):
        query = "SELECT * FROM events LIMIT 5000 LAST 1 HOURS"
        qr = Pages([{"n": i} for i in range(501)])
        collected = await collect_query(qr, query, "events", "offense_linked")
        self.assertEqual(qr.created, 1)
        self.assertEqual(qr.result_starts, [0, 500])
        self.assertTrue(collected["result_set_complete"])
        self.assertEqual(collected["outcome"], "complete_in_window")
        capped = await collect_query(Pages([{}] * 5000), query, "events", "offense_linked")
        self.assertFalse(capped["result_set_complete"])
        self.assertEqual(capped["outcome"], "limited")
        self.assertTrue(any("LIMIT reached" in w for w in capped["warnings"]))

    async def test_missing_count_and_page_budget_are_not_complete(self):
        query = "SELECT * FROM events LIMIT 5000 LAST 1 HOURS"
        unknown = await collect_query(Pages([{}], total=None), query, "events", "offense_linked")
        self.assertFalse(unknown["result_set_complete"])
        qr = Pages([{}] * 501)
        finding = await collect_query(qr, query, "events", "offense_linked", Budget(max_pages=1))
        self.assertFalse(finding["result_set_complete"])
        self.assertEqual(finding["next_start"], 500)
        self.assertEqual(qr.result_starts, [0])

    async def test_permission_failure_is_not_a_negative_search(self):
        query = "SELECT * FROM events LIMIT 5000 LAST 1 HOURS"
        with patch("soc_bridge.ariel_collection.start_query", AsyncMock(side_effect=RuntimeError("permission"))):
            finding = await collect_query(object(), query, "events", "offense_linked")
        self.assertEqual(finding["state"], "unavailable")
        self.assertFalse(finding["result_set_complete"])
        self.assertTrue(finding["warnings"])


class EvidenceSemanticsTests(unittest.TestCase):
    def test_millisecond_conversion_and_device_clock_are_distinct(self):
        self.assertEqual(utc(MS + 123), "2026-10-09T16:00:00.123Z")
        summary = event_summary([{"starttime": MS + 123, "devicetime": MS - 60000}])
        self.assertEqual(summary["observed_interval"]["start"], utc(MS + 123))

    def test_success_qid_does_not_override_4648_and_decoding_never_proves_completeness(self):
        command = "(Get-ItemProperty -Path HKLM:\\SYNTHETIC"
        blob = base64.b64encode(command.encode("utf-16le")).decode()
        rows = [{"event_name": "successful explicit credentials", "raw_payload": "EventID=4648"},
                {"raw_payload": "powershell.exe -EncodedCommand " + blob}]
        summary = host_summary(rows)
        self.assertIn("outcome", summary["explicit_credential_attempts"][0]["meaning"])
        self.assertEqual(summary["encoded_commands"][0]["decoded_utf16le"], command)
        self.assertFalse(summary["encoded_commands"][0]["executed_by_bridge"])
        self.assertIn("Not proven", summary["encoded_commands"][0]["completeness"])
        self.assertFalse(summary["no_anomaly_claim_permitted"])

    def test_missing_ports_or_non_dhcp_flow_does_not_get_dhcp_statement(self):
        self.assertFalse(flow_summary([{"sourceport": 67, "protocolid": 17}])["dhcp_port_pattern"])
        self.assertFalse(flow_summary([])["dhcp_port_pattern"])
        self.assertEqual(flow_summary([{}])["port_groups"][0]["missing_byte_fields"], 2)

    def test_actual_ibm_formatted_rule_json_is_parsed_without_expanding_mutation_allowlist(self):
        raw = "Rule ID: 12\nName: Synthetic\n\nFull JSON:\n{\"id\":12,\"enabled\":true}"
        response = CallToolResult(content=[TextContent(type="text", text=raw)])
        session = SimpleNamespace(call_tool=AsyncMock(return_value=response))
        client = RestrictedMCP(session, QRADAR_TOOLS, {"get_rule"}, {"get_rule"})
        import asyncio
        self.assertEqual(asyncio.run(client.call("get_rule", {"rule_id": 12}))["id"], 12)
        self.assertFalse({"update_rule", "set_offense_status", "assign_offense"} & QRADAR_TOOLS)


if __name__ == "__main__":
    unittest.main()
