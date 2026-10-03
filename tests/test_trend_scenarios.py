"""Dump targets, classification limits, Trend<->QRadar relations, transport safety and tool schemas."""

import asyncio
import unittest

from soc_bridge.capabilities import LOCAL_WRITE_TOOLS
from datetime import timedelta

from mcp.types import CallToolResult, TextContent

from soc_bridge import dump_analysis
from soc_bridge.alert_assessment import assess
from soc_bridge.ariel_collection import Budget
from soc_bridge.diagnostics import MCPToolFailure
from soc_bridge.kiro_server import mcp
from soc_bridge.trend_qradar import relate
from soc_bridge.trend_records import normalize
from soc_bridge.transports import (ALERT_TOOLSETS, ALERT_VISION_TOOLS, RestrictedMCP, tool_error_reason)

from trend_fixtures import APP_LAUNCH, CMD, GUID, HOST, PD, PD_ACCESS, PD_LAUNCH, PD_WRITE, T0, FakeVision, rec, z

UPSTREAM_WRITE_TOOLS = {  # names from the upstream write registries; must never be allowlisted
    "workbench_alert_update", "workbench_alert_notes_create", "workbench_alert_notes_delete",
    "workbench_alert_note_update", "dmm_exceptions_create", "dmm_exceptions_delete", "dmm_exception_update",
    "dmm_model_update", "threatintel_suspicious_objects_add", "threatintel_exceptions_add", "threatintel_sweep_trigger",
    "response_endpoints_isolate", "response_endpoints_terminate_process", "response_endpoints_run_script",
    "response_endpoints_run_osquery", "response_endpoints_collect_file", "sandbox_files_analyze", "sandbox_urls_analyze",
    "case_management_cases_create", "case_management_case_update", "endpoint_security_endpoints_delete",
    "oat_data_pipelines_create", "response_tasks_cancel"}


def records(*rows):
    return [normalize(r, "search_endpoint_activities_list", "q") for r in rows]


def run(coro):
    return asyncio.run(coro)


class DumpTargetTests(unittest.TestCase):
    def test_pid_reuse_makes_the_target_ambiguous(self):
        # A different image used the same PID earlier on the same endpoint.
        reused = rec("ev-other", -30, processFilePath="C:\\Windows\\notepad.exe", processPid=4321, processHashId="inst-np",
                     processLaunchTime=z(T0 - timedelta(minutes=30)))
        access_without_instance = dict(PD_ACCESS)
        access_without_instance.pop("objectProcessHashId")
        result = run(dump_analysis.analyze(FakeVision(), Budget(max_calls=0),
                                           records(APP_LAUNCH, reused, PD_LAUNCH, access_without_instance, PD_WRITE),
                                           [{"guid": GUID, "name": HOST, "ips": []}]))
        target = result["dumps"][0]["target"]
        self.assertEqual(target["status"], "ambiguous (PID reuse)")
        self.assertEqual(len(target["images"]), 2)

    def test_arguments_are_parsed_as_data(self):
        parsed = dump_analysis.parse_command('"C:\\Tools\\procdump64.exe" -accepteula -n 3 -ma lsass.exe "C:\\x y\\a.dmp"')
        self.assertEqual(parsed["dump_types"], ["full memory"])
        self.assertEqual(parsed["target_as_written"], "lsass.exe")
        self.assertFalse(parsed["target_is_pid"])
        self.assertEqual(parsed["destination_as_written"], "C:\\x y\\a.dmp")


class ClassificationTests(unittest.TestCase):
    def base_report(self, **extra):
        return {"alert_id": "WB-SYNTH-0001", "alert": {"model": "Synthetic"}, "clocks": {"anchor": {"provisional": False}},
                "auto_pivots": {"record_counts": {"linked": 1, "identifier_match": 0}, "continuation": []},
                "dump_analysis": {"dumps": []}, "enrichment": {}, "qradar_correlation": {"plan": []}, **extra}

    def dump(self, image, connections):
        return {"intent": "command line requests a full memory dump of 700", "execution": "observed: records",
                "dump_file": {"status": "file reference attributed to dump-tool instance", "paths": ["C:\\sample.dmp"]},
                "target": {"status": "confirmed by process-instance ID", "image": image}, "connections": connections}

    def test_lsass_reference_and_connection_are_suspicious_but_do_not_prove_malicious_transfer(self):
        report = self.base_report(dump_analysis={"dumps": [self.dump("C:\\Windows\\System32\\lsass.exe",
                                                                     [{"dst": "203.0.113.9"}])]})
        result = assess(report)
        self.assertEqual(result["classification"], "Inconclusive")
        self.assertEqual(result["malicious_discriminators"], [])
        self.assertTrue(result["suspicious_indicators"])
        self.assertIn("authorization/diagnostic source", " ".join(result["blocking"]))
        self.assertEqual(result["confidence"], "low")

    def test_non_lsass_dump_without_discriminator_is_not_benign(self):
        result = assess(self.base_report(dump_analysis={"dumps": [self.dump("C:\\App\\vendor.exe", [])]}))
        self.assertEqual(result["classification"], "Inconclusive")
        self.assertIn("Benign True Positive needs an authorization source", result["justification"])

    def test_empty_bounded_search_is_never_a_false_positive(self):
        report = self.base_report(auto_pivots={"record_counts": {"linked": 0, "identifier_match": 0}, "continuation": []})
        result = assess(report)
        self.assertEqual(result["classification"], "Inconclusive")
        self.assertIn("not evidence of a False Positive", result["justification"])
        self.assertIn("no Search record is linked", " ".join(result["blocking"]))


class RelationTests(unittest.TestCase):
    trend = normalize(PD_LAUNCH, "search_endpoint_activities_list", "q")

    def qr(self, host, image=None, command=None, pid=None, utc=None):
        return {"event_id": 1, "computer": host, "image": image, "command": command, "pid": pid, "utc_time": utc,
                "sha256": None, "provenance": {"search_id": "s"}}

    def test_ip_or_time_only_is_unverified(self):
        self.assertEqual(relate(self.trend, self.qr("ws-other.example.test", PD, CMD))["label"], "unverified")

    def test_same_host_one_identifier_is_candidate_two_is_confirmed(self):
        self.assertEqual(relate(self.trend, self.qr(HOST, PD))["label"], "candidate")
        utc = (T0.replace(microsecond=0)).strftime("%Y-%m-%d %H:%M:%S") + ".500"
        confirmed = relate(self.trend, self.qr(HOST, PD, CMD, "6000", utc))
        self.assertEqual(confirmed["label"], "confirmed")
        self.assertIn("command line equal", confirmed["identifiers_equal"])


class TransportSafetyTests(unittest.TestCase):
    def test_tool_error_reason_keeps_status_but_not_body(self):
        result = CallToolResult(isError=True, content=[TextContent(
            type="text", text="failed (HTTP 403): {\"secret\": \"token-value\", \"host\": \"internal.example.test\"}")])
        reason = tool_error_reason(result)
        self.assertIn("HTTP 403", reason)
        self.assertNotIn("token-value", reason)
        self.assertNotIn("internal.example.test", reason)
        licensed = tool_error_reason(CallToolResult(isError=True, content=[TextContent(
            type="text", text="failed (HTTP 403): feature license not enabled")]))
        self.assertIn("license/integration", licensed)

    def test_alert_allowlist_and_toolsets_exclude_write_tools(self):
        self.assertFalse(ALERT_VISION_TOOLS & UPSTREAM_WRITE_TOOLS)
        self.assertNotIn("all", ALERT_TOOLSETS.split(","))
        client = RestrictedMCP(object(), ALERT_VISION_TOOLS, ALERT_VISION_TOOLS | UPSTREAM_WRITE_TOOLS)
        for name in sorted(UPSTREAM_WRITE_TOOLS):
            with self.subTest(name=name), self.assertRaises(ValueError):
                run(client.call(name, {}))

    def test_upstream_http_categories_map_to_distinct_states(self):
        from soc_bridge.aql_errors import classify_failure
        cases = {"upstream returned HTTP 404; x": "not_found", "upstream returned HTTP 429; x": "rate_limited",
                 "upstream returned HTTP 400; x": "request_rejected", "upstream returned HTTP 503; x": "upstream_error",
                 "upstream returned HTTP 403; response mentions license/integration availability; x": "license_or_integration"}
        for reason, category in cases.items():
            self.assertEqual(classify_failure(MCPToolFailure("Vision One", "t", reason))["category"], category)


class ToolSchemaTests(unittest.TestCase):
    def test_fifteen_read_only_tools_with_unchanged_alert_schemas(self):
        tools = {tool.name: tool for tool in asyncio.run(mcp.list_tools())}
        self.assertEqual(len(tools), 26)
        self.assertTrue(all((tool.annotations.readOnlyHint or tool.name in LOCAL_WRITE_TOOLS) and not tool.annotations.destructiveHint for tool in tools.values()))
        self.assertEqual(set(tools["investigate_vision_alert"].inputSchema["properties"]), {"alert_id"})
        self.assertEqual(tools["investigate_vision_alert"].inputSchema["required"], ["alert_id"])
        self.assertEqual(set(tools["investigate_vision_event"].inputSchema["properties"]),
                         {"alert_id", "endpoint_ip", "event_time", "endpoint_host", "file_hash", "file_path",
                          "process_path", "qradar_utc_offset_hours"})
        self.assertEqual(tools["investigate_vision_event"].inputSchema["required"], ["alert_id", "endpoint_ip", "event_time"])


if __name__ == "__main__":
    unittest.main()
