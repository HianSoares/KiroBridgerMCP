"""Synthetic query lifecycle, policy boundaries and evidence preservation."""

import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from mcp.types import CallToolResult, TextContent

from soc_bridge.aql_search import (check_query, run_query, start_query, search_results,
                                   MAX_FIELD_CHARS)
from soc_bridge.transports import RestrictedMCP, QRADAR_TOOLS, live_qradar_query
from soc_bridge.kiro_server import mcp


SID = "c643b969-2626-410e-89e4-9b1e1308aab0"
QUERY = "SELECT starttime, UTF8(payload) AS RawPayload FROM events WHERE INOFFENSE(12345) LIMIT 100 LAST 1 HOURS"


class QRadar:
    def __init__(self, database="events", rows=None, states=None, total=None, valid=True):
        self.calls = []
        self.database = database
        self.rows = rows if rows is not None else [{"RawPayload": "pam_unix(su:session): for user root by demo(uid=1000)",
                                                   "Target Username": "root", "devicetime": 1790255701000}]
        self.states = list(states or ["COMPLETED"])
        self.total = len(self.rows) if total is None else total
        self.valid = valid

    async def call(self, name, args):
        self.calls.append((name, args))
        if name == "validate_aql":
            return {"valid": self.valid}
        if name == "create_ariel_search":
            return {"search_id": SID, "status": "WAIT"}
        if name == "get_ariel_search_status":
            state = self.states.pop(0) if len(self.states) > 1 else self.states[0]
            return {"status": state, "record_count": self.total}
        if name == "get_ariel_search_results":
            return {self.database: self.rows[args["start"]:args["start"] + args["limit"]]}
        raise AssertionError(name)


class QueryPolicyTests(unittest.TestCase):
    def test_custom_columns_payload_and_arbitrary_filters_are_allowed(self):
        scope = check_query(QUERY)
        self.assertEqual(scope["database"], "events")
        scope = check_query('SELECT "Target Username", QIDNAME(qid) FROM events WHERE qid=1 LIMIT 20 LAST 30 MINUTES')
        self.assertEqual(scope["window_hours"], .5)

    def test_flows_and_absolute_window(self):
        scope = check_query("SELECT sourceip, destinationport FROM flows LIMIT 50 START '2026-09-24 09:00:00' STOP '2026-09-24 10:00:00'")
        self.assertEqual(scope["database"], "flows")
        self.assertEqual(scope["window_hours"], 1)

    def test_justified_historical_aggregates(self):
        query = "SELECT destinationport, COUNT(*) AS hits FROM events GROUP BY destinationport LIMIT 100 LAST 7 DAYS"
        self.assertTrue(check_query(query, "Compare this host against its weekly baseline")["aggregated"])
        for q, why in [(query, ""), ("SELECT UTF8(payload), COUNT(*) FROM events LIMIT 10 LAST 7 DAYS", "baseline"),
                       ("SELECT *, COUNT(*) FROM events LIMIT 10 LAST 7 DAYS", "baseline"),
                       ("SELECT * FROM events LIMIT 10 LAST 7 DAYS", "baseline")]:
            with self.subTest(q=q), self.assertRaises(ValueError):
                check_query(q, why)

    def test_invalid_or_unbounded_queries_never_start_jobs(self):
        queries = ["SELECT * FROM events", "SELECT * FROM events LIMIT 0 LAST 1 HOURS",
                   "SELECT * FROM events LIMIT 5001 LAST 1 HOURS", "SELECT * FROM events LIMIT 10 LAST 0 HOURS",
                   "SELECT COUNT(*) FROM flows LIMIT 10 LAST 31 DAYS", "DELETE FROM events",
                   "SELECT * INTO output FROM events LIMIT 1 LAST 1 HOURS",
                   "SELECT * FROM assets LIMIT 1 LAST 1 HOURS",
                   "SELECT * FROM events WHERE x IN (SELECT x FROM events) LIMIT 10 LAST 1 HOURS",
                   "SELECT * FROM events LIMIT 10 LAST 1 HOURS; SELECT * FROM events",
                   "SELECT * FROM events -- LIMIT 10 LAST 1 HOURS",
                   "SELECT * FROM events /* LIMIT 10 LAST 1 HOURS */",
                   "SELECT * FROM events WHERE x='LIMIT 10 LAST 1 HOURS'",
                   "SELECT * FROM events LIMIT 10 START '2026-09-24 10:00:00' STOP '2026-09-24 09:00:00'",
                   "SELECT * FROM events LIMIT 10 TIMES OFFENSE_TIME(12345)",
                   "SELECT UTF8(payload FROM events LIMIT 10 LAST 1 HOURS",
                   "SELECT * FROM events WHERE x='unterminated LIMIT 10 LAST 1 HOURS"]
        for query in queries:
            with self.subTest(query=query):
                qr = QRadar()
                with self.assertRaises(ValueError):
                    asyncio.run(start_query(qr, query, "synthetic test"))
                self.assertEqual(qr.calls, [])

    def test_literals_do_not_trigger_syntax_policy(self):
        query = "SELECT UTF8(payload) FROM events WHERE UTF8(payload) LIKE '%DROP; -- LAST 99 DAYS%' LIMIT 10 LAST 1 HOURS"
        self.assertEqual(check_query(query)["window_hours"], 1)


class QueryLifecycleTests(unittest.TestCase):
    def test_validation_precedes_creation_and_payload_is_preserved(self):
        qr = QRadar()
        result = asyncio.run(run_query(qr, QUERY))
        self.assertEqual([name for name, _ in qr.calls][:2], ["validate_aql", "create_ariel_search"])
        self.assertEqual(result["rows"], qr.rows)
        self.assertEqual(result["search_id"], SID)
        self.assertTrue(result["results_available"])
        self.assertFalse(result["has_more"])

    def test_upstream_validation_failure_does_not_create_job(self):
        qr = QRadar(valid=False)
        with self.assertRaises(ValueError):
            asyncio.run(start_query(qr, QUERY))
        self.assertEqual(len(qr.calls), 1)

    def test_pending_search_resumes_without_recreating(self):
        qr = QRadar(states=["EXECUTE"] * 4 + ["COMPLETED"])
        pending = asyncio.run(run_query(qr, QUERY))
        self.assertFalse(pending["results_available"])
        self.assertEqual(pending["search_id"], SID)
        completed = asyncio.run(search_results(qr, SID))
        self.assertEqual(completed["rows"], qr.rows)
        self.assertEqual(sum(name == "create_ariel_search" for name, _ in qr.calls), 1)

    def test_failed_search_is_not_empty_completed_search(self):
        for state in ["ERROR", "CANCELED"]:
            with self.subTest(state=state):
                result = asyncio.run(run_query(QRadar(states=[state]), QUERY))
                self.assertFalse(result["results_available"])
                self.assertEqual(result["status"], state)

    def test_flow_pages_preserve_all_fields_and_offsets(self):
        rows = [{"sourceBytes": i, "destinationPackets": 3} for i in range(5)]
        qr = QRadar(database="flows", rows=rows)
        first = asyncio.run(search_results(qr, SID, 0, 2))
        second = asyncio.run(search_results(qr, SID, first["next_start"], 2))
        third = asyncio.run(search_results(qr, SID, second["next_start"], 2))
        self.assertEqual(first["rows"] + second["rows"] + third["rows"], rows)
        self.assertEqual(first["database"], "flows")
        self.assertIsNone(third["next_start"])

    def test_raw_payload_truncation_and_page_budget_are_explicit(self):
        qr = QRadar(rows=[{"RawPayload": "x" * (MAX_FIELD_CHARS + 50)} for _ in range(10)])
        result = asyncio.run(search_results(qr, SID, 0, 10))
        self.assertEqual(len(result["rows"][0]["RawPayload"]), MAX_FIELD_CHARS)
        self.assertIn("rows[0].RawPayload", result["truncated_fields"])
        self.assertTrue(result["has_more"])
        self.assertEqual(result["next_start"], result["returned_rows"])
        self.assertLess(result["returned_rows"], 10)

    def test_bad_page_or_search_id_is_rejected_before_job_creation(self):
        qr = QRadar()
        for size in [0, 501, True]:
            with self.assertRaises(ValueError):
                asyncio.run(run_query(qr, QUERY, limit=size))
        for sid in ["../invalid", ""]:
            with self.assertRaises(ValueError):
                asyncio.run(search_results(qr, sid))
        self.assertEqual(qr.calls, [])

    def test_empty_page_with_nonzero_total_cannot_cause_an_infinite_pagination_loop(self):
        with self.assertRaisesRegex(ValueError, "empty page before record_count"):
            asyncio.run(search_results(QRadar(rows=[], total=5), SID))


class MCPExposureTests(unittest.TestCase):
    def test_all_six_query_tools_are_exposed_with_correct_schemas(self):
        tools = {tool.name: tool for tool in asyncio.run(mcp.list_tools())}
        names = {"qradar_read_aql_resource", "qradar_validate_aql", "qradar_start_aql",
                 "qradar_get_search_status", "qradar_get_search_results", "qradar_run_aql"}
        self.assertTrue(names <= tools.keys())
        self.assertEqual(len(tools), 15)
        for name in ("qradar_verify_offense", "qradar_get_rule"):
            self.assertTrue(tools[name].annotations.readOnlyHint)
        for name in names:
            self.assertTrue(tools[name].annotations.readOnlyHint)
        self.assertEqual(tools["qradar_run_aql"].inputSchema["required"], ["query_expression"])

    def test_resources_use_actual_ibm_uris_and_reject_arbitrary_resources(self):
        session = SimpleNamespace(read_resource=AsyncMock(return_value=SimpleNamespace(
            contents=[SimpleNamespace(text='{"fields": [{"name": "devicetime"}]}')])) )
        qr = RestrictedMCP(session, QRADAR_TOOLS, set(), set(), "QRadar")
        resource = asyncio.run(qr.read_aql_resource("events"))
        session.read_resource.assert_awaited_once_with("qradar://aql/events/fields")
        self.assertEqual(resource["metadata"]["fields"][0]["name"], "devicetime")
        with self.assertRaises(ValueError):
            asyncio.run(qr.read_aql_resource("file:///etc/passwd"))

    def test_readonly_allowlist_still_blocks_mutations(self):
        qr = RestrictedMCP(object(), QRADAR_TOOLS, QRADAR_TOOLS)
        for name in ["assign_offense", "add_offense_note", "set_offense_status", "delete_ariel_search"]:
            with self.assertRaises(ValueError):
                asyncio.run(qr.call(name, {}))

    def test_ibm_text_and_structured_validation_responses(self):
        for response in [CallToolResult(content=[TextContent(type="text", text="✓ AQL query is valid\n\nQuery: synthetic")]),
                         CallToolResult(content=[], structuredContent={"result": {"valid": True}})]:
            session = SimpleNamespace(call_tool=AsyncMock(return_value=response))
            qr = RestrictedMCP(session, QRADAR_TOOLS, QRADAR_TOOLS)
            self.assertEqual(asyncio.run(qr.call("validate_aql", {"query_expression": QUERY})), {"valid": True})

    def test_qradar_only_transport_never_starts_trend(self):
        # Exercise actual client/session construction with fake streams, not a product connection.
        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def stream(*args, **kwargs):
            yield (object(), object(), object())

        session = SimpleNamespace(initialize=AsyncMock(), list_tools=AsyncMock(return_value=SimpleNamespace(
            tools=[SimpleNamespace(name=name) for name in QRADAR_TOOLS])),
            call_tool=AsyncMock(return_value=CallToolResult(content=[TextContent(type="text", text='{"status":"COMPLETED","record_count":0}')])) )

        @asynccontextmanager
        async def client(*args, **kwargs):
            yield session

        with patch("mcp.client.streamable_http.streamable_http_client", stream), patch("mcp.ClientSession", client), \
                patch("mcp.client.stdio.stdio_client", side_effect=AssertionError("Trend must not start")):
            result = asyncio.run(live_qradar_query("status", {"search_id": SID}, "http://127.0.0.1:5001/mcp", None))
        self.assertEqual(result["status"], "COMPLETED")


if __name__ == "__main__":
    unittest.main()
