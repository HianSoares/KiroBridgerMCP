"""Synthetic live transports: collected reports must survive teardown failures."""

import asyncio
import json
import unittest
from contextlib import ExitStack, asynccontextmanager
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import anyio

from soc_bridge import transports
from soc_bridge.alert_investigation import investigate_vision_alert, render_alert_markdown
from soc_bridge.alert_resume import AlertReadCache, AlertReadState
from soc_bridge.ariel_collection import Budget
from soc_bridge.capabilities import Ledger, ToolSet, Discovery
from soc_bridge.connection_lifecycle import InvestigationConnections
from soc_bridge.diagnostics import InvestigationUnavailable, MCPToolFailure
from soc_bridge.trend_qradar import correlate
from soc_bridge.workbench_extract import parse_alert

from test_alert_investigation import QRadar, qradar_with_sysmon
from test_offense_evidence import QRadar as ArielQRadar
from trend_fixtures import ALERT, ALERT_ID, FakeVision, NOW, T0, procdump_search, z


class LiveHarness:
    def __init__(self, broken=(), cancel_shutdown=False):
        self.broken = broken
        self.cancel_shutdown = cancel_shutdown
        self.closed = []

    @asynccontextmanager
    async def resource(self, name, value):
        try:
            yield value
        finally:
            self.closed.append(name)
            if name in self.broken:
                if self.cancel_shutdown:
                    raise asyncio.CancelledError()
                raise ExceptionGroup("SECRET-BODY", [anyio.ClosedResourceError()])

    def patch(self, collector, target="soc_bridge.alert_investigation.investigate_vision_alert"):
        stack = ExitStack()
        stack.enter_context(patch("httpx.AsyncClient", lambda **kw: self.resource("http", object())))
        stack.enter_context(patch("mcp.client.streamable_http.streamable_http_client",
                                  lambda *a, **kw: self.resource("qradar", (None, None))))
        stack.enter_context(patch("mcp.client.stdio.stdio_client",
                                  lambda *a, **kw: self.resource("trend", (None, None))))

        class Session:
            def __init__(self, *a, **kw):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

            async def initialize(self):
                return None

            async def call_tool(self, *args, **kw):
                return SimpleNamespace(isError=False, structuredContent={"items": []})

        stack.enter_context(patch("mcp.ClientSession", Session))
        names = ToolSet(transports.QRADAR_READ_TOOLS | transports.ALERT_VISION_TOOLS)
        names.discovery = Discovery("synthetic")
        names.discovery.names = names
        names.discovery.complete = True
        stack.enter_context(patch.object(transports, "tool_names", AsyncMock(return_value=names)))
        stack.enter_context(patch(target, collector))
        stack.enter_context(patch.object(transports, "ALERT_READ_CACHE", AlertReadCache(), create=True))
        return stack

    async def alert(self):
        return await transports.live_alert_investigation(
            ALERT_ID, "http://127.0.0.1:5001/mcp", "synthetic-token", "synthetic-key", "us")


class ShutdownTests(unittest.IsolatedAsyncioTestCase):
    async def test_qradar_start_search_id_survives_connection_shutdown(self):
        harness = LiveHarness(broken=("qradar",))
        with harness.patch(AsyncMock(return_value={"search_id": "synthetic-existing-job", "status": "WAIT"}),
                           "soc_bridge.aql_search.start_query"):
            report = await transports.live_qradar_query("start", {"query": "synthetic"},
                                                         "http://127.0.0.1:5001/mcp", None)
        self.assertEqual(report["search_id"], "synthetic-existing-job")
        self.assertTrue(report["connection_lifecycle"]["report_preserved"])

    async def test_real_stdio_sdk_opens_and_closes_in_the_same_task(self):
        import sys
        from pathlib import Path
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
        async with InvestigationConnections() as scope:
            stream = await scope.enter(stdio_client(StdioServerParameters(
                command=sys.executable, args=[str(Path(__file__).with_name("fake_stdio_mcp.py")), "normal"])),
                "synthetic", "stdio")
            session = await scope.enter(ClientSession(*stream), "synthetic", "session")
            await session.initialize()
            tools = await session.list_tools()
            report = scope.collected({"count": len(tools.tools)})
        self.assertEqual(scope.deliver(report), {"count": 1})

    async def test_hanging_cleanup_is_bounded_and_keeps_report(self):
        @asynccontextmanager
        async def hanging():
            yield None
            await asyncio.Event().wait()

        with patch.object(InvestigationConnections, "CLEANUP_SECONDS", 0.02):
            async with InvestigationConnections() as scope:
                await scope.enter(hanging(), "Vision One", "synthetic transport")
                report = scope.collected({"evidence": "preserved"})
        self.assertEqual(scope.deliver(report)["evidence"], "preserved")
        self.assertIn("timed out", report["connection_lifecycle"]["shutdown_errors"][0]["reason"])

    async def test_trend_cleanup_failure_delivers_evidence_and_names_source(self):
        harness = LiveHarness(broken=("trend",))
        evidence = {"alert_id": ALERT_ID, "evidence": [{"search_id": "synthetic-job", "cursor": 500}],
                    "assessment": {"classification": "Inconclusive"}}
        with harness.patch(AsyncMock(return_value=deepcopy(evidence))):
            report = await harness.alert()
        self.assertEqual(report["evidence"], evidence["evidence"])
        self.assertEqual(report["assessment"], evidence["assessment"])
        self.assertEqual(report["connection_lifecycle"]["shutdown_errors"][0]["source"], "Vision One")
        self.assertFalse(report["connection_lifecycle"]["retry_collection"])
        self.assertNotIn("SECRET-BODY", json.dumps(report))
        self.assertEqual(harness.closed, ["trend", "qradar", "http"])

    async def test_qradar_cleanup_is_not_blamed_on_trend(self):
        harness = LiveHarness(broken=("qradar",))
        with harness.patch(AsyncMock(return_value={"alert_id": ALERT_ID})):
            report = await harness.alert()
        self.assertEqual(report["connection_lifecycle"]["shutdown_errors"][0]["source"], "QRadar")

    async def test_multiple_cleanup_failures_are_recorded_and_all_resources_closed(self):
        harness = LiveHarness(broken=("trend", "qradar", "http"))
        with harness.patch(AsyncMock(return_value={"alert_id": ALERT_ID})):
            report = await harness.alert()
        self.assertEqual(len(report["connection_lifecycle"]["shutdown_errors"]), 3)
        self.assertEqual(harness.closed, ["trend", "qradar", "http"])

    async def test_real_collection_error_is_not_overwritten_by_cleanup(self):
        harness = LiveHarness(broken=("trend",))
        with harness.patch(AsyncMock(side_effect=MCPToolFailure("QRadar", "get_offense", "HTTP 403"))):
            with self.assertRaises(InvestigationUnavailable) as caught:
                await harness.alert()
        self.assertIn("QRadar tool get_offense", str(caught.exception))
        self.assertNotIn("connection closed", str(caught.exception))

    async def test_collection_cancellation_propagates_even_when_cleanup_fails(self):
        harness = LiveHarness(broken=("trend",))
        with harness.patch(AsyncMock(side_effect=asyncio.CancelledError())):
            with self.assertRaises(asyncio.CancelledError):
                await harness.alert()

    async def test_shutdown_cancellation_is_not_returned_as_success(self):
        harness = LiveHarness(broken=("trend",), cancel_shutdown=True)
        with harness.patch(AsyncMock(return_value={"alert_id": ALERT_ID})):
            with self.assertRaises(asyncio.CancelledError):
                await harness.alert()

    async def test_success_does_not_add_shutdown_warning(self):
        harness = LiveHarness()
        with harness.patch(AsyncMock(return_value={"alert_id": ALERT_ID})):
            report = await harness.alert()
        self.assertNotIn("connection_lifecycle", report)

    async def test_other_investigation_paths_preserve_reports(self):
        for kind, target in (("offense", "soc_bridge.core.investigate"),
                             ("case", "soc_bridge.case_investigation.investigate_offense_case"),
                             ("epm", "soc_bridge.extra_cases.investigate_epm_uac"),
                             ("web", "soc_bridge.extra_cases.investigate_web_reputation")):
            with self.subTest(kind=kind):
                harness = LiveHarness(broken=("qradar",))
                report = "Synthetic evidence" if kind in ("epm", "web") else {"capabilities": {}, "id": 12345}
                with harness.patch(AsyncMock(return_value=report), target):
                    args = ("http://127.0.0.1:5001/mcp", None, "synthetic-key", "us")
                    if kind == "offense":
                        result = await transports.live_investigation(12345, *args)
                    elif kind == "case":
                        result = await transports.live_case_investigation(12345, *args, include_trend=False)
                    else:
                        result = await transports.live_extra_case(kind, {}, *args)
                if isinstance(result, str):
                    self.assertIn("Synthetic evidence", result)
                    self.assertIn("shutdown warning", result)
                else:
                    self.assertEqual(result["id"], 12345)
                    self.assertTrue(result["connection_lifecycle"]["report_preserved"])

    async def test_alert_call_ledger_is_this_investigation_not_process_history(self):
        async def collector(qr, vision, *a, **kw):
            await vision.call("workbench_alert_notes_list", {"alertId": ALERT_ID})
            return {"alert_id": ALERT_ID}

        harness = LiveHarness()
        with harness.patch(collector):
            report = await harness.alert()
        self.assertEqual(report["call_outcomes"]["calls"], {"workbench_alert_notes_list": {"tested_ok": 1}})
        self.assertIn("this alert", report["call_outcomes"]["scope"])


class PartialCollectionTests(unittest.IsolatedAsyncioTestCase):
    async def test_continuation_values_are_not_cut_in_markdown(self):
        report = await self.investigate()
        plan = [{"action": "fetch_next_page", "search_id": "synthetic-existing-job", "cursor": 500,
                 "aql": "synthetic-long-query-" + "x" * 2500 + "-END-OF-QUERY"}]
        report["qradar_correlation"]["plan"] = plan
        report["auto_pivots"]["continuation"] = [{"action": "search_partition", "query": "y" * 2500 + "-END-OF-PARTITION"}]
        text = render_alert_markdown(report)
        self.assertIn(json.dumps(plan), text)
        self.assertIn("-END-OF-PARTITION", text)

    async def test_uncertain_creation_is_not_recreated_on_resume(self):
        class Uncertain(ArielQRadar):
            async def call(self, name, args):
                result = await super().call(name, args)
                if name == "create_ariel_search":
                    raise MCPToolFailure("QRadar", name, "upstream MCP connection closed unexpectedly")
                return result

        qr, state = Uncertain(), {}
        parsed, anchor = parse_alert(ALERT), {"time_utc": z(T0), "provisional": False}
        await correlate(qr, Budget(max_queries=2), parsed, {"records_all": []}, anchor, NOW, query_state=state)
        uncertain = {k for k, f in state.items() if f.get("outcome") == "creation_uncertain"}
        self.assertTrue(uncertain)
        created = len(qr.jobs)
        second = await correlate(qr, Budget(max_queries=0), parsed, {"records_all": []}, anchor, NOW, query_state=state)
        self.assertEqual(len(qr.jobs), created)
        for key in uncertain:
            self.assertEqual(second["queries"][key]["outcome"], "creation_uncertain")
            self.assertEqual(second["queries"][key]["continuation"]["action"], "verify_creation_before_retry")

    async def test_partial_page_resume_keeps_cursor_and_previous_rows(self):
        class Paged(ArielQRadar):
            async def call(self, name, args):
                result = await super().call(name, args)
                if name == "create_ariel_search":
                    sid = result["search_id"]
                    database, _ = self.jobs[sid]
                    if database == "events":
                        self.jobs[sid] = (database, [{"starttime": int(T0.timestamp()*1000) + i,
                                                     "raw_payload": "EventID=4648", "synthetic_index": i}
                                                    for i in range(601)])
                return result

        qr, state = Paged(), {}
        parsed, anchor = parse_alert(ALERT), {"time_utc": z(T0), "provisional": False}
        first = await correlate(qr, Budget(max_queries=2, max_pages=1), parsed, {"records_all": []}, anchor, NOW,
                                query_state=state)
        key = next(k for k, f in state.items() if f.get("next_start") == 500)
        sid = state[key]["search_id"]
        self.assertEqual(len(state[key]["rows"]), 500)
        created = len(qr.jobs)
        second = await correlate(qr, Budget(max_queries=0), parsed, {"records_all": []}, anchor, NOW, query_state=state)
        self.assertEqual(len(qr.jobs), created)
        self.assertEqual(second["queries"][key]["returned_rows"], 601)
        self.assertEqual(second["queries"][key]["resume"]["cursor"], 500)
        self.assertEqual([r["synthetic_index"] for r in state[key]["rows"]], list(range(601)))
        self.assertTrue(any(name == "get_ariel_search_results" and args["search_id"] == sid and args["start"] == 500
                            for name, args in qr.calls))
        self.assertTrue(first["plan"])

    async def test_changed_plan_does_not_replace_a_known_job(self):
        qr, state = ArielQRadar(), {}
        parsed, anchor = parse_alert(ALERT), {"time_utc": z(T0), "provisional": False}
        await correlate(qr, Budget(max_polls=0, max_queries=2), parsed, {"records_all": []}, anchor, NOW, query_state=state)
        key = next(k for k, f in state.items() if f.get("search_id"))
        sid = state[key]["search_id"]
        state[key]["aql"] += " synthetic-plan-change"
        created = len(qr.jobs)
        result = await correlate(qr, Budget(), parsed, {"records_all": []}, anchor, NOW, query_state=state)
        self.assertEqual(len(qr.jobs), created)
        self.assertEqual(result["queries"][key]["search_id"], sid)
        self.assertEqual(result["queries"][key]["resume"]["action"], "requires_resolution")
        self.assertTrue(result["error"])

    async def test_cancellation_keeps_checkpoint_and_propagates(self):
        async def cancelled(qr, query, database, scope, *a, progress, **kw):
            from soc_bridge.ariel_collection import snapshot
            progress(snapshot({"aql": query, "database": database, "scope": scope,
                               "search_id": "synthetic-existing-job", "rows": []}, "created"), "created")
            raise asyncio.CancelledError()

        state = {}
        with patch("soc_bridge.trend_qradar.collect_query", cancelled):
            with self.assertRaises(asyncio.CancelledError):
                await correlate(ArielQRadar(), Budget(), parse_alert(ALERT), {"records_all": []},
                                {"time_utc": z(T0)}, NOW, query_state=state)
        self.assertTrue(any(f.get("search_id") == "synthetic-existing-job" for f in state.values()))

    async def investigate(self):
        return await investigate_vision_alert(qradar_with_sysmon(), FakeVision(search=procdump_search),
                                              ALERT_ID, now=NOW, enable_vision_search=True, ariel_offset_hours=-3)

    async def test_enrichment_failure_keeps_search_and_qradar_evidence(self):
        with patch("soc_bridge.trend_enrichment.enrich", AsyncMock(side_effect=RuntimeError("SECRET-BODY"))):
            report = await self.investigate()
        self.assertGreater(report["auto_pivots"]["search_rows"], 0)
        self.assertTrue(report["qradar_correlation"]["queries"])
        self.assertEqual(report["collection"]["state"], "partial")
        text = render_alert_markdown(report)
        self.assertIn("Trend enrichment", text)
        self.assertNotIn("SECRET-BODY", text)

    async def test_correlation_failure_keeps_trend_evidence_and_reports_gap(self):
        with patch("soc_bridge.trend_qradar.load_catalog", AsyncMock(side_effect=MCPToolFailure(
                "QRadar", "fields", "HTTP 403"))):
            report = await self.investigate()
        self.assertGreater(report["auto_pivots"]["search_rows"], 0)
        error = report["qradar_correlation"]["error"]
        self.assertEqual(error["category"], "permission")
        self.assertFalse(error["retryable"])
        self.assertEqual(report["collection"]["state"], "partial")

    async def test_discovery_failure_is_not_complete_empty_coverage(self):
        with patch("soc_bridge.alert_discovery.discover", AsyncMock(side_effect=RuntimeError("SECRET-BODY"))):
            report = await self.investigate()
        self.assertEqual(report["alert_id"], ALERT_ID)
        self.assertEqual(report["assessment"]["classification"], "Inconclusive")
        self.assertNotEqual(report["assessment"]["requirements"]["search_coverage_complete"]["status"], "confirmed")
        self.assertIn("Trend Search/OAT", render_alert_markdown(report))

    async def test_failed_second_search_retains_records_from_first_search(self):
        from soc_bridge.alert_discovery import discover
        from soc_bridge.vision_search import search as original
        calls = 0

        async def search(*args, **kw):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise RuntimeError("SECRET-BODY")
            return await original(*args, **kw)

        with patch("soc_bridge.vision_search.search", search):
            result = await discover(FakeVision(search=procdump_search), Budget(), parse_alert(ALERT),
                                    {"time_utc": z(T0), "provisional": False})
        self.assertTrue(result["records_all"])
        self.assertEqual(result["error"]["stage"], "Trend Search/OAT")
        self.assertTrue(result["continuation"])

    async def test_known_jobs_resume_without_new_creation(self):
        qr, state = ArielQRadar(), {}
        parsed, anchor = parse_alert(ALERT), {"time_utc": z(T0), "provisional": False}
        first = await correlate(qr, Budget(max_polls=0, max_queries=2), parsed, {"records_all": []}, anchor, NOW,
                                query_state=state)
        ids = {k: f["search_id"] for k, f in state.items() if f.get("search_id")}
        self.assertTrue(ids)
        created = len(qr.jobs)
        second = await correlate(qr, Budget(max_queries=0), parsed, {"records_all": []}, anchor, NOW,
                                 query_state=state)
        self.assertEqual(len(qr.jobs), created)
        for key, sid in ids.items():
            self.assertEqual(second["queries"][key]["search_id"], sid)
            self.assertEqual(second["queries"][key]["resume"]["action"], "continued_same_search")
            self.assertTrue(second["queries"][key]["result_set_complete"])
        self.assertTrue(first["plan"])

    async def test_unexpected_error_after_creation_preserves_search_id_and_plan(self):
        async def broken(qr, query, database, scope, *a, progress, **kw):
            finding = {"aql": query, "database": database, "scope": scope, "search_id": "synthetic-existing-job",
                       "rows": [], "state": "WAIT"}
            from soc_bridge.ariel_collection import snapshot
            progress(snapshot(finding, "created"), "created")
            raise RuntimeError("SECRET-BODY")

        state = {}
        with patch("soc_bridge.trend_qradar.collect_query", broken):
            result = await correlate(ArielQRadar(), Budget(), parse_alert(ALERT), {"records_all": []},
                                     {"time_utc": z(T0)}, NOW, query_state=state)
        self.assertEqual(result["plan"][0]["search_id"], "synthetic-existing-job")
        self.assertEqual(result["plan"][0]["action"], "poll_same_search")
        self.assertTrue(state)
        self.assertNotIn("SECRET-BODY", json.dumps(result))

    async def test_workbench_failure_still_fails_without_fabricating_report(self):
        vision = FakeVision()
        vision.call = AsyncMock(side_effect=MCPToolFailure("Vision One", "workbench_alert_detail_get", "HTTP 403"))
        with self.assertRaises(MCPToolFailure):
            await investigate_vision_alert(QRadar(), vision, ALERT_ID, now=NOW)


class ResumeCacheTests(unittest.IsolatedAsyncioTestCase):
    async def test_reused_work_does_not_consume_new_call_record_partition_budget(self):
        session = SimpleNamespace(call_tool=AsyncMock(return_value=SimpleNamespace(isError=False, structuredContent={"items": []})))
        client = transports.RestrictedMCP(session, {"read"}, {"read"}, read_state=AlertReadState())
        await client.call("read", {"id": 1})
        budget = Budget(max_calls=1, max_records=1, max_partitions=1)
        budget.calls_made += 1
        budget.partitions_used += 1
        await budget.run(lambda: client.call("read", {"id": 1}), "read partition")
        budget.observe_rows(100)
        self.assertIsNone(budget.blocked("call"))
        self.assertIsNone(budget.blocked("record"))
        self.assertIsNone(budget.blocked("partition"))
        budget.calls_made += 1
        await budget.run(lambda: client.call("read", {"id": 2}), "new read")
        budget.observe_rows(1)
        self.assertEqual(budget.calls_made, 1)
        self.assertEqual(budget.records_seen, 1)
        self.assertEqual(budget.reused_records, 100)
        self.assertEqual(session.call_tool.await_count, 2)

    async def test_waiting_alert_state_cannot_be_evicted(self):
        cache = AlertReadCache()
        cache.MAX_ALERTS = 1
        state = AlertReadState()
        # A waiter counts as a user even when the lock has just been released.
        async with cache.session([ALERT_ID]) as state:
            state.users += 1
        try:
            with self.assertRaises(RuntimeError):
                async with cache.session(["WB-OTHER-1"]):
                    self.fail("active/waiting entry was evicted")
        finally:
            state.users -= 1

    async def test_cache_is_isolated_by_credentials_alert_and_arguments(self):
        cache = AlertReadCache()
        async with cache.session(["synthetic-token-a", ALERT_ID]) as state:
            state.put("Vision One", "read", {"id": 1}, {"items": ["synthetic"]})
        async with cache.session(["synthetic-token-b", ALERT_ID]) as other:
            self.assertFalse(other.get("Vision One", "read", {"id": 1})[0])
        async with cache.session(["synthetic-token-a", "WB-OTHER-1"]) as other:
            self.assertFalse(other.get("Vision One", "read", {"id": 1})[0])
        async with cache.session(["synthetic-token-a", ALERT_ID]) as same:
            self.assertTrue(same.get("Vision One", "read", {"id": 1})[0])
            self.assertFalse(same.get("Vision One", "read", {"id": 2})[0])
        self.assertNotIn("synthetic-token", repr(cache.loops))

    async def test_completed_reads_are_reused_but_polling_and_creation_are_not(self):
        session = SimpleNamespace(call_tool=AsyncMock(return_value=SimpleNamespace(isError=False, structuredContent={})))
        names = {"workbench_alert_detail_get", "get_ariel_search_status", "create_ariel_search"}
        ledger = Ledger()
        client = transports.RestrictedMCP(session, names, names, ledger=ledger, read_state=AlertReadState())
        for name in names:
            for _ in range(2):
                await client.call(name, {})
        self.assertEqual(session.call_tool.await_count, 5)
        self.assertEqual(ledger.describe()["calls"]["workbench_alert_detail_get"], {"tested_ok": 1, "reused_read": 1})

    async def test_failed_reads_are_not_cached(self):
        session = SimpleNamespace(call_tool=AsyncMock(side_effect=RuntimeError("SECRET-BODY")))
        client = transports.RestrictedMCP(session, {"read"}, {"read"}, read_state=AlertReadState())
        for _ in range(2):
            with self.assertRaises(MCPToolFailure):
                await client.call("read", {})
        self.assertEqual(session.call_tool.await_count, 2)

    async def test_same_alert_runs_serialize_and_share_known_job(self):
        cache = AlertReadCache()
        started = asyncio.Event()
        release = asyncio.Event()

        async def first():
            async with cache.session([ALERT_ID]) as state:
                started.set()
                await release.wait()
                state.queries["synthetic"] = {"search_id": "same-job"}

        task = asyncio.create_task(first())
        await started.wait()

        async def second():
            async with cache.session([ALERT_ID]) as state:
                return state.queries["synthetic"]["search_id"]

        waiting = asyncio.create_task(second())
        await asyncio.sleep(0)
        self.assertFalse(waiting.done())
        release.set()
        await task
        self.assertEqual(await waiting, "same-job")

    async def test_expired_cache_and_copied_results_do_not_leak_state(self):
        cache = AlertReadCache()
        async with cache.session([ALERT_ID]) as state:
            state.put("Vision One", "read", {}, {"items": [1]})
            _, value = state.get("Vision One", "read", {})
            value["items"].append(2)
            self.assertEqual(state.get("Vision One", "read", {})[1]["items"], [1])
            state.touched = -999999
        state.touched = -999999
        async with cache.session([ALERT_ID]) as replacement:
            self.assertIsNot(replacement, state)


if __name__ == "__main__":
    unittest.main()
