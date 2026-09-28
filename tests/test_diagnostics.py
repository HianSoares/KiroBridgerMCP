"""A failed collection must identify its stage without leaking credentials."""

import asyncio
import unittest

import httpx

from soc_bridge.diagnostics import InvestigationUnavailable, failure_reason, unavailable
from soc_bridge.transports import RestrictedMCP


class DiagnosticsTests(unittest.TestCase):
    def test_nested_taskgroup_shows_status_without_url_or_secret(self):
        request = httpx.Request("POST", "http://127.0.0.1:5001/mcp?token=DO-NOT-LEAK")
        response = httpx.Response(401, request=request)
        error = httpx.HTTPStatusError("Secret: DO-NOT-LEAK", request=request, response=response)
        grouped = ExceptionGroup("unhandled errors in a TaskGroup", [ExceptionGroup("inner", [error])])
        result = str(unavailable("QRadar MCP initialization", grouped))
        self.assertIn("QRadar MCP initialization", result)
        self.assertIn("HTTP 401", result)
        self.assertNotIn("DO-NOT-LEAK", result)
        self.assertNotIn("TaskGroup", result)

    def test_connection_and_docker_failure_are_distinct(self):
        self.assertIn("Docker executable", failure_reason(ExceptionGroup("group", [FileNotFoundError("SECRET")])) )
        self.assertIn("closed unexpectedly", failure_reason(type("EndOfStream", (Exception,), {})()))

    def test_failed_workbench_call_reports_tool_without_returning_payload(self):
        class Session:
            async def call_tool(self, name, arguments):
                raise ExceptionGroup("group", [RuntimeError("SECRET: raw incident payload")])

        async def check():
            await RestrictedMCP(Session(), {"workbench_alert_detail_get"},
                                {"workbench_alert_detail_get"}, source="Vision One").call(
                "workbench_alert_detail_get", {"alertId": "WB-TEST-1"})

        with self.assertRaises(RuntimeError) as caught:
            asyncio.run(check())
        message = str(caught.exception)
        self.assertIn("Vision One workbench_alert_detail_get", message)
        self.assertNotIn("SECRET", message)

    def test_failed_server_response_names_tool(self):
        class Result:
            isError = True
            content = []

        class Session:
            async def call_tool(self, name, arguments):
                return Result()

        async def check():
            await RestrictedMCP(Session(), {"workbench_alert_detail_get"},
                                {"workbench_alert_detail_get"}, source="Vision One").call(
                "workbench_alert_detail_get", {"alertId": "WB-TEST-1"})

        with self.assertRaises(RuntimeError) as caught:
            asyncio.run(check())
        self.assertIn("upstream returned a tool error", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
