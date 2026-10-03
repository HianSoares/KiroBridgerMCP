"""Real MCP HTTP sessions against a synthetic local server; no product credentials."""

import asyncio
from pathlib import Path
import socket
import subprocess
import sys
import time
import unittest

from soc_bridge.transports import live_qradar_query


class ArielTransportTests(unittest.TestCase):
    def test_resources_queries_and_pagination_survive_separate_mcp_sessions(self):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        server = subprocess.Popen([sys.executable, str(Path(__file__).with_name("fake_qradar_mcp.py")), str(port)],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            # Startup can exceed 10 s on a loaded Windows host while the full suite runs.
            deadline = time.monotonic() + 30
            while True:
                if server.poll() is not None:
                    self.fail("Synthetic QRadar MCP server exited before startup")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=.1):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        self.fail("Synthetic QRadar MCP server did not start")
                    time.sleep(.05)

            async def scenario():
                url = f"http://127.0.0.1:{port}/mcp"
                metadata = await live_qradar_query("resource", {"resource": "events"}, url, None)
                self.assertEqual(metadata["metadata"]["fields"][0]["name"], "payload")
                for name in ["flows", "functions", "guide"]:
                    resource = await live_qradar_query("resource", {"resource": name}, url, None)
                    self.assertIn("qradar://aql/", resource["resource"])
                for database in ["events", "flows"]:
                    query = f"SELECT * FROM {database} LIMIT 100 LAST 1 HOURS"
                    first = await live_qradar_query("run", {"query": query, "limit": 1}, url, None)
                    self.assertEqual(first["database"], database)
                    self.assertEqual(first["rows"][0]["RawPayload"], "synthetic event")
                    self.assertEqual(first["next_start"], 1)
                    # A fresh session must retrieve the same upstream job, not recreate it.
                    second = await live_qradar_query("results", {"search_id": first["search_id"], "start": 1, "limit": 1}, url, None)
                    self.assertEqual(second["search_id"], first["search_id"])
                    self.assertEqual(second["rows"][0]["RawPayload"], "second synthetic event")
                    self.assertFalse(second["has_more"])
                rule = await live_qradar_query("rule", {"rule_id": 12}, url, None)
                self.assertEqual(rule["id"], 12)
                verified = await live_qradar_query("verify_offense", {"offense_id": 12345}, url, None)
                self.assertEqual(verified["offense_id"], 12345)
                self.assertEqual(verified["rules"][0]["metadata"]["id"], 12)
                self.assertEqual(verified["flows"]["distinct_destinations_in_search"], 1)
                self.assertTrue(verified["queries"]["events"]["result_set_complete"])
                self.assertEqual(verified["host"]["explicit_credential_attempts"][0]["event_id"], 4648)
                self.assertFalse(verified["assessment"]["final_benign_verdict_permitted"])

                found = await live_qradar_query("find_offenses", {
                    "description": "Synthetic matching offenses", "limit": 2}, url, None)
                self.assertEqual([r["id"] for r in found["offenses"]], [12345, 12346])
                self.assertFalse(found["discovery_exhausted"])
                self.assertEqual(found["next_offset"], 4)
                self.assertEqual(found["upstream_total_count"], 5)
                self.assertIsNone(found["total_count"])
                failed = await live_qradar_query("find_offenses", {
                    "description": "Synthetic upstream error", "status": "HIDDEN"}, url, None)
                self.assertEqual(failed["error"]["category"], "upstream_tool_error")
                self.assertTrue(failed["mcp_tool_call_attempted"])
                self.assertEqual(failed["budget"]["calls_made"], 1)
                self.assertNotIn("private-error-body", str(failed))
                batch = await live_qradar_query("investigate_offenses", {
                    "description": "Synthetic matching offenses", "max_offenses": 2}, url, None)
                self.assertEqual([r["offense_id"] for r in batch["reports"]], [12345, 12346])
                last = await live_qradar_query("investigate_offenses", {
                    **batch["continuation_plan"][-1]["parameters"]}, url, None)
                self.assertEqual(last["reports"][0]["offense_id"], 12347)
                self.assertTrue(last["discovery"]["discovery_exhausted"])

            asyncio.run(scenario())
        finally:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
