"""Regressions: list-valued users must not break the Search digest, and process instance identifiers
beyond 2**53 stay exact (no float conversion, rounding or grouping) through parsing, digest, rendering
and MCP output. Synthetic data only."""

import asyncio
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from mcp import StdioServerParameters

from soc_bridge import xdr_followup
from soc_bridge.trend_search import collect, parameters
from soc_bridge.transports import live_trend_search
from soc_bridge.xdr_followup import digest, followup, instance_id

from fake_trend_bigint_mcp import HOST, NEGATIVE, POSITIVE

ROOT = Path(__file__).resolve().parents[1]
BOUNDS = {"start_date_time": "2026-10-01T00:00:00Z", "end_date_time": "2026-10-01T01:00:00Z"}
IDS = POSITIVE + NEGATIVE


def run(coro):
    return asyncio.run(coro)


def selection():
    return parameters(f'endpointHostName:"{HOST}"', **BOUNDS)


def client(rows):
    return SimpleNamespace(call=AsyncMock(return_value={"items": rows}))


ROW = {"uuid": "syn-1", "eventTime": 1790000000000, "endpointHostName": HOST, "logonUser": ["EXAMPLE\\svc.synth"],
       "processHashId": -(2 ** 62) - 12345, "processPid": 4100, "processFilePath": "C:\\Tools\\tool.exe",
       "processCmd": "tool.exe run", "dst": "198.51.100.5", "dpt": 443}


class ListUserRegressionTests(unittest.TestCase):
    def test_list_valued_logon_user_keeps_a_complete_collection_complete(self):
        result = run(collect(client([ROW]), selection()))
        self.assertEqual(result["errors"], [])
        self.assertTrue(result["result_set_complete"])
        self.assertEqual(result["outcome"], "complete_in_window")
        actor = result["evidence_digest"]["actors"][0]
        self.assertEqual(actor["users"], ["EXAMPLE\\svc.synth"])
        self.assertEqual(actor["observations"][0]["user"], ["EXAMPLE\\svc.synth"])  # native value kept as returned
        self.assertEqual(result["records"][0]["data"], ROW)

    def test_a_local_digest_failure_is_reported_without_changing_the_collection(self):
        with patch.object(xdr_followup, "digest", side_effect=TypeError("synthetic digest bug")):
            result = run(collect(client([ROW]), selection()))
        self.assertTrue(result["result_set_complete"])
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["returned_records"], 1)
        failure = result["evidence_digest"]
        self.assertEqual((failure["state"], failure["error"]["type"]), ("failed", "TypeError"))
        self.assertIn("local processing", failure["stage"])
        self.assertNotIn("synthetic digest bug", json.dumps(failure))  # type and location only


class LargeIdentifierTests(unittest.TestCase):
    def test_values_collide_as_float_but_not_as_identifiers(self):
        self.assertEqual(float(POSITIVE[0]), float(POSITIVE[1]))
        self.assertEqual(float(NEGATIVE[0]), float(NEGATIVE[1]))
        self.assertEqual([instance_id(v) for v in IDS], [str(v) for v in IDS])
        self.assertIsNone(instance_id(float(POSITIVE[0])))  # a float can never be an exact identifier
        self.assertIsNone(instance_id(True))

    def rows(self):
        from fake_trend_bigint_mcp import rows
        return rows()

    def test_digest_keeps_each_instance_exact_and_separate(self):
        d = digest([{"data": r} for r in self.rows()], "search_endpoint_activities_list", "q", True, 0)
        self.assertEqual([a["instance"] for a in d["actors"]], [str(v) for v in IDS])
        self.assertTrue(all(a["instance_native_type"] == "int" and a["pids"] and "conflict" not in a for a in d["actors"]))
        self.assertEqual(sorted(d["identifiers"]["instances"]), sorted(str(v) for v in IDS))
        aggregate = d["image_aggregates"][0]
        self.assertEqual(aggregate["instances"], [str(v) for v in IDS])
        occurrences = d["commands"][0]["occurrences"]
        self.assertEqual([o["instance"] for o in occurrences], [str(v) for v in IDS])
        self.assertEqual([f["object_instance"] for f in d["file_objects"]], [str(-v) for v in IDS])
        text = json.dumps(d)
        for value in IDS:
            self.assertIn(f'"{value}"', text)
        for rounded in {int(float(v)) for v in IDS}:
            self.assertNotIn(str(rounded), text)  # no rounded form anywhere

    def test_real_mcp_path_preserves_native_integers_and_exact_text(self):
        def synthetic(**kwargs):
            return StdioServerParameters(command=sys.executable, args=[str(ROOT / "tests" / "fake_trend_bigint_mcp.py")])
        with patch("mcp.StdioServerParameters", side_effect=synthetic):
            result = run(live_trend_search("search", {"query": f'endpointHostName:"{HOST}"', **BOUNDS},
                                           "synthetic-key", "us"))
        self.assertEqual(result["errors"], [])
        self.assertTrue(result["result_set_complete"])
        self.assertEqual([r["data"]["processHashId"] for r in result["records"]], list(IDS))
        self.assertTrue(all(type(r["data"]["processHashId"]) is int for r in result["records"]))
        self.assertEqual([a["instance"] for a in result["evidence_digest"]["actors"]], [str(v) for v in IDS])
        # What the MCP tool returns is serialized JSON: the native integers keep every digit.
        serialized = json.dumps(result)
        for value in IDS:
            self.assertIn(str(value), serialized)
        self.assertEqual([r["data"]["processHashId"] for r in json.loads(serialized)["records"]], list(IDS))

    def test_mcp_tool_output_carries_every_digit(self):
        from soc_bridge.kiro_server import mcp
        rows = self.rows()
        report = run(collect(client(rows), selection()))
        with patch("soc_bridge.kiro_server.live_trend_search", AsyncMock(return_value=report)), \
                patch.dict("os.environ", {"TREND_VISION_ONE_API_KEY": "synthetic-key"}):
            output = run(mcp.call_tool("trend_search_data", {"query": f'endpointHostName:"{HOST}"', **BOUNDS}))
        blocks = output[0] if isinstance(output, tuple) else output
        text = "".join(getattr(b, "text", "") for b in blocks)
        for value in IDS:
            self.assertIn(str(value), text)
        parsed = json.loads(text)
        self.assertEqual([r["data"]["processHashId"] for r in parsed["records"]], list(IDS))

    def test_seeds_keep_integer_instances_and_do_not_invent_a_numeric_query(self):
        records = []
        for n, value in enumerate(IDS):
            records.append({"tool": "search_endpoint_activities_list", "uuid": f"u{n}", "endpoint_host": HOST,
                            "endpoint_guid": None, "endpoint_ips": [], "event_time_utc": "2026-10-01T00:00:00.000Z",
                            "relation": {"label": "linked"},
                            "process": {"hashId": value, "filePath": "C:\\Tools\\tool.exe", "pid": 5000 + n}})
        report = {"extraction": {"endpoints": [{"name": HOST, "guid": None, "ips": [], "sources": ["alert detail"]}],
                                 "observables": {}},
                  "anchor": {"time_utc": "2026-10-01T00:00:00Z", "provisional": False}, "alert": {}}
        follow = followup(report, records)
        seeds = follow["seeds"]
        self.assertEqual([i["id"] for i in seeds["instances"]], [str(v) for v in IDS])
        self.assertTrue(all(i["id_native_type"] == "int" for i in seeds["instances"]))
        self.assertEqual([i["id"] for i in seeds["instance_queries_not_planned"]], [str(v) for v in IDS])
        self.assertFalse([p for p in follow["phases"] if p["kind"].startswith("instance_")])
        self.assertTrue(all(str(v) in json.dumps(follow) for v in IDS))


if __name__ == "__main__":
    unittest.main()
