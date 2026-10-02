"""Search partitions, OAT tokens, clocks and record roles with synthetic Vision One responses."""

import asyncio
import unittest
from datetime import timedelta

from soc_bridge.ariel_collection import Budget
from soc_bridge.diagnostics import MCPToolFailure
from soc_bridge.time_anchor import build_clocks, parse, utc_ms
from soc_bridge.trend_records import MAX_FIELD, full_hashes, normalize
from soc_bridge import vision_search
from soc_bridge.workbench_extract import parse_alert

from trend_fixtures import ALERT, PD_LAUNCH, T0, z

SEARCH_ARGS = {"query", "startDateTime", "endDateTime", "top", "mode"}


class Paged:
    """Returns `per_window(start, end)` rows; a full page forces partitioning."""

    def __init__(self, rows_for, fail=None):
        self.rows_for, self.fail, self.calls = rows_for, fail, []

    async def call(self, tool, args):
        self.calls.append(dict(args))
        if self.fail and self.fail(args):
            raise MCPToolFailure("Vision One", tool, "upstream returned HTTP 403; check API permissions")
        if args.get("mode") == "countOnly":
            return {"totalCount": 7}
        start, end = parse(args["startDateTime"])[0], parse(args["endDateTime"])[0]
        return self.rows_for(start, end)


def run(coro):
    return asyncio.run(coro)


def events_between(start, end, every=timedelta(seconds=30)):
    rows, t = [], T0
    while t < T0 + timedelta(hours=1):
        if start <= t < end:
            rows.append({"uuid": f"u-{int(t.timestamp())}", "eventTime": z(t), "processFilePath": "C:\\x.exe"})
        t += every
    return {"items": rows}


class SearchTests(unittest.TestCase):
    def test_full_page_splits_window_and_dedups_without_invented_tokens(self):
        vision = Paged(lambda s, e: {"items": events_between(s, e)["items"][:50]})
        finding = run(vision_search.search(vision, Budget(max_calls=100, max_partitions=100), "search_endpoint_activities_list",
                                           'endpointGuid:"x"', T0, T0 + timedelta(hours=1), top="50", count=True))
        self.assertEqual(finding["state"], "complete_in_window")
        self.assertEqual(finding["records_fetched"], 120)  # every 30 s for an hour, each once
        self.assertGreater(len(finding["partitions"]), 3)
        self.assertTrue(all(set(c) <= SEARCH_ARGS for c in vision.calls))  # no skipToken/nextLink sent
        self.assertFalse(finding["continuation_supported_by_upstream"])
        self.assertEqual(finding["count_only"]["value"], 7)
        self.assertIn("not proof that every row was fetched", finding["count_only"]["semantics"])
        self.assertIn("says nothing about whether the endpoint logged everything", finding["coverage_note"])

    def test_minimum_partition_still_full_is_limited_with_refine_plan(self):
        dense = Paged(lambda s, e: {"items": [{"uuid": f"d-{i}-{s.timestamp()}"} for i in range(50)]})
        finding = run(vision_search.search(dense, Budget(max_calls=100, max_partitions=100), "search_endpoint_activities_list",
                                           'endpointGuid:"x"', T0, T0 + timedelta(minutes=3), top="50"))
        self.assertEqual(finding["state"], "limited")
        self.assertTrue(any(c["action"] == "refine_filters" for c in finding["continuation"]))

    def test_budget_exhaustion_keeps_progress_and_lists_pending_partitions(self):
        vision = Paged(lambda s, e: {"items": events_between(s, e)["items"][:50]})
        finding = run(vision_search.search(vision, Budget(max_calls=2, max_partitions=100), "search_endpoint_activities_list",
                                           'endpointGuid:"x"', T0, T0 + timedelta(hours=1), top="50"))
        self.assertEqual(finding["state"], "partial")
        self.assertTrue(finding["records"])
        pending = [c for c in finding["continuation"] if c["action"] == "search_partition"]
        self.assertTrue(pending)
        self.assertTrue(all(c["reason"] == "upstream call budget exhausted" for c in pending))

    def test_nextlink_signal_triggers_partitioning_not_a_fake_cursor(self):
        calls = []

        async def call(tool, args):
            calls.append(args)
            return {"items": [{"uuid": args["startDateTime"]}], "nextLink": "https://example.test/next"}
        vision = type("V", (), {"call": staticmethod(call)})()
        finding = run(vision_search.search(vision, Budget(max_calls=5, max_partitions=5), "search_detections_list",
                                           'fileHash:"' + "a" * 40 + '"', T0, T0 + timedelta(minutes=10)))
        self.assertTrue(finding["partitions"][0]["upstream_signalled_more"])
        self.assertTrue(all("nextLink" not in a and "skipToken" not in a for a in calls))

    def test_permission_error_on_one_partition_is_partial_not_empty(self):
        vision = Paged(lambda s, e: {"items": events_between(s, e)["items"][:50]},
                       fail=lambda a: a["startDateTime"] > z(T0 + timedelta(minutes=40)))
        finding = run(vision_search.search(vision, Budget(max_calls=100, max_partitions=100), "search_endpoint_activities_list",
                                           'endpointGuid:"x"', T0, T0 + timedelta(hours=1), top="50"))
        self.assertEqual(finding["state"], "partial")
        self.assertEqual(finding["errors"][0]["category"], "permission")
        self.assertTrue(finding["records"])

    def test_rejects_unsupported_parameters_before_calling(self):
        vision = Paged(lambda s, e: {"items": []})
        for kwargs in ({"tool": "search_x"}, {"top": "7"}):
            params = {"tool": "search_endpoint_activities_list", "top": "500", **kwargs}
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                run(vision_search.search(vision, Budget(), params["tool"], "q", T0, T0 + timedelta(minutes=1), top=params["top"]))
        self.assertEqual(vision.calls, [])

    def test_oat_pages_by_next_batch_token_and_reports_pending_token(self):
        pages = [{"items": [{"uuid": "o1"}], "nextBatchToken": "t1"}, {"items": [{"uuid": "o2"}], "nextBatchToken": "t2"},
                 {"items": [{"uuid": "o3"}]}]
        sent = []

        async def call(tool, args):
            sent.append(args)
            return pages[len(sent) - 1]
        vision = type("V", (), {"call": staticmethod(call)})()
        full = run(vision_search.oat(vision, Budget(), "agentGuid eq 'x'", T0, T0 + timedelta(hours=1)))
        self.assertEqual([i["uuid"] for i in full["items"]], ["o1", "o2", "o3"])
        self.assertEqual([a.get("nextBatchToken") for a in sent], [None, "t1", "t2"])
        sent.clear()
        capped = run(vision_search.oat(vision, Budget(), "agentGuid eq 'x'", T0, T0 + timedelta(hours=1), max_batches=1))
        self.assertEqual(capped["state"], "partial")
        self.assertTrue(capped["continuation"]["nextBatchToken_present"])
        self.assertNotIn("t1", str(capped["continuation"]))


class ClockTests(unittest.TestCase):
    def test_utc_milliseconds_without_double_conversion(self):
        self.assertEqual(utc_ms("2026-09-30T14:00:01.123Z"), "2026-09-30T14:00:01.123Z")
        self.assertEqual(utc_ms("2026-09-30T11:00:01.123-03:00"), "2026-09-30T14:00:01.123Z")
        self.assertEqual(parse("2026-09-30T14:00:01")[1], True)
        self.assertEqual(parse("2026-09-30T14:00:01Z")[1], False)

    def test_created_only_is_provisional_and_match_time_beats_it(self):
        bare = {"createdDateTime": z(T0 + timedelta(minutes=10))}
        clocks = build_clocks(bare, parse_alert(bare))
        self.assertTrue(clocks["anchor"]["provisional"])
        self.assertIn("provisional", clocks["anchor"]["basis"])
        full = build_clocks(ALERT, parse_alert(ALERT))
        self.assertEqual(full["anchor"]["time_utc"], z(T0 + timedelta(seconds=1)))
        self.assertIn("matchedEvents.matchedDateTime", full["anchor"]["basis"])
        self.assertIn("do not confirm the QRadar console timezone", full["timezone_note"])

    def test_first_investigated_is_flagged_as_a_human_action(self):
        detail = {"firstInvestigatedDateTime": z(T0)}
        anchor = build_clocks(detail, parse_alert(detail))["anchor"]
        self.assertIn("human action", anchor["basis"])


class RecordTests(unittest.TestCase):
    def test_roles_instances_signers_and_long_commands(self):
        long_cmd = "cmd.exe /c " + "x" * 5000
        record = normalize(dict(PD_LAUNCH, processCmd=long_cmd, endpointGUID="AB-CD"), "search_endpoint_activities_list", "q")
        self.assertEqual(record["process"]["cmd"], long_cmd)  # analysed whole, not cut to 240
        self.assertEqual(record["object"]["processHashId"], "inst-pd")
        self.assertEqual(record["process"]["hashId"], "inst-cmd")
        self.assertEqual(record["parent"]["filePath"].lower().rsplit("\\", 1)[-1], "vendorapp.exe")
        self.assertEqual(record["object"]["signerValid"], [True])
        self.assertEqual(record["endpoint_guid"], PD_LAUNCH["endpointGuid"])
        self.assertEqual(full_hashes(record["object"]), {"fileHashSha256": "cd" * 32})
        self.assertEqual(full_hashes(record["process"]), {})

    def test_bridge_cut_is_explicit(self):
        record = normalize({"processCmd": "y" * (MAX_FIELD + 5), "payload": "raw"}, "search_endpoint_activities_list", "q")
        self.assertEqual(record["cut_by_bridge"], ["processCmd"])
        self.assertEqual(record["dropped_fields"], ["payload"])

    def test_abbreviated_hash_is_not_comparable(self):
        record = normalize({"objectFileHashSha256": "abcd"}, "search_endpoint_activities_list", "q")
        self.assertEqual(full_hashes(record["object"]), {})


if __name__ == "__main__":
    unittest.main()
