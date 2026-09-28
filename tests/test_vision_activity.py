"""Bounded Vision One Search pivots with a fabricated endpoint event."""

import asyncio
import unittest

from soc_bridge.vision_activity import collect_vision_activity


class Vision:
    def __init__(self):
        self.calls = []

    async def call(self, tool, args):
        self.calls.append((tool, args))
        if tool == "search_detections_list":
            return {"items": [{"eventTime": "2026-09-24T13:15:01Z",
                               "eventName": "File Detection for RClone", "fileHash": "a" * 40,
                               "fullPath": r"C:\Demo\rclone.exe", "payload": "DO NOT SEND TO KIRO"}]}
        if tool == "search_endpoint_activities_list":
            if "endpointHostName" in args["query"]:
                return {"items": [{"eventTime": "2026-09-24T13:17:01Z",
                                   "eventName": "File created", "processFilePath": r"C:\Other.exe",
                                   "objectFilePath": r"C:\Demo\rclone.exe"}]}
            return {"items": []}
        raise AssertionError(tool)


class VisionActivityTests(unittest.TestCase):
    def test_valid_host_hash_query_three_pivots_and_redact_payload(self):
        v = Vision()
        report = asyncio.run(collect_vision_activity(v, "2026-09-24T13:15:01Z", "DEMO-PC", "a" * 40))
        self.assertEqual([f["state"] for f in report["findings"]], ["completed"] * 3)
        self.assertEqual(report["window"]["start"], "2026-09-24T12:45:01+00:00")
        self.assertIn('processFileHashSha1:"', v.calls[2][1]["query"])
        self.assertNotIn("DO NOT SEND TO KIRO", str(report))
        self.assertTrue(all(args["top"] == "50" for _, args in v.calls))

    def test_rejects_untrusted_strings_before_query(self):
        v = Vision()
        report = asyncio.run(collect_vision_activity(v, "2026-09-24T13:15:01Z", "x\" OR *", "evilhash"))
        self.assertEqual(v.calls, [])
        self.assertEqual(len(report["warnings"]), 3)

    def test_missing_search_permission_is_explicit_and_nonfatal(self):
        class Denied(Vision):
            async def call(self, tool, args):
                raise PermissionError("Search key is missing role")

        report = asyncio.run(collect_vision_activity(Denied(), "2026-09-24T13:15:01Z", "DEMO-PC"))
        self.assertEqual(report["findings"][0]["state"], "unavailable")
        self.assertIn("Search permissions", report["warnings"][0])
        self.assertNotIn("missing role", str(report))


if __name__ == "__main__":
    unittest.main()
