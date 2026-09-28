"""Synthetic checks for alert-first correlation and its coverage limits."""

import asyncio
import unittest

from soc_bridge.alert_investigation import alert_ips, alert_entities, investigate_vision_alert, render_alert_markdown


ALERT = {"id": "WB-TEST-20260924-00001", "name": "RClone Detection",
         "createdDateTime": "2026-09-24T12:00:00Z", "severity": "high",
         "impactScope": [{"entityType": "ip", "entityValue": "198.51.100.24"}],
         "indicators": [{"indicatorValue": "192.0.2.8"}],
         "endpointName": "DEMO-PC", "processName": "rclone.exe",
         "description": "RClone command contacted 203.0.113.5; this is narrative text only"}


class Vision:
    async def call(self, tool, args):
        assert tool == "workbench_alert_detail_get"
        assert args == {"alertId": ALERT["id"]}
        return dict(ALERT)


class QRadar:
    def __init__(self):
        self.queries = []

    async def call(self, tool, args):
        self.queries.append((tool, args))
        if tool == "list_source_addresses":
            if "198.51.100.24" in args["filter"]:
                return [{"source_ip": "198.51.100.24", "offense_ids": [71]}]
            return []
        if tool == "list_local_destination_addresses":
            # A row for a different IP must never become a lead.
            return [{"local_destination_ip": "203.0.113.10", "offense_ids": [999]}]
        if tool == "get_offense":
            assert args == {"offense_id": 71}
            return {"id": 71, "description": "Test offense", "magnitude": 5,
                    "start_time": "2026-09-24T11:58:00Z", "last_updated_time": "2026-09-24T12:10:00Z"}
        if tool == "validate_aql":
            return {"valid": True}
        if tool == "create_ariel_search":
            return {"search_id": "c643b969-2626-410e-89e4-9b1e1308aab0"}
        if tool == "get_ariel_search_status":
            return {"status": "COMPLETED", "record_count": 0}
        if tool == "get_ariel_search_results":
            return {"events": []}
        raise AssertionError(tool)


class AlertInvestigationTests(unittest.TestCase):
    def test_alert_id_alone_discovers_unique_detection_host_and_process_and_focuses_ip(self):
        sha = "a" * 40
        class AutoVision:
            async def call(self, tool, args):
                if tool == "workbench_alert_detail_get":
                    return {"id": ALERT["id"], "model": "RClone Detection",
                            "createdDateTime": "2026-09-24T13:23:06Z"}
                if tool == "search_detections_list":
                    return {"items": [{"eventTime": "2026-09-24T13:15:01Z",
                                      "endpointHostName": "DEMO-PC", "fileHash": sha,
                                      "fullPath": r"C:\Users\Demo\rclone.exe",
                                      "endpointIp": ["198.51.100.24"]}]}
                if tool == "search_endpoint_activities_list":
                    if "endpointHostName:" in args["query"]:
                        return {"items": [{"endpointHostName": "DEMO-PC",
                                          "endpointIp": ["10.12.34.56", "169.254.0.1"],
                                          "eventTime": "2026-09-24T13:16:00Z"}]}
                    return {"items": [{"eventTime": "2026-09-24T12:48:26Z",
                                      "processFileHashSha1": sha, "endpointHostName": "DEMO-PC",
                                      "objectFilePath": r"C:\Demo\rclone.conf"}]}
                raise AssertionError(tool)

        qr = QRadar()
        report = asyncio.run(investigate_vision_alert(
            qr, AutoVision(), ALERT["id"], ariel_offset_hours=-3, enable_vision_search=True))
        self.assertEqual(report["auto_pivots"]["source"], "unique nearby RClone detection candidate")
        self.assertEqual(report["auto_pivots"]["discovery_status"], "unique nearby host/hash candidate")
        self.assertEqual(report["auto_pivots"]["search_calls"], 1)
        self.assertEqual(report["searched_ips"], ["10.12.34.56", "198.51.100.24"])
        self.assertEqual(report["vision_activity"]["host_ips"], ["10.12.34.56"])
        self.assertEqual(report["ariel_process_focus"]["window"]["utc_start"], "2026-09-24T12:48:14+00:00")
        self.assertIn("starttime >=", report["ariel_process_focus"]["searches"][0]["aql"])
        self.assertIn("not a verified", render_alert_markdown(report))
        self.assertIn("model-or-name-v2", render_alert_markdown(report))

    def test_multiple_private_interfaces_get_separate_bounded_process_time_checks(self):
        sha = "a" * 40
        private = ["10.12.34.56", "172.22.240.1", "192.168.56.1"]

        class ThreeInterfaces:
            async def call(self, tool, args):
                if tool == "workbench_alert_detail_get":
                    return {"id": ALERT["id"], "model": "RClone Detection",
                            "createdDateTime": "2026-09-24T13:23:06Z"}
                if tool == "search_detections_list":
                    if args["query"] != 'malName:"HZ_RCLONE64"':
                        return {"items": []}
                    return {"items": [{"eventTime": "2026-09-24T13:15:01Z",
                                      "endpointHostName": "DEMO-PC", "fileHash": sha,
                                      "fullPath": r"C:\Demo\rclone.exe", "endpointIp": "198.51.100.24"}]}
                if tool == "search_endpoint_activities_list":
                    if args["query"].startswith("endpointHostName:"):
                        return {"items": [{"endpointHostName": "DEMO-PC", "endpointIp": private,
                                          "eventTime": "2026-09-24T13:16:00Z"}]}
                    return {"items": [{"eventTime": "2026-09-24T12:48:26Z",
                                      "processFileHashSha1": sha, "endpointHostName": "DEMO-PC"}]}
                raise AssertionError(tool)

        qr = QRadar()
        report = asyncio.run(investigate_vision_alert(qr, ThreeInterfaces(), ALERT["id"],
                                                      enable_vision_search=True, ariel_offset_hours=-3))
        self.assertEqual(report["searched_ips"], ["198.51.100.24"])
        self.assertIsNone(report["ariel_process_focus"])
        self.assertEqual([item["candidate_ip"] for item in report["ariel_private_focus"]], private)
        self.assertEqual(report["auto_pivots"]["search_field"], "malName")
        focused_aql = [a["query_expression"] for name, a in qr.queries
                       if name == "create_ariel_search" and "starttime >=" in a["query_expression"]]
        self.assertEqual(len(focused_aql), 3)
        self.assertTrue(all(any(f"sourceip = '{ip}'" in q for q in focused_aql) for ip in private))
        self.assertTrue(any("no interface was automatically attributed" in msg for msg in report["warnings"]))
        self.assertIn("multiple candidate private IPs", render_alert_markdown(report))

    def test_non_rclone_model_skips_detection_search(self):
        from soc_bridge.auto_pivot import discover_alert_pivots

        class VisionWithNoAllowedCalls:
            async def call(self, tool, args):
                raise AssertionError("Unexpected search for unrelated model")

        result = asyncio.run(discover_alert_pivots(VisionWithNoAllowedCalls(), {
            "model": "Generic file detection", "description": "RClone Detection",
            "createdDateTime": "2026-09-24T13:23:06Z"}))
        self.assertEqual(result["source"], "none")
        self.assertEqual(result["search_calls"], 0)
        self.assertIn("skipped: exact RClone", result["discovery_status"])

    def test_multiple_detection_identities_do_not_autopivot(self):
        class Ambiguous:
            async def call(self, tool, args):
                if tool == "workbench_alert_detail_get":
                    return {"id": ALERT["id"], "name": "RClone Detection",
                            "createdDateTime": "2026-09-24T13:23:06Z"}
                if tool == "search_detections_list":
                    return {"items": [{"eventTime": "2026-09-24T13:15:01Z", "endpointHostName": name,
                                       "fileHash": "a" * 40, "fullPath": r"C:\rclone.exe",
                                       "endpointIp": "10.12.34.56"} for name in ("PC-A", "PC-B")]}
                raise AssertionError(tool)
        qr = QRadar()
        report = asyncio.run(investigate_vision_alert(qr, Ambiguous(), ALERT["id"],
                                                       enable_vision_search=True, ariel_offset_hours=-3))
        self.assertEqual(report["searched_ips"], [])
        self.assertEqual(qr.queries, [])
        self.assertTrue(any("No unique" in w for w in report["warnings"]))

    def test_detection_path_fallback_when_filename_search_empty(self):
        from soc_bridge.auto_pivot import discover_alert_pivots

        class PathOnly:
            def __init__(self):
                self.queries = []

            async def call(self, tool, args):
                self.queries.append(args["query"])
                if args["query"].startswith("fileName:"):
                    return {"items": []}
                return {"items": [{"eventTime": "2026-09-24T13:15:01Z",
                                  "endpointHostName": "DEMO-PC", "fileHash": "a" * 40,
                                  "fullPath": r"C:\Demo\rclone.exe"}]}

        vision = PathOnly()
        result = asyncio.run(discover_alert_pivots(vision, {
            "name": "RClone Detection", "createdDateTime": "2026-09-24T13:23:06Z"}))
        self.assertEqual(result["host"], "DEMO-PC")
        self.assertEqual(len(vision.queries), 2)

    def test_fullpath_fallback_recovers_detection_that_filename_fields_miss(self):
        from soc_bridge.auto_pivot import discover_alert_pivots

        class FullPathOnly:
            def __init__(self):
                self.queries = []

            async def call(self, tool, args):
                self.queries.append(args["query"])
                if args["query"].startswith('fullPath:'):
                    return {"items": [{"eventTime": "2026-09-24T13:15:01Z",
                                      "endpointHostName": "DEMO-PC", "fileHash": "a" * 40,
                                      "fullPath": r"C:\Demo\rclone.exe"}]}
                return {"items": []}

        vision = FullPathOnly()
        result = asyncio.run(discover_alert_pivots(vision, {
            "model": "RClone Detection", "createdDateTime": "2026-09-24T13:23:06Z"}))
        self.assertEqual(result["host"], "DEMO-PC")
        self.assertEqual(result["search_calls"], 3)
        self.assertEqual(result["search_rows"], 1)
        self.assertEqual(result["search_field"], "fullPath")
        self.assertTrue(all(q.endswith('"rclone.exe"') for q in vision.queries))

    def test_unsupported_fullpath_field_still_checks_filepathname(self):
        from soc_bridge.auto_pivot import discover_alert_pivots

        class FilePathNameOnly:
            async def call(self, tool, args):
                if args["query"].startswith('fullPath:'):
                    raise ValueError("Sensitive upstream response omitted")
                if args["query"].startswith('filePathName:'):
                    return {"items": [{"eventTime": "2026-09-24T13:15:01Z",
                                      "endpointHostName": "DEMO-PC", "fileHash": "a" * 40,
                                      "fullPath": r"C:\Demo\rclone.exe"}]}
                return {"items": []}

        result = asyncio.run(discover_alert_pivots(FilePathNameOnly(), {
            "model": "RClone Detection", "createdDateTime": "2026-09-24T13:23:06Z"}))
        self.assertEqual(result["search_calls"], 4)
        self.assertEqual(result["host"], "DEMO-PC")
        self.assertIn("1 RClone detection query field", result["warnings"][-2])
        self.assertNotIn("Sensitive upstream", str(result))

    def test_model_signature_fallback_requires_exact_rclone_executable_path(self):
        from soc_bridge.auto_pivot import discover_alert_pivots

        class ModelOnly:
            async def call(self, tool, args):
                if args["query"] == 'malName:"HZ_RCLONE64"':
                    return {"items": [
                        {"eventTime": "2026-09-24T13:15:01Z", "endpointHostName": "DEMO-PC",
                         "fileHash": "a" * 40, "fullPath": r"C:\Demo\rclone.exe"},
                        {"eventTime": "2026-09-24T13:15:01Z", "endpointHostName": "OTHER-PC",
                         "fileHash": "b" * 40, "fullPath": r"C:\Demo\other.exe"},
                    ]}
                return {"items": []}

        result = asyncio.run(discover_alert_pivots(ModelOnly(), {
            "model": "RClone Detection", "createdDateTime": "2026-09-24T13:23:06Z"}))
        self.assertEqual(result["host"], "DEMO-PC")
        self.assertEqual(result["hash"], "a" * 40)
        self.assertEqual(result["search_calls"], 5)
        self.assertEqual(result["search_field"], "malName")
        self.assertEqual(result["candidates"], 1)

    def test_model_query_with_no_file_path_is_not_attributed(self):
        from soc_bridge.auto_pivot import discover_alert_pivots

        class NoPath:
            async def call(self, tool, args):
                if args["query"].startswith("malName:"):
                    return {"items": [{"eventTime": "2026-09-24T13:15:01Z",
                                      "endpointHostName": "DEMO-PC", "fileHash": "a" * 40}]}
                return {"items": []}

        result = asyncio.run(discover_alert_pivots(NoPath(), {
            "model": "RClone Detection", "createdDateTime": "2026-09-24T13:23:06Z"}))
        self.assertEqual(result["host"], "")
        self.assertEqual(result["candidates"], 0)

    def test_finds_exact_ip_and_time_and_does_not_scrape_description(self):
        qr = QRadar()
        report = asyncio.run(investigate_vision_alert(qr, Vision(), ALERT["id"]))
        self.assertEqual(report["alert_ips"], ["192.0.2.8", "198.51.100.24"])
        self.assertEqual([x["offense_id"] for x in report["offenses"]], [71])
        self.assertEqual(report["offenses"][0]["timing"], "overlaps or within six hours")
        self.assertEqual(report["entities"]["processes"], ["rclone.exe"])
        self.assertNotIn("203.0.113.5", str(report["alert_ips"]))
        self.assertIn("do not search Ariel events", render_alert_markdown(report))
        self.assertTrue(all(args["limit"] == 100 for tool, args in qr.queries
                            if tool in {"list_source_addresses", "list_local_destination_addresses"}))

    def test_no_ip_does_not_query_qradar(self):
        class NoIPs(Vision):
            async def call(self, tool, args):
                return {"id": ALERT["id"], "name": "RClone Detection", "hostName": "HOST-1"}

        qr = QRadar()
        report = asyncio.run(investigate_vision_alert(qr, NoIPs(), ALERT["id"]))
        self.assertEqual(qr.queries, [])
        self.assertTrue(any("no explicit IP" in x for x in report["warnings"]))
        self.assertIn("No successful address-index query", render_alert_markdown(report))

    def test_view_event_fields_are_separate_and_enable_bounded_ip_lookup(self):
        class NoIPs(Vision):
            async def call(self, tool, args):
                if tool == "workbench_alert_detail_get":
                    return {"id": ALERT["id"], "name": "RClone Detection",
                            "createdDateTime": "2026-09-20T12:00:00Z"}
                if tool == "search_detections_list":
                    return {"items": [{"eventTime": "2026-09-24T12:00:01Z", "fileHash": "a" * 40}]}
                if tool == "search_endpoint_activities_list":
                    return {"items": []}
                raise AssertionError(tool)

        qr = QRadar()
        report = asyncio.run(investigate_vision_alert(
            qr, NoIPs(), ALERT["id"], event_evidence={
                "endpoint_ip": "198.51.100.24", "event_time": "2026-09-24T12:00:00Z",
                "endpoint_host": "DEMO-PC", "file_path": r"C:\Demo\rclone.exe",
                "process_path": r"C:\Demo\Other.exe", "file_hash": "a" * 40},
            ariel_offset_hours=-3, enable_vision_search=True))
        self.assertEqual(report["alert_ips"], [])
        self.assertEqual(report["searched_ips"], ["198.51.100.24"])
        self.assertEqual(report["successful_queries"], 2)
        self.assertEqual(report["offenses"][0]["offense_id"], 71)
        self.assertEqual(report["offenses"][0]["timing"], "overlaps or within six hours")
        self.assertEqual(report["alert_time"], "2026-09-24T12:00:00+00:00")
        self.assertIn("analyst-supplied", render_alert_markdown(report).lower())
        self.assertIn("QRadar Ariel events", render_alert_markdown(report))
        self.assertEqual(len(report["ariel"]["searches"]), 2)
        self.assertEqual(len(report["vision_activity"]["findings"]), 3)
        self.assertIn("Vision One Search", [e["source"] for e in report["timeline"]["entries"]])
        self.assertIn("analyst-supplied View event", [e["source"] for e in report["timeline"]["entries"]])
        self.assertTrue(all(args["limit"] == 100 for tool, args in qr.queries
                            if tool in {"list_source_addresses", "list_local_destination_addresses"}))

    def test_rejects_invalid_manual_event_before_qradar_lookups(self):
        qr = QRadar()
        with self.assertRaises(ValueError):
            asyncio.run(investigate_vision_alert(qr, Vision(), ALERT["id"],
                        event_evidence={"endpoint_ip": "not-an-ip", "event_time": "2026-09-24T12:00:00Z"}))
        self.assertEqual(qr.queries, [])

    def test_structured_view_event_fields_if_returned_by_api(self):
        detail = {"endpointIp": "198.51.100.24", "endpointHostName": "DEMO-PC",
                  "fileHash": "a" * 40, "fullPath": r"C:\Demo\rclone.exe"}
        self.assertEqual(alert_ips(detail), ["198.51.100.24"])
        self.assertEqual(alert_entities(detail)["hosts"], ["DEMO-PC"])
        self.assertEqual(alert_entities(detail)["hashes"], ["a" * 40])

    def test_rejects_unexpected_alert_id_before_address_queries(self):
        class WrongVision(Vision):
            async def call(self, tool, args):
                return {"id": "WB-OTHER", "indicatorValue": "198.51.100.24"}

        qr = QRadar()
        with self.assertRaises(ValueError):
            asyncio.run(investigate_vision_alert(qr, WrongVision(), ALERT["id"]))
        self.assertEqual(qr.queries, [])


if __name__ == "__main__":
    unittest.main()
