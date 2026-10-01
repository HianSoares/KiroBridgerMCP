"""Synthetic offense-first context: no tenant telemetry or credentials."""

import unittest
from datetime import datetime, timezone

from soc_bridge.core import investigate, render_markdown


T = "2026-09-25T13:15:02Z"
MS = int(datetime.fromisoformat(T.replace("Z", "+00:00")).timestamp() * 1000)


class QRadar:
    def __init__(self, capped=False):
        self.calls = []
        self.capped = capped
        self.query = ""

    async def call(self, name, args):
        self.calls.append((name, args))
        if name == "get_offense":
            return {"id": 90212, "description": "Synthetic UDP scanner", "offense_source": "192.0.2.10",
                    "start_time": MS - 2000, "last_updated_time": MS + 24000,
                    "magnitude": 5, "event_count": 32}
        if name == "list_source_addresses":
            return {"items": [{"source_ip": "192.0.2.10", "offense_ids": [90212]}]}
        if name == "list_local_destination_addresses":
            return {"items": []}
        if name == "validate_aql":
            return {"valid": True}
        if name == "create_ariel_search":
            self.query = args["query_expression"]
            return {"search_id": "synthetic-123"}
        if name == "get_ariel_search_status":
            return {"status": "COMPLETED", "record_count": (100 if self.capped and "starttime >=" not in self.query else 1)}
        if name == "get_ariel_search_results":
            event = {"starttime": MS, "sourceip": "192.0.2.10",
                     "destinationip": "203.0.113.9", "destinationport": 53,
                     "event_name": "Firewall Deny", "payload": "SENSITIVE PAYLOAD"}
            return {"events": [event] * (100 if self.capped and "starttime >=" not in self.query else 1)}
        raise AssertionError(name)


class Vision:
    def __init__(self, include_network=True):
        self.include_network = include_network

    async def call(self, name, args):
        if name == "workbench_alerts_list":
            return {"items": []}
        if name == "search_detections_list":
            return {"items": []}
        if name == "search_endpoint_activities_list":
            return {"items": [{"uuid": "synthetic-event-123", "eventTime": T,
                     "endpointIp": ["192.0.2.10"], "endpointHostName": "TEST-PC",
                     "endpointGUID": "11111111-2222-3333-4444-555555555555",
                     "dst": "203.0.113.9" if self.include_network else "198.51.100.7",
                     "dpt": 53, "eventName": "Synthetic network event",
                     "processCmd": "PRIVATE COMMAND"}]}
        raise AssertionError(name)


class OffenseContextTests(unittest.IsolatedAsyncioTestCase):
    async def test_no_workbench_alert_still_queries_ariel_and_endpoint(self):
        qr = QRadar()
        report = await investigate(qr, Vision(), 90212, deep=True, ariel_offset_hours=-3)
        self.assertEqual(report["alerts"], [])
        context = report["offense_context"]
        self.assertEqual(context["vision"][0]["matched_ip_time"], 1)
        self.assertEqual(len(context["network_leads"]), 1)
        output = render_markdown(report)
        self.assertIn("magnitude: 5", output)
        self.assertIn("event_count: 32", output)
        self.assertIn("Search ID: synthetic-123", output)
        self.assertIn("Cross-source network leads", output)
        self.assertIn("Metadata interval without padding", output)
        self.assertIn("Status: preliminary", output)
        self.assertEqual(report["search_window_padding_seconds"], 3600)
        self.assertEqual(report["offense_evidence"]["metadata_interval"]["padding_seconds"], 0)
        self.assertNotIn("PRIVATE COMMAND", output)
        self.assertNotIn("SENSITIVE PAYLOAD", output)
        self.assertTrue(any(name == "create_ariel_search" for name, _ in qr.calls))

    async def test_capped_ariel_narrows_before_matching(self):
        report = await investigate(QRadar(capped=True), Vision(), 90212,
                                   deep=True, ariel_offset_hours=-3)
        searches = report["offense_context"]["ariel"]
        self.assertEqual(len(searches), 2)
        self.assertEqual(searches[0]["searches"][0]["sample_count"], 100)
        self.assertEqual(searches[1]["searches"][0]["sample_count"], 1)
        self.assertEqual(searches[1]["window"]["focus_seconds"], 60)

    async def test_mismatched_destination_does_not_form_network_lead(self):
        report = await investigate(QRadar(), Vision(include_network=False), 90212,
                                   deep=True, ariel_offset_hours=-3)
        self.assertEqual(report["offense_context"]["network_leads"], [])

    async def test_workbench_failure_still_collects_endpoint_search(self):
        class VisionWithoutWorkbench(Vision):
            async def call(self, name, args):
                if name == "workbench_alerts_list":
                    raise RuntimeError("search not permitted")
                return await super().call(name, args)

        report = await investigate(QRadar(), VisionWithoutWorkbench(), 90212,
                                   deep=True, ariel_offset_hours=-3)
        self.assertEqual(report["alerts"], [])
        self.assertEqual(report["offense_context"]["vision"][0]["matched_ip_time"], 1)
        self.assertTrue(any("coverage partial" in warning for warning in report["warnings"]))


if __name__ == "__main__":
    unittest.main()
