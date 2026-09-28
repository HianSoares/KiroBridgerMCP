"""Synthetic checks for bounded Ariel search, source provenance and local time conversion."""

import asyncio
import unittest

from soc_bridge.ariel import investigate_ariel, make_queries


class QRadar:
    def __init__(self):
        self.calls = []

    async def call(self, tool, args):
        self.calls.append((tool, args))
        if tool == "validate_aql":
            return {"valid": True}
        if tool == "create_ariel_search":
            return {"search_id": "c643b969-2626-410e-89e4-9b1e1308aab0"}
        if tool == "get_ariel_search_status":
            return {"status": "COMPLETED", "record_count": 1}
        if tool == "get_ariel_search_results":
            return {"events": [{"starttime": 1790255701000, "sourceip": "192.0.2.10",
                                "destinationip": "198.51.100.24", "event_name": "Firewall Deny",
                                "payload": "PRIVATE DATA MUST NOT REACH KIRO"}]}
        raise AssertionError(tool)


class ArielTests(unittest.TestCase):
    def test_qradar_brazil_local_time_is_three_hours_behind_utc(self):
        queries, win = make_queries("198.51.100.24", "DEMO-PC", "2026-09-24T13:15:01Z", -3)
        self.assertEqual(win["qradar_local_start"], "2026-09-24 09:45:01")
        self.assertEqual(win["qradar_local_end"], "2026-09-24 10:45:01")
        self.assertIn("LIMIT 100 START '2026-09-24 09:45:01'", queries[0][1])
        self.assertIn("TEXT SEARCH 'DEMO-PC'", queries[1][1])
        self.assertNotIn("PRIVATE DATA", str(queries))

    def test_searches_are_bounded_and_exclude_raw_payload(self):
        qr = QRadar()
        report = asyncio.run(investigate_ariel(qr, "198.51.100.24", "DEMO-PC",
                                               "2026-09-24T13:15:01Z", -3))
        self.assertEqual([s["state"] for s in report["searches"]], ["COMPLETED", "COMPLETED"])
        self.assertNotIn("PRIVATE DATA", str(report))
        self.assertEqual(sum(t == "create_ariel_search" for t, _ in qr.calls), 2)
        self.assertTrue(all(a["limit"] == 100 for t, a in qr.calls if t == "get_ariel_search_results"))

    def test_bad_hostname_does_not_enter_aql(self):
        queries, _ = make_queries("198.51.100.24", "X' OR 1=1", "2026-09-24T13:15:01Z", -3)
        self.assertEqual(len(queries), 1)

    def test_focused_query_filters_exact_seconds_in_where(self):
        queries, win = make_queries("10.12.34.56", "DEMO-PC", "2026-09-24T12:48:26Z", -3,
                                    focus_seconds=12)
        self.assertEqual(len(queries), 1)
        self.assertEqual(win["utc_start"], "2026-09-24T12:48:14+00:00")
        self.assertIn("starttime >= 1790254094000", queries[0][1])
        self.assertIn("starttime < 1790254118000", queries[0][1])
        self.assertIn("START '2026-09-24 09:48:14'", queries[0][1])

    def test_wrong_timezone_is_visible_from_result_timestamps(self):
        class WrongTimezone(QRadar):
            async def call(self, tool, args):
                if tool == "get_ariel_search_results":
                    return {"events": [{"starttime": 1790264813387, "event_name": "Firewall Deny"}]}
                return await super().call(tool, args)

        report = asyncio.run(investigate_ariel(WrongTimezone(), "198.51.100.24", "",
                                               "2026-09-24T13:15:01Z", -3))
        self.assertEqual(report["searches"][0]["outside_utc_window"], 1)
        self.assertTrue(any("UTC offset" in warning for warning in report["warnings"]))


if __name__ == "__main__":
    unittest.main()
