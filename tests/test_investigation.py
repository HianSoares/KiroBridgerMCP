"""Meaningful correlation checks with synthetic, reproducible data."""

import asyncio
import unittest

from soc_bridge.core import investigate, render_markdown
from soc_bridge.demo import DemoQRadar, DemoVision


class InvestigationTests(unittest.TestCase):
    def test_correlates_specific_ip_and_time_without_declaring_incident(self):
        report = asyncio.run(investigate(DemoQRadar(), DemoVision(), 1842))
        self.assertEqual(report["alerts"][0]["alert_id"], "WB-2048")
        self.assertEqual(report["alerts"][0]["temporal_check"], "within window")
        self.assertEqual(report["alerts"][0]["score"], 70)
        self.assertEqual(report["alerts"][0]["indicators"], ["198.51.100.24"])
        self.assertIn("does not establish a shared incident", render_markdown(report))

    def test_unrelated_alert_is_not_reported(self):
        class UnrelatedVision(DemoVision):
            async def call(self, name, arguments):
                if name == "workbench_alerts_list":
                    return {"items": []}
                return await super().call(name, arguments)

        report = asyncio.run(investigate(DemoQRadar(), UnrelatedVision(), 1842))
        self.assertEqual(report["alerts"], [])
        self.assertIn("does not prove absence", " ".join(report["warnings"]))

    def test_rejects_wrong_offense_id(self):
        with self.assertRaises(ValueError):
            asyncio.run(investigate(DemoQRadar(), DemoVision(), 1))

    def test_optional_address_failure_is_visible(self):
        class PartialQRadar(DemoQRadar):
            async def call(self, name, arguments):
                if name == "list_source_addresses":
                    raise RuntimeError("Unavailable")
                return await super().call(name, arguments)

        report = asyncio.run(investigate(PartialQRadar(), DemoVision(), 1842))
        self.assertEqual(len(report["alerts"]), 1)  # offense_source still provides an IP
        self.assertTrue(any("coverage is partial" in w for w in report["warnings"]))


if __name__ == "__main__":
    unittest.main()
