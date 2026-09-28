"""Keep offense-first Workbench availability independent from optional Search."""

import unittest

from soc_bridge.transports import RestrictedMCP, VISION_TOOLS, WORKBENCH_TOOLS


class AllowlistTests(unittest.TestCase):
    def test_offense_first_requires_only_workbench(self):
        client = RestrictedMCP(object(), WORKBENCH_TOOLS, WORKBENCH_TOOLS)
        self.assertEqual(client.allowed, WORKBENCH_TOOLS)
        self.assertTrue(VISION_TOOLS - WORKBENCH_TOOLS)

    def test_optional_search_does_not_block_alert_first(self):
        client = RestrictedMCP(object(), VISION_TOOLS, WORKBENCH_TOOLS,
                               {"workbench_alert_detail_get"})
        self.assertEqual(client.available, WORKBENCH_TOOLS)


if __name__ == "__main__":
    unittest.main()
