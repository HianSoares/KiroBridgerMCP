"""A single Kiro entry point accepts IDs without asking for incident fields."""

import asyncio
import unittest
from unittest.mock import patch

from soc_bridge.kiro_server import investigate_case, mcp


class CaseDispatchTests(unittest.TestCase):
    def test_case_tool_routes_both_ids_and_rejects_unknown_references(self):
        async def offense(offense_id):
            return f"offense:{offense_id}"

        async def alert(alert_id):
            return f"alert:{alert_id}"

        with patch("soc_bridge.kiro_server.investigate_offense", offense), \
             patch("soc_bridge.kiro_server.investigate_vision_alert", alert):
            self.assertEqual(asyncio.run(investigate_case(" 1842 ")), "offense:1842")
            self.assertEqual(asyncio.run(investigate_case("WB-TEST-1")), "alert:WB-TEST-1")
            for invalid in ("", "-5", "0005", "10.12.34.56"):
                with self.assertRaises(ValueError):
                    asyncio.run(investigate_case(invalid))

        self.assertIn("investigate_case", [tool.name for tool in mcp._tool_manager.list_tools()])


if __name__ == "__main__":
    unittest.main()
