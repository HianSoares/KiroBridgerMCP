"""Ensure local setup does not overwrite an existing Kiro MCP configuration."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "configure_kiro.py"
SPEC = importlib.util.spec_from_file_location("configure_kiro", SCRIPT)
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class ConfigureKiroTests(unittest.TestCase):
    def test_creates_config_with_local_python_and_no_secret(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
            python = root / ".venv" / "bin" / "python"
            python.parent.mkdir(parents=True)
            python.touch()
            path = module.configure(root, python)
            config = json.loads(path.read_text(encoding="utf-8"))
            bridge = config["mcpServers"]["soc-bridge-readonly"]
            self.assertEqual(bridge["command"], str(python.absolute()))
            self.assertEqual(bridge["autoApprove"], ["investigate_demo"])
            self.assertEqual(bridge["env"]["TREND_VISION_ONE_API_KEY"], "${TREND_VISION_ONE_API_KEY}")

    def test_preserves_other_servers_and_existing_auto_approve(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pyproject.toml").touch()
            python = root / ".venv" / "bin" / "python"
            python.parent.mkdir(parents=True)
            python.touch()
            path = root / ".kiro" / "settings" / "mcp.json"
            path.parent.mkdir(parents=True)
            original = {"mcpServers": {
                "other": {"command": "other-server"},
                "soc-bridge-readonly": {
                    "autoApprove": ["investigate_demo", "investigate_case"],
                    "env": {"TREND_VISION_ONE_REGION": "eu"},
                },
            }, "customSetting": True}
            path.write_text(json.dumps(original), encoding="utf-8")
            module.configure(root, python)
            first = path.read_text(encoding="utf-8")
            module.configure(root, python)
            self.assertEqual(path.read_text(encoding="utf-8"), first)
            config = json.loads(first)
            self.assertTrue(config["customSetting"])
            self.assertEqual(config["mcpServers"]["other"], original["mcpServers"]["other"])
            bridge = config["mcpServers"]["soc-bridge-readonly"]
            self.assertEqual(bridge["autoApprove"], ["investigate_demo", "investigate_case"])
            self.assertEqual(bridge["env"]["TREND_VISION_ONE_REGION"], "eu")


if __name__ == "__main__":
    unittest.main()
