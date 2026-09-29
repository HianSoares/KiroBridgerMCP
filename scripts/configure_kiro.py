"""Configure the workspace's local SOC Bridge MCP without storing credentials.

Run with this project's .venv Python after ``pip install -e .``.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile


def configure(project: Path, interpreter: Path) -> Path:
    """Merge one MCP entry while keeping unrelated servers and user choices."""
    if not (project / "pyproject.toml").is_file():
        raise ValueError("Project root must contain pyproject.toml")
    if not interpreter.is_file():
        raise ValueError("Project .venv Python is missing; create .venv first")

    path = project / ".kiro" / "settings" / "mcp.json"
    if path.exists():
        config = json.loads(path.read_text(encoding="utf-8-sig"))
        if not isinstance(config, dict) or not isinstance(config.get("mcpServers", {}), dict):
            raise ValueError("Invalid mcp.json: expected an mcpServers object")
    else:
        config = {}

    servers = config.setdefault("mcpServers", {})
    server = servers.setdefault("soc-bridge-readonly", {})
    if not isinstance(server, dict):
        raise ValueError("Invalid soc-bridge-readonly configuration")
    env = server.setdefault("env", {})
    if not isinstance(env, dict):
        raise ValueError("Invalid soc-bridge-readonly env configuration")

    # The interpreter's absolute path matters on Windows, where python may be
    # a Microsoft Store alias and the project path may contain spaces.
    server["command"] = str(interpreter.absolute())
    server["args"] = ["-m", "soc_bridge.kiro_server"]
    server.setdefault("autoApprove", ["investigate_demo"])
    env.setdefault("QRADAR_MCP_URL", "http://127.0.0.1:5001/mcp")
    env.setdefault("QRADAR_MCP_TOKEN", "${QRADAR_MCP_TOKEN}")
    env.setdefault("TREND_VISION_ONE_API_KEY", "${TREND_VISION_ONE_API_KEY}")
    env.setdefault("TREND_VISION_ONE_REGION", "us")

    path.parent.mkdir(parents=True, exist_ok=True)
    # Never print config content: existing entries might contain secrets.
    fd, temporary = tempfile.mkstemp(prefix="mcp-", suffix=".json", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(config, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return path


def main() -> int:
    project = Path(__file__).resolve().parent.parent
    interpreter = project / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    try:
        if Path(sys.prefix).resolve() != (project / ".venv").resolve():
            raise ValueError("Run with the project's .venv Python, not system Python")
        path = configure(project, interpreter)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Kiro MCP configuration failed: {exc}", file=sys.stderr)
        return 1
    print(f"Configured {path} for soc-bridge-readonly. Open this project in Kiro and run investigate_demo.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
