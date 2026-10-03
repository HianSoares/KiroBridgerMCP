"""Kiro on Windows starting the bridge inside WSL 2 through wsl.exe.

Kiro for Windows spawns MCP servers as Windows processes, so a Linux path such as
``.venv/bin/python`` cannot be its ``command``. The entry built here runs
``wsl.exe --distribution <distro> --cd <project> --exec <project>/.venv/bin/python
-m soc_bridge.wsl_launch``: --exec skips the Linux shell and its profile files, and
every argument is a separate JSON item, so paths with spaces stay intact.

Windows environment variables reach the Linux process only when listed in WSLENV;
the ``/u`` flag limits each one to the Windows -> Linux direction. A listed variable
that is undefined in Windows arrives as an empty string, which wsl_launch removes.
"""

from __future__ import annotations

import json
import os
from pathlib import Path, PurePosixPath
import re
import tempfile

SERVER = "soc-bridge-readonly"
LAUNCH_MODULE = "soc_bridge.wsl_launch"
BRIDGE_ENV = ("QRADAR_MCP_URL", "QRADAR_MCP_TOKEN", "TREND_VISION_ONE_API_KEY", "TREND_VISION_ONE_REGION",
              "QRADAR_AQL_UTC_OFFSET_HOURS", "QRADAR_AQL_TIMEZONE_VERIFIED")
SECRET_ENV = ("QRADAR_MCP_TOKEN", "TREND_VISION_ONE_API_KEY")
DEFAULT_ENV = {"QRADAR_MCP_URL": "http://127.0.0.1:5001/mcp", "QRADAR_MCP_TOKEN": "${QRADAR_MCP_TOKEN}",
               "TREND_VISION_ONE_API_KEY": "${TREND_VISION_ONE_API_KEY}", "TREND_VISION_ONE_REGION": "us"}
DISTRO = re.compile(r"^[A-Za-z0-9._-]+$")
REFERENCE = re.compile(r"^\$\{[A-Za-z_][A-Za-z0-9_]*\}$")


def env_state(value: str | None) -> str:
    """Describe a variable without ever returning its value."""
    if value is None:
        return "absent"
    if value == "":
        return "empty"
    if REFERENCE.match(value.strip()):
        return "unexpanded reference"
    return "set"


def merge_wslenv(existing: str | None) -> str:
    """Keep unrelated WSLENV entries; list each bridge variable once with /u."""
    if existing is not None and not isinstance(existing, str):
        raise ValueError("Invalid WSLENV value in soc-bridge-readonly env")
    ours = set(BRIDGE_ENV)
    kept = [entry for entry in (existing or "").split(":") if entry and entry.split("/", 1)[0] not in ours]
    return ":".join(kept + [f"{name}/u" for name in BRIDGE_ENV])


def _linux_path(value: str | PurePosixPath, label: str) -> str:
    text = str(value)
    if not text.startswith("/") or any(c in text for c in '"\0\n\r'):
        raise ValueError(f"{label} must be an absolute Linux path without quotes or line breaks")
    return text


def launch_args(distro: str, project: str | PurePosixPath, python: str | PurePosixPath) -> list[str]:
    if not DISTRO.match(distro or ""):
        raise ValueError("WSL distribution name must contain only letters, digits, '.', '-' or '_'")
    return ["--distribution", distro, "--cd", _linux_path(project, "Project path"),
            "--exec", _linux_path(python, "Python path"), "-m", LAUNCH_MODULE]


def powershell_command(args: list[str]) -> str:
    """A copyable PowerShell line running wsl.exe with the same separate arguments."""
    return "wsl.exe " + " ".join("'" + arg.replace("'", "''") + "'" for arg in args)


def windows_folder(distro: str, project: str) -> str:
    """Folder to open in Kiro for Windows: a drive path for /mnt/<x>/, else \\\\wsl.localhost."""
    match = re.match(r"^/mnt/([a-z])(/.*)?$", project)
    if match:
        return f"{match.group(1).upper()}:" + (match.group(2) or "/").replace("/", "\\")
    return f"\\\\wsl.localhost\\{distro}" + project.replace("/", "\\")


def linux_python(linux_root: str) -> str:
    return str(PurePosixPath(linux_root) / ".venv" / "bin" / "python")


def configure_wsl(project: Path, distro: str, linux_root: str | None = None) -> Path:
    """Merge the wsl.exe entry for soc-bridge-readonly; keep every other server and choice.

    linux_root is the project path as seen inside WSL (default: project itself)."""
    if not (project / "pyproject.toml").is_file():
        raise ValueError("Project root must contain pyproject.toml")
    venv = project / ".venv"
    if not (venv / "bin" / "python").is_file():
        if (venv / "Scripts" / "python.exe").is_file():
            raise ValueError("This .venv was created by Windows Python; use a separate clone in the Linux filesystem")
        raise ValueError("Linux .venv Python is missing; create .venv inside WSL first")
    root = linux_root or project.as_posix()
    args = launch_args(distro, root, linux_python(root))

    path = project / ".kiro" / "settings" / "mcp.json"
    mode = 0o600
    if path.exists():
        config = json.loads(path.read_text(encoding="utf-8-sig"))
        if not isinstance(config, dict) or not isinstance(config.get("mcpServers", {}), dict):
            raise ValueError("Invalid mcp.json: expected an mcpServers object")
        mode = path.stat().st_mode & 0o777
    else:
        config = {}
    servers = config.setdefault("mcpServers", {})
    server = servers.setdefault(SERVER, {})
    if not isinstance(server, dict):
        raise ValueError("Invalid soc-bridge-readonly configuration")
    env = server.setdefault("env", {})
    if not isinstance(env, dict):
        raise ValueError("Invalid soc-bridge-readonly env configuration")

    server["command"] = "wsl.exe"
    server["args"] = args
    server.setdefault("autoApprove", ["investigate_demo"])
    for name, value in DEFAULT_ENV.items():
        env.setdefault(name, value)
    env["WSLENV"] = merge_wslenv(env.get("WSLENV"))

    path.parent.mkdir(parents=True, exist_ok=True)
    # Never print config content: existing entries might contain secrets.
    fd, temporary = tempfile.mkstemp(prefix="mcp-", suffix=".json", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(config, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        if os.name != "nt":
            os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return path
