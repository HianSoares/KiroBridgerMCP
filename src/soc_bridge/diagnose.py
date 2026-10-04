"""Common diagnostics for Windows and WSL: bridge, environment, connections and capabilities.

Output names stages, states and remediation only. It never contains tokens, authentication
headers, URLs with credentials or upstream messages (which may echo secrets): failures are
reduced to the bridge's fixed categories. Trend checks start the local Vision One container
only when requested; tools/list does not call the Trend API.
"""

from __future__ import annotations

import asyncio
import os
import platform
import shutil
import socket
import sys
from importlib import metadata
from typing import Any

from .capabilities import GLOBAL_LEDGER, discover
from .diagnostics import failure_reason
from .wsl_setup import BRIDGE_ENV, env_state

QRADAR_URL_DEFAULT = "http://127.0.0.1:5001/mcp"


def bridge_identity() -> dict:
    try:
        version = metadata.version("soc-bridge-investigator")
    except metadata.PackageNotFoundError:
        version = "not installed (source tree)"
    return {"name": "soc-bridge-investigator", "version": version, "python": platform.python_version(),
            "platform": platform.system(), "wsl_distribution": os.environ.get("WSL_DISTRO_NAME"),
            "executable_in_venv": sys.prefix != getattr(sys, "base_prefix", sys.prefix)}


def environment_states() -> dict:
    return {name: env_state(os.environ.get(name)) for name in BRIDGE_ENV}


async def pack_consistency() -> dict:
    """Agents may only reference tools the bridge exposes (central capability source)."""
    from pathlib import Path
    import re
    from .capabilities import public_tools
    tools = await public_tools()
    root = Path(__file__).resolve().parents[2] / ".kiro" / "agents"
    problems = []
    for path in sorted(root.glob("*.md")) if root.is_dir() else []:
        text = path.read_text(encoding="utf-8")
        for name in re.findall(r"@soc-bridge-readonly/([A-Za-z0-9_]+)", text):
            if name not in tools:
                problems.append(f"{path.name}: unknown tool {name}")
    return {"tools": len(tools), "local_writes": sorted(n for n, t in tools.items() if not t["read_only"]),
            "problems": problems, "state": "consistent" if not problems else "inconsistent"}


async def _qradar(url: str, token: str | None, timeout: float) -> dict:
    from contextlib import AsyncExitStack
    from urllib.parse import urlparse
    import httpx
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client
    from .transports import QRADAR_MUTATIONS, QRADAR_READ_TOOLS
    out: dict[str, Any] = {"stages": []}
    parsed = urlparse(url)
    if (parsed.scheme != "http" or parsed.hostname not in ("localhost", "127.0.0.1", "::1")
            or parsed.path != "/mcp" or parsed.username or parsed.password or parsed.query):
        out["stages"].append({"stage": "url_validation", "state": "failed"})
        out["remediation"] = "Set QRADAR_MCP_URL to http://127.0.0.1:<port>/mcp (loopback only)"
        return out
    out["stages"].append({"stage": "url_validation", "state": "ok"})
    try:
        with socket.create_connection((parsed.hostname, parsed.port or 80), timeout=3):
            pass
        out["stages"].append({"stage": "tcp", "state": "ok", "meaning": "port open; not proof of MCP authentication"})
    except OSError as exc:
        out["stages"].append({"stage": "tcp", "state": "failed", "category": type(exc).__name__})
        out["remediation"] = "Start the QRadar MCP container and check the published loopback port"
        return out
    stage = "mcp_initialize"
    try:
        async with AsyncExitStack() as stack:
            http = await stack.enter_async_context(httpx.AsyncClient(headers={"SEC": token} if token else {},
                                                                     timeout=timeout, trust_env=False))
            streams = await stack.enter_async_context(streamable_http_client(url, http_client=http))
            session = await stack.enter_async_context(ClientSession(streams[0], streams[1]))
            init = await asyncio.wait_for(session.initialize(), timeout)
            info = getattr(init, "serverInfo", None)
            out["server"] = {"name": getattr(info, "name", None), "version": getattr(info, "version", None),
                             "protocol": getattr(init, "protocolVersion", None)}
            out["stages"].append({"stage": stage, "state": "ok"})
            stage = "tools_discovery"
            found = await discover(session, "QRadar", deadline_seconds=timeout)
            out["discovery"] = found.describe(QRADAR_READ_TOOLS)
            out["discovery"]["mutations_advertised_but_blocked"] = len(found.names & QRADAR_MUTATIONS)
            out["stages"].append({"stage": stage, "state": "ok" if found.complete else "partial",
                                  "reason": found.stop_reason})
    except Exception as exc:
        out["stages"].append({"stage": stage, "state": "failed", "category": failure_reason(exc)})
        out["remediation"] = ("Check QRADAR_MCP_TOKEN / the QRadar MCP config.json and container logs"
                              if "401" in failure_reason(exc) or "403" in failure_reason(exc)
                              else "Inspect the QRadar MCP container logs; rerun diagnostics")
    return out


async def _trend(api_key: str, region: str, timeout: float) -> dict:
    from contextlib import AsyncExitStack
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    from .transports import ALERT_TOOLSETS, ALERT_VISION_TOOLS
    out: dict[str, Any] = {"stages": []}
    if not api_key:
        out["stages"].append({"stage": "api_key", "state": "absent"})
        out["remediation"] = "Provide TREND_VISION_ONE_API_KEY to the bridge process (see the WSL/installation guide)"
        return out
    if not shutil.which("docker"):
        out["stages"].append({"stage": "docker_cli", "state": "absent"})
        out["remediation"] = "Install Docker Desktop (or enable its WSL integration) and reopen the terminal"
        return out
    stage = "container_start"
    try:
        async with AsyncExitStack() as stack:
            params = StdioServerParameters(command="docker", args=[
                "run", "-i", "--rm", "-e", "TREND_VISION_ONE_API_KEY", "ghcr.io/trendmicro/vision-one-mcp-server",
                "-region", region, "-readonly=true", f"-toolsets={ALERT_TOOLSETS}"],
                env={**os.environ, "TREND_VISION_ONE_API_KEY": api_key})
            streams = await stack.enter_async_context(stdio_client(params))
            session = await stack.enter_async_context(ClientSession(streams[0], streams[1]))
            stage = "mcp_initialize"
            init = await asyncio.wait_for(session.initialize(), timeout)
            info = getattr(init, "serverInfo", None)
            out["server"] = {"name": getattr(info, "name", None), "version": getattr(info, "version", None)}
            out["stages"].append({"stage": "mcp_initialize", "state": "ok"})
            stage = "tools_discovery"
            found = await discover(session, "Vision One", deadline_seconds=timeout)
            out["discovery"] = found.describe(ALERT_VISION_TOOLS)
            out["stages"].append({"stage": stage, "state": "ok" if found.complete else "partial",
                                  "reason": found.stop_reason})
    except Exception as exc:
        out["stages"].append({"stage": stage, "state": "failed", "category": failure_reason(exc)})
        out["remediation"] = ("If the log shows 'unknown toolset', run docker pull ghcr.io/trendmicro/vision-one-mcp-server; "
                              "otherwise check Docker and the region")
    return out


async def diagnose(check_trend: bool = False, timeout: float = 20.0) -> dict:
    url = os.environ.get("QRADAR_MCP_URL") or QRADAR_URL_DEFAULT
    token = os.environ.get("QRADAR_MCP_TOKEN") or None
    report = {"bridge": bridge_identity(), "environment": environment_states(), "pack": await pack_consistency(),
              "qradar": await _qradar(url, token, timeout)}
    if check_trend:
        report["trend"] = await _trend(os.environ.get("TREND_VISION_ONE_API_KEY", ""),
                                       os.environ.get("TREND_VISION_ONE_REGION", "us"), timeout)
    else:
        report["trend"] = {"stages": [{"stage": "not_requested", "state": "skipped"}],
                           "note": "Run with check_trend to start the local Vision One container and list its tools"}
    report["call_outcomes"] = GLOBAL_LEDGER.describe()
    report["handling"] = ("States and categories only: no token, header, credential URL or upstream message is shown. "
                          "Advertised tools are not proof of permission or license; only call outcomes show access.")
    return report


def render(report: dict) -> str:
    lines = [f"SOC Bridge {report['bridge']['version']} (Python {report['bridge']['python']}, "
             f"{report['bridge']['platform']}{', WSL ' + report['bridge']['wsl_distribution'] if report['bridge']['wsl_distribution'] else ''})"]
    lines.append("Environment: " + ", ".join(f"{k}={v}" for k, v in report["environment"].items()))
    lines.append(f"Kiro pack: {report['pack']['state']} ({report['pack']['tools']} tools)" +
                 (f"; {report['pack']['problems']}" if report["pack"]["problems"] else ""))
    for source in ("qradar", "trend"):
        section = report[source]
        stages = ", ".join(f"{s['stage']}={s['state']}" + (f" ({s['category']})" if s.get("category") else "")
                           for s in section["stages"])
        lines.append(f"{source}: {stages}")
        if section.get("server"):
            lines.append(f"  server: {section['server']}")
        if section.get("discovery"):
            disc = section["discovery"]
            missing = disc.get("absent", disc.get("availability_unknown"))
            lines.append(f"  tools: {disc['advertised']} advertised, {len(disc['available_allowed'])} allowed available, "
                         f"{'absent' if disc['complete'] else 'availability unknown'}: {missing}")
        if section.get("remediation"):
            lines.append(f"  fix: {section['remediation']}")
    return "\n".join(lines)
