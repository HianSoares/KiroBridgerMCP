"""Live sessions for registry-bound upstream calls (query here; changes reuse it from change_control).

Each call opens one upstream session, walks the complete tools/list, checks that the tool is announced
and that its announced schema still matches the audited contract, then makes exactly one tool call.
An incomplete discovery blocks the call even when the tool appeared on a page that was read.
Vision One always starts the audited image (pinned by digest) with the toolset of the requested tool
only; query calls always use ``-readonly=true``, so the container cannot register a write tool at all.
A matching schema does not prove that the handler's effect is unchanged; for QRadar the running
version cannot be verified by the bridge (see ``version_binding``).
"""

from __future__ import annotations

import asyncio
import hashlib
import mimetypes
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .capabilities import GLOBAL_LEDGER, discover
from .connection_lifecycle import InvestigationConnections
from .diagnostics import failure_reason
from .upstream_access import (PLATFORMS, Refused, contract_drift, gate_query, normalize, registry, trend_image,
                              version_binding, _index)

MOUNT_TARGET = "/approved"
REGIONS = {"au", "ca", "eu", "id", "in", "jp", "mea", "sg", "uk", "us", "za"}
SOURCES = {"qradar": "QRadar", "vision_one": "Vision One"}


def _settings() -> dict[str, str]:
    return {"url": os.environ.get("QRADAR_MCP_URL", "http://127.0.0.1:5001/mcp"),
            "token": os.environ.get("QRADAR_MCP_TOKEN", ""),
            "api_key": os.environ.get("TREND_VISION_ONE_API_KEY", ""),
            "region": os.environ.get("TREND_VISION_ONE_REGION", "us")}


def _check_qradar_url(url: str) -> None:
    parsed = urlparse(url)
    if (parsed.scheme != "http" or parsed.hostname not in ("localhost", "127.0.0.1", "::1")
            or parsed.path != "/mcp" or parsed.username or parsed.password or parsed.query or parsed.fragment):
        raise Refused("configuration", "QRADAR_MCP_URL must be a local http://127.0.0.1:<port>/mcp endpoint")


def _mount_args(mounts: list[tuple[str, str]] | None) -> list[str]:
    """One read-only bind mount per approved file; never a directory of the user."""
    args = []
    for host, target in mounts or []:
        if any(c in host + target for c in ',"\n') or not target.startswith(MOUNT_TARGET + "/"):
            raise Refused("configuration", "staged file path cannot be mounted safely")
        args += ["--mount", f"type=bind,source={host},target={target},readonly"]
    return args


async def open_session(stack: InvestigationConnections, platform: str, toolset: str = "", readonly: bool = True,
                       settings: dict[str, str] | None = None, mounts: list[tuple[str, str]] | None = None) -> Any:
    """Enter the transport and session for one upstream; credentials only travel to that upstream."""
    from mcp import ClientSession, StdioServerParameters
    s = settings or _settings()
    if platform == "qradar":
        import httpx
        from mcp.client.streamable_http import streamable_http_client
        _check_qradar_url(s["url"])
        # Loopback only: never route the token through an environment proxy.
        http = await stack.enter(httpx.AsyncClient(headers={"SEC": s["token"]} if s["token"] else {},
                                                   timeout=60.0, trust_env=False), "QRadar", "HTTP client")
        stream = await stack.enter(streamable_http_client(s["url"], http_client=http), "QRadar",
                                   "Streamable HTTP transport")
        return await stack.enter(ClientSession(stream[0], stream[1]), "QRadar", "MCP session")
    from mcp.client.stdio import stdio_client
    if s["region"] not in REGIONS:
        raise Refused("configuration", "TREND_VISION_ONE_REGION is not a supported Vision One region")
    if not s["api_key"]:
        raise Refused("configuration", "TREND_VISION_ONE_API_KEY is not set for this bridge process")
    if toolset not in {t["category"] for t in registry()["tools"] if t["platform"] == "vision_one"}:
        raise Refused("configuration", "unknown Vision One toolset")
    if mounts and readonly:
        raise Refused("configuration", "file mounts are only used for approved uploads")
    params = StdioServerParameters(command="docker", args=[
        "run", "-i", "--rm", "-e", "TREND_VISION_ONE_API_KEY", *_mount_args(mounts), trend_image(),
        "-region", s["region"], f"-readonly={'true' if readonly else 'false'}", f"-toolsets={toolset}"],
        env={**os.environ, "TREND_VISION_ONE_API_KEY": s["api_key"]})
    stream = await stack.enter(stdio_client(params), "Vision One", "Docker stdio transport")
    return await stack.enter(ClientSession(stream[0], stream[1]), "Vision One", "MCP session")


def _failure(stage: str, category: str, message: str, attempted: bool, t: dict | None = None) -> dict[str, Any]:
    out = {"outcome": "error", "stage": stage, "upstream_call_attempted": attempted,
           "error": {"category": category, "meaning": message}}
    if attempted:
        out["error"]["result_state"] = ("unknown: the request was sent and no valid answer was received; the "
                                        "upstream may or may not have processed it")
    if t is not None:
        out.update(platform=t["platform"], tool=t["name"], effect=t["effect"])
        if attempted and t["effect"] == "query_job":
            out["error"]["job_state"] = ("creation uncertain: the search job may exist upstream without a returned ID; "
                                         "check recent searches before creating it again")
    return out


async def call_registered(t: dict, arguments: dict, *, readonly: bool, timeout_seconds: float,
                          max_chars: int, settings: dict[str, str] | None = None, skip_items: int = 0,
                          mounts: list[tuple[str, str]] | None = None,
                          progress: dict[str, Any] | None = None) -> tuple[dict, Any]:
    """One session, complete discovery, contract check and exactly one tool call.

    ``progress`` (if given) is updated in place with the stage and whether the call was sent, so a
    caller can tell, even after cancellation, whether the upstream may have received the request.
    """
    progress = progress if progress is not None else {}
    progress.update(stage="connection", sent=False)
    source = SOURCES[t["platform"]]
    raw = None
    try:
        async with asyncio.timeout(timeout_seconds):
            async with InvestigationConnections() as stack:
                session = await open_session(stack, t["platform"], (t.get("server_flags") or {}).get("toolset", ""),
                                             readonly=readonly, settings=settings, mounts=mounts)
                progress["stage"] = "initialization"
                init = await session.initialize()
                progress["stage"] = "tools/list discovery"
                found = await discover(session, source, deadline_seconds=min(30.0, timeout_seconds))
                found.server = {"name": getattr(init.serverInfo, "name", None),
                                "version": getattr(init.serverInfo, "version", None)}
                discovery = {"complete": found.complete, "pages": found.pages, "server": found.server,
                             "stop_reason": found.stop_reason}
                drift = contract_drift(t, {"inputSchema": found.schemas.get(t["name"])})
                if not found.complete:
                    out = _failure(progress["stage"], "discovery_incomplete",
                                   f"tools/list did not complete ({found.stop_reason}); the call is blocked even if "
                                   "the tool appeared on a page that was read", False, t)
                elif t["name"] not in found.names:
                    out = _failure(progress["stage"], "tool_absent", "the running server does not announce this tool "
                                   "(toolset, feature toggle, version or read-only mode)", False, t)
                elif drift:
                    out = _failure(progress["stage"], "contract_changed", "the announced schema differs from the "
                                   "audited contract; the tool stays blocked until the audit is refreshed", False, t)
                    out["differences"] = drift
                else:
                    progress["stage"] = "tool call"
                    progress["sent"] = True
                    raw = await session.call_tool(t["name"], arguments=arguments)
                    progress["stage"] = "response"
                    out = normalize(t, arguments, raw, max_chars, skip_items)
                    GLOBAL_LEDGER.record(f"{t['platform']}/{t['name']}",
                                         "tested_ok" if out["outcome"] != "error" else "rejected")
                out["discovery"] = discovery
                out["version_binding"] = version_binding(t["platform"])
                stack.collected(out)
            return stack.deliver(out), raw
    except Refused as refused:
        return {**refused.describe(), "platform": t["platform"], "tool": t["name"]}, None
    except TimeoutError:
        return _failure(progress["stage"], "timeout", f"no answer within {timeout_seconds:g} s", progress["sent"],
                        t), None
    except Exception as exc:
        category = ("connection_lost_or_invalid_response" if progress["sent"] else
                    "connection" if progress["stage"] in ("connection", "initialization") else "upstream_error")
        return _failure(progress["stage"], category, failure_reason(exc), progress["sent"], t), None


def _limits(max_chars: Any, timeout_seconds: Any, skip_items: Any = 0) -> tuple[int, float]:
    if isinstance(max_chars, bool) or not isinstance(max_chars, int) or not 1000 <= max_chars <= 200_000:
        raise Refused("invalid_arguments", "max_output_chars must be 1000..200000")
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)) or \
            not 5 <= timeout_seconds <= 180:
        raise Refused("invalid_arguments", "timeout_seconds must be 5..180")
    if isinstance(skip_items, bool) or not isinstance(skip_items, int) or not 0 <= skip_items <= 100_000:
        raise Refused("invalid_arguments", "skip_items must be 0..100000")
    return max_chars, float(timeout_seconds)


async def live_upstream_query(platform: str, tool: str, arguments: Any = None, max_output_chars: int = 50_000,
                              timeout_seconds: float = 60, settings: dict[str, str] | None = None,
                              skip_items: int = 0) -> dict[str, Any]:
    try:
        t, args = gate_query(platform, tool, arguments)
        max_chars, timeout = _limits(max_output_chars, timeout_seconds, skip_items)
    except Refused as refused:
        return {**refused.describe(), "platform": platform, "tool": tool}
    out, _ = await call_registered(t, args, readonly=True, timeout_seconds=timeout, max_chars=max_chars,
                                   settings=settings, skip_items=skip_items)
    out["budget"] = {"calls": 1, "timeout_seconds": timeout, "max_output_chars": max_chars, "skip_items": skip_items}
    return out


def downloads_dir() -> Path:
    configured = os.environ.get("SOC_BRIDGE_DOWNLOAD_DIR", "").strip()
    if configured:
        return Path(configured)
    project = Path(__file__).resolve().parents[2]
    base = project if (project / "pyproject.toml").is_file() else Path.cwd()
    return base / "reports" / "downloads"


async def live_upstream_download(platform: str, tool: str, arguments: Any = None, timeout_seconds: float = 120,
                                 settings: dict[str, str] | None = None) -> dict[str, Any]:
    """Save binary bodies (reports, packages) of a query-access tool under reports/downloads."""
    try:
        t, args = gate_query(platform, tool, arguments)
        _, timeout = _limits(50_000, timeout_seconds)
    except Refused as refused:
        return {**refused.describe(), "platform": platform, "tool": tool}
    out, raw = await call_registered(t, args, readonly=True, timeout_seconds=timeout, max_chars=20_000,
                                     settings=settings)
    if raw is None or out.get("outcome") == "error":
        return out
    import base64
    saved = []
    target = downloads_dir()
    for block in getattr(raw, "content", None) or []:
        blob = getattr(getattr(block, "resource", None), "blob", None)
        if blob is None:
            continue
        data = base64.b64decode(blob)
        digest = hashlib.sha256(data).hexdigest()
        mime = getattr(block.resource, "mimeType", None) or "application/octet-stream"
        extension = mimetypes.guess_extension(mime.split(";")[0].strip()) or ".bin"
        target.mkdir(parents=True, exist_ok=True)
        path = target / f"{t['platform']}-{t['name']}-{digest[:16]}{extension}"
        if not path.exists():
            path.write_bytes(data)
        saved.append({"path": str(path), "bytes": len(data), "sha256": digest, "mime_type": mime})
    out["saved_files"] = saved
    out["storage_note"] = ("Saved under reports/downloads (ignored by Git) or SOC_BRIDGE_DOWNLOAD_DIR. Files are "
                           "untrusted vendor content; never open or run them as part of the investigation.")
    if not saved:
        out["saved_files_note"] = "the response had no binary body; nothing was written"
    return out


async def live_inventory(platform: str, settings: dict[str, str] | None = None, timeout_seconds: float = 90) -> dict:
    """Compare the running server with the audited registry: announced, absent, unreviewed, drifted."""
    if platform not in PLATFORMS:
        return Refused("invalid_arguments", f"platform must be one of {sorted(PLATFORMS)}").describe()
    audited = {name: t for (p, name), t in _index().items() if p == platform}
    stage = "connection"
    try:
        async with asyncio.timeout(timeout_seconds):
            async with InvestigationConnections() as stack:
                # Vision One: one read-only container with every toolset shows what this installation registers.
                if platform == "qradar":
                    session = await open_session(stack, "qradar", settings=settings)
                else:
                    session = await _open_all_toolsets(stack, settings)
                stage = "initialization"
                await session.initialize()
                stage = "tools/list discovery"
                found = await discover(session, SOURCES[platform])
                stack.collected(found)
            found = stack.deliver(found)
    except Refused as refused:
        return refused.describe()
    except TimeoutError:
        return _failure(stage, "timeout", f"no answer within {timeout_seconds:g} s", False)
    except Exception as exc:
        return _failure(stage, "connection" if stage != "tools/list discovery" else "upstream_error",
                        failure_reason(exc), False)
    expected = {n for n, t in audited.items() if platform == "qradar" or t["server_flags"]["readonly"]}
    unreviewed = sorted(found.names - set(audited))
    drifted = {n: d for n in sorted(found.names & set(audited))
               if (d := contract_drift(audited[n], {"inputSchema": found.schemas.get(n)}))}
    return {"platform": platform, "discovery": {"complete": found.complete, "pages": found.pages,
                                                "stop_reason": found.stop_reason},
            "announced": len(found.names), "audited": len(audited),
            "audited_expected_in_this_mode": len(expected),
            ("absent" if found.complete else "availability_unknown"): sorted(expected - found.names),
            "announced_but_pending_review": unreviewed, "schema_drift": drifted,
            "note": ("Vision One is listed with -readonly=true, so write tools are not registered by design." if
                     platform == "vision_one" else "QRadar announces all tools enabled by its feature toggles.")}


async def _open_all_toolsets(stack: InvestigationConnections, settings: dict[str, str] | None) -> Any:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    s = settings or _settings()
    if s["region"] not in REGIONS:
        raise Refused("configuration", "TREND_VISION_ONE_REGION is not a supported Vision One region")
    if not s["api_key"]:
        raise Refused("configuration", "TREND_VISION_ONE_API_KEY is not set for this bridge process")
    params = StdioServerParameters(command="docker", args=[
        "run", "-i", "--rm", "-e", "TREND_VISION_ONE_API_KEY", trend_image(), "-region", s["region"],
        "-readonly=true", "-toolsets=all"], env={**os.environ, "TREND_VISION_ONE_API_KEY": s["api_key"]})
    stream = await stack.enter(stdio_client(params), "Vision One", "Docker stdio transport")
    return await stack.enter(ClientSession(stream[0], stream[1]), "Vision One", "MCP session")
