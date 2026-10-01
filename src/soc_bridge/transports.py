"""Narrow, read-only MCP clients. Imported only in live mode."""

from __future__ import annotations

import json
from typing import Any

from .diagnostics import MCPToolFailure, failure_reason, unavailable
from .aql_search import AQL_RESOURCES


QRADAR_TOOLS = {"get_offense", "list_source_addresses", "list_local_destination_addresses",
                "validate_aql", "create_ariel_search", "get_ariel_search_status", "get_ariel_search_results"}
WORKBENCH_TOOLS = {"workbench_alerts_list", "workbench_alert_detail_get"}
VISION_TOOLS = WORKBENCH_TOOLS | {"search_detections_list", "search_endpoint_activities_list",
                                  "endpoint_security_endpoints_list"}


def unpack(result: Any) -> Any:
    if result.isError:
        raise RuntimeError("MCP tool reported an error; inspect server logs locally")
    structured = getattr(result, "structuredContent", None)
    if structured is not None and isinstance(structured, (dict, list)):
        # Some MCP servers wrap the actual result in a result field.
        if isinstance(structured, dict) and "result" in structured:
            return structured["result"]
        return structured
    for block in result.content:
        if hasattr(block, "text"):
            try:
                return json.loads(block.text)
            except json.JSONDecodeError as exc:
                raise ValueError("MCP returned non-JSON text") from exc
    raise ValueError("MCP returned no readable JSON")


class RestrictedMCP:
    def __init__(self, session: Any, allowed: set[str], available: set[str],
                 required: set[str] | None = None, source: str = "MCP"):
        self.session = session
        self.allowed = allowed
        self.available = available
        self.source = source
        missing = (required if required is not None else allowed) - available
        if missing:
            raise RuntimeError(f"MCP server is missing expected read tools: {', '.join(sorted(missing))}")

    async def call(self, name: str, arguments: dict[str, Any]) -> Any:
        if name not in self.allowed:
            raise ValueError(f"Tool not permitted: {name}")
        if name not in self.available:
            raise RuntimeError(f"Optional MCP tool unavailable: {name}")
        try:
            result = await self.session.call_tool(name, arguments=arguments)
        except Exception as exc:
            raise MCPToolFailure(self.source, name, failure_reason(exc)) from None
        if result.isError:
            raise MCPToolFailure(self.source, name, "upstream returned a tool error; check API permissions and local MCP logs")
        if name == "validate_aql":
            structured = getattr(result, "structuredContent", None)
            if isinstance(structured, dict):
                value = structured.get("result", structured)
                if isinstance(value, dict) and value.get("valid") is True:
                    return {"valid": True}
            if result.content and getattr(result.content[0], "text", "").startswith("✓ AQL query is valid"):
                return {"valid": True}
            raise ValueError("QRadar did not confirm that AQL is valid")
        return unpack(result)

    async def read_aql_resource(self, resource: str) -> Any:
        """Read only the four documented upstream AQL metadata resources."""
        if resource not in AQL_RESOURCES:
            raise ValueError("resource must be events, flows, functions or guide")
        try:
            result = await self.session.read_resource(AQL_RESOURCES[resource])
        except Exception as exc:
            raise MCPToolFailure(self.source, "read_aql_resource", failure_reason(exc)) from None
        parts = [block.text for block in result.contents if hasattr(block, "text")]
        if len(parts) != 1:
            raise ValueError("AQL resource returned no single readable text document")
        if resource == "guide":
            return {"resource": AQL_RESOURCES[resource], "text": parts[0]}
        try:
            metadata = json.loads(parts[0])
        except json.JSONDecodeError:
            raise ValueError("AQL metadata resource returned non-JSON text") from None
        return {"resource": AQL_RESOURCES[resource], "metadata": metadata}


async def live_qradar_query(operation: str, parameters: dict[str, Any], url: str,
                            token: str | None) -> dict[str, Any]:
    """QRadar-only query session. Does not require Trend credentials or Docker."""
    from contextlib import AsyncExitStack
    from urllib.parse import urlparse
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client
    import httpx
    from .aql_search import validate_query, start_query, search_status, search_results, run_query

    parsed = urlparse(url)
    if (parsed.scheme != "http" or parsed.hostname not in ("localhost", "127.0.0.1", "::1")
            or parsed.path != "/mcp" or parsed.username or parsed.password or parsed.query or parsed.fragment):
        raise ValueError("QRadar MCP URL must be a local http://127.0.0.1:<port>/mcp endpoint")
    operations = {"validate": validate_query, "start": start_query, "status": search_status,
                  "results": search_results, "run": run_query}
    if operation not in {*operations, "resource"}:
        raise ValueError("Unknown QRadar query operation")
    required = {"validate": {"validate_aql"},
                "start": {"validate_aql", "create_ariel_search"},
                "status": {"get_ariel_search_status"},
                "results": {"get_ariel_search_status", "get_ariel_search_results"},
                "run": {"validate_aql", "create_ariel_search", "get_ariel_search_status", "get_ariel_search_results"},
                "resource": set()}[operation]
    stage = "QRadar MCP connection"
    try:
        async with AsyncExitStack() as stack:
            # This is always loopback: never route telemetry/tokens through an environment proxy.
            http = await stack.enter_async_context(httpx.AsyncClient(headers={"SEC": token} if token else {}, timeout=30.0, trust_env=False))
            stream = await stack.enter_async_context(streamable_http_client(url, http_client=http))
            session = await stack.enter_async_context(ClientSession(stream[0], stream[1]))
            stage = "QRadar MCP initialization"
            await session.initialize()
            stage = "QRadar MCP tool listing"
            available = {tool.name for tool in (await session.list_tools()).tools}
            client = RestrictedMCP(session, QRADAR_TOOLS, available, required, "QRadar")
            stage = f"QRadar AQL {operation}"
            if operation == "resource":
                return await client.read_aql_resource(**parameters)
            return await operations[operation](client, **parameters)
    except (ValueError, MCPToolFailure):
        raise
    except Exception as exc:
        raise MCPToolFailure("QRadar", operation, f"{stage}: {failure_reason(exc)}") from None


async def live_investigation(offense_id: int, url: str, token: str | None,
                             api_key: str, region: str) -> dict[str, Any]:
    """QRadar Streamable HTTP on loopback + local Vision One stdio container."""
    from contextlib import AsyncExitStack
    import os
    from urllib.parse import urlparse
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    from mcp.client.streamable_http import streamable_http_client
    import httpx
    from .core import investigate

    parsed = urlparse(url)
    if parsed.scheme != "http" or parsed.hostname not in ("localhost", "127.0.0.1", "::1") or parsed.path != "/mcp":
        raise ValueError("QRadar MCP URL must be a local http://127.0.0.1:<port>/mcp endpoint")
    if region not in {"au", "ca", "eu", "id", "in", "jp", "mea", "sg", "uk", "us", "za"}:
        raise ValueError("Unsupported Vision One region")
    if not api_key:
        raise ValueError("TREND_VISION_ONE_API_KEY is required")

    headers = {"SEC": token} if token else {}
    stage = "QRadar MCP connection"
    try:
        async with AsyncExitStack() as stack:
            http = await stack.enter_async_context(httpx.AsyncClient(headers=headers, timeout=30.0))
            qr_stream = await stack.enter_async_context(streamable_http_client(url, http_client=http))
            qr = await stack.enter_async_context(ClientSession(qr_stream[0], qr_stream[1]))
            stage = "QRadar MCP initialization"
            await qr.initialize()

            stage = "Vision One Docker MCP startup"
            params = StdioServerParameters(
                command="docker",
                args=["run", "-i", "--rm", "-e", "TREND_VISION_ONE_API_KEY",
                      "ghcr.io/trendmicro/vision-one-mcp-server", "-region", region,
                      "-readonly=true", "-toolsets=workbench,search"],
                env={**os.environ, "TREND_VISION_ONE_API_KEY": api_key},
            )
            v_stream = await stack.enter_async_context(stdio_client(params))
            vision = await stack.enter_async_context(ClientSession(v_stream[0], v_stream[1]))
            stage = "Vision One MCP initialization"
            await vision.initialize()
            stage = "QRadar MCP tool listing"
            qtools = {t.name for t in (await qr.list_tools()).tools}
            stage = "Vision One MCP tool listing"
            vtools = {t.name for t in (await vision.list_tools()).tools}
            stage = "offense evidence collection"
            report = await investigate(RestrictedMCP(qr, QRADAR_TOOLS, qtools, {"get_offense"}, "QRadar"),
                                       RestrictedMCP(vision, VISION_TOOLS, vtools,
                                                     WORKBENCH_TOOLS, source="Vision One"), offense_id,
                                       deep=True, ariel_offset_hours=int(os.environ.get("QRADAR_AQL_UTC_OFFSET_HOURS", "-3")))
            stage = "MCP connection shutdown"
        return report
    except Exception as exc:
        raise unavailable(stage, exc) from None


async def live_alert_investigation(alert_id: str, url: str, token: str | None,
                                   api_key: str, region: str,
                                   event_evidence: dict[str, str] | None = None,
                                   ariel_offset_hours: int | None = None,
                                   enable_vision_search: bool = True) -> dict[str, Any]:
    """Investigate one Vision One alert against bounded QRadar offense address indexes."""
    from contextlib import AsyncExitStack
    import os
    from urllib.parse import urlparse
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    from mcp.client.streamable_http import streamable_http_client
    import httpx
    from .alert_investigation import investigate_vision_alert

    parsed = urlparse(url)
    if parsed.scheme != "http" or parsed.hostname not in ("localhost", "127.0.0.1", "::1") or parsed.path != "/mcp":
        raise ValueError("QRadar MCP URL must be a local http://127.0.0.1:<port>/mcp endpoint")
    if region not in {"au", "ca", "eu", "id", "in", "jp", "mea", "sg", "uk", "us", "za"}:
        raise ValueError("Unsupported Vision One region")
    if not api_key:
        raise ValueError("TREND_VISION_ONE_API_KEY is required")

    stage = "QRadar MCP connection"
    try:
        async with AsyncExitStack() as stack:
            http = await stack.enter_async_context(httpx.AsyncClient(headers={"SEC": token} if token else {}, timeout=30.0))
            qr_stream = await stack.enter_async_context(streamable_http_client(url, http_client=http))
            qr = await stack.enter_async_context(ClientSession(qr_stream[0], qr_stream[1]))
            stage = "QRadar MCP initialization"
            await qr.initialize()
            stage = "Vision One Docker MCP startup"
            params = StdioServerParameters(
                command="docker",
                args=["run", "-i", "--rm", "-e", "TREND_VISION_ONE_API_KEY",
                      "ghcr.io/trendmicro/vision-one-mcp-server", "-region", region,
                      "-readonly=true", "-toolsets=workbench,search"],
                env={**os.environ, "TREND_VISION_ONE_API_KEY": api_key},
            )
            v_stream = await stack.enter_async_context(stdio_client(params))
            vision = await stack.enter_async_context(ClientSession(v_stream[0], v_stream[1]))
            stage = "Vision One MCP initialization"
            await vision.initialize()
            stage = "QRadar MCP tool listing"
            qtools = {t.name for t in (await qr.list_tools()).tools}
            stage = "Vision One MCP tool listing"
            vtools = {t.name for t in (await vision.list_tools()).tools}
            stage = "Vision One Workbench alert retrieval and QRadar evidence collection"
            report = await investigate_vision_alert(
                RestrictedMCP(qr, QRADAR_TOOLS, qtools, {"get_offense"}, "QRadar"),
                RestrictedMCP(vision, VISION_TOOLS, vtools, {"workbench_alert_detail_get"}, "Vision One"), alert_id,
                event_evidence=event_evidence, ariel_offset_hours=ariel_offset_hours,
                enable_vision_search=enable_vision_search)
            stage = "MCP connection shutdown"
        return report
    except Exception as exc:
        raise unavailable(stage, exc) from None


async def live_extra_case(kind: str, parameters: dict[str, Any], url: str, token: str | None,
                          api_key: str, region: str) -> str:
    """Connect to the same two upstreams, retaining strict read-only allowlists."""
    from contextlib import AsyncExitStack
    import os
    from urllib.parse import urlparse
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    from mcp.client.streamable_http import streamable_http_client
    import httpx
    from .extra_cases import investigate_epm_uac, investigate_web_reputation

    parsed = urlparse(url)
    if parsed.scheme != "http" or parsed.hostname not in ("localhost", "127.0.0.1", "::1") or parsed.path != "/mcp":
        raise ValueError("QRadar MCP URL must be a local http://127.0.0.1:<port>/mcp endpoint")
    if region not in {"au", "ca", "eu", "id", "in", "jp", "mea", "sg", "uk", "us", "za"}:
        raise ValueError("Unsupported Vision One region")
    if not api_key:
        raise ValueError("TREND_VISION_ONE_API_KEY is required")
    if kind not in {"epm", "web"}:
        raise ValueError("Unknown investigation type")
    stage = "QRadar MCP connection"
    try:
        async with AsyncExitStack() as stack:
            http = await stack.enter_async_context(httpx.AsyncClient(headers={"SEC": token} if token else {}, timeout=30.0))
            stream = await stack.enter_async_context(streamable_http_client(url, http_client=http))
            qr = await stack.enter_async_context(ClientSession(stream[0], stream[1]))
            stage = "QRadar MCP initialization"
            await qr.initialize()
            stage = "Vision One Docker MCP startup"
            params = StdioServerParameters(command="docker", args=["run", "-i", "--rm", "-e", "TREND_VISION_ONE_API_KEY",
                "ghcr.io/trendmicro/vision-one-mcp-server", "-region", region, "-readonly=true", "-toolsets=search,endpoint"],
                env={**os.environ, "TREND_VISION_ONE_API_KEY": api_key})
            v_stream = await stack.enter_async_context(stdio_client(params))
            vision = await stack.enter_async_context(ClientSession(v_stream[0], v_stream[1]))
            stage = "Vision One MCP initialization"
            await vision.initialize()
            stage = "read-only tool listing"
            qtools = {t.name for t in (await qr.list_tools()).tools}
            vtools = {t.name for t in (await vision.list_tools()).tools}
            q = RestrictedMCP(qr, QRADAR_TOOLS, qtools,
                              {"validate_aql", "create_ariel_search", "get_ariel_search_status", "get_ariel_search_results"}, "QRadar")
            v = RestrictedMCP(vision, VISION_TOOLS, vtools, {"search_detections_list"}, "Vision One")
            stage = "EPM UAC / FortiGate evidence collection"
            if kind == "epm":
                return await investigate_epm_uac(q, v, **parameters)
            return await investigate_web_reputation(q, v, **parameters)
    except Exception as exc:
        raise unavailable(stage, exc) from None
