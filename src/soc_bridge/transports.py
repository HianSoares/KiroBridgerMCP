"""Narrow, read-only MCP clients. Imported only in live mode."""

from __future__ import annotations

import json
import re
from typing import Any

from .diagnostics import MCPToolFailure, failure_reason, unavailable
from .aql_errors import AQLValidationError, ResponseFormatError
from .aql_search import AQL_RESOURCES


QRADAR_TOOLS = {"list_offenses", "get_offense", "get_rule", "list_offense_closing_reasons", "list_source_addresses", "list_local_destination_addresses",
                "validate_aql", "create_ariel_search", "get_ariel_search_status", "get_ariel_search_results"}
# GET-only context reads (qradar_context.py). Each was checked in the IBM handler: HTTP GET,
# arguments forwarded, Range-header pagination where offset/limit exist.
QRADAR_CONTEXT_TOOLS = {
    "get_offense_notes", "list_offense_types", "list_assets", "list_asset_properties", "get_network_hierarchy",
    "list_log_sources", "get_log_source", "list_log_source_types", "list_rules", "list_building_blocks",
    "get_building_block", "get_qid_record_by_qid", "get_low_level_category", "get_high_level_category",
    "list_dsm_event_mappings", "list_reference_sets", "list_reference_maps", "get_reference_map",
    "list_reference_tables", "get_reference_table", "list_saved_searches", "list_vulnerabilities", "get_case",
    "geolocate_ip"}
QRADAR_READ_TOOLS = QRADAR_TOOLS | QRADAR_CONTEXT_TOOLS
# Operations with an effect on QRadar besides Ariel search creation. Never allowlisted.
QRADAR_MUTATIONS = {
    "add_offense_note", "assign_offense", "set_offense_follow_up", "set_offense_protected", "set_offense_status",
    "delete_ariel_search", "delete_saved_search", "add_staged_network", "delete_staged_network",
    "update_staged_network", "deploy_qradar_config", "create_dsm_event_mapping", "create_qid_record",
    "update_dsm_event_mapping", "update_qid_record", "add_to_reference_map", "add_to_reference_set",
    "add_to_reference_table", "create_reference_map", "create_reference_set", "create_reference_table",
    "delete_reference_map", "delete_reference_set", "delete_reference_table", "remove_from_reference_map",
    "remove_from_reference_set", "remove_from_reference_table", "update_reference_set", "dns_lookup", "whois_lookup"}
WORKBENCH_TOOLS = {"workbench_alerts_list", "workbench_alert_detail_get"}
VISION_TOOLS = WORKBENCH_TOOLS | {"search_detections_list", "search_endpoint_activities_list",
                                  "endpoint_security_endpoints_list"}
# Read-only enrichment tools used by alert-first investigation. Each name was checked
# against the upstream registry (ReadOnlyHint=true); write tools stay excluded.
ALERT_ENRICHMENT_TOOLS = {
    "workbench_alert_notes_list", "workbench_observed_attack_techniques_list",
    "workbench_insight_get", "workbench_insight_impact_scope_entities_list",
    "workbench_insight_indicators_list", "workbench_insight_matched_highlights_list",
    "search_network_activities_list", "search_identity_activities_list", "search_email_activities_list",
    "endpoint_security_endpoint_get",
    "threatintel_suspicious_objects_list", "threatintel_exceptions_list",
    "dmm_models_list", "dmm_custom_models_list", "dmm_custom_filters_list", "dmm_exceptions_list",
    "crem_attack_surface_devices_list", "crem_high_risk_devices_list",
    "case_management_cases_list", "audit_logs_list", "sandbox_analysis_results_list", "response_tasks_list",
    "workbench_insights_list", "sandbox_analysis_result_get", "sandbox_analysis_result_suspicious_objects_list",
    "response_task_get", "case_management_case_get", "case_management_case_contents_list", "eiqs_endpoints_list",
    "search_activity_statistics_get", "search_sensor_statistics_get", "crem_vulnerable_devices_list",
    "search_container_activities_list", "search_mobile_activities_list"}
ALERT_VISION_TOOLS = VISION_TOOLS | ALERT_ENRICHMENT_TOOLS
# Toolsets loaded for alert-first investigation; with -readonly=true the upstream registers
# only their read tools, and ALERT_VISION_TOOLS narrows further.
ALERT_TOOLSETS = "workbench,search,endpoint,threatintel,dmm,crem,cases,audit,sandbox,response,eiqs"
HTTP_STATUS = re.compile(r"\(HTTP (\d{3})\)")
LICENSE_HINT = re.compile(r"licen[cs]e|not (?:enabled|activated|entitled|subscribed)|subscription|integration|"
                          r"not supported in your region|feature is not available", re.I)


def tool_error_reason(result: Any) -> str:
    """Status code and a coarse hint only; the upstream body is never copied."""
    text = " ".join(getattr(block, "text", "") for block in (result.content or []))[:20000]
    status = HTTP_STATUS.search(text)
    reason = f"upstream returned HTTP {status[1]}" if status else "upstream returned a tool error"
    if LICENSE_HINT.search(text):
        reason += "; response mentions license/integration availability"
    return reason + "; check API permissions and local MCP logs"


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
        if name == "list_offenses":
            from .offense_response import decode_listing
            return decode_listing(result, self.source)
        if result.isError:
            raise MCPToolFailure(self.source, name, tool_error_reason(result))
        if name == "validate_aql":
            structured = getattr(result, "structuredContent", None)
            if isinstance(structured, dict):
                value = structured.get("result", structured)
                if isinstance(value, dict) and value.get("valid") is True:
                    return {"valid": True}
            if result.content and getattr(result.content[0], "text", "").startswith("✓ AQL query is valid"):
                return {"valid": True}
            raise AQLValidationError("QRadar did not confirm that AQL is valid")
        if name in ("get_rule", "get_building_block"):
            # IBM's formatter appends the JSON object after a fixed heading.
            for block in result.content:
                raw = getattr(block, "text", "")
                if "\nFull JSON:\n" in raw:
                    try:
                        data = json.loads(raw.rsplit("\nFull JSON:\n", 1)[1])
                    except json.JSONDecodeError:
                        raise ValueError("Rule metadata has invalid trailing JSON") from None
                    if not isinstance(data, dict):
                        raise ValueError("Rule/building block metadata must be a JSON object")
                    return data
        if name == "workbench_alerts_list":
            try:
                return unpack(result)
            except ValueError:
                raise ResponseFormatError("Vision One listing returned unreadable JSON") from None
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
    from .offense_evidence import verify_offense
    from .offense_batch import find_offenses, investigate_offenses

    parsed = urlparse(url)
    if (parsed.scheme != "http" or parsed.hostname not in ("localhost", "127.0.0.1", "::1")
            or parsed.path != "/mcp" or parsed.username or parsed.password or parsed.query or parsed.fragment):
        raise ValueError("QRadar MCP URL must be a local http://127.0.0.1:<port>/mcp endpoint")
    from .qradar_context import assess_closure, context_lookup
    operations = {"validate": validate_query, "start": start_query, "status": search_status,
                  "results": search_results, "run": run_query, "verify_offense": verify_offense,
                  "find_offenses": find_offenses, "investigate_offenses": investigate_offenses,
                  "context": context_lookup, "assess_closure": assess_closure}
    if operation not in {*operations, "resource", "rule"}:
        raise ValueError("Unknown QRadar query operation")
    required = {"validate": {"validate_aql"},
                "start": {"validate_aql", "create_ariel_search"},
                "status": {"get_ariel_search_status"},
                "results": {"get_ariel_search_status", "get_ariel_search_results"},
                "run": {"validate_aql", "create_ariel_search", "get_ariel_search_status", "get_ariel_search_results"},
                "find_offenses": {"list_offenses"}, "investigate_offenses": {"get_offense"},
                "resource": set(), "verify_offense": {"get_offense"}, "rule": {"get_rule"},
                "context": set(), "assess_closure": {"get_offense"}}[operation]
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
            client = RestrictedMCP(session, QRADAR_READ_TOOLS, available, required, "QRadar")
            stage = f"QRadar AQL {operation}"
            if operation == "resource":
                return await client.read_aql_resource(**parameters)
            if operation == "rule":
                rule_id = parameters.get("rule_id")
                if isinstance(rule_id, bool) or not isinstance(rule_id, int) or rule_id < 0:
                    raise ValueError("rule_id must be a nonnegative integer")
                rule = await client.call("get_rule", {"rule_id": rule_id})
                if not isinstance(rule, dict) or rule.get("id") != rule_id:
                    raise ValueError("Unexpected rule metadata ID")
                return rule
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
            http = await stack.enter_async_context(httpx.AsyncClient(headers=headers, timeout=30.0, trust_env=False))
            qr_stream = await stack.enter_async_context(streamable_http_client(url, http_client=http))
            qr = await stack.enter_async_context(ClientSession(qr_stream[0], qr_stream[1]))
            stage = "QRadar MCP initialization"
            await qr.initialize()

            stage = "Vision One Docker MCP startup"
            params = StdioServerParameters(
                command="docker",
                args=["run", "-i", "--rm", "-e", "TREND_VISION_ONE_API_KEY",
                      "ghcr.io/trendmicro/vision-one-mcp-server", "-region", region,
                      "-readonly=true", f"-toolsets={ALERT_TOOLSETS}"],
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
            # Related Workbench alerts get the alert-first Trend depth (deepening.py), bounded to two.
            report = await investigate(RestrictedMCP(qr, QRADAR_READ_TOOLS, qtools, {"get_offense"}, "QRadar"),
                                       RestrictedMCP(vision, ALERT_VISION_TOOLS, vtools,
                                                     WORKBENCH_TOOLS, source="Vision One"), offense_id,
                                       deep=True, ariel_offset_hours=int(os.environ.get("QRADAR_AQL_UTC_OFFSET_HOURS", "-3")),
                                       deepen_alerts=2)
            stage = "MCP connection shutdown"
        return report
    except Exception as exc:
        raise unavailable(stage, exc) from None


async def live_alert_investigation(alert_id: str, url: str, token: str | None,
                                   api_key: str, region: str,
                                   event_evidence: dict[str, str] | None = None,
                                   ariel_offset_hours: int | None = None,
                                   enable_vision_search: bool = True,
                                   timezone_verified: bool = False) -> dict[str, Any]:
    """Investigate one Vision One alert: Workbench, Search/OAT, read-only enrichments and QRadar."""
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
            # Loopback only: never route telemetry/tokens through an environment proxy.
            http = await stack.enter_async_context(httpx.AsyncClient(headers={"SEC": token} if token else {},
                                                                     timeout=30.0, trust_env=False))
            qr_stream = await stack.enter_async_context(streamable_http_client(url, http_client=http))
            qr = await stack.enter_async_context(ClientSession(qr_stream[0], qr_stream[1]))
            stage = "QRadar MCP initialization"
            await qr.initialize()
            stage = "Vision One Docker MCP startup"
            params = StdioServerParameters(
                command="docker",
                args=["run", "-i", "--rm", "-e", "TREND_VISION_ONE_API_KEY",
                      "ghcr.io/trendmicro/vision-one-mcp-server", "-region", region,
                      "-readonly=true", f"-toolsets={ALERT_TOOLSETS}"],
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
                RestrictedMCP(qr, QRADAR_READ_TOOLS, qtools, {"get_offense"}, "QRadar"),
                RestrictedMCP(vision, ALERT_VISION_TOOLS, vtools, {"workbench_alert_detail_get"}, "Vision One"),
                alert_id, event_evidence=event_evidence, ariel_offset_hours=ariel_offset_hours,
                enable_vision_search=enable_vision_search, timezone_verified=timezone_verified)
            stage = "MCP connection shutdown"
        return report
    except Exception as exc:
        raise unavailable(stage, exc) from None


async def live_trend_discovery(parameters: dict[str, Any], api_key: str, region: str) -> dict[str, Any]:
    """Trend-only discovery: no QRadar connection, token or query is needed."""
    import asyncio
    from contextlib import AsyncExitStack
    import os
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    from .trend_discovery import find_alerts, failed, parameters as validate_parameters

    # Validate before Docker starts; bad arguments are distinct from collection failures.
    selection = validate_parameters(**parameters)
    if region not in {"au", "ca", "eu", "id", "in", "jp", "mea", "sg", "uk", "us", "za"}:
        raise ValueError("Unsupported Vision One region")
    if not api_key:
        raise ValueError("TREND_VISION_ONE_API_KEY is required")
    stage = "Vision One Docker MCP startup"
    report = None
    try:
        async with asyncio.timeout(60):
            async with AsyncExitStack() as stack:
                params = StdioServerParameters(command="docker", args=["run", "-i", "--rm", "-e",
                    "TREND_VISION_ONE_API_KEY", "ghcr.io/trendmicro/vision-one-mcp-server", "-region", region,
                    "-readonly=true", "-toolsets=workbench"],
                    env={**os.environ, "TREND_VISION_ONE_API_KEY": api_key})
                stream = await stack.enter_async_context(stdio_client(params))
                session = await stack.enter_async_context(ClientSession(stream[0], stream[1]))
                stage = "Vision One MCP initialization"
                await session.initialize()
                stage = "Vision One MCP tool listing"
                available = {t.name for t in (await session.list_tools()).tools}
                client = RestrictedMCP(session, {"workbench_alerts_list"}, available, set(), "Vision One")
                stage = "Vision One Workbench listing"
                report = await find_alerts(client, **{k: selection[k] for k in
                    ("status", "severity", "start_date_time", "end_date_time", "limit")})
                report["selection"]["default_window"] = selection["default_window"]
                stage = "Vision One MCP shutdown"
        return report
    except Exception as exc:
        if report is not None:
            report["shutdown_error"] = failed(stage, exc)["error"]
            return report
        return {"selection": selection, **failed(stage, exc),
                "mcp_tool_call_attempted": None if stage == "Vision One Workbench listing" else False}


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
            q = RestrictedMCP(qr, QRADAR_READ_TOOLS, qtools,
                              {"validate_aql", "create_ariel_search", "get_ariel_search_status", "get_ariel_search_results"}, "QRadar")
            v = RestrictedMCP(vision, VISION_TOOLS, vtools, {"search_detections_list"}, "Vision One")
            stage = "EPM UAC / FortiGate evidence collection"
            if kind == "epm":
                return await investigate_epm_uac(q, v, **parameters)
            return await investigate_web_reputation(q, v, **parameters)
    except Exception as exc:
        raise unavailable(stage, exc) from None
