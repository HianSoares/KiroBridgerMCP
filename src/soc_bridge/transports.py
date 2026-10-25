"""Narrow, read-only MCP clients. Imported only in live mode."""

from __future__ import annotations

import json
import re
from typing import Any

from .capabilities import GLOBAL_LEDGER, Ledger, outcome_for, tool_names
from .diagnostics import MCPToolFailure, collection_failure, failure_reason, unavailable
from .connection_lifecycle import InvestigationConnections
from .alert_resume import ALERT_READ_CACHE
from .trend_search import DIRECT_SEARCH_TOOLS
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
ALERT_VISION_TOOLS = VISION_TOOLS | ALERT_ENRICHMENT_TOOLS | set(DIRECT_SEARCH_TOOLS)
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
                 required: set[str] | None = None, source: str = "MCP", ledger: Ledger | None = None, read_state=None):
        self.session = session
        self.allowed = allowed
        self.available = available
        self.source = source
        self.ledger = GLOBAL_LEDGER
        self.run_ledger = ledger
        self.read_state = read_state
        discovery = getattr(available, "discovery", None)
        missing = (required if required is not None else allowed) - available
        if missing and discovery is not None and not discovery.complete:
            # A partial tools/list never proves absence.
            raise RuntimeError(f"Availability of required read tools unknown: tools/list discovery incomplete "
                               f"({discovery.stop_reason}): {', '.join(sorted(missing))}")
        if missing:
            raise RuntimeError(f"MCP server is missing expected read tools: {', '.join(sorted(missing))}")

    async def call(self, name: str, arguments: dict[str, Any]) -> Any:
        if name not in self.allowed:
            raise ValueError(f"Tool not permitted: {name}")
        if name not in self.available:
            discovery = getattr(self.available, "discovery", None)
            if discovery is not None and not discovery.complete:
                raise RuntimeError(f"Optional MCP tool availability unknown: {name}")
            raise RuntimeError(f"Optional MCP tool unavailable: {name}")
        if self.read_state is not None:
            reused, value = self.read_state.get(self.source, name, arguments)
            if reused:
                from .ariel_collection import ACTIVE_READ_BUDGET
                active = ACTIVE_READ_BUDGET.get()
                if active is not None:
                    active[0].reuse_read(active[1])
                if self.run_ledger is not None:
                    self.run_ledger.record(name, "reused_read")
                return value
        try:
            value = await self._call(name, arguments)
        except Exception as exc:
            from .aql_errors import classify_failure
            outcome = outcome_for(classify_failure(exc)["category"])
            self.ledger.record(name, outcome)
            if self.run_ledger is not None:
                self.run_ledger.record(name, outcome)
            raise
        self.ledger.record(name, "tested_ok")
        if self.run_ledger is not None:
            self.run_ledger.record(name, "tested_ok")
        if self.read_state is not None:
            self.read_state.put(self.source, name, arguments, value)
        return value

    async def _call(self, name: str, arguments: dict[str, Any]) -> Any:
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
    from urllib.parse import urlparse
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client
    import httpx
    from .aql_search import validate_query, start_query, search_status, search_results, run_query
    from .offense_evidence import verify_offense
    from .offense_batch import find_offenses, investigate_offenses
    from .offense_priority import list_offenses

    parsed = urlparse(url)
    if (parsed.scheme != "http" or parsed.hostname not in ("localhost", "127.0.0.1", "::1")
            or parsed.path != "/mcp" or parsed.username or parsed.password or parsed.query or parsed.fragment):
        raise ValueError("QRadar MCP URL must be a local http://127.0.0.1:<port>/mcp endpoint")
    from .qradar_context import assess_closure, context_lookup
    operations = {"validate": validate_query, "start": start_query, "status": search_status,
                  "results": search_results, "run": run_query, "verify_offense": verify_offense,
                  "find_offenses": find_offenses, "investigate_offenses": investigate_offenses,
                  "list_offenses": list_offenses,
                  "context": context_lookup, "assess_closure": assess_closure}
    if operation not in {*operations, "resource", "rule"}:
        raise ValueError("Unknown QRadar query operation")
    required = {"validate": {"validate_aql"},
                "start": {"validate_aql", "create_ariel_search"},
                "status": {"get_ariel_search_status"},
                "results": {"get_ariel_search_status", "get_ariel_search_results"},
                "run": {"validate_aql", "create_ariel_search", "get_ariel_search_status", "get_ariel_search_results"},
                "find_offenses": {"list_offenses"}, "list_offenses": {"list_offenses"},
                "investigate_offenses": {"get_offense"},
                "resource": set(), "verify_offense": {"get_offense"}, "rule": {"get_rule"},
                "context": set(), "assess_closure": {"get_offense"}}[operation]
    stage = "QRadar MCP connection"
    try:
        async with InvestigationConnections() as stack:
            # This is always loopback: never route telemetry/tokens through an environment proxy.
            http = await stack.enter(httpx.AsyncClient(headers={"SEC": token} if token else {}, timeout=30.0, trust_env=False), "QRadar", "HTTP client")
            stream = await stack.enter(streamable_http_client(url, http_client=http), "QRadar", "Streamable HTTP transport")
            session = await stack.enter(ClientSession(stream[0], stream[1]), "QRadar", "MCP session")
            stage = "QRadar MCP initialization"
            await session.initialize()
            stage = "QRadar MCP tool listing"
            available = await tool_names(session, "QRadar")
            client = RestrictedMCP(session, QRADAR_READ_TOOLS, available, required, "QRadar")
            stage = f"QRadar AQL {operation}"
            if operation == "resource":
                report = await client.read_aql_resource(**parameters)
            elif operation == "rule":
                rule_id = parameters.get("rule_id")
                if isinstance(rule_id, bool) or not isinstance(rule_id, int) or rule_id < 0:
                    raise ValueError("rule_id must be a nonnegative integer")
                rule = await client.call("get_rule", {"rule_id": rule_id})
                if not isinstance(rule, dict) or rule.get("id") != rule_id:
                    raise ValueError("Unexpected rule metadata ID")
                report = rule
            else:
                report = await operations[operation](client, **parameters)
            stack.collected(report)
            stage = "QRadar MCP connection shutdown"
        return stack.deliver(report)
    except (ValueError, MCPToolFailure):
        raise
    except Exception as exc:
        raise MCPToolFailure("QRadar", operation, f"{stage}: {failure_reason(exc)}") from None


async def live_investigation(offense_id: int, url: str, token: str | None,
                             api_key: str, region: str) -> dict[str, Any]:
    """QRadar Streamable HTTP on loopback + local Vision One stdio container."""
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
        async with InvestigationConnections() as stack:
            http = await stack.enter(httpx.AsyncClient(headers=headers, timeout=30.0, trust_env=False), "QRadar", "HTTP client")
            qr_stream = await stack.enter(streamable_http_client(url, http_client=http), "QRadar", "Streamable HTTP transport")
            qr = await stack.enter(ClientSession(qr_stream[0], qr_stream[1]), "QRadar", "MCP session")
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
            v_stream = await stack.enter(stdio_client(params), "Vision One", "Docker stdio transport")
            vision = await stack.enter(ClientSession(v_stream[0], v_stream[1]), "Vision One", "MCP session")
            stage = "Vision One MCP initialization"
            await vision.initialize()
            stage = "QRadar MCP tool listing"
            qtools = await tool_names(qr, "QRadar")
            stage = "Vision One MCP tool listing"
            vtools = await tool_names(vision, "Vision One")
            stage = "offense evidence collection"
            # Related Workbench alerts get the alert-first Trend depth (deepening.py), bounded to two.
            report = await investigate(RestrictedMCP(qr, QRADAR_READ_TOOLS, qtools, {"get_offense"}, "QRadar"),
                                       RestrictedMCP(vision, ALERT_VISION_TOOLS, vtools,
                                                     WORKBENCH_TOOLS, source="Vision One"), offense_id,
                                       deep=True, ariel_offset_hours=int(os.environ.get("QRADAR_AQL_UTC_OFFSET_HOURS", "-3")),
                                       deepen_alerts=2)
            stack.collected(report)
            stage = "MCP connection shutdown"
        return stack.deliver(report)
    except Exception as exc:
        raise unavailable(stage, exc) from None


async def live_case_investigation(offense_id: int, url: str, token: str | None, api_key: str, region: str,
                                 case_id: str = "", offset_hours: int = -3, timezone_verified: bool = False,
                                 include_trend: bool = True, rerun_queries: list[str] | None = None) -> dict[str, Any]:
    """Persisted, resumable offense case. Trend is used when a key and Docker are available;
    otherwise the case records Vision One as not configured instead of failing."""
    import os
    import shutil
    from urllib.parse import urlparse
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    from mcp.client.streamable_http import streamable_http_client
    import httpx
    from .case_investigation import investigate_offense_case

    parsed = urlparse(url)
    if parsed.scheme != "http" or parsed.hostname not in ("localhost", "127.0.0.1", "::1") or parsed.path != "/mcp":
        raise ValueError("QRadar MCP URL must be a local http://127.0.0.1:<port>/mcp endpoint")
    use_trend = bool(include_trend and api_key and shutil.which("docker"))
    if use_trend and region not in {"au", "ca", "eu", "id", "in", "jp", "mea", "sg", "uk", "us", "za"}:
        raise ValueError("Unsupported Vision One region")
    stage = "QRadar MCP connection"
    try:
        async with InvestigationConnections() as stack:
            http = await stack.enter(httpx.AsyncClient(headers={"SEC": token} if token else {},
                                                                     timeout=30.0, trust_env=False), "QRadar", "HTTP client")
            qr_stream = await stack.enter(streamable_http_client(url, http_client=http), "QRadar", "Streamable HTTP transport")
            qr = await stack.enter(ClientSession(qr_stream[0], qr_stream[1]), "QRadar", "MCP session")
            stage = "QRadar MCP initialization"
            await qr.initialize()
            stage = "QRadar MCP tool discovery"
            qtools = await tool_names(qr, "QRadar")
            capabilities = {"qradar": qtools.discovery.describe(QRADAR_READ_TOOLS)}
            vision = None
            if use_trend:
                # Vision One is a secondary source here: its failure is recorded, the QRadar case continues.
                trend_stage = "Vision One Docker MCP startup"
                try:
                    params = StdioServerParameters(command="docker", args=[
                        "run", "-i", "--rm", "-e", "TREND_VISION_ONE_API_KEY", "ghcr.io/trendmicro/vision-one-mcp-server",
                        "-region", region, "-readonly=true", f"-toolsets={ALERT_TOOLSETS}"],
                        env={**os.environ, "TREND_VISION_ONE_API_KEY": api_key})
                    v_stream = await stack.enter(stdio_client(params), "Vision One", "Docker stdio transport")
                    vsession = await stack.enter(ClientSession(v_stream[0], v_stream[1]), "Vision One", "MCP session")
                    trend_stage = "Vision One MCP initialization"
                    await vsession.initialize()
                    trend_stage = "Vision One MCP tool discovery"
                    vtools = await tool_names(vsession, "Vision One")
                    capabilities["vision_one"] = vtools.discovery.describe(ALERT_VISION_TOOLS)
                    vision = RestrictedMCP(vsession, ALERT_VISION_TOOLS, vtools, WORKBENCH_TOOLS, source="Vision One")
                except Exception as exc:
                    capabilities["vision_one"] = {"state": "unavailable", "stage": trend_stage,
                                                  "category": failure_reason(exc),
                                                  "next_action": "Run bridge_diagnostics with check_trend=true"}
            else:
                capabilities["vision_one"] = {"state": "not_used", "reason": "include_trend disabled, key absent or Docker missing"}
            stage = "case investigation"
            report = await investigate_offense_case(
                RestrictedMCP(qr, QRADAR_READ_TOOLS, qtools, {"get_offense"}, "QRadar"), vision, offense_id,
                case_id=case_id, offset_hours=offset_hours, timezone_verified=timezone_verified,
                include_trend=include_trend, rerun_queries=rerun_queries, capabilities=capabilities)
            report["capabilities"]["call_outcomes"] = GLOBAL_LEDGER.describe()
            stack.collected(report)
            stage = "MCP connection shutdown"
        return stack.deliver(report)
    except (ValueError, MCPToolFailure):
        raise
    except Exception as exc:
        raise unavailable(stage, exc) from None


async def live_alert_investigation(alert_id: str, url: str, token: str | None,
                                   api_key: str, region: str,
                                   event_evidence: dict[str, str] | None = None,
                                   ariel_offset_hours: int | None = None,
                                   enable_vision_search: bool = True,
                                   timezone_verified: bool = False) -> dict[str, Any]:
    """Resume an alert's reads/jobs in this bridge process, isolated by credentials and scope."""
    identity = [url, token, api_key, region, alert_id, event_evidence, ariel_offset_hours,
                enable_vision_search, timezone_verified]
    async with ALERT_READ_CACHE.session(identity) as state:
        return await _live_alert_investigation(
            alert_id, url, token, api_key, region, event_evidence, ariel_offset_hours,
            enable_vision_search, timezone_verified, read_state=state)


async def _live_alert_investigation(alert_id: str, url: str, token: str | None,
                                   api_key: str, region: str,
                                   event_evidence: dict[str, str] | None = None,
                                   ariel_offset_hours: int | None = None,
                                   enable_vision_search: bool = True,
                                   timezone_verified: bool = False, read_state=None) -> dict[str, Any]:
    """Investigate one Vision One alert: Workbench, Search/OAT, read-only enrichments and QRadar."""
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

    run_ledger = Ledger()
    stage = "Vision One Docker MCP startup"
    try:
        async with InvestigationConnections() as stack:
            # The requested alert is the primary source. An unavailable secondary
            # QRadar must not prevent collection of independent Trend evidence.
            params = StdioServerParameters(
                command="docker",
                args=["run", "-i", "--rm", "-e", "TREND_VISION_ONE_API_KEY",
                      "ghcr.io/trendmicro/vision-one-mcp-server", "-region", region,
                      "-readonly=true", f"-toolsets={ALERT_TOOLSETS}"],
                env={**os.environ, "TREND_VISION_ONE_API_KEY": api_key},
            )
            v_stream = await stack.enter(stdio_client(params), "Vision One", "Docker stdio transport")
            vision = await stack.enter(ClientSession(v_stream[0], v_stream[1]), "Vision One", "MCP session")
            stage = "Vision One MCP initialization"
            await vision.initialize()
            stage = "Vision One MCP tool listing"
            vtools = await tool_names(vision, "Vision One")
            vclient = RestrictedMCP(vision, ALERT_VISION_TOOLS, vtools, {"workbench_alert_detail_get"},
                                    "Vision One", ledger=run_ledger, read_state=read_state)
            qr_ready = False
            qr_error = None
            try:
                async with InvestigationConnections() as qr_stack:
                    stage = "QRadar MCP connection"
                    http = await qr_stack.enter(httpx.AsyncClient(headers={"SEC": token} if token else {},
                        timeout=30.0, trust_env=False), "QRadar", "HTTP client")
                    stream = await qr_stack.enter(streamable_http_client(url, http_client=http),
                                                  "QRadar", "Streamable HTTP transport")
                    qr = await qr_stack.enter(ClientSession(stream[0], stream[1]), "QRadar", "MCP session")
                    stage = "QRadar MCP initialization"
                    await qr.initialize()
                    stage = "QRadar MCP tool listing"
                    qtools = await tool_names(qr, "QRadar")
                    qclient = RestrictedMCP(qr, QRADAR_READ_TOOLS, qtools, {"get_offense"},
                                            "QRadar", ledger=run_ledger, read_state=read_state)
                    qr_ready = True
                    stage = "Vision One Workbench alert retrieval and QRadar evidence collection"
                    report = await investigate_vision_alert(
                        qclient, vclient, alert_id, event_evidence=event_evidence,
                        ariel_offset_hours=ariel_offset_hours, enable_vision_search=enable_vision_search,
                        timezone_verified=timezone_verified, now=read_state.now if read_state else None,
                        query_state=read_state.queries if read_state else None)
                    qr_stack.collected(report)
            except Exception as exc:
                if qr_ready:
                    raise  # Primary collection failures are not QRadar startup failures.
                qr_error = collection_failure(stage, MCPToolFailure("QRadar", stage, failure_reason(exc)))
            if not qr_ready:
                if qr_error is None:
                    # An SDK cancel scope may suppress its internal cancellation
                    # after a transport failure. Preserve that positive diagnostic.
                    reason = (qr_stack.errors[-1]["reason"] if qr_stack.errors else
                              "QRadar initialization did not return a session")
                    qr_error = collection_failure(stage, MCPToolFailure("QRadar", stage, reason))
                if qr_stack.errors:
                    qr_error["connection_shutdown_errors"] = list(qr_stack.errors)
                # The failed QRadar resources have been closed in their original
                # task before the primary Trend collection continues.
                stage = "Vision One evidence collection (QRadar unavailable)"
                report = await investigate_vision_alert(
                    None, vclient, alert_id, event_evidence=event_evidence,
                    ariel_offset_hours=ariel_offset_hours, enable_vision_search=enable_vision_search,
                    timezone_verified=timezone_verified, now=read_state.now if read_state else None,
                    query_state=read_state.queries if read_state else None,
                    qradar_correlation=False, qradar_unavailable=qr_error)
            from datetime import datetime, timezone
            from .core import iso
            resumed_at = iso(datetime.now(timezone.utc))
            report["generated_at"] = resumed_at
            if report.get("clocks"):
                report["clocks"]["collected_at"] = resumed_at
            report["resumption"] = {"snapshot_started_at": iso(read_state.now) if read_state else resumed_at,
                                    "resumed_at": resumed_at, "scope": "same alert, credentials and parameters in this running bridge",
                                    "ttl_seconds": 900, "durable": False,
                                    "note": "Read snapshot anchored to the first run; restart/expiry/eviction clears it. "
                                            "Use returned search IDs/cursors to resume after that; do not blindly recreate jobs."}
            report["call_outcomes"] = run_ledger.describe()
            report["call_outcomes"]["scope"] = "this alert investigation only"
            stack.collected(report)
            stage = "MCP connection shutdown"
        return stack.deliver(qr_stack.deliver(report) if qr_ready else report)
    except Exception as exc:
        raise unavailable(stage, exc) from None


async def live_trend_search(operation: str, parameters: dict[str, Any], api_key: str, region: str) -> dict[str, Any]:
    """Search/catalog through Trend alone; never connects QRadar or requires a Workbench ID."""
    import os
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    from .ariel_collection import Budget
    from .trend_search import collect, failed, parameters as validate, resource, validate_source

    if operation not in {"search", "resource"}:
        raise ValueError("Unknown Trend Search operation")
    selection = validate(**parameters) if operation == "search" else {"source": parameters.get("source", "endpoint")}
    validate_source(selection["source"])
    if region not in {"au", "ca", "eu", "id", "in", "jp", "mea", "sg", "uk", "us", "za"}:
        raise ValueError("Unsupported Vision One region")
    if not api_key:
        raise ValueError("TREND_VISION_ONE_API_KEY is required")
    budget = Budget(max_seconds=60, max_calls=selection.get("max_calls", 12),
                    max_partitions=selection.get("max_calls", 12), max_records=selection.get("limit", 1000))
    ledger = Ledger()
    report = None
    stage = "Vision One Search Docker startup"
    try:
        async with InvestigationConnections() as stack:
            params = StdioServerParameters(command="docker", args=["run", "-i", "--rm", "-e",
                "TREND_VISION_ONE_API_KEY", "ghcr.io/trendmicro/vision-one-mcp-server", "-region", region,
                "-readonly=true", "-toolsets=search"], env={**os.environ, "TREND_VISION_ONE_API_KEY": api_key})
            stream = await stack.enter(stdio_client(params), "Vision One", "Docker stdio transport")
            session = await stack.enter(ClientSession(stream[0], stream[1]), "Vision One", "MCP session")
            stage = "Vision One Search MCP initialization"
            await budget.run(session.initialize, stage)
            stage = "Vision One Search tool listing"
            available = await budget.run(lambda: tool_names(session, "Vision One"), stage)
            if operation == "resource":
                report = resource(selection["source"], available)
            else:
                client = RestrictedMCP(session, set(DIRECT_SEARCH_TOOLS), available, set(), "Vision One", ledger=ledger)
                report = {}
                stage = "Vision One Search collection"
                await collect(client, selection, budget=budget, report=report)
            report["call_outcomes"] = ledger.describe()
            report["call_outcomes"]["scope"] = "this Trend Search call only"
            stack.collected(report)
            stage = "Vision One Search shutdown"
        if report is None:
            raise RuntimeError("Vision One Search initialization did not return")
        return stack.deliver(report)
    except Exception as exc:
        if report is not None:
            report.setdefault("errors", []).append(collection_failure(stage, exc))
            report.update(outcome="partial", result_set_complete=False,
                          returned_records=len(report.get("records", [])),
                          any_matching_record=True if report.get("records") else None)
            report["budget"] = budget.describe()
            return report
        return failed(stage, MCPToolFailure("Vision One", stage, failure_reason(exc)), selection)


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
                available = await tool_names(session, "Vision One")
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
        async with InvestigationConnections() as stack:
            http = await stack.enter(httpx.AsyncClient(headers={"SEC": token} if token else {}, timeout=30.0, trust_env=False), "QRadar", "HTTP client")
            stream = await stack.enter(streamable_http_client(url, http_client=http), "QRadar", "Streamable HTTP transport")
            qr = await stack.enter(ClientSession(stream[0], stream[1]), "QRadar", "MCP session")
            stage = "QRadar MCP initialization"
            await qr.initialize()
            stage = "Vision One Docker MCP startup"
            params = StdioServerParameters(command="docker", args=["run", "-i", "--rm", "-e", "TREND_VISION_ONE_API_KEY",
                "ghcr.io/trendmicro/vision-one-mcp-server", "-region", region, "-readonly=true", "-toolsets=search,endpoint"],
                env={**os.environ, "TREND_VISION_ONE_API_KEY": api_key})
            v_stream = await stack.enter(stdio_client(params), "Vision One", "Docker stdio transport")
            vision = await stack.enter(ClientSession(v_stream[0], v_stream[1]), "Vision One", "MCP session")
            stage = "Vision One MCP initialization"
            await vision.initialize()
            stage = "read-only tool listing"
            qtools = await tool_names(qr, "QRadar")
            vtools = await tool_names(vision, "Vision One")
            q = RestrictedMCP(qr, QRADAR_READ_TOOLS, qtools,
                              {"validate_aql", "create_ariel_search", "get_ariel_search_status", "get_ariel_search_results"}, "QRadar")
            v = RestrictedMCP(vision, VISION_TOOLS, vtools, {"search_detections_list"}, "Vision One")
            stage = "EPM UAC / FortiGate evidence collection"
            if kind == "epm":
                report = await investigate_epm_uac(q, v, **parameters)
            else:
                report = await investigate_web_reputation(q, v, **parameters)
            stack.collected(report)
            stage = "MCP connection shutdown"
        return stack.deliver(report)
    except Exception as exc:
        raise unavailable(stage, exc) from None
