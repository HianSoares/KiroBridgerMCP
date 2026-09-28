"""Local read-only MCP server: Kiro reasons over the investigation report."""

from __future__ import annotations

import os

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from .core import investigate, render_markdown
from .alert_investigation import render_alert_markdown
from .demo import DemoQRadar, DemoVision
from .transports import live_investigation, live_alert_investigation, live_extra_case


mcp = FastMCP("SOC Bridge Investigator")


@mcp.tool(annotations=ToolAnnotations(read_only_hint=True))
async def investigate_case(reference: str) -> str:
    """Investigate by ID alone: QRadar offense number or Vision One WB alert ID.

    Discovers only bounded read-only pivots from both platforms. Candidate
    detections are explicitly labelled when Workbench omits View event fields.
    """
    ref = reference.strip()
    if ref.isascii() and ref.isdecimal() and ref[0:1] != "0":
        return await investigate_offense(int(ref))
    if ref.startswith("WB-"):
        return await investigate_vision_alert(ref)
    raise ValueError("Use a positive numeric QRadar offense ID or exact WB- alert ID")


@mcp.tool(annotations=ToolAnnotations(read_only_hint=True))
async def investigate_offense(offense_id: int) -> str:
    """Read offense, bounded Ariel events and Vision One Workbench/Search evidence.

    Only accepts positive offense IDs. Calls read-only tools in both upstream MCP
    servers, then returns a bounded report. A network match is a candidate,
    not a proof of the same process or an automatic verdict.
    """
    if offense_id < 1:
        raise ValueError("offense_id must be positive")
    report = await live_investigation(
        offense_id,
        os.environ.get("QRADAR_MCP_URL", "http://127.0.0.1:5001/mcp"),
        os.environ.get("QRADAR_MCP_TOKEN"),
        os.environ.get("TREND_VISION_ONE_API_KEY", ""),
        os.environ.get("TREND_VISION_ONE_REGION", "us"),
    )
    return render_markdown(report)


@mcp.tool(annotations=ToolAnnotations(read_only_hint=True))
async def investigate_vision_alert(alert_id: str) -> str:
    """Read a Vision One alert, discover candidate entities, and query QRadar.

    Uses bounded read-only detection/endpoint searches when the Workbench alert
    detail omits View event entities. A candidate is not a verified alert event.
    """
    report = await live_alert_investigation(
        alert_id,
        os.environ.get("QRADAR_MCP_URL", "http://127.0.0.1:5001/mcp"),
        os.environ.get("QRADAR_MCP_TOKEN"),
        os.environ.get("TREND_VISION_ONE_API_KEY", ""),
        os.environ.get("TREND_VISION_ONE_REGION", "us"),
        ariel_offset_hours=int(os.environ.get("QRADAR_AQL_UTC_OFFSET_HOURS", "-3")),
    )
    return render_alert_markdown(report)


@mcp.tool(annotations=ToolAnnotations(read_only_hint=True))
async def investigate_vision_event(alert_id: str, endpoint_ip: str, event_time: str,
                                   endpoint_host: str = "", file_hash: str = "",
                                   file_path: str = "", process_path: str = "",
                                   qradar_utc_offset_hours: int = -3) -> str:
    """Correlate analyst-copied Vision One View event fields with QRadar offense indexes.

    Requires exact event IP and ISO-8601 timestamp. The supplied event fields
    are labeled manual and are not independently verified by the MCP server.
    Runs bounded Ariel event searches when the upstream tools are available.
    qradar_utc_offset_hours is the QRadar console's offset from UTC (for
    example -3 in Brazil). Never performs a response action.
    """
    evidence = {"endpoint_ip": endpoint_ip, "event_time": event_time,
                "endpoint_host": endpoint_host, "file_hash": file_hash,
                "file_path": file_path, "process_path": process_path}
    report = await live_alert_investigation(
        alert_id,
        os.environ.get("QRADAR_MCP_URL", "http://127.0.0.1:5001/mcp"),
        os.environ.get("QRADAR_MCP_TOKEN"),
        os.environ.get("TREND_VISION_ONE_API_KEY", ""),
        os.environ.get("TREND_VISION_ONE_REGION", "us"), event_evidence=evidence,
        ariel_offset_hours=qradar_utc_offset_hours,
    )
    return render_alert_markdown(report)


@mcp.tool(annotations=ToolAnnotations(read_only_hint=True))
async def investigate_epm_uac(last_event_id: str, last_event_date: str,
                              endpoint_host: str = "", qradar_utc_offset_hours: int = -3) -> str:
    """Locate one EPM_API UacAudit by lastEventId/time, then seek cautious Trend candidates.

    If the EPM payload lacks lastEventComputerName, a verified hostname can be
    supplied explicitly. Filename alone never identifies the attempted binary.
    """
    return await live_extra_case("epm", {"event_id": last_event_id, "occurred_at": last_event_date,
        "endpoint_host": endpoint_host, "offset": qradar_utc_offset_hours},
        os.environ.get("QRADAR_MCP_URL", "http://127.0.0.1:5001/mcp"),
        os.environ.get("QRADAR_MCP_TOKEN"), os.environ.get("TREND_VISION_ONE_API_KEY", ""),
        os.environ.get("TREND_VISION_ONE_REGION", "us"))


@mcp.tool(annotations=ToolAnnotations(read_only_hint=True))
async def investigate_web_reputation(url_or_domain: str, event_time: str,
                                     endpoint_ip: str = "", qradar_utc_offset_hours: int = -3,
                                     endpoint_host: str = "", endpoint_guid: str = "",
                                     event_id: str = "") -> str:
    """Compare one Trend web-reputation URL/domain with FortiGate logs in QRadar.

    Supply domain and timestamp with explicit timezone from a single event.
    With event UUID and hostname, try to discover endpoint IP in Vision One;
    GUID improves attribution. An explicit endpoint IP remains optional.
    Inventory IPs are current only, never proof of historical traffic.
    No block rule, network message, or response action is performed.
    """
    return await live_extra_case("web", {"url_or_domain": url_or_domain, "event_time": event_time,
        "endpoint_ip": endpoint_ip, "offset": qradar_utc_offset_hours,
        "endpoint_host": endpoint_host, "endpoint_guid": endpoint_guid, "event_id": event_id},
        os.environ.get("QRADAR_MCP_URL", "http://127.0.0.1:5001/mcp"),
        os.environ.get("QRADAR_MCP_TOKEN"), os.environ.get("TREND_VISION_ONE_API_KEY", ""),
        os.environ.get("TREND_VISION_ONE_REGION", "us"))


@mcp.tool(annotations=ToolAnnotations(read_only_hint=True))
async def investigate_demo() -> str:
    """Return a fabricated QRadar and Vision One investigation, no credentials needed."""
    return render_markdown(await investigate(DemoQRadar(), DemoVision(), 1842))


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
