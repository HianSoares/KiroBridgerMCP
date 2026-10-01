"""Deterministic correlation and reporting; no network or LLM dependencies."""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol


class ToolCaller(Protocol):
    async def call(self, name: str, arguments: dict[str, Any]) -> Any: ...


def records(value: Any) -> list[dict[str, Any]]:
    """Handle common MCP/API envelopes without treating an error as empty data."""
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    if isinstance(value, dict):
        for key in ("items", "data", "results", "alerts"):
            if key in value:
                return records(value[key])
    raise ValueError("Unexpected list response shape; inspect the server response")


def address(value: Any) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def instant(value: Any) -> datetime | None:
    if isinstance(value, (int, float)):
        if value > 1e11:
            value /= 1000
        try:
            return datetime.fromtimestamp(value, timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def iso(dt: datetime | None) -> str | None:
    return dt.isoformat(timespec="seconds") if dt else None


def window(offense: dict[str, Any]) -> tuple[datetime | None, datetime | None]:
    start = next((instant(offense.get(k)) for k in ("start_time", "first_event_flow_seen") if instant(offense.get(k))), None)
    end = next((instant(offense.get(k)) for k in ("last_updated_time", "last_event_flow_seen") if instant(offense.get(k))), None)
    if start and not end:
        end = start
    if end and not start:
        start = end
    return (start - timedelta(hours=1) if start else None,
            end + timedelta(hours=1) if end else None)


@dataclass
class Evidence:
    alert_id: str
    name: str
    severity: str
    created_at: str | None
    indicators: list[str]
    match_fields: list[str]
    temporal_check: str
    score: int
    detail: dict[str, Any]


def _escape_filter(value: str) -> str:
    # This is defense in depth; only parsed IP addresses are accepted above.
    return value.replace("'", "''")


async def investigate(qradar: ToolCaller, vision: ToolCaller, offense_id: int,
                      max_indicators: int = 8, max_alerts: int = 20,
                      deep: bool = False, ariel_offset_hours: int = -3) -> dict[str, Any]:
    """Use read-only MCP tools. No changes to either security platform."""
    if offense_id < 1 or not 1 <= max_indicators <= 30 or not 1 <= max_alerts <= 100:
        raise ValueError("Invalid investigation limits")
    offense = await qradar.call("get_offense", {"offense_id": offense_id})
    if not isinstance(offense, dict) or str(offense.get("id")) != str(offense_id):
        raise ValueError("QRadar returned an offense with an unexpected ID or shape")

    warnings: list[str] = []
    ips: set[str] = set()
    for key in ("offense_source", "source_ip", "local_destination_ip"):
        found = address(offense.get(key))
        if found:
            ips.add(found)
    # IBM's address-list tools expose offense_ids. Query with a bounded range;
    # never silently claim completeness when a query fails or limits are hit.
    for tool, ip_field in (("list_source_addresses", "source_ip"),
                           ("list_local_destination_addresses", "local_destination_ip")):
        try:
            response = await qradar.call(tool, {"filter": f"offense_ids contains {offense_id}", "limit": 100})
            rows = records(response)
            if len(rows) == 100:
                warnings.append(f"{tool}: 100-row cap reached; address coverage may be incomplete")
            for row in rows:
                if offense_id in row.get("offense_ids", []):
                    found = address(row.get(ip_field))
                    if found:
                        ips.add(found)
        except Exception as exc:
            warnings.append(f"{tool} unavailable: {type(exc).__name__}; address coverage is partial")

    chosen = sorted(ips)[:max_indicators]
    if len(ips) > len(chosen):
        warnings.append(f"Indicator cap reached: checked {len(chosen)} of {len(ips)} IPs")
    begin, end = window(offense)
    if begin is None:
        warnings.append("QRadar offense has no usable time; Vision One search has no time bounds")

    candidates: dict[str, dict[str, Any]] = {}
    for ip in chosen:
        for field in ("indicatorValue", "impactScopeEntityValue"):
            query: dict[str, Any] = {"filter": f"{field} eq '{_escape_filter(ip)}'"}
            if begin:
                query["startDateTime"] = iso(begin)
                query["endDateTime"] = iso(end)
            try:
                response = await vision.call("workbench_alerts_list", query)
                alerts = records(response)
            except Exception as exc:
                warnings.append(f"Vision One Workbench {field}={ip} unavailable ({type(exc).__name__}); coverage partial")
                continue
            # Some Vision One responses are paginated; this MVP intentionally
            # never follows untrusted next URLs or reports an exhaustive search.
            if isinstance(response, dict) and (response.get("nextLink") or response.get("next")):
                warnings.append(f"Vision One has more results for {field}={ip}; only first page inspected")
            for alert in alerts:
                alert_id = alert.get("id")
                if not alert_id:
                    continue
                key = str(alert_id)
                entry = candidates.setdefault(key, {"summary": alert, "matched": set(), "ips": set()})
                entry["matched"].add(field)
                entry["ips"].add(ip)
            if len(candidates) >= max_alerts:
                warnings.append("Alert cap reached; later indicators were not investigated")
                break
        if len(candidates) >= max_alerts:
            break

    evidence: list[Evidence] = []
    for alert_id, entry in list(candidates.items())[:max_alerts]:
        detail = await vision.call("workbench_alert_detail_get", {"alertId": alert_id})
        if not isinstance(detail, dict):
            warnings.append(f"Alert {alert_id}: detail response unavailable; summary used")
            detail = entry["summary"]
        created = instant(detail.get("createdDateTime") or entry["summary"].get("createdDateTime"))
        temporal = "unknown"
        if begin and created:
            temporal = "within window" if begin <= created <= end else "outside window"
        severity = str(detail.get("severity") or entry["summary"].get("severity") or "unknown")
        # This is an investigation ranking, not a probability or verdict.
        score = (20 + (20 if len(entry["matched"]) == 2 else 0)
                 + (20 if temporal == "within window" else 0)
                 + (10 if severity.lower() in ("high", "critical") else 0))
        evidence.append(Evidence(alert_id, str(detail.get("name") or entry["summary"].get("name") or "Unnamed alert"),
                                 severity, iso(created), sorted(entry["ips"]), sorted(entry["matched"]),
                                 temporal, score, detail))
    evidence.sort(key=lambda x: (-x.score, x.alert_id))
    if not evidence:
        warnings.append("No matching Workbench alert returned in the inspected results; this does not prove absence of activity")
    report = {
        "generated_at": iso(datetime.now(timezone.utc)),
        "offense": offense,
        "searched_ips": chosen,
        "search_window": {"start": iso(begin), "end": iso(end)},
        "alerts": [e.__dict__ for e in evidence],
        "warnings": list(dict.fromkeys(warnings)),
        "method": "Exact IP server-side filters; one hour padding; bounded first-page results; read-only MCP calls",
    }
    if deep:
        from .offense_context import collect_offense_context
        report["offense_context"] = await collect_offense_context(
            qradar, vision, offense, chosen, ariel_offset_hours)
    return report


def render_markdown(report: dict[str, Any]) -> str:
    offense = report["offense"]
    lines = [f"# Investigation of QRadar offense {offense['id']}", "",
             f"Generated (UTC): {report['generated_at']}",
             f"QRadar summary: {offense.get('description') or 'No description'}", "",
             "## Scope and method", "",
             f"Searched IPs: {', '.join(report['searched_ips']) or 'none'}",
             f"Window: {report['search_window']['start'] or 'unbounded'} to {report['search_window']['end'] or 'unbounded'}",
             report["method"], "", "## Vision One leads", ""]
    if not report["alerts"]:
        lines.append("No matching alert in the inspected results.")
    for alert in report["alerts"]:
        lines.extend([f"### {alert['alert_id']} — {alert['name']}", "",
                      f"- Severity: {alert['severity']}",
                      f"- Seen: {alert['created_at'] or 'unknown'}; temporal check: {alert['temporal_check']}",
                      f"- IP evidence: {', '.join(alert['indicators'])}; fields: {', '.join(alert['match_fields'])}",
                      f"- Investigation rank: {alert['score']}/70 (heuristic, not a verdict)", ""])
    if "offense_context" in report:
        context = report["offense_context"]
        lines += ["## QRadar offense metadata", ""]
        for key in ("status", "magnitude", "event_count", "flow_count", "offense_source",
                    "source_network", "assigned_to"):
            if key in offense and offense[key] is not None:
                lines.append(f"- {key}: {str(offense[key]).replace(chr(10), ' ')[:160]}")
        lines += ["", "## QRadar Ariel event sample", ""]
        if not context["ariel"]:
            lines.append("Not collected: no usable offense source IP/time or Ariel was unavailable.")
        for batch in context["ariel"]:
            win = batch["window"]
            lines.append(f"- UTC window: {win['utc_start']} to {win['utc_end']}; "
                         f"QRadar local offset {win['qradar_utc_offset_hours']:+d} h (confirm).")
            for search in batch["searches"]:
                lines.append(f"- {search['pivot']}: {search['state']}, "
                             f"sample {search.get('sample_count', 0)}/100, "
                             f"reported total {search.get('total')}; AQL: `{search['aql']}`")
                lines.append(f"  - Search ID: {search.get('search_id') or 'not provided'}")
                if search.get("top_events"):
                    lines.append(f"  - Event names in sample: {search['top_events']}")
                for row in search.get("rows", [])[:8]:
                    lines.append("  - " + ", ".join(f"{k}={str(row[k])[:100]}" for k in
                        ("time_utc", "sourceip", "sourceport", "destinationip", "destinationport", "event_name", "log_source")
                        if row.get(k) is not None))
        lines += ["", "## Vision One Search by offense IP", ""]
        if context.get("vision_window"):
            win = context["vision_window"]
            lines.append(f"Window: {win['start']} to {win['end']}; IP {context.get('ip')}; "
                         "first 50 rows per source, first 20 retained.")
        for finding in context["vision"]:
            lines.append(f"- {finding['tool']}: {finding['state']}; "
                         f"page rows {finding.get('page_rows', 'unavailable')}/50; "
                         f"exact IP/time {finding.get('matched_ip_time', 'unavailable')}; "
                         f"page capped: {finding.get('capped', 'unknown')}.")
            for hit in finding["rows"][:8]:
                lines.append(f"  - {hit['time_utc']} host={hit['host'] or 'unknown'}, "
                             f"uuid={hit['uuid'] or 'unknown'}, event={hit['event_name'] or 'unknown'}, "
                             f"dst={hit['destination'] or 'unknown'}:{hit['destination_port'] or 'unknown'}")
        lines += ["", "## Cross-source network leads", ""]
        if not context["network_leads"]:
            lines.append("No exact IP/destination/port plus ≤60s lead in the displayed samples. "
                         "This does not rule out related telemetry, especially when a search is capped.")
        for lead in context["network_leads"]:
            lines.append(f"- QRadar {lead['qradar_time']} / Trend {lead['trend_time']}: "
                         f"destination {lead['destination']}:{lead['destination_port']}; "
                         f"QRadar event={lead['qradar_event']}; Trend event={lead['trend_event']}.")
        lines.append("These are candidate network matches, not proof the same process caused the QRadar event.")
        lines.extend(f"- Coverage warning: {warning}" for warning in context["warnings"])
    lines.extend(["", "## Coverage limits", ""])
    lines.extend(f"- {w}" for w in report["warnings"])
    if not report["warnings"] and not report.get("offense_context", {}).get("warnings"):
        lines.append("- No additional collection warnings in this run. Searches remain bounded to first-page results.")
    lines.extend(["", "Analyst review required. Matching an IP and time window alone does not establish a shared incident.", ""])
    return "\n".join(lines)


def render_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False, default=str) + "\n"
