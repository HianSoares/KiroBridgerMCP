"""Workbench alert-first investigation: structured extraction, Search/OAT evidence, enrichments and QRadar.

Read-only throughout. Every relation is labelled (linked, identifier match, candidate,
unverified) with its criteria; collected telemetry is data and is never executed.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from .alert_assessment import assess, timeline
from .ariel_collection import Budget
from .core import address, instant, iso, records, window
from .time_anchor import build_clocks, utc_ms
from .workbench_extract import parse_alert

ALERT_ID = re.compile(r"^WB-[A-Za-z0-9-]{3,100}$")
SUMMARY_KEYS = ("name", "description", "severity", "status", "investigationStatus",
                "investigationResult", "model", "score", "createdDateTime",
                "updatedDateTime", "firstInvestigatedDateTime")
OFFENSE_KEYS = ("description", "status", "magnitude", "event_count", "flow_count",
                "source_network", "offense_source", "assigned_to", "start_time", "last_updated_time")
LEGACY_CATEGORIES = {"host": "hosts", "user": "users", "process": "processes", "command": "commands",
                     "path": "files", "file": "files", "hash": "hashes"}


def alert_ips(detail: dict[str, Any]) -> list[str]:
    """Explicit IP fields, IP lists and typed IP entities/indicators; never free text."""
    return sorted({o["value"] for o in parse_alert(detail)["observables"].get("ip", [])})


def alert_entities(detail: dict[str, Any], parsed: dict | None = None) -> dict[str, list[str]]:
    """Legacy category view of the structured extraction (values are not cut to 240 characters)."""
    parsed = parsed or parse_alert(detail)
    found: dict[str, set[str]] = {}
    for category, items in parsed["observables"].items():
        legacy = LEGACY_CATEGORIES.get(category)
        if legacy:
            found.setdefault(legacy, set()).update(o["value"] for o in items)
    return {category: sorted(values)[:12] for category, values in found.items() if values}


def _offense_ids(rows: list[dict[str, Any]], ip: str, key: str) -> set[int]:
    ids: set[int] = set()
    for row in rows:
        if address(row.get(key)) != ip:
            continue
        for item in row.get("offense_ids", []) if isinstance(row.get("offense_ids"), list) else []:
            try:
                value = int(item)
                if value > 0:
                    ids.add(value)
            except (TypeError, ValueError):
                pass
    return ids


def default_budget() -> Budget:
    """Shared ceiling with reservations: broad or optional reads cannot consume what the
    hypothesis checks, the Trend<->QRadar correlation and the enrichments need."""
    budget = Budget(max_seconds=90, max_queries=8, max_calls=70, max_records=6000, max_partitions=16)
    budget.reserve("hypothesis", calls=10, seconds=10)
    budget.reserve("correlation", calls=12, seconds=25, queries=6)
    budget.reserve("enrichment", calls=14, seconds=8)
    return budget


def _merge_manual(parsed: dict, manual: dict) -> None:
    """Analyst-supplied View event fields join the extraction labelled as unverified."""
    source = "analyst-supplied View event (unverified)"
    host = manual.get("endpoint_host")
    endpoint = next((e for e in parsed["endpoints"] if host and (e.get("name") or "").lower() == host.lower()), None)
    if endpoint:
        endpoint["ips"] = sorted(set(endpoint["ips"]) | {manual["endpoint_ip"]})
        endpoint["sources"].append(source)
    else:
        parsed["endpoints"].append({"name": host or None, "guid": None, "ips": [manual["endpoint_ip"]],
                                    "sources": [source]})
    for key, category, role in (("file_hash", "hash", "unknown"), ("file_path", "path", "object"),
                                ("process_path", "path", "process")):
        if manual.get(key):
            parsed["observables"].setdefault(category, []).append(
                {"value": manual[key], "role": role, "sources": [source], "cut_by_bridge": False})


async def investigate_vision_alert(qradar: Protocol, vision: Protocol, alert_id: str,
                                   max_ips: int = 8, max_offenses: int = 20,
                                   event_evidence: dict[str, str] | None = None,
                                   ariel_offset_hours: int | None = None,
                                   enable_vision_search: bool = False,
                                   timezone_verified: bool = False,
                                   budget: Budget | None = None,
                                   now: datetime | None = None,
                                   qradar_correlation: bool = True) -> dict[str, Any]:
    if not isinstance(alert_id, str) or not ALERT_ID.fullmatch(alert_id) or not 1 <= max_ips <= 30 or not 1 <= max_offenses <= 100:
        raise ValueError("Invalid alert ID or investigation limits")
    if not isinstance(timezone_verified, bool):
        raise ValueError("timezone_verified must be a boolean")
    budget = budget or default_budget()
    now = now or datetime.now(timezone.utc)
    budget.enter("primary")
    budget.calls_made += 1
    detail = await budget.run(lambda: vision.call("workbench_alert_detail_get", {"alertId": alert_id}), "alert detail")
    if isinstance(detail, dict) and isinstance(detail.get("data"), dict):
        detail = detail["data"]
    if not isinstance(detail, dict) or str(detail.get("id")) != alert_id:
        raise ValueError("Vision One returned an unexpected alert ID or response shape")

    warnings: list[str] = []
    parsed = parse_alert(detail)
    api_ips = sorted({o["value"] for o in parsed["observables"].get("ip", [])})
    manual: dict[str, str] = {}
    if event_evidence is not None:
        ip = address(event_evidence.get("endpoint_ip"))
        event_time = instant(event_evidence.get("event_time"))
        if not ip or not event_time:
            raise ValueError("Manual event requires a valid endpoint IP and ISO-8601 time")
        manual = {k: str(v).strip()[:2048] for k, v in event_evidence.items()
                  if k in {"endpoint_ip", "event_time", "endpoint_host", "file_hash", "file_path", "process_path"} and v}
        manual["endpoint_ip"] = ip
        manual["event_time"] = iso(event_time)
        _merge_manual(parsed, manual)
        warnings.append("Event fields were manually supplied from Vision One View event; the MCP did not retrieve or verify them")
    clocks = build_clocks(detail, parsed, collected_at=now)
    anchor = dict(clocks["anchor"])
    if manual and anchor.get("provisional"):
        anchor = {"time_utc": utc_ms(manual["event_time"]), "basis": "analyst-supplied View event time (unverified by the bridge)",
                  "source": "manual_event", "provisional": False, "unverified": True}
    if anchor.get("provisional"):
        warnings.append(f"Provisional time anchor: {anchor['basis']}")

    discovery: dict[str, Any] | None = None
    dumps: dict[str, Any] = {"applicable": False}
    enrichment: dict[str, Any] = {}
    hypothesis_checks: dict[str, Any] = {}
    insights: dict[str, Any] = {"state": "not_started", "reason": "Vision One reads beyond the alert detail are disabled"}
    insight_obs: dict[str, list] = {}
    if enable_vision_search:
        from .alert_discovery import discover
        from .dump_analysis import analyze as analyze_dumps
        from .trend_enrichment import enrich, hypothesis_reads, insight_observables, read_insights
        # Primary: the alert's own identifiers first (insights that reference it, then Search/OAT).
        insights = await read_insights(vision, budget, alert_id, detail, now)
        insight_obs = insight_observables(insights)
        discovery = await discover(vision, budget, parsed, anchor)
        warnings.extend(discovery["warnings"])
        records_all = discovery["records_all"]
        clocks = build_clocks(detail, parsed,
                              linked=[r for r in records_all if r["relation"]["label"] == "linked"],
                              candidates=[r for r in records_all if r["relation"]["label"] == "identifier_match"],
                              oat=[i for o in discovery["oat"] for i in o["items"]], collected_at=now)
        if not clocks["anchor"].get("provisional") or not manual:
            anchor = clocks["anchor"]
        budget.enter("hypothesis")
        dumps = await analyze_dumps(vision, budget, records_all, parsed["endpoints"])
        hypothesis_checks = await hypothesis_reads(vision, budget, alert_id, parsed, discovery, anchor, dumps,
                                                   insight_obs.get("hash", []), now)
    else:
        budget.release("hypothesis", "Vision One reads beyond the alert detail are disabled")
        budget.release("enrichment", "Vision One reads beyond the alert detail are disabled")
    budget.enter("correlation")

    all_ips: list[str] = []
    ip_origin: dict[str, str] = {}
    for ip, origin in ([(manual["endpoint_ip"], "analyst-supplied View event")] if manual else []) + \
            [(ip, "alert detail") for ip in api_ips] + [(ip, "linked/identifier-matched Search record") for ip in sorted(
                {ip for r in (discovery or {}).get("records_all", []) if r["relation"]["label"] != "context"
                 for ip in r.get("endpoint_ips", [])})] + \
            [(o["value"], o["source"]) for o in insight_obs.get("ip", []) if address(o["value"])]:
        if ip not in all_ips:
            all_ips.append(ip)
            ip_origin[ip] = origin
    ips = [ip for ip in all_ips if ":" not in ip][:max_ips]
    if not qradar_correlation:
        # Started from an offense: that offense is the QRadar side. No offense lookup runs here,
        # which also prevents an offense -> alert -> offense loop.
        ips = []
        budget.release("correlation", "QRadar side skipped: alert deepened from an offense investigation")
        warnings.append("QRadar lookups skipped: this alert was deepened from an offense investigation")
    elif len(all_ips) > len(ips):
        warnings.append(f"IP cap/IPv6: inspected {len(ips)} of {len(all_ips)} available IPs in QRadar address indexes")
    if qradar_correlation and not ips:
        warnings.append("Alert detail has no explicit IP field; QRadar IP-based offense correlation cannot run")
    seen = instant(anchor.get("time_utc"))
    # Evidence correlation has priority over potentially numerous offense leads.
    # A lead index alone does not fulfill the reserved Ariel correlation phase.
    correlation = None
    if qradar_correlation and ariel_offset_hours is not None and seen:
        from .trend_qradar import correlate
        correlation = await correlate(qradar, budget, parsed, discovery or {"records_all": []}, anchor, now,
                                      ariel_offset_hours, timezone_verified, manual.get("endpoint_ip"))
        warnings.extend(correlation["notes"])
    leads: dict[int, set[str]] = {}
    successful_queries = 0
    lead_queries: list[dict] = []
    for ip in ips:
        for tool, key in (("list_source_addresses", "source_ip"),
                          ("list_local_destination_addresses", "local_destination_ip")):
            reason = budget.blocked("call")
            if reason:
                lead_queries.append({"ip": ip, "tool": tool, "state": "not_executed", "reason": reason})
                warnings.append(f"{tool} for {ip}: not executed ({reason}); this is not an empty result")
                continue
            budget.calls_made += 1
            try:
                rows = records(await budget.run(lambda: qradar.call(tool, {"filter": f'{key} = "{ip}"', "limit": 100}), tool))
                successful_queries += 1
                lead_queries.append({"ip": ip, "tool": tool, "state": "executed", "rows": len(rows)})
                if len(rows) >= 100:
                    warnings.append(f"{tool} for {ip}: first 100 rows only; results may be incomplete")
                for offense_id in _offense_ids(rows, ip, key):
                    leads.setdefault(offense_id, set()).add(ip)
            except Exception as exc:
                lead_queries.append({"ip": ip, "tool": tool, "state": "failed", "error": type(exc).__name__})
                warnings.append(f"{tool} for {ip}: query failed ({type(exc).__name__}); coverage is partial")
    if len(leads) > max_offenses:
        warnings.append(f"Offense cap: inspected {max_offenses} of {len(leads)} candidate IDs")
    matches: list[dict[str, Any]] = []
    for offense_id in sorted(leads)[:max_offenses]:
        reason = budget.blocked("call")
        if reason:
            warnings.append(f"Offense {offense_id}: detail not read ({reason})")
            continue
        budget.calls_made += 1
        try:
            offense = await budget.run(lambda: qradar.call("get_offense", {"offense_id": offense_id}), "get_offense")
            if not isinstance(offense, dict) or str(offense.get("id")) != str(offense_id):
                raise ValueError("unexpected offense response")
        except Exception as exc:
            warnings.append(f"Offense {offense_id}: detail unavailable ({type(exc).__name__})")
            continue
        begin, end = window(offense)
        if seen and begin and end:
            near = begin - timedelta(hours=5) <= seen <= end + timedelta(hours=5)
            timing = "overlaps or within six hours" if near else "outside six-hour context"
        else:
            timing = "unknown"
        via_insight = all(not ip_origin.get(ip, "").startswith(("alert", "analyst", "linked")) for ip in leads[offense_id])
        matches.append({"offense_id": offense_id, "shared_ips": sorted(leads[offense_id]), "timing": timing,
                        "ip_origins": {ip: ip_origin.get(ip) for ip in sorted(leads[offense_id])},
                        "relation": ("candidate lead via an insight-related IP (not demonstrated for this alert)" if via_insight
                                     else "lead (shared IP in offense address index; not a process link)"),
                        "start": iso(begin + timedelta(hours=1)) if begin else None,
                        "last_updated": iso(end - timedelta(hours=1)) if end else None,
                        "fields": {k: offense[k] for k in OFFENSE_KEYS if k in offense}})
    matches.sort(key=lambda m: (m["timing"] != "overlaps or within six hours", m["offense_id"]))
    if not matches and qradar_correlation:
        warnings.append("No QRadar offense lead in inspected address indexes; this does not exclude events or flows"
                        if successful_queries else "No QRadar address-index query was executed")
    if enable_vision_search:
        budget.enter("enrichment")
        hypotheses = {"network_transfer": bool(dumps.get("applicable"))}
        enrichment = await enrich(vision, budget, alert_id, detail, parsed, discovery, anchor, hypotheses, now)
    report = {"alert_id": alert_id, "generated_at": iso(now),
              "alert": {k: detail[k] for k in SUMMARY_KEYS if k in detail},
              "alert_ips": api_ips, "searched_ips": ips, "manual_event": manual,
              "successful_queries": successful_queries, "entities": alert_entities(detail, parsed),
              "extraction": {k: v for k, v in parsed.items() if k != "observables"} | {
                  "observables": {k: v[:30] for k, v in parsed["observables"].items()}},
              "clocks": clocks, "anchor": anchor, "alert_time": anchor.get("time_utc"), "offenses": matches,
              "qradar_correlation": correlation, "ariel": None, "ariel_process_focus": None, "ariel_private_focus": [],
              "vision_activity": None,
              "auto_pivots": {k: v for k, v in discovery.items() if k != "records_all"} if discovery else None,
              "dump_analysis": dumps, "enrichment": enrichment, "hypothesis_checks": hypothesis_checks,
              "insights": insights, "insight_observables": {k: v[:20] for k, v in insight_obs.items()},
              "lead_queries": lead_queries, "budget": budget.describe(),
              "warnings": list(dict.fromkeys(warnings)),
              "method": ("Primary: structured Workbench extraction, Insights that reference the alert, hash/path/process-instance "
                         "Search pivots before endpoint-wide context and OAT -> Hypothesis: dump analysis, hash intel/sandbox, "
                         "response tasks, identity and telemetry availability -> Correlation: QRadar address-index leads and "
                         "budgeted Ariel queries (reserved budget) -> Optional enrichments")}
    report["timeline"] = timeline(report)
    report["assessment"] = assess(report)
    return report


def render_alert_markdown(report: dict[str, Any]) -> str:
    from .alert_render import render
    return render(report)
