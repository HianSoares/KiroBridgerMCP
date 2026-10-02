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
                                   now: datetime | None = None) -> dict[str, Any]:
    if not isinstance(alert_id, str) or not ALERT_ID.fullmatch(alert_id) or not 1 <= max_ips <= 30 or not 1 <= max_offenses <= 100:
        raise ValueError("Invalid alert ID or investigation limits")
    if not isinstance(timezone_verified, bool):
        raise ValueError("timezone_verified must be a boolean")
    budget = budget or Budget(max_seconds=75, max_queries=8, max_calls=40, max_records=5000, max_partitions=16)
    now = now or datetime.now(timezone.utc)
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
    if enable_vision_search:
        from .alert_discovery import discover
        from .dump_analysis import analyze as analyze_dumps
        from .trend_enrichment import enrich
        discovery = await discover(vision, budget, parsed, anchor)
        warnings.extend(discovery["warnings"])
        records_all = discovery["records_all"]
        clocks = build_clocks(detail, parsed,
                              linked=[r for r in records_all if r["relation"]["label"] == "linked"],
                              candidates=[r for r in records_all if r["relation"]["label"] == "identifier_match"],
                              oat=[i for o in discovery["oat"] for i in o["items"]], collected_at=now)
        if not clocks["anchor"].get("provisional") or not manual:
            anchor = clocks["anchor"]
        dumps = await analyze_dumps(vision, budget, records_all, parsed["endpoints"])
        hypotheses = {"network_transfer": bool(dumps.get("applicable"))}
        enrichment = await enrich(vision, budget, alert_id, detail, parsed, discovery, anchor, hypotheses, now)

    all_ips: list[str] = []
    for ip in ([manual["endpoint_ip"]] if manual else []) + api_ips + sorted(
            {ip for r in (discovery or {}).get("records_all", []) if r["relation"]["label"] != "context"
             for ip in r.get("endpoint_ips", [])}):
        if ip not in all_ips:
            all_ips.append(ip)
    ips = [ip for ip in all_ips if ":" not in ip][:max_ips]
    if len(all_ips) > len(ips):
        warnings.append(f"IP cap/IPv6: inspected {len(ips)} of {len(all_ips)} available IPs in QRadar address indexes")
    if not ips:
        warnings.append("Alert detail has no explicit IP field; QRadar IP-based offense correlation cannot run")
    seen = instant(anchor.get("time_utc"))
    leads: dict[int, set[str]] = {}
    successful_queries = 0
    for ip in ips:
        for tool, key in (("list_source_addresses", "source_ip"),
                          ("list_local_destination_addresses", "local_destination_ip")):
            try:
                rows = records(await budget.run(lambda: qradar.call(tool, {"filter": f'{key} = "{ip}"', "limit": 100}), tool))
                successful_queries += 1
                if len(rows) >= 100:
                    warnings.append(f"{tool} for {ip}: first 100 rows only; results may be incomplete")
                for offense_id in _offense_ids(rows, ip, key):
                    leads.setdefault(offense_id, set()).add(ip)
            except Exception as exc:
                warnings.append(f"{tool} for {ip}: query failed ({type(exc).__name__}); coverage is partial")
    if len(leads) > max_offenses:
        warnings.append(f"Offense cap: inspected {max_offenses} of {len(leads)} candidate IDs")
    matches: list[dict[str, Any]] = []
    for offense_id in sorted(leads)[:max_offenses]:
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
        matches.append({"offense_id": offense_id, "shared_ips": sorted(leads[offense_id]), "timing": timing,
                        "relation": "lead (shared IP in offense address index; not a process link)",
                        "start": iso(begin + timedelta(hours=1)) if begin else None,
                        "last_updated": iso(end - timedelta(hours=1)) if end else None,
                        "fields": {k: offense[k] for k in OFFENSE_KEYS if k in offense}})
    matches.sort(key=lambda m: (m["timing"] != "overlaps or within six hours", m["offense_id"]))
    if not matches:
        warnings.append("No QRadar offense lead in inspected address indexes; this does not exclude events or flows"
                        if successful_queries else "No QRadar address-index query was executed")
    correlation = None
    if ariel_offset_hours is not None and seen:
        from .trend_qradar import correlate
        correlation = await correlate(qradar, budget, parsed, discovery or {"records_all": []}, anchor, now,
                                      ariel_offset_hours, timezone_verified, manual.get("endpoint_ip"))
        warnings.extend(correlation["notes"])
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
              "dump_analysis": dumps, "enrichment": enrichment, "budget": budget.describe(),
              "warnings": list(dict.fromkeys(warnings)),
              "method": ("Structured Workbench extraction -> endpoint/hash/path Search pivots and OAT within a shared budget -> "
                         "read-only enrichments -> QRadar address-index leads and budgeted Ariel queries with epoch predicates")}
    report["timeline"] = timeline(report)
    report["assessment"] = assess(report)
    return report


def render_alert_markdown(report: dict[str, Any]) -> str:
    from .alert_render import render
    return render(report)
