"""Workbench alert-first QRadar offense leads; read-only and bounded."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from .core import address, instant, iso, records, window


ALERT_ID = re.compile(r"^WB-[A-Za-z0-9-]{3,100}$")
IP_KEYS = {"ip", "ipaddress", "sourceip", "destinationip", "endpointip",
           "indicatorvalue", "impactscopeentityvalue"}
TYPED_VALUE_KEYS = {"value", "entityvalue"}
TYPE_KEYS = {"type", "entitytype", "indicatortype"}
SUMMARY_KEYS = ("name", "description", "severity", "status", "investigationStatus",
                "investigationResult", "model", "score", "createdDateTime",
                "updatedDateTime", "firstInvestigatedDateTime")
OFFENSE_KEYS = ("description", "status", "magnitude", "event_count", "flow_count",
                "source_network", "offense_source", "assigned_to", "start_time", "last_updated_time")
ENTITY_KEYS = {"hostname": "hosts", "endpointhostname": "hosts", "endpointname": "hosts", "computername": "hosts",
               "username": "users", "accountname": "users",
               "processname": "processes", "processfilepath": "processes",
               "commandline": "commands", "processcommandline": "commands",
               "filename": "files", "filepath": "files", "fullpath": "files",
               "filehash": "hashes", "sha1": "hashes", "sha256": "hashes"}


def alert_ips(detail: dict[str, Any]) -> list[str]:
    """Only extract explicit IP fields or typed IP values, never scrape free text."""
    found: set[str] = set()

    def visit(node: Any, depth: int = 0) -> None:
        if depth > 10:
            return
        if isinstance(node, list):
            for item in node[:150]:
                visit(item, depth + 1)
        elif isinstance(node, dict):
            kind = " ".join(str(v) for k, v in node.items() if k.lower() in TYPE_KEYS).lower()
            is_ip_type = bool(re.search(r"\bip(?:v[46]| address)?\b", kind))
            for key, value in node.items():
                normalized = key.replace("_", "").lower()
                if isinstance(value, str) and (normalized in IP_KEYS or
                     (normalized in TYPED_VALUE_KEYS and is_ip_type)):
                    ip = address(value)
                    if ip:
                        found.add(ip)
                elif isinstance(value, (dict, list)):
                    visit(value, depth + 1)

    visit(detail)
    return sorted(found)


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


def alert_entities(detail: dict[str, Any]) -> dict[str, list[str]]:
    """Only show selected structured fields; bound the content sent to Kiro."""
    found: dict[str, set[str]] = {category: set() for category in ENTITY_KEYS.values()}

    def visit(node: Any, depth: int = 0) -> None:
        if depth > 10:
            return
        if isinstance(node, list):
            for value in node[:150]:
                visit(value, depth + 1)
        elif isinstance(node, dict):
            for key, value in node.items():
                category = ENTITY_KEYS.get(key.replace("_", "").lower())
                if category and isinstance(value, str) and value.strip():
                    found[category].add(value.strip().replace("\n", " ")[:240])
                elif isinstance(value, (dict, list)):
                    visit(value, depth + 1)

    visit(detail)
    return {category: sorted(values)[:12] for category, values in found.items() if values}


async def investigate_vision_alert(qradar: Protocol, vision: Protocol, alert_id: str,
                                   max_ips: int = 8, max_offenses: int = 20,
                                   event_evidence: dict[str, str] | None = None,
                                   ariel_offset_hours: int | None = None,
                                   enable_vision_search: bool = False) -> dict[str, Any]:
    if not ALERT_ID.fullmatch(alert_id) or not 1 <= max_ips <= 30 or not 1 <= max_offenses <= 100:
        raise ValueError("Invalid alert ID or investigation limits")
    detail = await vision.call("workbench_alert_detail_get", {"alertId": alert_id})
    if isinstance(detail, dict) and isinstance(detail.get("data"), dict):
        detail = detail["data"]
    if not isinstance(detail, dict) or str(detail.get("id")) != alert_id:
        raise ValueError("Vision One returned an unexpected alert ID or response shape")

    warnings: list[str] = []
    api_ips = alert_ips(detail)
    all_ips = list(api_ips)
    manual: dict[str, str] = {}
    auto: dict[str, Any] | None = None
    if event_evidence is not None:
        ip = address(event_evidence.get("endpoint_ip"))
        event_time = instant(event_evidence.get("event_time"))
        if not ip or not event_time:
            raise ValueError("Manual event requires a valid endpoint IP and ISO-8601 time")
        manual = {k: str(v).strip()[:350] for k, v in event_evidence.items()
                  if k in {"endpoint_ip", "event_time", "endpoint_host", "file_hash",
                           "file_path", "process_path"} and v}
        manual["endpoint_ip"] = ip
        manual["event_time"] = iso(event_time)
        all_ips = [ip] + [value for value in all_ips if value != ip]
        warnings.append("Event fields were manually supplied from Vision One View event; the MCP did not retrieve or verify them")
    elif enable_vision_search:
        from .auto_pivot import discover_alert_pivots
        auto = await discover_alert_pivots(vision, detail)
        warnings.extend(auto["warnings"])
        all_ips.extend(ip for ip in auto["ips"] if ip not in all_ips)

    seen = (instant(manual["event_time"]) if manual else
            instant(auto["event_time"]) if auto and auto["event_time"] else
            instant(detail.get("createdDateTime")) or instant(detail.get("firstInvestigatedDateTime")))
    if not seen:
        warnings.append("Alert has no usable creation time; offense timing cannot be checked")

    host = manual.get("endpoint_host", "") or (auto or {}).get("host", "")
    if not host:
        host = next(iter(alert_entities(detail).get("hosts", [])), "")
    vision_activity = None
    if enable_vision_search and seen:
        from .vision_activity import collect_vision_activity
        file_hash = manual.get("file_hash", "") or (auto or {}).get("hash", "")
        vision_activity = await collect_vision_activity(vision, iso(seen), host, file_hash)
        warnings.extend(vision_activity["warnings"])
        if not manual and len(vision_activity["host_ips"]) == 1:
            internal_ip = vision_activity["host_ips"][0]
            all_ips = [internal_ip] + [ip for ip in all_ips if ip != internal_ip]
            warnings.append("Private IP inferred from exact-host Vision One activity; verify DHCP/asset identity before attributing QRadar events")
    ips = all_ips[:max_ips]
    if len(all_ips) > len(ips):
        warnings.append(f"IP cap: inspected {len(ips)} of {len(all_ips)} available IPs")
    if not ips:
        warnings.append("Alert detail has no explicit IP field; QRadar IP-based offense correlation cannot run")
    leads: dict[int, set[str]] = {}
    successful_queries = 0
    for ip in ips:
        for tool, key in (("list_source_addresses", "source_ip"),
                          ("list_local_destination_addresses", "local_destination_ip")):
            try:
                rows = records(await qradar.call(tool, {"filter": f'{key} = "{ip}"', "limit": 100}))
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
            offense = await qradar.call("get_offense", {"offense_id": offense_id})
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
        matches.append({"offense_id": offense_id, "shared_ips": sorted(leads[offense_id]),
                        "timing": timing, "start": iso(begin + timedelta(hours=1)) if begin else None,
                        "last_updated": iso(end - timedelta(hours=1)) if end else None,
                        "fields": {k: offense[k] for k in OFFENSE_KEYS if k in offense}})
    matches.sort(key=lambda m: (m["timing"] != "overlaps or within six hours", m["offense_id"]))
    if not matches:
        if successful_queries:
            warnings.append("No QRadar offense lead in inspected address indexes; this does not exclude events or flows")
        else:
            warnings.append("No QRadar address-index query was executed")
    ariel = None
    if ips and seen and ariel_offset_hours is not None:
        from .ariel import investigate_ariel
        ariel = await investigate_ariel(qradar, ips[0], host, iso(seen), ariel_offset_hours)
        warnings.extend(ariel["warnings"])
    process_focus = None
    private_focus: list[dict[str, Any]] = []
    if (ariel_offset_hours is not None and not manual and vision_activity
            and vision_activity["host_ips"]):
        process_events = [instant(row.get("time_utc")) for finding in vision_activity["findings"]
                          if finding["pivot"] == "process hash activity" and finding["state"] == "completed"
                          for row in finding["rows"]
                          if (host and str(row.get("endpointHostName", "")).casefold() == host.casefold()
                              and str(row.get("processFileHashSha1") or row.get("processFileHashSha256") or "").lower()
                              == str((auto or {}).get("hash", "")).lower())]
        process_times = [t for t in process_events if t is not None]
        if process_times:
            from .ariel import investigate_ariel
            host_ips = vision_activity["host_ips"]
            observed = iso(min(process_times))
            if len(host_ips) == 1:
                process_focus = await investigate_ariel(qradar, host_ips[0], "",
                                                        observed, ariel_offset_hours, focus_seconds=12)
                warnings.extend(process_focus["warnings"])
            elif len(host_ips) <= 3:
                for candidate_ip in host_ips:
                    sample = await investigate_ariel(qradar, candidate_ip, "", observed,
                                                     ariel_offset_hours, focus_seconds=12)
                    private_focus.append({"candidate_ip": candidate_ip, "result": sample})
                    warnings.extend(f"Candidate IP {candidate_ip}: {note}" for note in sample["warnings"])
                warnings.append("Multiple private interfaces: each exact IP was checked in a 24-second process-time window; no interface was automatically attributed to this host or process")
            else:
                warnings.append(f"Host exposed {len(host_ips)} private IPs; focused QRadar checks skipped above the three-IP limit")
    report = {"alert_id": alert_id, "generated_at": iso(datetime.now(timezone.utc)),
            "alert": {k: detail[k] for k in SUMMARY_KEYS if k in detail},
            "alert_ips": api_ips, "searched_ips": ips, "manual_event": manual,
            "successful_queries": successful_queries,
            "entities": alert_entities(detail), "alert_time": iso(seen), "offenses": matches,
            "ariel": ariel, "ariel_process_focus": process_focus,
            "ariel_private_focus": private_focus,
            "vision_activity": vision_activity, "auto_pivots": auto,
            "warnings": list(dict.fromkeys(warnings)),
            "method": "Exact alert IP -> QRadar source/destination address indexes -> linked offense IDs -> offense details; first 100 rows per IP and index"}
    from .timeline import build_timeline
    report["timeline"] = build_timeline(report)
    return report


def render_alert_markdown(report: dict[str, Any]) -> str:
    a = report["alert"]
    lines = [f"# Vision One alert {report['alert_id']} -> QRadar", "",
             f"Generated (UTC): {report['generated_at']}", "",
             "## Vision One evidence", ""]
    for key in SUMMARY_KEYS:
        if key in a:
            lines.append(f"- {key}: {str(a[key]).replace(chr(10), ' ')[:500]}")
    lines.extend([f"- IPs in alert API detail: {', '.join(report['alert_ips']) or 'none'}",
                  f"- IPs searched in QRadar: {', '.join(report['searched_ips']) or 'none'}",
                  "", "## Structured alert entities", ""])
    for category, values in report["entities"].items():
        lines.extend(f"- {category}: {value}" for value in values)
    if not report["entities"]:
        lines.append("- No structured host, user, process, command, file or hash fields found.")
    if report["manual_event"]:
        lines.extend(["", "## Analyst-supplied View event evidence (unverified by this tool)", ""])
        for key, value in report["manual_event"].items():
            lines.append(f"- {key}: {value.replace(chr(10), ' ')}")
        lines.append("- File creation or detection alone does not demonstrate RClone execution or exfiltration.")
    if report.get("auto_pivots"):
        auto = report["auto_pivots"]
        lines.extend(["", "## Automatically discovered pivots", "",
                      f"- Discovery logic: {auto['logic']}",
                      f"- Discovery status: {auto['discovery_status']}",
                      f"- Detection searches attempted: {auto['search_calls']}; rows on inspected page: {auto['search_rows']}; matching candidates: {auto['candidates']}",
                      f"- Detection query field with results: {auto['search_field']}",
                      f"- Source: {auto['source']}", f"- Candidate host: {auto['host'] or 'none'}",
                      f"- Candidate hash: {auto['hash'] or 'none'}",
                      f"- Candidate event time: {auto['event_time'] or 'none'}",
                      f"- Candidate event IPs: {', '.join(auto['ips']) or 'none'}",
                      f"- Exact-host private IPs: {', '.join((report['vision_activity'] or {}).get('host_ips', [])) or 'none'}",
                      "- A nearby detection is a candidate, not a verified Workbench View event link."])
    lines.extend(["", "## QRadar offense leads", ""])
    for item in report["offenses"]:
        lines.extend([f"### Offense {item['offense_id']}", "",
                      f"- Shared IP: {', '.join(item['shared_ips'])}",
                      f"- Time check: {item['timing']}",
                      f"- QRadar interval: {item['start'] or 'unknown'} to {item['last_updated'] or 'unknown'}"])
        for key, value in item["fields"].items():
            if key not in ("start_time", "last_updated_time"):
                lines.append(f"- QRadar {key}: {str(value).replace(chr(10), ' ')[:500]}")
        lines.append("")
    if not report["offenses"]:
        lines.append("No offense lead in inspected address indexes." if report["successful_queries"]
                     else "No successful address-index query was run; inspect the warnings above.")
    if report["ariel"]:
        ariel = report["ariel"]
        local = ariel["window"]
        lines.extend(["", "## QRadar Ariel events", "",
                      f"- UTC window: {local['utc_start']} to {local['utc_end']}",
                      f"- QRadar local query: {local['qradar_local_start']} to {local['qradar_local_end']} "
                      f"(UTC offset {local['qradar_utc_offset_hours']:+d} h; confirm QRadar timezone)",
                      f"- Method: {ariel['method']}"])
        for search in ariel["searches"]:
            lines.append(f"- Pivot {search['pivot']}: {search['state']}; "
                         f"returned sample {search.get('sample_count', 0)} / reported total "
                         f"{search.get('total') if search.get('total') is not None else 'unknown'}")
            lines.append(f"  - AQL: {search['aql']}")
            if search.get("search_id"):
                lines.append(f"  - Search ID: {search['search_id']}")
            if search.get("outside_utc_window"):
                lines.append(f"  - Warning: {search['outside_utc_window']} results outside requested UTC window")
            if search.get("top_events"):
                lines.append(f"  - Event names in sample: {search['top_events']}")
            for row in search["rows"]:
                lines.append(f"  - {str(row)[:400]}")
        lines.append("- Events sharing a public IP may be unrelated to the endpoint; host text is a separate lead, not an established identity match.")
    if report.get("ariel_process_focus"):
        focused = report["ariel_process_focus"]
        lines.extend(["", "## QRadar near process-hash activity (candidate host IP)", "",
                      f"- UTC window: {focused['window']['utc_start']} to {focused['window']['utc_end']}",
                      "- Exact starttime predicate in AQL compensates for QRadar minute rounding."])
        for search in focused["searches"]:
            lines.extend([f"- IP pivot: {search['state']}; sample {search.get('sample_count', 0)} / "
                          f"reported {search.get('total', 'unknown')}",
                          f"  - AQL: {search['aql']}"])
            for row in search["rows"]:
                lines.append(f"  - {str(row)[:400]}")
        lines.append("- IP/time overlap does not identify the process behind firewall traffic or prove a transfer.")
    if report.get("ariel_private_focus"):
        lines.extend(["", "## QRadar near process activity (multiple candidate private IPs)", "",
                      "Each IP was queried independently in a 24-second UTC window. The candidates may include virtual interfaces; results do not establish the endpoint's active IP or attribute traffic to RClone."])
        for candidate in report["ariel_private_focus"]:
            focused = candidate["result"]
            lines.append(f"- Candidate IP {candidate['candidate_ip']}: UTC {focused['window']['utc_start']} to {focused['window']['utc_end']}")
            for search in focused["searches"]:
                lines.append(f"  - Pivot {search['pivot']}: {search['state']}; sample {search.get('sample_count', 0)} / "
                             f"reported {search.get('total') if search.get('total') is not None else 'unknown'}; "
                             f"AQL: {search['aql']}")
                for row in search["rows"]:
                    lines.append(f"    - {str(row)[:400]}")
    if report["vision_activity"]:
        activity = report["vision_activity"]
        lines.extend(["", "## Vision One endpoint and detection searches", "",
                      f"- UTC window: {activity['window']['start']} to {activity['window']['end']}",
                      f"- Method: {activity['method']}"])
        for finding in activity["findings"]:
            lines.append(f"- {finding['pivot']}: {finding['state']}; "
                         f"results on first page: {finding.get('returned', 'unknown')}; "
                         f"query: {finding['query']}")
            for row in finding["rows"]:
                lines.append(f"  - {str(row)[:480]}")
        lines.append("- A matching file detection is separate from observed process execution. Check process command line and network activity before drawing conclusions.")
    timeline = report["timeline"]
    lines.extend(["", "## Evidence timeline (UTC, collected sample)", ""])
    for entry in timeline["entries"]:
        lines.append(f"- {entry['time_utc']} | {entry['source']} | {entry['type']} | "
                     f"{entry['summary']} | ref={entry['reference']}")
    if not timeline["entries"]:
        lines.append("- No event timestamp returned by the enabled searches.")
    if timeline["truncated"]:
        lines.append(f"- Timeline capped at {len(timeline['entries'])} of {timeline['total_sampled_entries']} collected entries.")
    lines.append(f"- {timeline['note']}")
    lines.extend(["", "## Coverage and analyst checks", "", f"- Method: {report['method']}"])
    lines.extend(f"- {item}" for item in report["warnings"])
    lines.extend(["- Review endpoint, account, process and command-line evidence in Vision One; verify the same entities in QRadar Log Activity.",
                  ("- Address indexes identify candidate offenses; Ariel results above are bounded event samples, not proof of the same incident."
                   if report["ariel"] else "- Address indexes identify candidate offenses; they do not search Ariel events or prove the same incident."),
                  "- An IP and a time overlap are investigation leads, not a verdict.", ""])
    return "\n".join(lines)
