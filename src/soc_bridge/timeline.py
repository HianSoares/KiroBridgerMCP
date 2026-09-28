"""Evidence timeline with source labels, without asserting causal links."""

from __future__ import annotations

from typing import Any

from .core import instant, iso


def build_timeline(report: dict[str, Any], limit: int = 40) -> dict[str, Any]:
    rows: list[dict[str, str]] = []

    def add(time: Any, source: str, kind: str, summary: str, reference: str = "") -> None:
        dt = instant(time)
        if dt:
            rows.append({"time_utc": iso(dt), "source": source, "type": kind,
                         "summary": summary.replace("\n", " ")[:200], "reference": reference[:100]})

    add(report.get("alert", {}).get("createdDateTime"), "Vision One alert API", "alert created",
        str(report.get("alert", {}).get("name", "Workbench alert")), report["alert_id"])
    manual = report.get("manual_event") or {}
    if manual:
        add(manual.get("event_time"), "analyst-supplied View event", "event (unverified)",
            f"host={manual.get('endpoint_host', 'unknown')} ip={manual.get('endpoint_ip', 'unknown')}", report["alert_id"])
    auto = report.get("auto_pivots") or {}
    if auto.get("event_time"):
        add(auto["event_time"], "Vision One Search", "nearby detection candidate",
            f"host={auto.get('host', '?')} hash={auto.get('hash', '?')}", report["alert_id"])
    for result in (report.get("ariel") or {}).get("searches", []):
        if result.get("state") != "COMPLETED":
            continue
        for event in result.get("rows", []):
            add(event.get("time_utc"), "QRadar Ariel", f"{result['pivot']} pivot",
                f"{event.get('event_name', 'event')} source={event.get('sourceip', '?')} "
                f"destination={event.get('destinationip', '?')} log={event.get('log_source', '?')}",
                str(result.get("search_id", "")))
    for result in (report.get("ariel_process_focus") or {}).get("searches", []):
        if result.get("state") != "COMPLETED":
            continue
        for event in result.get("rows", []):
            add(event.get("time_utc"), "QRadar Ariel", "focused host-IP lead",
                f"{event.get('event_name', 'event')} source={event.get('sourceip', '?')} "
                f"destination={event.get('destinationip', '?')} port={event.get('destinationport', '?')}",
                str(result.get("search_id", "")))
    for candidate in report.get("ariel_private_focus", []):
        for result in candidate["result"]["searches"]:
            if result.get("state") != "COMPLETED":
                continue
            for event in result.get("rows", [])[:3]:
                add(event.get("time_utc"), "QRadar Ariel", "candidate private IP lead",
                    f"ip={candidate['candidate_ip']} {event.get('event_name', 'event')} "
                    f"source={event.get('sourceip', '?')} destination={event.get('destinationip', '?')}",
                    str(result.get("search_id", "")))
    for finding in (report.get("vision_activity") or {}).get("findings", []):
        if finding.get("state") != "completed":
            continue
        for event in finding.get("rows", []):
            add(event.get("time_utc"), "Vision One Search", finding["pivot"],
                f"{event.get('eventName', 'activity')} process={event.get('processFilePath', '?')} "
                f"object={event.get('objectFilePath', event.get('fullPath', '?'))}",
                str(event.get("uuid", "")))
    seen: set[tuple[str, str, str, str, str]] = set()
    ordered: list[dict[str, str]] = []
    for row in sorted(rows, key=lambda r: (r["time_utc"], r["source"], r["reference"])):
        key = (row["time_utc"], row["source"], row["type"], row["reference"], row["summary"])
        if key not in seen:
            seen.add(key)
            ordered.append(row)
    return {"entries": ordered[:limit], "total_sampled_entries": len(ordered),
            "truncated": len(ordered) > limit,
            "note": "Collected sample only; timestamps do not establish a shared incident or process execution"}
