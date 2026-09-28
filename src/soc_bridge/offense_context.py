"""Bounded Ariel and Vision One evidence for a QRadar offense reference."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from .ariel import investigate_ariel
from .core import address, instant, iso, records


def _event_ips(value: Any) -> set[str]:
    values = value if isinstance(value, list) else [value]
    return {ip for raw in values if (ip := address(raw))}


def _offense_interval(offense: dict[str, Any]) -> tuple[Any, Any]:
    start = instant(offense.get("start_time") or offense.get("first_event_flow_seen"))
    end = instant(offense.get("last_updated_time") or offense.get("last_event_flow_seen"))
    return start or end, end or start


async def collect_offense_context(qradar: Any, vision: Any, offense: dict[str, Any],
                                  searched_ips: list[str], offset: int) -> dict[str, Any]:
    """Inspect one source IP and its event time; never suggest exhaustive coverage."""
    result: dict[str, Any] = {"status": "skipped", "warnings": [], "ariel": [],
                              "vision": [], "network_leads": []}
    ip = address(offense.get("offense_source")) or next(iter(searched_ips), None)
    start, end = _offense_interval(offense)
    if not ip or not start or not end:
        result["warnings"].append("No validated offense IP/time for Ariel and Vision One Search")
        return result
    if not -12 <= offset <= 14:
        result["warnings"].append("QRadar UTC offset invalid; no contextual search performed")
        return result
    result["ip"] = ip
    result["offense_utc_start"], result["offense_utc_end"] = iso(start), iso(end)
    if end < start:
        result["warnings"].append("Offense end precedes start; no contextual search performed")
        return result
    duration = (end - start).total_seconds()
    if duration > 3600:
        result["warnings"].append("Offense spans over one hour; inspect the first 60 minutes only")
        end = start + timedelta(hours=1)
    center = start + (end - start) / 2
    result["status"] = "partial"
    result["qradar_utc_offset_hours"] = offset

    # Start with surrounding events, then narrow if the first page hits 100.
    # A focused result replaces the broad sample as evidence for correlation;
    # both search windows and their states remain in the report.
    try:
        ariel = await investigate_ariel(qradar, ip, "", iso(center), offset)
        result["ariel"].append(ariel)
        for seconds in (60, 20):
            first = ariel["searches"][0]
            if first["state"] != "COMPLETED" or not (
                first.get("sample_count", 0) >= 100 or
                isinstance(first.get("total"), int) and first["total"] >= 100
            ):
                break
            ariel = await investigate_ariel(qradar, ip, "", iso(center), offset,
                                             focus_seconds=seconds)
            result["ariel"].append(ariel)
        for search in result["ariel"]:
            result["warnings"].extend(search["warnings"])
    except Exception as exc:
        result["warnings"].append(f"Ariel context unavailable ({type(exc).__name__})")

    # Query Search even when Workbench returned no alert. A Search event with
    # the same IP is a lead, not evidence of the same process or incident.
    query_start = iso(start - timedelta(minutes=5))
    query_end = iso(end + timedelta(minutes=5))
    result["vision_window"] = {"start": query_start, "end": query_end}
    for tool in ("search_endpoint_activities_list", "search_detections_list"):
        finding: dict[str, Any] = {"tool": tool, "state": "unavailable", "rows": []}
        result["vision"].append(finding)
        try:
            response = await vision.call(tool, {"query": f'endpointIp:"{ip}"',
                "startDateTime": query_start, "endDateTime": query_end, "top": "50"})
            rows = records(response)
            finding["state"] = "COMPLETED"
            finding["page_rows"] = len(rows)
            finding["capped"] = len(rows) >= 50 or (isinstance(response, dict) and
                bool(response.get("nextLink") or response.get("next")))
            if finding["capped"]:
                result["warnings"].append(f"Vision One {tool}: first 50 rows only; results may be incomplete")
            verified = []
            for row in rows[:50]:
                stamp = instant(row.get("eventTime") or row.get("eventTimeDT"))
                if ip not in _event_ips(row.get("endpointIp")) or not stamp or not (
                    start - timedelta(minutes=5) <= stamp <= end + timedelta(minutes=5)):
                    continue
                verified.append({"time_utc": iso(stamp), "uuid": str(row.get("uuid") or "")[:100],
                    "host": str(row.get("endpointHostName") or "")[:100],
                    "guid": str(row.get("endpointGUID") or row.get("endpointGuid") or "")[:100],
                    "event_name": str(row.get("eventName") or row.get("filterName") or "")[:120],
                    "destination": address(row.get("dst")) or address(row.get("objectIp")) or "",
                    "destination_port": str(row.get("dpt") or row.get("objectPort") or "")[:8]})
            finding["matched_ip_time"] = len(verified)
            finding["rows"] = verified[:20]
        except Exception as exc:
            result["warnings"].append(f"Vision One {tool} unavailable ({type(exc).__name__}); Search coverage partial")

    if result["ariel"] and result["ariel"][-1]["searches"][0]["state"] == "COMPLETED":
        sample = result["ariel"][-1]["searches"][0]["rows"]
        endpoint_events = next((f["rows"] for f in result["vision"] if
                                f["tool"] == "search_endpoint_activities_list"), [])
        for qr in sample:
            qr_time = instant(qr.get("time_utc"))
            dst = address(qr.get("destinationip"))
            dpt = str(qr.get("destinationport") or "")
            if address(qr.get("sourceip")) != ip or not qr_time or not dst or not dpt:
                continue
            for hit in endpoint_events:
                ht = instant(hit.get("time_utc"))
                if (ht and abs((ht - qr_time).total_seconds()) <= 60 and
                    hit.get("destination") == dst and hit.get("destination_port") == dpt):
                    result["network_leads"].append({
                        "qradar_time": qr["time_utc"], "trend_time": hit["time_utc"],
                        "destination": dst, "destination_port": dpt,
                        "qradar_event": str(qr.get("event_name") or "")[:120],
                        "trend_event": hit.get("uuid") or hit.get("event_name")})
                    if len(result["network_leads"]) >= 8:
                        break
            if len(result["network_leads"]) >= 8:
                break
    result["status"] = ("collected" if any(
        search["state"] == "COMPLETED" for batch in result["ariel"] for search in batch["searches"]
    ) or any(finding["state"] == "COMPLETED" for finding in result["vision"]) else "partial")
    result["warnings"] = list(dict.fromkeys(result["warnings"]))
    return result
