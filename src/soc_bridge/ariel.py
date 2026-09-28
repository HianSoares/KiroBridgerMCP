"""Bounded, fixed-template QRadar Ariel searches for Vision One event context."""

from __future__ import annotations

import re
from collections import Counter
from datetime import timedelta
from typing import Any, Protocol

from .core import address, instant, iso


HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
SEARCH_ID = re.compile(r"^[A-Za-z0-9-]{8,100}$")


def make_queries(ip: str, host: str, observed: str, offset_hours: int,
                 focus_seconds: int | None = None) -> tuple[list[tuple[str, str]], dict[str, Any]]:
    """The AQL START/STOP strings use the QRadar UI's local time, not UTC."""
    when = instant(observed)
    ip = address(ip)
    if not when or not ip or not -12 <= offset_hours <= 14 or (focus_seconds is not None and not 5 <= focus_seconds <= 60):
        raise ValueError("Ariel search needs an IP, ISO time and valid QRadar UTC offset")
    local = when + timedelta(hours=offset_hours)
    delta = timedelta(seconds=focus_seconds) if focus_seconds else timedelta(minutes=30)
    begin = local - delta
    end = local + delta
    # QRadar rounds AQL START/STOP to whole minutes. A numeric starttime
    # predicate is required to actually constrain a seconds-level query.
    exact = (f" AND starttime >= {int((when - delta).timestamp() * 1000)}"
             f" AND starttime < {int((when + delta).timestamp() * 1000)}") if focus_seconds else ""
    interval = f"LIMIT 100 START '{begin:%Y-%m-%d %H:%M:%S}' STOP '{end:%Y-%m-%d %H:%M:%S}'"
    select = ("SELECT starttime, sourceip, sourceport, destinationip, destinationport, username, "
              "QIDNAME(qid) AS event_name, LOGSOURCENAME(logsourceid) AS log_source FROM events")
    queries = [("ip", f"{select} WHERE (sourceip = '{ip}' OR destinationip = '{ip}'){exact} {interval}")]
    if not focus_seconds and host and HOST.fullmatch(host):
        queries.append(("hostname", f"{select} WHERE TEXT SEARCH '{host}' {interval}"))
    return queries, {"utc_start": iso(when - delta),
                     "utc_end": iso(when + delta),
                     "qradar_local_start": begin.strftime("%Y-%m-%d %H:%M:%S"),
                     "qradar_local_end": end.strftime("%Y-%m-%d %H:%M:%S"),
                     "qradar_utc_offset_hours": offset_hours, "focus_seconds": focus_seconds}


async def investigate_ariel(qradar: Protocol, ip: str, host: str, observed: str,
                            offset_hours: int, focus_seconds: int | None = None) -> dict[str, Any]:
    queries, win = make_queries(ip, host, observed, offset_hours, focus_seconds)
    utc_begin = instant(win["utc_start"])
    utc_end = instant(win["utc_end"])
    warnings: list[str] = []
    if host and not HOST.fullmatch(host):
        warnings.append("Hostname omitted from AQL search: invalid or unsafe hostname format")
    searches: list[dict[str, Any]] = []
    for pivot, aql in queries:
        result: dict[str, Any] = {"pivot": pivot, "aql": aql,
                                  "state": "not started", "rows": [], "total": None}
        searches.append(result)
        try:
            valid = await qradar.call("validate_aql", {"query_expression": aql})
            if not isinstance(valid, dict) or valid.get("valid") is not True:
                raise ValueError("AQL validation did not succeed")
            created = await qradar.call("create_ariel_search", {"query_expression": aql})
            sid = created.get("search_id") if isinstance(created, dict) else None
            if not isinstance(sid, str) or not SEARCH_ID.fullmatch(sid):
                raise ValueError("Ariel search did not return a valid search ID")
            result["search_id"] = sid
            # Bounded to ~12 seconds per pivot; no indefinite polling or bulk retrieval.
            for _ in range(4):
                status = await qradar.call("get_ariel_search_status", {"search_id": sid, "wait_seconds": 3})
                state = str(status.get("status", "unknown")).upper() if isinstance(status, dict) else "unknown"
                result["state"] = state
                if state in {"ERROR", "CANCELED"}:
                    warnings.append(f"Ariel {pivot} search ended with {state}; results unavailable")
                    break
                if state == "COMPLETED":
                    payload = await qradar.call("get_ariel_search_results", {"search_id": sid, "start": 0, "limit": 100})
                    events = payload.get("events", []) if isinstance(payload, dict) else []
                    if not isinstance(events, list):
                        raise ValueError("Unexpected Ariel result format")
                    result["total"] = status.get("record_count")
                    trimmed = []
                    outside = 0
                    for row in events[:100]:
                        if isinstance(row, dict):
                            safe = {k: row[k] for k in ("starttime", "sourceip", "sourceport",
                                                       "destinationip", "destinationport",
                                                       "username", "event_name", "log_source") if k in row}
                            event_time = instant(row.get("starttime"))
                            safe["time_utc"] = iso(event_time)
                            if event_time and not utc_begin <= event_time <= utc_end:
                                outside += 1
                            trimmed.append(safe)
                    result["rows"] = trimmed[:20]
                    result["sample_count"] = len(trimmed)
                    result["outside_utc_window"] = outside
                    result["top_events"] = dict(Counter(str(r.get("event_name", "unknown"))[:120]
                                                        for r in trimmed).most_common(8))
                    if len(events) >= 100 or (isinstance(result["total"], int) and result["total"] >= 100):
                        warnings.append(f"Ariel {pivot} search reached the 100-event cap; sample is incomplete")
                    if outside and not focus_seconds and all(
                        (event_time := instant(r.get("starttime"))) is not None and
                        utc_begin - timedelta(minutes=1) <= event_time <= utc_end + timedelta(minutes=1)
                        for r in events[:100] if isinstance(r, dict)
                    ):
                        warnings.append(f"Ariel {pivot}: {outside} events outside exact window by up to one minute; QRadar rounds START/STOP to minute boundaries")
                    elif outside:
                        warnings.append(f"Ariel {pivot}: {outside} sampled timestamps lie outside the requested UTC window; check QRadar UTC offset before interpreting results")
                    break
            else:
                warnings.append(f"Ariel {pivot} search is still running; rerun later to collect completed results")
        except Exception as exc:
            result["state"] = "unavailable"
            warnings.append(f"Ariel {pivot} search failed ({type(exc).__name__}); coverage is partial")
    return {"window": win, "searches": searches, "warnings": warnings,
            "method": "Fixed AQL for exact IP and optional hostname text; seconds-level numeric starttime filter when focused; events only; 100 rows per search, 20 displayed"}
