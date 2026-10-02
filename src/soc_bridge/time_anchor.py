"""Separate clocks for one alert and an anchor that prefers the real event time.

Parsing is done once: ISO strings ending in Z or with an offset become aware UTC
datetimes; epoch numbers are treated as milliseconds above 1e11. A string with no
offset is reported as "naive" instead of being silently shifted. The Trend endpoint
clock never confirms the QRadar console timezone.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .core import instant


def parse(value: Any) -> tuple[datetime | None, bool]:
    """(UTC datetime or None, naive flag)."""
    if isinstance(value, str):
        text = value.strip()
        naive = bool(text) and not (text.endswith(("Z", "z")) or "+" in text[10:] or text[10:].count("-") > 0)
        return instant(text), naive
    return instant(value), False


def utc_ms(value: Any) -> str | None:
    stamp = value if isinstance(value, datetime) else parse(value)[0]
    if stamp is None:
        return None
    return stamp.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def build_clocks(detail: dict, parsed: dict, linked: list[dict] | None = None,
                 candidates: list[dict] | None = None, oat: list[dict] | None = None,
                 collected_at: datetime | None = None) -> dict:
    """linked/candidates are normalized Search records; oat are normalized OAT items."""
    naive: list[str] = []

    def entry(value: Any, source: str, kind: str, **extra: Any) -> dict | None:
        stamp, is_naive = parse(value)
        if stamp is None:
            return None
        if is_naive:
            naive.append(source)
        return {"time_utc": utc_ms(stamp), "source": source, "kind": kind, "naive_input": is_naive, **extra}

    clocks: dict[str, Any] = {"event": [], "match": [], "detection_or_ingestion": [], "alert": {},
                              "collected_at": utc_ms(collected_at or datetime.now(timezone.utc))}
    for record in linked or []:
        item = entry(record.get("event_time_raw"), f"{record['tool']}:{record.get('uuid')}", "event",
                     link="linked by matchedEvents uuid")
        if item:
            clocks["event"].append(item)
    for record in candidates or []:
        item = entry(record.get("event_time_raw"), f"{record['tool']}:{record.get('uuid')}", "event",
                     link="candidate (identifier/endpoint/time match, not linked by uuid)")
        if item:
            clocks["event"].append(item)
    for rule in parsed.get("matched_rules", []):
        for flt in rule["matched_filters"]:
            item = entry(flt.get("matched_date_time"), flt["source"], "filter match")
            if item:
                clocks["match"].append(item)
            for event in flt["matched_events"]:
                item = entry(event.get("matched_date_time"), f"{flt['source']}.matchedEvents:{event.get('uuid')}",
                             "event match")
                if item:
                    clocks["match"].append(item)
    for item in oat or []:
        for key, kind in (("detected_date_time", "OAT detection"), ("ingested_date_time", "OAT ingestion")):
            e = entry(item.get(key), f"oat:{item.get('uuid')}", kind, link=item.get("link"))
            if e:
                clocks["detection_or_ingestion"].append(e)
    for key, name in (("createdDateTime", "created"), ("updatedDateTime", "updated"),
                      ("firstInvestigatedDateTime", "first_investigated")):
        e = entry(detail.get(key), f"alert.{key}", f"alert {name}")
        if e:
            clocks["alert"][name] = e
    clocks["anchor"] = choose_anchor(clocks)
    clocks["naive_inputs"] = naive
    clocks["timezone_note"] = ("Trend times are UTC as returned. They do not confirm the QRadar console timezone; "
                               "local START/STOP needs a verified offset, while LAST and epoch predicates do not.")
    return clocks


def choose_anchor(clocks: dict) -> dict:
    linked = [e for e in clocks["event"] if e.get("link", "").startswith("linked")]
    event_matches = [e for e in clocks["match"] if e["kind"] == "event match"]
    filter_matches = [e for e in clocks["match"] if e["kind"] == "filter match"]
    oat_linked = [e for e in clocks["detection_or_ingestion"]
                  if e["kind"] == "OAT detection" and str(e.get("link", "")).startswith("linked")]
    candidates = [e for e in clocks["event"] if e.get("link", "").startswith("candidate")]
    order = ((linked, "event time of a Search record linked to the alert by matchedEvents uuid", False),
             (event_matches, "matchedEvents.matchedDateTime (match time of a matched event)", False),
             (filter_matches, "matchedFilters.matchedDateTime (filter match time)", False),
             (oat_linked, "OAT detectedDateTime linked by uuid", False),
             (candidates, "event time of a candidate record (not linked by uuid)", True))
    for items, basis, provisional in order:
        if items:
            first = min(items, key=lambda e: e["time_utc"])
            return {"time_utc": first["time_utc"], "basis": basis, "source": first["source"],
                    "provisional": provisional}
    for name, basis in (("created", "alert createdDateTime (provisional: alert creation, not event time)"),
                        ("first_investigated", "alert firstInvestigatedDateTime (provisional: a human action time)")):
        if name in clocks["alert"]:
            e = clocks["alert"][name]
            return {"time_utc": e["time_utc"], "basis": basis, "source": e["source"], "provisional": True}
    return {"time_utc": None, "basis": "no usable time", "source": None, "provisional": True}
