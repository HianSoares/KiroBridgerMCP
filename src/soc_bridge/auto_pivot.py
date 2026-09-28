"""Conservative, bounded entity discovery from a Workbench alert ID."""

from __future__ import annotations

from datetime import timedelta
from typing import Any, Protocol

from .core import address, instant, iso, records
from .vision_activity import HASH, HOST


async def discover_alert_pivots(vision: Protocol, detail: dict[str, Any]) -> dict[str, Any]:
    """Use structured alert fields, or a narrow, explicitly labelled detection lead.

    Workbench alert detail does not expose the portal's View event in all tenants.
    Only the known RClone model has an additional fixed query; no narrative text
    is ever converted into an unbounded search expression.
    """
    from .alert_investigation import alert_entities

    entities = alert_entities(detail)
    hosts = [h for h in entities.get("hosts", []) if HOST.fullmatch(h)]
    hashes = [h for h in entities.get("hashes", []) if HASH.fullmatch(h)]
    found: dict[str, Any] = {
        "host": hosts[0] if len(hosts) == 1 else "",
        "hash": hashes[0] if len(hashes) == 1 else "",
        "event_time": "", "ips": [], "source": "alert detail" if hosts or hashes else "none",
        "warnings": [], "candidates": 0, "search_calls": 0,
        "search_rows": 0, "discovery_status": "not started",
        "search_field": "none",
        "logic": "model-or-name-v2",
    }
    if found["host"] and found["hash"]:
        found["discovery_status"] = "host and hash already present in alert detail"
        return found
    created = instant(detail.get("createdDateTime"))
    # Workbench tenants can expose the detection label as ``model`` instead of
    # ``name``. Require an exact match in either structured field; do not
    # search by a substring from the alert description.
    models = {str(detail.get(field) or "").strip().casefold() for field in ("name", "model")}
    if not created:
        found["discovery_status"] = "skipped: no valid alert creation time"
        found["warnings"].append("Automatic detection search skipped: alert creation time is missing or invalid")
        return found
    if "rclone detection" not in models:
        found["discovery_status"] = "skipped: exact RClone Detection label absent from name/model"
        found["warnings"].append("Automatic detection search skipped: alert name/model is not exactly RClone Detection")
        return found
    parameters = {"startDateTime": iso(created - timedelta(minutes=30)),
                  "endDateTime": iso(created + timedelta(minutes=5)), "top": "50"}
    # The detected file can be exposed in ``fullPath`` while filename/path
    # filters are not indexed for that detection source. The model-specific
    # Trend detection label is a final bounded candidate lookup; its results
    # still need an exact executable basename, host, hash and time validation.
    # A server version may reject a field; one failure must not suppress the
    # remaining read-only queries.
    queries = ('fileName:"rclone.exe"', 'filePath:"rclone.exe"',
               'fullPath:"rclone.exe"', 'filePathName:"rclone.exe"',
               'malName:"HZ_RCLONE64"', 'malName:"RCLONE"')
    rows: list[dict[str, Any]] = []
    failures = 0
    for query in queries:
        found["search_calls"] += 1
        try:
            response = await vision.call("search_detections_list", {"query": query, **parameters})
            rows = records(response)
        except Exception:
            failures += 1
            continue
        if rows:
            found["search_field"] = query.split(":", 1)[0]
            break
    if failures:
        found["warnings"].append(f"{failures} RClone detection query field(s) unavailable; other fields were checked")
    if failures == len(queries):
        found["discovery_status"] = "detection search failed"
        found["warnings"].append("Automatic RClone detection lookup unavailable for all bounded query fields")
        return found
    found["search_rows"] = len(rows)
    if len(rows) >= 50 or (isinstance(response, dict) and (response.get("nextLink") or response.get("next"))):
        found["discovery_status"] = "first page capped; attribution skipped"
        found["warnings"].append("RClone detection lookup reached its first-page cap; automatic attribution skipped")
        return found
    candidates: list[dict[str, Any]] = []
    for row in rows:
        when = instant(row.get("eventTime") or row.get("eventTimeDT"))
        name = str(row.get("fullPath") or row.get("filePath") or row.get("fileName") or "")
        host = str(row.get("endpointHostName") or row.get("hostName") or "")
        sha = str(row.get("fileHash") or "")
        if (when and created - timedelta(minutes=30) <= when <= created + timedelta(minutes=5)
                and name.replace("/", "\\").rsplit("\\", 1)[-1].casefold() == "rclone.exe"
                and HOST.fullmatch(host) and HASH.fullmatch(sha)):
            candidates.append({"host": host, "hash": sha.lower(), "event_time": iso(when),
                               "ips": [ip for value in (row.get("endpointIp"), row.get("src"))
                                       for ip in _addresses(value)]})
    found["candidates"] = len(candidates)
    identities = {(item["host"].casefold(), item["hash"]) for item in candidates}
    if len(identities) != 1 or not candidates:
        found["discovery_status"] = ("no detections matched bounded filename/path/model searches"
                                     if not rows else "no unique host/hash in bounded detection results")
        found["warnings"].append("No unique RClone host/hash candidate near the alert; cannot auto-attribute View event")
        return found
    if found["host"] and found["host"].casefold() != candidates[0]["host"].casefold():
        found["discovery_status"] = "alert host disagrees with candidate"
        found["warnings"].append("Alert host differs from detection candidate; automatic attribution skipped")
        return found
    if found["hash"] and found["hash"].lower() != candidates[0]["hash"]:
        found["discovery_status"] = "alert hash disagrees with candidate"
        found["warnings"].append("Alert hash differs from detection candidate; automatic attribution skipped")
        return found
    chosen = min(candidates, key=lambda item: abs((instant(item["event_time"]) - created).total_seconds()))
    found.update({"host": chosen["host"], "hash": chosen["hash"],
                  "event_time": chosen["event_time"],
                  "ips": sorted({ip for item in candidates for ip in item["ips"]}),
                  "source": "unique nearby RClone detection candidate",
                  "discovery_status": "unique nearby host/hash candidate"})
    found["warnings"].append("RClone detection is a time/model candidate; the API did not prove it belongs to this Workbench alert")
    return found


def _addresses(value: Any) -> list[str]:
    items = value if isinstance(value, list) else [value]
    return [ip for item in items if (ip := address(item))]
