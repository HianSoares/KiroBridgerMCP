"""Demonstrated link between a related Trend alert and the offense activity.

An offense-first investigation finds Workbench alerts by IP and time. That association
selects alerts to deepen; it does not show that the alert and the offense describe the same
activity. A link is demonstrated only when an offense-linked QRadar process record (returned
by an INOFFENSE query) and the alert share a strong identifier of the executed activity
(full file hash or exact command line) on the same host. Anything weaker stays a candidate:
a True Positive verdict on a candidate alert does not confirm malicious activity in the
offense and does not corroborate the QRadar evidence.
"""

from __future__ import annotations

from typing import Any

from .process_chain import same_host

HASH_LENGTHS = (32, 40, 64)
REQUIRED = ("a full file hash or the exact command line shared by an offense-linked QRadar process record "
            "and the alert, on the same host")


def _norm(value: Any) -> str | None:
    return " ".join(value.split()).lower() if isinstance(value, str) and value.strip() else None


def identifiers(report: dict) -> dict:
    """Strong identifiers and hosts of a Trend alert report (structured extraction first)."""
    observables = ((report or {}).get("extraction") or {}).get("observables") or {}
    legacy = (report or {}).get("entities") or {}

    def values(category: str, legacy_name: str) -> set[str]:
        found = {_norm(o.get("value")) for o in observables.get(category, []) if isinstance(o, dict)}
        found |= {_norm(v) for v in legacy.get(legacy_name, []) if isinstance(v, str)}
        return {v for v in found if v}

    hashes = {h for h in values("hash", "hashes") if len(h) in HASH_LENGTHS and all(c in "0123456789abcdef" for c in h)}
    return {"hashes": sorted(hashes), "commands": sorted(values("command", "commands")),
            "hosts": sorted(values("host", "hosts"))}


def link(result: dict, alert_id: str, ids: dict | None, association: dict | None = None) -> dict:
    """"demonstrated" with the matching records, or "candidate" with what is missing."""
    ids = ids or {}
    hashes, commands, hosts = set(ids.get("hashes", [])), set(ids.get("commands", [])), ids.get("hosts", [])
    matches = []
    for item in (result.get("processes") or {}).get("process_creations", []):
        prov = item.get("provenance") or {}
        if prov.get("scope") != "offense_linked":
            continue  # host-context records are near the offense, not part of it
        shared = []
        record_hashes = {str(v.get("value")).lower() for v in (item.get("hashes") or {}).values()
                         if isinstance(v, dict) and v.get("comparable")}
        if record_hashes & hashes:
            shared.append("file hash")
        command = _norm(item.get("command_line"))
        if command and not item.get("command_line_preview_truncated") and command in commands:
            shared.append("exact command line")
        if not shared:
            continue
        host = item.get("host_norm")
        if not host or not any(same_host(host, h) for h in hosts):
            continue  # same identifier on another or unknown host is not the same activity
        matches.append({"qradar_record": {k: prov.get(k) for k in ("query", "search_id", "result_row_index",
                                                                    "starttime_utc")},
                        "host": host, "shared_identifiers": shared,
                        "behavior": "process execution in an offense-linked record and in the Trend alert"})
    if matches:
        return {"alert_id": alert_id, "level": "demonstrated", "matches": matches[:10],
                "basis": "shared strong identifier and pertinent behavior on the same host"}
    return {"alert_id": alert_id, "level": "candidate",
            "basis": "related only by the IP/time association used to select the alert"
                     + (f" ({', '.join(association.get('match_fields') or [])})" if association else ""),
            "missing": REQUIRED,
            "alert_identifiers_available": {k: len(v) for k, v in ids.items()}}
