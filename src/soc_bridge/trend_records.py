"""Normalize Vision One Search/OAT records by role, keeping values whole and cuts explicit.

Groups: process (the actor), parent, object (what the actor acted on), endpoint,
logon/user, network and event metadata. Hash fields describe executable files;
processHashId/objectProcessHashId identify process instances and are kept apart.
endpointGuid is the Trend agent GUID, never a Sysmon ProcessGuid.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from typing import Any

from .time_anchor import utc_ms

MAX_FIELD = 32768
PREVIEW = 2000
ROLE_PREFIXES = ("process", "parent", "object", "endpoint", "logon")
NETWORK_KEYS = {"src", "dst", "spt", "dpt", "request", "requestBase", "serverIp", "clientIp", "serverPort",
                "clientPort", "app", "act", "resolvedUrlIp", "hostName", "dhost", "shost", "peerIp", "interestedIp"}
EVENT_KEYS = {"uuid", "eventId", "eventSubId", "eventName", "eventSubName", "eventTime", "eventTimeDT", "tags",
              "filterRiskLevel", "productCode", "pname", "osName", "malName", "riskLevel", "detectionName",
              "firstSeen", "lastSeen", "logReceivedTime", "ruleName", "act", "action"}
DROPPED = {"payload", "rawData", "raw_payload"}
# Detection Data uses its own names for the detected file; these are object-role facts.
DETECTION_FILE_KEYS = {"fileName": "fileName", "filePath": "filePath", "fullPath": "fullPath",
                       "filePathName": "filePathName", "fileHash": "fileHash", "fileHashSha256": "fileHashSha256"}


def _bound(value: Any, path: str, cuts: list[str]) -> Any:
    if isinstance(value, str) and len(value) > MAX_FIELD:
        cuts.append(path)
        return value[:MAX_FIELD]
    if isinstance(value, list):
        if len(value) > 100:
            cuts.append(f"{path}[100:]")
        return [_bound(v, f"{path}[{i}]", cuts) for i, v in enumerate(value[:100])]
    if isinstance(value, dict):
        return {k: _bound(v, f"{path}.{k}", cuts) for k, v in list(value.items())[:100]}
    return value


def _ips(value: Any) -> list[str]:
    out = []
    for item in value if isinstance(value, list) else [value]:
        try:
            out.append(str(ipaddress.ip_address(str(item).strip())))
        except ValueError:
            continue
    return out


def normalize(row: dict, tool: str, query: str, partition: dict | None = None) -> dict:
    """One Search/OAT row grouped by role; analysis runs on these values before any preview cut."""
    cuts: list[str] = []
    groups: dict[str, dict] = {"process": {}, "parent": {}, "object": {}, "endpoint": {}, "logon": {},
                               "network": {}, "event": {}, "detection_file": {}, "other": {}}
    dropped = []
    for key, value in row.items():
        if key in DROPPED:
            dropped.append(key)
            continue
        value = _bound(value, key, cuts)
        prefix = next((p for p in ROLE_PREFIXES if key.startswith(p) and len(key) > len(p) and key[len(p)].isupper()), None)
        if prefix:
            rest = key[len(prefix):]
            rest = rest.lower() if rest.isupper() else rest[0].lower() + rest[1:]
            if rest in groups[prefix]:
                groups["other"][key] = value  # alias collision (e.g. endpointGuid/endpointGUID): keep both
            else:
                groups[prefix][rest] = value
        elif key in DETECTION_FILE_KEYS:
            groups["detection_file"][key] = value
        elif key in NETWORK_KEYS:
            groups["network"][key] = value
        elif key in EVENT_KEYS:
            groups["event"][key] = value
        else:
            groups["other"][key] = value
    endpoint = groups["endpoint"]
    raw_time = row.get("eventTime") or row.get("eventTimeDT") or row.get("detectedDateTime")
    record = {"tool": tool, "query": query, "uuid": row.get("uuid"),
              "event_time_raw": raw_time, "event_time_utc": utc_ms(raw_time),
              "endpoint_guid": endpoint.get("guid"),
              "endpoint_host": endpoint.get("hostName") or endpoint.get("name"),
              "endpoint_ips": _ips(endpoint.get("ip") or endpoint.get("ips") or []),
              **{name: data for name, data in groups.items() if data},
              "cut_by_bridge": cuts, "dropped_fields": dropped}
    if partition:
        record["partition"] = partition
    return record


def preview(text: Any, size: int = PREVIEW) -> dict:
    """Preview for display only; analysis must use the full value."""
    if not isinstance(text, str):
        return {"value": text, "preview_cut": False}
    return {"value": text[:size], "preview_cut": len(text) > size, "characters": len(text)}


def full_hashes(group: dict) -> dict:
    """Full-length hex digests by algorithm for one role group; abbreviated values are excluded."""
    out = {}
    for name, length in (("fileHashSha256", 64), ("fileHashSha1", 40), ("fileHashMd5", 32)):
        value = group.get(name)
        if isinstance(value, str) and len(value) == length and re.fullmatch(r"[0-9A-Fa-f]+", value):
            out[name] = value.lower()
    return out


def identity(record: dict) -> tuple:
    """Conservative dedup key: uuid when present, else the full row content."""
    if record.get("uuid"):
        return ("uuid", record["tool"], str(record["uuid"]))
    body = {k: v for k, v in record.items() if k not in {"query", "partition"}}
    return ("content", record["tool"], hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest())
