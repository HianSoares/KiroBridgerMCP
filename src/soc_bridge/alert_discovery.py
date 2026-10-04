"""Model-independent evidence discovery for one Workbench alert.

1. Use the alert's own entities and indicators.
2. Search with those identifiers (endpoint GUID/host/IP, role-specific hashes, file names).
3. Read OAT for the same endpoints.
4. Follow process instances (processHashId) to later activity and connections.
Records are labelled linked (uuid in matchedEvents), identifier_match or context.
The model/alert name is never used as a search expression or as proof of execution.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Any

from . import vision_search
from .ariel_collection import Budget
from .core import address
from .time_anchor import parse
from .trend_records import endpoint_identity, full_hashes, preview

MAX_ENDPOINTS = 5
MAX_INDICATOR_PIVOTS = 8
MAX_INSTANCES = 4
MAX_LISTED = 50
GUID = re.compile(r"^\{?([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\}?$")
HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")
TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,119}$")
HASH = re.compile(r"^(?:[0-9A-Fa-f]{32}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})$")
INSTANCE_ID = re.compile(r"^[A-Za-z0-9_-]{6,128}$")
HASH_FIELDS = {40: "FileHashSha1", 64: "FileHashSha256", 32: "FileHashMd5"}


def term(field: str, value: str) -> str:
    """Only validated values reach the TMV1-Query expression; nothing is escaped."""
    return f'{field}:"{value}"'


def endpoint_clause(endpoint: dict, detections: bool = False) -> tuple[str | None, str]:
    guid = GUID.fullmatch(endpoint.get("guid") or "")
    if guid:
        return term("endpointGUID" if detections else "endpointGuid", guid[1].lower()), "endpoint GUID"
    name = endpoint.get("name") or ""
    if HOST.fullmatch(name):
        return term("endpointHostName", name), "endpoint host name (partial match upstream)"
    ip = next((address(ip) for ip in endpoint.get("ips", []) if address(ip)), None)
    if ip:
        return term("endpointIp", ip), "endpoint IP (partial match; shared/NAT addresses possible)"
    return None, "no validated endpoint identifier"


def basename(path: str) -> str:
    return path.replace("/", "\\").rstrip("\\").rsplit("\\", 1)[-1]


def indicator_pivots(parsed: dict) -> list[dict]:
    """Role-specific pivots from hashes and file paths in the alert itself."""
    pivots: list[dict] = []
    for item in parsed["observables"].get("hash", []):
        value = item["value"].lower()
        if not HASH.fullmatch(value):
            continue
        suffix = HASH_FIELDS[len(value)]
        roles = [item["role"]] if item["role"] in ("process", "object", "parent") else ["process", "object"]
        for role in roles:
            pivots.append({"tool": "search_endpoint_activities_list", "query": term(f"{role}{suffix}", value),
                           "purpose": f"{role} hash from {item['sources'][0]}", "match": ("hash", role, value)})
        if len(value) in (40, 64):
            pivots.append({"tool": "search_detections_list", "query": term("fileHash", value),
                           "purpose": f"detections of file hash from {item['sources'][0]}", "match": ("hash", "object", value)})
    for item in parsed["observables"].get("path", []):
        name = basename(item["value"])
        if not TOKEN.fullmatch(name):
            continue
        role = item["role"] if item["role"] in ("process", "object", "parent") else "object"
        pivots.append({"tool": "search_endpoint_activities_list", "query": term(f"{role}FilePath", name),
                       "purpose": f"{role} file name from {item['sources'][0]} (exact path checked after retrieval)",
                       "match": ("path", role, item["value"])})
    return pivots[:MAX_INDICATOR_PIVOTS]


def classify(record: dict, parsed: dict, endpoints: list[dict]) -> tuple[str, list[str]]:
    """linked > identifier_match > context; the reasons name the exact fields compared."""
    if record.get("uuid") and record["uuid"] in parsed["matched_event_uuids"]:
        return "linked", ["record uuid listed in matchedRules.matchedFilters.matchedEvents"]
    reasons = []
    hashes = {o["value"].lower() for o in parsed["observables"].get("hash", [])}
    for role in ("process", "object", "parent"):
        for name, value in full_hashes(record.get(role, {})).items():
            if value in hashes:
                reasons.append(f"{role}.{name} equals an alert hash")
    det = record.get("detection_file", {})
    if isinstance(det.get("fileHash"), str) and det["fileHash"].lower() in hashes:
        reasons.append("detection fileHash equals an alert hash")
    paths = {o["value"].lower() for o in parsed["observables"].get("path", [])}
    for role in ("process", "object", "parent"):
        path = record.get(role, {}).get("filePath")
        if isinstance(path, str) and path.lower() in paths:
            reasons.append(f"{role}.filePath equals an alert path")
    commands = {o["value"] for o in parsed["observables"].get("command", [])}
    for role in ("process", "object", "parent"):
        if record.get(role, {}).get("cmd") in commands:
            reasons.append(f"{role}.cmd equals an alert command line")
    same_endpoint = any((e.get("guid") and str(record.get("endpoint_guid") or "").lower().strip("{}") ==
                         e["guid"].lower().strip("{}")) or
                        (e.get("name") and str(record.get("endpoint_host") or "").lower() == e["name"].lower())
                        for e in endpoints)
    if reasons and (same_endpoint or not endpoints):
        return "identifier_match", reasons + (["same endpoint"] if same_endpoint else [])
    return "context", (["same endpoint and time window only"] if same_endpoint else ["time window only"])


def summary(record: dict) -> dict:
    """Bounded display view; analysis uses the full normalized record."""
    view = {"tool": record["tool"], "uuid": record.get("uuid"), "time_utc": record.get("event_time_utc"),
            "endpoint_guid": record.get("endpoint_guid"), "endpoint_host": record.get("endpoint_host"),
            "endpoint_ips": record.get("endpoint_ips"), "event": record.get("event", {}),
            "cut_by_bridge": record.get("cut_by_bridge", [])}
    for role in ("process", "parent", "object", "logon", "network", "detection_file"):
        group = record.get(role)
        if group:
            view[role] = {k: (preview(v) if isinstance(v, str) and len(v) > 300 else v) for k, v in group.items()}
    return view


def window_for(anchor: dict) -> tuple[datetime, datetime, str]:
    when = parse(anchor.get("time_utc"))[0]
    if anchor.get("provisional"):
        return (when - timedelta(minutes=60), when + timedelta(minutes=15),
                "anchor is provisional (alert creation or candidate): window extends 60 min before it")
    return when - timedelta(minutes=15), when + timedelta(minutes=15), "anchor is an event/match time: ±15 min"


async def discover(vision: Any, budget: Budget, parsed: dict, anchor: dict) -> dict:
    from .diagnostics import collection_failure
    out = {"logic": "alert-entities-v3", "pivots": [], "oat": [], "instance_followups": [],
           "warnings": [], "continuation": []}
    collected = []
    try:
        return await _discover(vision, budget, parsed, anchor, out, collected)
    except Exception as exc:
        error = collection_failure("Trend Search/OAT", exc)
        out["error"] = error
        out["discovery_status"] = "partial: interrupted"
        out["warnings"].append(f"Trend Search/OAT interrupted ({error['category']}); earlier records preserved")
        out["continuation"].append({"action": "resolve_collection_failure", "stage": "Trend Search/OAT",
                                    "retryable": error["retryable"]})
        return _finish(out, collected, parsed, parsed["endpoints"][:MAX_ENDPOINTS])


async def _discover(vision, budget, parsed, anchor, out, collected):
    endpoints = parsed["endpoints"][:MAX_ENDPOINTS]
    if len(parsed["endpoints"]) > MAX_ENDPOINTS:
        out["warnings"].append(f"Endpoint cap: {MAX_ENDPOINTS} of {len(parsed['endpoints'])} endpoints searched")
    out["endpoints"] = endpoints
    if not anchor.get("time_utc"):
        out["discovery_status"] = "skipped: no usable time anchor"
        return _finish(out, [], parsed, endpoints)
    start, end, why = window_for(anchor)
    out["window"] = {"start": vision_search._iso(start), "end": vision_search._iso(end), "justification": why}
    seen: dict = {}
    broad: list[dict] = []
    for endpoint in endpoints:
        clause, basis = endpoint_clause(endpoint)
        if clause:
            broad.append({"tool": "search_endpoint_activities_list", "query": clause,
                          "purpose": f"endpoint activity by {basis}", "priority": "broad context"})
            det_clause, _ = endpoint_clause(endpoint, detections=True)
            broad.append({"tool": "search_detections_list", "query": det_clause, "purpose": f"detections by {basis}",
                          "priority": "broad context"})
        else:
            out["warnings"].append(f"Endpoint from {endpoint['sources'][0]}: {basis}; not searched")
    scoped = [e for e in endpoints if endpoint_clause(e)[0]]
    specific: list[dict] = []
    for pivot in indicator_pivots(parsed):
        # One pivot per endpoint: no endpoint is picked silently over the others.
        for endpoint in scoped or [None]:
            clause = endpoint_clause(endpoint, pivot["tool"] == "search_detections_list")[0] if endpoint else None
            query = f"{clause} and {pivot['query']}" if clause else pivot["query"]
            specific.append({**pivot, "query": query, "priority": "specific identifier",
                             "purpose": pivot["purpose"] + ("" if clause else " (no endpoint scope: results are candidates)")})
    if not specific and not broad:
        out["discovery_status"] = "no identifiers in the alert detail to search with"
        out["warnings"].append("No endpoint, hash or file path was extracted; no bounded search is justified")
        return _finish(out, [], parsed, endpoints)
    out["priority_order"] = ["alert hashes/paths on the alert endpoints", "process instances found by them",
                             "OAT for the alert endpoints", "endpoint-wide activity and detections",
                             "process instances found only in endpoint-wide activity"]
    followed: set = set()

    async def run(plans: list[dict]) -> None:
        for plan in plans:
            finding = await vision_search.search(vision, budget, plan["tool"], plan["query"], start, end,
                                                 purpose=plan["purpose"], count=False, seen=seen)
            out["pivots"].append({k: v for k, v in finding.items() if k != "records"} | {"priority": plan["priority"]})
            out["continuation"].extend(finding["continuation"])
            collected.extend(finding["records"])

    async def follow() -> None:
        instances = {}
        for record in collected:
            label, _ = classify(record, parsed, endpoints)
            if label not in ("linked", "identifier_match") or not endpoint_identity(record):
                continue
            for role, field in (("process", "hashId"), ("object", "processHashId")):
                hash_id = record.get(role, {}).get(field)
                if isinstance(hash_id, str) and INSTANCE_ID.fullmatch(hash_id):
                    key = (endpoint_identity(record), hash_id)
                    if key in followed:
                        continue
                    instance = instances.setdefault(key, {"record": record, "id": hash_id, "roles": []})
                    if role not in instance["roles"]:
                        instance["roles"].append(role)
        room = MAX_INSTANCES - len(followed)
        if len(instances) > room:
            out["warnings"].append(f"Process-instance cap: {MAX_INSTANCES} instances followed in total; "
                                   f"{len(instances) - max(room, 0)} not followed")
        for key, instance in list(instances.items())[:max(room, 0)]:
            followed.add(key)
            hash_id, record = instance["id"], instance["record"]
            scope, _ = endpoint_clause({"guid": record.get("endpoint_guid"), "name": record.get("endpoint_host"),
                                        "ips": record.get("endpoint_ips", [])})
            if not scope:
                out["warnings"].append("Process-instance followup skipped: no validated endpoint scope")
                continue
            when = parse(record.get("event_time_raw"))[0] or start
            finding = await vision_search.search(vision, budget, "search_endpoint_activities_list",
                                                 f"{scope} and {term('processHashId', hash_id)}", when - timedelta(minutes=1),
                                                 when + timedelta(minutes=60), purpose="later activity of the same process instance",
                                                 seen=seen)
            out["instance_followups"].append({k: v for k, v in finding.items() if k != "records"} |
                                             {"process_hash_id": hash_id, "source_roles": instance["roles"],
                                              "endpoint": endpoint_identity(record)})
            out["continuation"].extend(finding["continuation"])
            collected.extend(finding["records"])

    await run(specific)
    await follow()
    for endpoint in endpoints:
        guid = GUID.fullmatch(endpoint.get("guid") or "")
        name = endpoint.get("name") or ""
        expr = (f"agentGuid eq '{guid[1].lower()}'" if guid else
                f"endpointName eq '{name}'" if HOST.fullmatch(name) else None)
        if expr:
            result = await vision_search.oat(vision, budget, expr, start, end)
            for item in result["items"]:
                item["link"] = ("linked by uuid" if item.get("uuid") in parsed["matched_event_uuids"]
                                else "candidate (same endpoint and window)")
            out["oat"].append(result)
    await run(broad)
    await follow()
    return _finish(out, collected, parsed, endpoints)


def _finish(out: dict, collected: list[dict], parsed: dict, endpoints: list[dict]) -> dict:
    classes: dict[str, list[dict]] = {"linked": [], "identifier_match": [], "context": []}
    for record in collected:
        label, reasons = classify(record, parsed, endpoints)
        record["relation"] = {"label": label, "reasons": reasons}
        classes[label].append(record)
    out["records_all"] = collected  # full values for analysis; never rendered whole
    out["records"] = {label: [summary(r) | {"relation": r["relation"]} for r in items[:MAX_LISTED]]
                      for label, items in classes.items()}
    out["record_counts"] = {label: len(items) for label, items in classes.items()}
    calls = sum(len(p.get("partitions", [])) for p in out["pivots"] + out["instance_followups"])
    out["search_calls"] = calls
    out["search_rows"] = len(collected)
    out["candidates"] = len(classes["identifier_match"])
    out["search_field"] = next((p["query"].split(":", 1)[0].rsplit(" ", 1)[-1] for p in out["pivots"]
                                if p.get("records_fetched")), None)
    hosts = sorted({e["name"] for e in endpoints if e.get("name")})
    hashes = sorted({o["value"].lower() for o in parsed["observables"].get("hash", []) if HASH.fullmatch(o["value"])})
    out["host"] = hosts[0] if len(hosts) == 1 else ""
    out["hash"] = hashes[0] if len(hashes) == 1 else ""
    if len(hosts) > 1 or len(hashes) > 1:
        out["warnings"].append("Multiple endpoints or hashes: none was chosen silently; each was searched or listed")
    linked_times = sorted(r["event_time_utc"] for r in classes["linked"] if r.get("event_time_utc"))
    out["event_time"] = linked_times[0] if linked_times else None
    out["ips"] = sorted({ip for e in endpoints for ip in e.get("ips", [])})
    out["source"] = ("records linked by matchedEvents uuid" if classes["linked"] else
                     "identifier matches (candidates)" if classes["identifier_match"] else "none")
    out.setdefault("discovery_status", "linked evidence found" if classes["linked"] else
                   "identifier-matched candidates only" if classes["identifier_match"] else
                   "context records only (no link to the alert demonstrated)" if collected else
                   "searches returned no records in the inspected window")
    return out
