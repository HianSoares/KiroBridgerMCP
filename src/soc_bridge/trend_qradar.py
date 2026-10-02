"""Trend -> QRadar with the budgeted Ariel collector: short window first, explicit epochs, labelled relations.

IPs are queried one by one with their provenance (alert entity, endpoint record or
analyst). A shared/public IP or a host name in text does not tie a QRadar event to
the Trend process. Relations need the same host plus independent process identifiers;
a Trend endpoint GUID and a Sysmon ProcessGuid are different identifiers and are never compared.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta
from typing import Any

from . import focused_queries
from .aql_fields import EVENT_COLUMNS, FLOW_COLUMNS, LOGICAL_FIELDS, FieldCatalog, load_catalog, plan_select
from .ariel_collection import Budget, BudgetExhausted, collect_query
from .offense_evidence import query_tail
from .process_chain import HOST, same_host
from .time_anchor import parse, utc_ms
from .windows_events import extract, parse_hashes, value_of

MAX_IPS = 4
STAGE1 = timedelta(minutes=2)
STAGE2 = timedelta(minutes=30)
TIME_TOLERANCE = 2.0


def candidate_ips(parsed: dict, discovery: dict, manual_ip: str | None) -> list[dict]:
    found: dict[str, dict] = {}

    def add(ip: str, source: str) -> None:
        try:
            parsed_ip = ipaddress.ip_address(ip)
        except ValueError:
            return
        entry = found.setdefault(str(parsed_ip), {"ip": str(parsed_ip), "sources": [], "version": parsed_ip.version,
                                                  "private": parsed_ip.is_private})
        entry["sources"].append(source)

    if manual_ip:
        add(manual_ip, "analyst-supplied View event (unverified by the bridge)")
    for endpoint in parsed["endpoints"]:
        for ip in endpoint.get("ips", []):
            add(ip, f"alert endpoint entity {endpoint.get('name') or endpoint.get('guid')}")
    for record in discovery.get("records_all", []):
        if record.get("relation", {}).get("label") in ("linked", "identifier_match"):
            for ip in record.get("endpoint_ips", []):
                add(ip, f"endpoint IP in Trend record {record.get('uuid')}")
    ordered = sorted(found.values(), key=lambda e: (not e["private"], e["ip"]))
    for entry in ordered:
        entry["attribution"] = ("interface reported for the endpoint; historical assignment (DHCP/NAT/VPN) unverified"
                                if entry["private"] else
                                "public/shared address: NAT or egress possible; not an endpoint identity")
    return ordered


def _qradar_records(finding: dict, plan: Any) -> list[dict]:
    out = []
    for index, row in enumerate(finding.get("rows", [])):
        record = extract(row, plan.property_map(), finding.get("truncated_rows", {}).get(str(index), []))
        if record["event_id"] is None:
            continue
        hashes = parse_hashes(value_of(record, "Hashes") or "") if value_of(record, "Hashes") else {}
        out.append({"event_id": record["event_id"], "computer": value_of(record, "Computer"),
                    "image": value_of(record, "Image"), "command": value_of(record, "CommandLine"),
                    "pid": value_of(record, "ProcessId"), "utc_time": value_of(record, "UtcTime"),
                    "sha256": (hashes.get("SHA256") or {}).get("value") if (hashes.get("SHA256") or {}).get("comparable") else None,
                    "process_guid_sysmon": value_of(record, "ProcessGuid"),
                    "provenance": {"query": finding["scope"], "search_id": finding.get("search_id"),
                                   "result_row_index": index, "starttime_utc": utc_ms(row.get("starttime"))},
                    "payload_truncated_by_bridge": record["payload_truncated_by_bridge"]})
    return out


def relate(trend: dict, qr: dict) -> dict:
    """File equality is a lead; confirmation needs a compatible process creation."""
    host = same_host((trend.get("endpoint_host") or "").lower() or None, (qr.get("computer") or "").lower() or None)
    matched, roles, execution = [], [], {}
    trend_time = parse(trend.get("event_time_raw"))[0]
    qr_time = parse(qr.get("utc_time"))[0]
    for role in ("process", "object"):
        group = trend.get(role, {})
        hits = []
        if group.get("filePath") and qr.get("image") and group["filePath"].lower() == qr["image"].lower():
            hits.append("image path equal")
        if group.get("cmd") and qr.get("command") and group["cmd"] == qr["command"]:
            hits.append("command line equal")
        pid_equal = group.get("pid") is not None and qr.get("pid") is not None and str(group["pid"]) == str(qr["pid"])
        launch_time = parse(group.get("launchTime"))[0]
        comparable = (qr.get("event_id") == 1 and pid_equal and launch_time and qr_time and trend_time
                      and launch_time <= trend_time and abs((launch_time - qr_time).total_seconds()) <= TIME_TOLERANCE
                      and not trend.get("cut_by_bridge") and not qr.get("payload_truncated_by_bridge"))
        role_execution = {"pid_equal": bool(pid_equal), "trend_launch_time_utc": utc_ms(launch_time),
                          "qradar_utc_time": utc_ms(qr_time), "compatible_creation": bool(comparable)}
        if comparable:
            hits.append(f"PID and launch time equal within {TIME_TOLERANCE:.0f}s of Sysmon process creation")
        sha = str(group.get("fileHashSha256") or "").lower()
        if qr.get("sha256") and len(sha) == 64 and sha == qr["sha256"].lower():
            hits.append("full SHA-256 equal")
        has_content = any(hit in hits for hit in ("image path equal", "command line equal", "full SHA-256 equal"))
        selected_content = any(hit in matched for hit in ("image path equal", "command line equal", "full SHA-256 equal"))
        score = (role_execution["compatible_creation"] and has_content, len(hits))
        selected_score = (execution.get("compatible_creation", False) and selected_content, len(matched))
        if score > selected_score:
            matched, roles, execution = hits, [role], role_execution
    content_match = any(hit in matched for hit in ("image path equal", "command line equal", "full SHA-256 equal"))
    if host and execution.get("compatible_creation") and content_match:
        label = "confirmed"
    elif host and matched:
        label = "candidate"
    else:
        label = "unverified"
    return {"label": label, "trend_uuid": trend.get("uuid"), "trend_role": roles[0] if roles else None,
            "qradar": qr["provenance"], "qradar_event_id": qr["event_id"], "same_host": host, "identifiers_equal": matched,
            "execution_match": execution,
            "criteria": ("confirmed = same host, equal PID, Trend role launchTime matching Sysmon EventID 1 UtcTime "
                         "within 2s, and a path/command/full hash match in that same role. File identity alone, missing "
                         "launch time or other event types remain candidates. Trend endpoint GUID and Sysmon ProcessGuid are "
                         "different identifiers and are not compared.")}


async def correlate(qradar: Any, budget: Budget, parsed: dict, discovery: dict, anchor: dict, now: datetime,
                    offset_hours: int = -3, timezone_verified: bool = False, manual_ip: str | None = None) -> dict:
    out: dict[str, Any] = {"ips": candidate_ips(parsed, discovery, manual_ip), "stages": [], "queries": {},
                           "qradar_records": [], "relations": [], "plan": [], "notes": []}
    when = parse(anchor.get("time_utc"))[0]
    if not when:
        out["notes"].append("No time anchor: QRadar correlation not run")
        return out
    ips = [e for e in out["ips"] if e["version"] == 4][:MAX_IPS]
    if any(e["version"] == 6 for e in out["ips"]):
        out["notes"].append("IPv6 addresses listed but not queried: the bridge has not verified QRadar IPv6 field names")
    if len(out["ips"]) > MAX_IPS:
        out["notes"].append(f"IP cap: {MAX_IPS} of {len(out['ips'])} addresses queried")
    try:
        catalog = await budget.run(lambda: load_catalog(qradar, "events"), "events field resource")
    except BudgetExhausted:
        catalog = FieldCatalog("events", "not_read_time_budget")
    out["field_catalog"] = catalog.describe()
    plan = plan_select(EVENT_COLUMNS, catalog, tuple(LOGICAL_FIELDS))
    flow_plan = plan_select(FLOW_COLUMNS, FieldCatalog("flows"))
    hosts = sorted({e["name"] for e in parsed["endpoints"] if e.get("name") and HOST.fullmatch(e["name"])})[:2]
    stages = [("stage1", STAGE1, "short window around the anchor")]
    for name, delta, why in stages:
        start, end = when - delta, min(when + delta, now)
        tail, scope = query_tail(start, end, offset_hours, timezone_verified, now)
        stage = {"stage": name, "window_utc": [utc_ms(start), utc_ms(end)], "why": why, "time_clause": scope}
        out["stages"].append(stage)
        if not tail:
            stage["state"] = "not_run"
            out["plan"].append({"action": "run_with_verified_timezone", "reason": scope.get("reason"),
                                "epoch_predicate": focused_queries.epoch_predicate(
                                    "starttime", int(start.timestamp() * 1000), int(end.timestamp() * 1000)),
                                "note": "Historical window: confirm the console offset, then run with START/STOP"})
            continue
        epochs = focused_queries.epoch_predicate("starttime", int(start.timestamp() * 1000), int(end.timestamp() * 1000))
        for entry in ips:
            ip = entry["ip"]
            where = f"(sourceip = '{ip}' OR destinationip = '{ip}') AND {epochs}"
            sql = f"FROM events WHERE {where} ORDER BY starttime ASC LIMIT 1000 {tail}"
            key = f"{name}:events:{ip}"
            finding = await collect_query(qradar, f"{plan.select()} {sql}", "events", key, budget,
                                          f"{plan.select(False)} {sql}" if plan.optional else None, plan)
            out["queries"][key] = finding
            out["qradar_records"].extend(_qradar_records(finding, plan))
            if name == "stage1":
                flow_epochs = focused_queries.epoch_predicate("firstpackettime", int(start.timestamp() * 1000),
                                                              int(end.timestamp() * 1000))
                flow_sql = (f"{flow_plan.select()} FROM flows WHERE (sourceip = '{ip}' OR destinationip = '{ip}') AND "
                            f"{flow_epochs} LIMIT 1000 {tail}")
                out["queries"][f"{name}:flows:{ip}"] = await collect_query(qradar, flow_sql, "flows",
                                                                           f"{name}:flows:{ip}", budget)
        if name == "stage1":
            for host in hosts:
                sql = (f"FROM events WHERE UTF8(payload) ILIKE '%{host}%' AND {epochs} ORDER BY starttime ASC "
                       f"LIMIT 200 {tail}")
                key = f"{name}:host_text:{host}"
                finding = await collect_query(qradar, f"{plan.select()} {sql}", "events", key, budget,
                                              f"{plan.select(False)} {sql}" if plan.optional else None, plan)
                out["queries"][key] = finding
                out["qradar_records"].extend(_qradar_records(finding, plan))
            found_any = any(q.get("returned_rows") for k, q in out["queries"].items() if ":events:" in k)
            if anchor.get("provisional") or not found_any:
                stages.append(("stage2", STAGE2, "hypothesis: " + (
                    "the anchor is provisional, so the event may lie outside the short window"
                    if anchor.get("provisional") else "nothing in the short window; widen once around the anchor")))
                ips = ips[:2]
                hosts = []
    trend_records = [r for r in discovery.get("records_all", [])
                     if r.get("relation", {}).get("label") in ("linked", "identifier_match")]
    for trend in trend_records[:50]:
        for qr in out["qradar_records"][:300]:
            relation = relate(trend, qr)
            if relation["label"] != "unverified" or relation["same_host"]:
                out["relations"].append(relation)
    if not out["relations"] and out["qradar_records"]:
        out["notes"].append("QRadar Windows records were found by IP/time or host text only: unverified relation to "
                            "the Trend process (IP/time or text overlap is not a process link)")
    for key, finding in out["queries"].items():
        if finding.get("continuation"):
            out["plan"].append({"query": key, **finding["continuation"]})
        finding.pop("rows", None)
    out["qradar_records"] = out["qradar_records"][:60]
    out["relations"] = out["relations"][:50]
    return out
