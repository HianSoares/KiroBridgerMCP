"""Offense-linked collection and evidence limits; never infer authorization from ports."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

from . import focused_queries, integrity_evidence, process_chain, linux_evidence, closure_assessment, lockout_evidence
from .aql_fields import EVENT_COLUMNS, FLOW_COLUMNS, LOGICAL_FIELDS, FieldCatalog, load_catalog, plan_select
from .ariel_collection import Budget, BudgetExhausted, collect_query, number
from .core import address, instant
from .offense_assessment import assess, gap, query_gaps
from .windows_events import extract

SEARCH_LIMIT = 5000
PAGE_LIMIT = 500
MAX_RULES = 20
MAX_PARENT_LOOKUPS = 4
RELEVANT_IDS = set(process_chain.CREATION_IDS) | set(process_chain.SCRIPT_IDS) | set(integrity_evidence.INTEGRITY_IDS)

__all__ = ["Budget", "collect_query", "collect_offense_evidence", "verify_offense", "render_evidence",
           "event_summary", "flow_summary", "host_summary", "query_tail", "utc"]


def utc(value: Any) -> str | None:
    stamp = value.astimezone(timezone.utc) if isinstance(value, datetime) else instant(value)
    return stamp.isoformat(timespec="milliseconds").replace("+00:00", "Z") if stamp else None


def interval(rows: list[dict], key: str) -> dict:
    stamps = [stamp for row in rows if (stamp := instant(row.get(key))) is not None]
    return {"start": utc(min(stamps)) if stamps else None,
            "end": utc(max(stamps)) if stamps else None, "clock": key}


def value(row: dict, key: str) -> Any:
    return next((v for k, v in row.items() if k.lower() == key.lower()), None)


def query_tail(start: datetime, end: datetime, offset: int, verified: bool,
               now: datetime) -> tuple[str | None, dict]:
    """Recent offenses use a relative window; historical local time needs verification."""
    scope = {"start_utc": utc(start), "end_utc": utc(end),
             "offset_hours": offset, "timezone_verified": verified}
    if timedelta(0) <= now - start < timedelta(hours=24) and end <= now:
        return "LAST 24 HOURS", {**scope, "mode": "relative", "search_window": "LAST 24 HOURS",
            "relative_anchor_utc": utc(now), "search_start_utc": utc(now - timedelta(hours=24)),
            "search_end_utc": utc(now), "offset_dependency": "none: LAST and epoch predicates do not use the local offset",
            "bounds_note": "Approximate anchor; LAST is evaluated when each job starts"}
    if not verified:
        return None, {**scope, "reason": "Historical/future window requires a verified QRadar timezone"}
    begin = start - timedelta(minutes=1)
    stop = end + timedelta(minutes=1)
    if stop - begin > timedelta(hours=24):
        return None, {**scope, "reason": "Raw offense interval exceeds 24 hours; partition bounded searches"}
    local_start, local_end = begin + timedelta(hours=offset), stop + timedelta(hours=offset)
    tail = f"START '{local_start:%Y-%m-%d %H:%M:%S}' STOP '{local_end:%Y-%m-%d %H:%M:%S}'"
    return tail, {**scope, "mode": "absolute", "search_window": tail,
                  "offset_dependency": "START/STOP are console-local: requires the verified offset",
                  "search_start_utc": utc(begin), "search_end_utc": utc(stop)}


def event_summary(rows: list[dict]) -> dict:
    groups = Counter((str(row.get("event_name") or "unknown"),
                      str(row.get("log_source") or "unknown")) for row in rows)
    return {"observed_interval": interval(rows, "starttime"),
            "groups": [{"event_name": name, "log_source": source, "rows": count}
                       for (name, source), count in groups.most_common(50)],
            "groups_omitted": max(0, len(groups) - 50),
            "count_unit": "Ariel rows; not assumed equivalent to offense event_count"}


def flow_summary(rows: list[dict]) -> dict:
    destinations: set[str] = set()
    groups: dict[tuple, dict] = {}
    for row in rows:
        dst = address(row.get("destinationip"))
        if dst:
            destinations.add(dst)
        key = tuple(number(row.get(k)) for k in ("protocolid", "sourceport", "destinationport"))
        group = groups.setdefault(key, {"rows": 0, "destinations": set(),
                                        "sourcebytes": 0, "destinationbytes": 0,
                                        "missing_byte_fields": 0})
        group["rows"] += 1
        if dst:
            group["destinations"].add(dst)
        for field in ("sourcebytes", "destinationbytes"):
            count = number(row.get(field))
            if count is None:
                group["missing_byte_fields"] += 1
            else:
                group[field] += count
    port_groups = [{"protocolid": key[0], "sourceport": key[1], "destinationport": key[2],
                   "rows": group["rows"], "distinct_destinations": len(group["destinations"]),
                   "sourcebytes": group["sourcebytes"], "destinationbytes": group["destinationbytes"],
                   "missing_byte_fields": group["missing_byte_fields"]}
                  for key, group in groups.items()]
    dhcp = bool(rows) and all(key[0] == 17 and key[1] == 67 and key[2] in (67, 68) for key in groups)
    return {"port_groups": port_groups[:100], "port_groups_omitted": max(0, len(port_groups) - 100),
            "distinct_destinations_in_collected_rows": len(destinations),
            "destinations_sample": sorted(destinations)[:100],
            "destinations_omitted": max(0, len(destinations) - 100),
            "observed_interval": interval(rows, "firstpackettime"),
            "dhcp_port_pattern": dhcp,
            "interpretation": "Ports describe compatibility only; destination roles and authorization are unverified",
            "zero_rows_note": "Zero INOFFENSE flows does not show the host or a process had no communication",
            "return_bytes_semantics": "Zero destinationbytes means no return bytes observed by this flow source"}


def host_summary(rows: list[dict]) -> dict:
    attempts, commands, lengths = [], [], Counter()
    for row in rows:
        payload = str(row.get("raw_payload") or "")
        if payload:
            lengths[len(payload)] += 1
        event_id = re.search(r'(?:EventID|Event ID|EventCode)\s*[:=]\s*"?(\d+)', payload, re.I)
        if not event_id:
            event_id = re.search(r'<EventID[^>]*>(\d+)</EventID>', payload, re.I)
        if event_id and event_id[1] == "4648" and len(attempts) < 20:
            attempts.append({"starttime": row.get("starttime"), "time_utc": utc(row.get("starttime")),
                             "event_id": 4648, "qid_name": row.get("event_name"),
                             "username_as_reported": row.get("username"),
                             "meaning": "Explicit credential attempt; outcome and service attribution unverified"})
        for match in re.finditer(r'-(?:EncodedCommand|enc)\s+([A-Za-z0-9+/=]+)', payload, re.I):
            if len(commands) >= 20:
                break
            blob = match[1]
            decoded = None
            try:
                decoded = base64.b64decode(blob, validate=True).decode("utf-16le")
            except (ValueError, binascii.Error, UnicodeError):
                pass
            commands.append({"time_utc": utc(row.get("starttime")), "base64_observed": blob[:2048],
                             "decoded_utf16le": decoded[:2048] if decoded else decoded,
                             "preview_truncated": len(blob) > 2048 or bool(decoded and len(decoded) > 2048),
                             "completeness": "Not proven by successful decoding; compare original record",
                             "executed_by_bridge": False})
    return {"explicit_credential_attempts": attempts, "encoded_commands": commands,
            "payload_lengths": [{"characters": size, "rows": count} for size, count in lengths.most_common(10)],
            "payload_limit_component": "Unknown; compare Ariel, console, collector and original record",
            "attribution": "IP/time context only; null custom properties do not prove data absent",
            "no_anomaly_claim_permitted": False}


def record_identity(row: dict, record: dict) -> tuple[tuple | None, str]:
    """Identity of one stored record, or None when the evidence cannot tell two records apart.

    Same origin (log source), stored and device times, event ID, host/provider/channel
    and record number when present, plus identical content (payload, or the selected
    properties for payload-less rows). Missing parts make the key stricter, never looser.
    """
    origin, stored = row.get("log_source"), row.get("starttime")
    if origin in (None, "") or stored is None:
        return None, "kept separate: log source or stored time missing"
    payload = row.get("raw_payload")
    if isinstance(payload, str) and payload:
        content = "payload:" + hashlib.sha256(payload.encode("utf-8", "replace")).hexdigest()
    else:
        properties = sorted((k, v["value"]) for k, v in record["fields"].items() if v["source"].startswith("property:"))
        if not properties:
            return None, "kept separate: no payload or selected properties to compare"
        content = "properties:" + hashlib.sha256(json.dumps(properties).encode("utf-8")).hexdigest()
    fields = record["fields"]
    parts = {"log_source": str(origin), "starttime": stored, "devicetime": row.get("devicetime"),
             "event_id": record["event_id"], "content": content}
    for name in ("Computer", "Provider", "Channel", "RecordNumber"):
        if name in fields:
            parts[name] = fields[name]["value"].lower()
    return tuple(sorted((k, str(v)) for k, v in parts.items())), "matched on " + ", ".join(sorted(parts))


def _records(name: str, finding: dict, property_map: dict, seen: dict) -> list[dict]:
    """Parse relevant Windows records with provenance; the same record from two queries is kept once."""
    out = []
    for index, row in enumerate(finding.get("rows", [])):
        record = extract(row, property_map, finding.get("truncated_rows", {}).get(str(index), []))
        if record["event_id"] not in RELEVANT_IDS:
            continue
        key, basis = record_identity(row, record)
        provenance = {"query": name, "scope": finding["scope"], "search_id": finding.get("search_id"),
                      "result_row_index": index, "starttime": row.get("starttime"),
                      "starttime_utc": utc(row.get("starttime")), "devicetime_utc": utc(row.get("devicetime")),
                      "qid_name": row.get("event_name"), "log_source": row.get("log_source"),
                      "event_id_source": record["event_id_source"], "payload_format": record["payload_format"],
                      "identity": basis}
        if key is not None and key in seen:
            seen[key]["provenance"].setdefault("also_returned_by", []).append(
                {"query": name, "scope": finding["scope"], "search_id": finding.get("search_id"),
                 "result_row_index": index})
            continue
        record["provenance"] = provenance
        if key is not None:
            seen[key] = record
        out.append(record)
    return out


async def collect_offense_evidence(qradar: Any, offense: dict, offset_hours: int = -3,
                                   timezone_verified: bool = False, now: datetime | None = None,
                                   budget: Budget | None = None, confirmations: list | None = None,
                                   resume: dict | None = None, rerun: set[str] | None = None,
                                   closure_options: dict | None = None, keep_rows: bool = False) -> dict:
    """Collect linked records, flow census, rules, host context and evidence-triggered pivots.

    ``resume`` maps query names to saved findings (with rows): known jobs continue from their
    cursor, complete ones are reused, uncertain creations are not recreated. ``rerun`` names
    queries the analyst explicitly asked to start again as new jobs."""
    oid = offense.get("id")
    if isinstance(oid, bool) or not isinstance(oid, int) or oid < 1:
        raise ValueError("Positive integer offense ID required")
    if isinstance(offset_hours, bool) or not isinstance(offset_hours, int) or not -12 <= offset_hours <= 14:
        raise ValueError("QRadar offset must be an integer between -12 and 14")
    if not isinstance(timezone_verified, bool):
        raise ValueError("timezone_verified must be a boolean")
    if budget is not None and not isinstance(budget, Budget):
        raise ValueError("budget must be a Budget")
    budget = budget or Budget()
    now = now or datetime.now(timezone.utc)
    start = instant(offense.get("start_time") or offense.get("first_event_flow_seen"))
    end = instant(offense.get("last_updated_time") or offense.get("last_event_flow_seen")) or start
    result: dict = {"offense_id": oid, "collected_at": utc(now),
        "metadata": {key: offense.get(key) for key in ("id", "description", "status", "magnitude",
            "severity", "credibility", "relevance", "event_count", "flow_count", "start_time",
            "last_updated_time", "close_time", "closing_reason_id", "rules", "offense_source")},
        "metadata_interval": {"start": utc(start), "end": utc(end), "padding_seconds": 0},
        "queries": {}, "rules": [], "warnings": [], "gaps": [], "gap_details": [],
        "field_catalogs": {}, "focused_queries": {}, "continuation_plan": []}

    def add_gap(text: str, gap_id: str, scope: str, state: str, blocks: list[str], action: str = "",
                evidence: dict | None = None) -> None:
        result["gaps"].append(text)
        result["gap_details"].append(gap(gap_id, scope, state, blocks, evidence, action, text))

    catalogs = {}
    for db in ("events", "flows"):
        try:
            catalogs[db] = await budget.run(lambda: load_catalog(qradar, db), f"{db} field resource")
        except BudgetExhausted:
            catalogs[db] = FieldCatalog(db, "not_read_time_budget")
    for db, catalog in catalogs.items():
        result["field_catalogs"][db] = catalog.describe()
        if catalog.state != "available":
            result["warnings"].append(f"{db} field resource unavailable or unparsed; optional properties not "
                                      "requested; canonical SELECT still requires QRadar validation")
    event_plan = plan_select(EVENT_COLUMNS, catalogs["events"], tuple(LOGICAL_FIELDS))
    flow_plan = plan_select(FLOW_COLUMNS, catalogs["flows"])
    plans: dict[str, Any] = {}

    async def run(name: str, query: str, database: str, scope: str, plan: Any, fallback: str | None) -> dict:
        saved = (resume or {}).get(name)
        if saved is not None and name not in (rerun or set()) and (
                saved.get("search_id") or saved.get("outcome") in ("creation_uncertain", "empty", "complete_in_window")):
            finding = await collect_query(qradar, query, database, scope, budget, fallback, plan, resume=saved)
            if finding.get("aql") != query and finding.get("aql") != fallback:
                finding.setdefault("warnings", []).append(
                    "Resumed the saved job: its AQL differs from the one this run would plan (window/time changed)")
        else:
            finding = await collect_query(qradar, query, database, scope, budget, fallback, plan)
        result["queries"][name] = finding
        plans[name] = plan
        return finding

    tail = None
    if start and end and end >= start:
        tail, result["linked_window"] = query_tail(start, end, offset_hours, timezone_verified, now)
    else:
        result["linked_window"] = {"reason": "Missing or invalid offense metadata interval"}
    if tail:
        # INOFFENSE association, never a source-IP substitute. No local offset for recent cases.
        where = f"WHERE INOFFENSE({oid}) LIMIT {SEARCH_LIMIT} {tail}"
        await run("events", f"{event_plan.select()} FROM events {where}", "events", "offense_linked",
                  event_plan, f"{event_plan.select(False)} FROM events {where}" if event_plan.optional else None)
        # Prioritize account evidence before network context when 4740 is actually observed.
        linked_lockouts = lockout_evidence.analyze(result["queries"].get("events"), "events")
        result["lockout"] = linked_lockouts
        if linked_lockouts["detected"]:
            context_start, context_end = start - timedelta(minutes=15), min(end + timedelta(minutes=15), now)
            context_tail, context_window = query_tail(context_start, context_end, offset_hours, timezone_verified, now)
            result["lockout"]["context_window"] = context_window
            if context_tail:
                spec = lockout_evidence.pivot(event_plan, context_tail,
                    int(context_start.timestamp() * 1000), int(context_end.timestamp() * 1000), linked_lockouts)
                result["focused_queries"]["lockout_authentication"] = focused_queries.describe(spec, "Parsed 4740 target account")
                if isinstance(spec, dict):
                    finding = await run("lockout_authentication", spec["query"], "events", spec["scope"], event_plan, spec["fallback"])
                    context = lockout_evidence.analyze(finding, "lockout_authentication")
                    result["lockout"]["authentication_candidates"] = lockout_evidence.correlate(linked_lockouts, context)
                    result["lockout"]["candidate_limit"] = 100
                    result["lockout"]["candidate_limit_reached"] = len(result["lockout"]["authentication_candidates"]) == 100
                    result["lockout"]["lockouts_not_correlated_due_to_cap"] = max(0, linked_lockouts["event_id_counts"].get(4740, 0) - 100)
                    result["lockout"]["context"] = {k: v for k, v in context.items() if k != "records_for_analysis"}
                    result["lockout"]["accounts_omitted_from_pivot"] = spec["accounts_omitted"]
            else:
                result["lockout"]["context_not_collected"] = context_window.get("reason")
        result.get("lockout", {}).pop("records_for_analysis", None)
        if result.get("lockout", {}).get("detected"):
            result["lockout"]["root_cause_assessment"] = {
                "state": "unverified", "confidence": "insufficient for root cause or closure",
                "hypotheses": [
                    {"hypothesis": "Stored credentials in a service/task/application", "state": "open",
                     "required_evidence": "Caller identity, owning process/task and credential configuration; post-remediation observations"},
                    {"hypothesis": "Unauthorized authentication attempts", "state": "open",
                     "required_evidence": "Observed failure codes, verified source and session/process attribution, authorization and behavior"},
                    {"hypothesis": "Detection/attribution issue", "state": "open",
                     "required_evidence": "Active CRE tests, original target-account records and count/window reconciliation"}],
                "note": "Recurrence or an account name alone does not distinguish these hypotheses."}

        await run("flows", f"{flow_plan.select()} FROM flows {where}", "flows", "offense_linked", flow_plan, None)
        await run("flow_census", "SELECT COUNT(*) AS total_rows, UNIQUECOUNT(destinationip) AS "
                  f"distinct_destinations FROM flows {where}", "flows", "offense_linked", None, None)
    else:
        add_gap(result["linked_window"]["reason"], "linked-window", "offense_linked", "not_collected",
                ["benign_verdict", "complete_offense_record_review", "offense_network_claims"],
                "Confirm the console timezone (timezone_verified=true) or partition the interval")

    events = result["queries"].get("events", {}).get("rows", [])
    flows = result["queries"].get("flows", {}).get("rows", [])
    result["events"] = event_summary(events)
    result["flows"] = flow_summary(flows)
    census = result["queries"].get("flow_census", {})
    result["flows"]["census"] = census.get("rows", [])[:1]
    result["flows"]["census_record_count"] = census.get("record_count")
    result["flows"]["census_semantics"] = ("record_count counts aggregation groups; total_rows is the COUNT(*) "
                                           "column. Without a returned row no numeric value is inferred.")
    if census.get("result_set_complete") and len(census.get("rows", [])) == 1:
        census_row = census["rows"][0]
        result["flows"]["distinct_destinations_in_search"] = number(value(census_row, "distinct_destinations"))
        result["flows"]["total_rows_in_search"] = number(value(census_row, "total_rows"))
        if (result["queries"].get("flows", {}).get("result_set_complete") and
                (number(value(census_row, "total_rows")) != len(flows) or
                 number(value(census_row, "distinct_destinations")) != result["flows"]["distinct_destinations_in_collected_rows"])):
            add_gap("Flow census and fetched rows differ; reconcile snapshots/coverage", "census:mismatch",
                    "offense_linked", "unreconciled", ["offense_network_claims", "dhcp_pattern"],
                    "Compare windows/snapshots; do not assign a cause")
    elif census:
        result["flows"]["distinct_destinations_in_search"] = None
        result["flows"]["total_rows_in_search"] = None
        add_gap("Flow COUNT/UNIQUECOUNT census unavailable or invalid", "census:unavailable", "offense_linked",
                census.get("outcome", "unavailable"), ["offense_network_claims", "dhcp_pattern"],
                (census.get("continuation") or {}).get("note", "Resume or re-run the census when it can change a conclusion"))
    result["count_comparison"] = {database: {"metadata_count": offense.get(f"{singular}_count"),
        "collected_ariel_rows": len(result["queries"].get(database, {}).get("rows", [])),
        "status": "unresolved", "explanation": "Different units/windows/snapshots; no assumed coalescing cause"}
        for database, singular in (("events", "event"), ("flows", "flow"))}
    for database in ("events", "flows"):
        finding = result["queries"].get(database, {})
        comparison = result["count_comparison"][database]
        if finding.get("result_set_complete") and comparison["metadata_count"] == comparison["collected_ariel_rows"]:
            comparison["status"] = "numbers_match_in_window; unit equivalence not proven"
        else:
            add_gap(f"{database} coverage/count reconciliation unresolved", f"count:{database}", "offense_linked",
                    "unreconciled", ["benign_verdict"], "Reconcile units, window and snapshot before comparing")
    refs = offense.get("rules")
    if not isinstance(refs, list) or not refs:
        add_gap("Contributing rule IDs not returned in offense metadata", "rules:ids", "rules", "not_returned",
                ["benign_verdict", "detection_error_assessment"], "Read the offense in the console")
        refs = []
    if len(refs) > MAX_RULES:
        add_gap("Contributing rule metadata cap reached", "rules:cap", "rules", "limited", ["benign_verdict"])
    for ref in refs[:MAX_RULES]:
        if not isinstance(ref, dict) or number(ref.get("id")) is None or number(ref.get("id")) < 0:
            add_gap("Invalid contributing rule reference", "rules:invalid", "rules", "invalid", ["benign_verdict"])
            continue
        entry = {"id": number(ref["id"]), "type": ref.get("type"), "state": "unavailable"}
        try:
            details = await budget.run(lambda: qradar.call("get_rule", {"rule_id": entry["id"]}), "rule metadata")
            if not isinstance(details, dict) or number(details.get("id")) != entry["id"]:
                raise ValueError("Rule metadata ID mismatch")
            entry.update(state="collected", metadata=details)
        except BudgetExhausted as exc:
            entry.update(state="not_read", reason=f"Rule metadata not read: {exc}")
        except Exception as exc:
            entry["reason"] = f"Rule metadata unavailable ({type(exc).__name__})"
        result["rules"].append(entry)
    add_gap("Rule metadata/event text does not establish the complete active CRE tests or responses",
            "rules:cre-definition", "rules", "outside_bridge", ["benign_verdict"],
            "Read the active rule tests/responses in the QRadar rule editor")

    # Count every retrieved Linux record before witness samples are clipped.
    linux_linked = linux_evidence.analyze(result["queries"].get("events"), "events")
    result["linux"] = {"detected": bool(linux_linked["daemon_rows"]), "offense": linux_linked}
    if linux_linked["daemon_rows"] and start and end and end >= start:
        strict_end = min(end, now)
        strict_tail, strict_window = query_tail(start, strict_end, offset_hours, timezone_verified, now)
        if strict_end < start:
            strict_tail = None
            strict_window["reason"] = "Offense interval starts after collection time; no observable strict window"
        result["linux"]["strict_window"] = {**strict_window, "basis": "Frozen offense metadata snapshot; no padding"}
        if strict_tail:
            bounds = (int(start.timestamp() * 1000), int(strict_end.timestamp() * 1000))
            linux_plan = plan_select(EVENT_COLUMNS, catalogs["events"])
            linux_hosts = sorted({r["host"] for r in linux_linked["records"] if r.get("host")})
            for name, identity in (("linux_ssh_window", False), ("linux_identity_window", True)):
                spec = focused_queries.linux_auth(linux_plan, strict_tail, *bounds, ip=address(offense.get("offense_source")),
                                                 hosts=linux_hosts, identity=identity)
                result["focused_queries"][name] = focused_queries.describe(spec, "Linux daemon record in INOFFENSE")
                if isinstance(spec, dict):
                    finding = await run(name, spec["query"], "events", spec["scope"], linux_plan, spec["fallback"])
                    summary = linux_evidence.analyze(finding, name, bounds)
                    result["linux"]["identity_window" if identity else "ssh_window"] = summary
                    if not summary["recognized_message_census_complete"]:
                        add_gap("Linux authentication coverage/parsing incomplete; no absence claim", f"linux:{name}",
                                spec["scope"], "incomplete", ["linux_authentication_claims"],
                                "Resume the same job/pages or inspect unparsed original records")
                else:
                    add_gap(spec, f"linux:{name}:anchor", "linux_authentication", "not_built",
                            ["linux_authentication_claims", "benign_verdict"],
                            "Obtain a verified host IP/name before a focused authentication query")
        else:
            add_gap("Strict Linux authentication window unavailable", "linux:window", "linux_authentication",
                    "not_collected", ["linux_authentication_claims"], "Confirm historical timezone or partition the window")

    observed = result["events"]["observed_interval"]
    host_start, host_end = instant(observed["start"]), instant(observed["end"])
    ip = address(offense.get("offense_source"))
    host_tail = None
    if ip and host_start and host_end:
        host_start, host_end = host_start - timedelta(minutes=15), host_end + timedelta(minutes=15)
        requested_end = utc(host_end)
        host_end = min(host_end, now)
        host_tail, result["host_window"] = query_tail(host_start, host_end, offset_hours, timezone_verified, now)
        result["host_window"]["requested_end_utc"] = requested_end
        result["host_window"]["future_margin_not_observable"] = requested_end != utc(host_end)
        if host_tail:
            numeric = focused_queries.epoch_predicate("starttime", int(host_start.timestamp() * 1000),
                                                      int(host_end.timestamp() * 1000))
            predicate = (f"(sourceip = '{ip}' OR destinationip = '{ip}') AND {numeric} AND "
                "(QIDNAME(qid) ILIKE '%logon%' OR QIDNAME(qid) ILIKE '%authentication%' OR "
                "QIDNAME(qid) ILIKE '%credential%' OR QIDNAME(qid) ILIKE '%ticket%' OR "
                "QIDNAME(qid) ILIKE '%Process Create%' OR QIDNAME(qid) ILIKE '%ProcessCreate%' OR "
                "QIDNAME(qid) ILIKE '%ProcessAccess%' OR UTF8(payload) ILIKE '%Process Create:%' OR "
                "UTF8(payload) ILIKE '%A new process has been created%')")
            if linux_linked["daemon_rows"]:
                predicate = (f"(sourceip = '{ip}' OR destinationip = '{ip}') AND {numeric} AND "
                             + focused_queries._any_payload(focused_queries.LINUX_CONTEXT_MARKERS))
            tail_sql = f"FROM events WHERE {predicate} ORDER BY starttime ASC LIMIT {SEARCH_LIMIT} {host_tail}"
            await run("host_context", f"{event_plan.select()} {tail_sql}", "events", "host_ip_time_context",
                      event_plan, f"{event_plan.select(False)} {tail_sql}" if event_plan.optional else None)
        else:
            add_gap("Host pivot needs a verified historical timezone", "host:timezone", "host_ip_time_context",
                    "not_collected", ["host_activity_absence_claims"], "Confirm the console timezone")
    else:
        add_gap("No offense source IP/linked event time to anchor host pivot", "host:anchor",
                "host_ip_time_context", "not_collected", ["host_activity_absence_claims"],
                "Pivot on a verified host identifier with qradar_run_aql")

    seen: dict = {}
    records = []
    for name in list(result["queries"]):
        if result["queries"][name]["database"] == "events":
            records += _records(name, result["queries"][name], (plans.get(name) or event_plan).property_map(), seen)
    analysis = process_chain.analyze(records)
    if host_tail:
        window = (int(host_start.timestamp() * 1000), int(host_end.timestamp() * 1000))
        hosts = sorted({p["host_norm"] for p in analysis["process_creations"] if p.get("host_norm")})
        looked: set[str] = set()
        for round_number in range(3):
            wanted = process_chain.wanted_parents(analysis, looked)
            if not wanted or len(looked) >= MAX_PARENT_LOOKUPS:
                break
            for missing in wanted[:MAX_PARENT_LOOKUPS - len(looked)]:
                parent = process_chain.guid(missing["parent_guid"])
                looked.add(parent)
                spec = focused_queries.parent_lookup(event_plan, host_tail, *window, parent)
                name = f"parent_lookup_{len(looked)}"
                result["focused_queries"][name] = focused_queries.describe(spec, f"missing parent {parent}")
                if isinstance(spec, dict):
                    finding = await run(name, spec["query"], "events", spec["scope"], event_plan, spec["fallback"])
                    records += _records(name, finding, event_plan.property_map(), seen)
            analysis = process_chain.analyze(records)
        triggers = []
        powershell = analysis["powershell_processes"]
        if powershell:
            triggers.append(("script_blocks", focused_queries.script_blocks(event_plan, host_tail, *window, ip, hosts),
                             f"{len(powershell)} PowerShell process creation(s) observed"))
        if any(p.get("image") for p in analysis["process_creations"]):
            triggers.append(("integrity", focused_queries.integrity(event_plan, host_tail, *window, ip, hosts),
                             "Observed process images: test for code-integrity failures on the same host"))
        flow_finding = result["queries"].get("flows", {})
        if analysis["process_creations"] and (not flow_finding.get("result_set_complete") or not flows):
            triggers.append(("host_flows", focused_queries.host_flows(host_tail, *window, ip),
                             "Process activity observed while INOFFENSE flows are empty or incomplete"))
        for name, spec, why in triggers:
            result["focused_queries"][name] = focused_queries.describe(spec, why)
            if isinstance(spec, dict):
                plan = event_plan if spec["database"] == "events" else flow_plan
                finding = await run(name, spec["query"], spec["database"], spec["scope"], plan, spec["fallback"])
                if spec["database"] == "events":
                    records += _records(name, finding, plan.property_map(), seen)
        analysis = process_chain.analyze(records)
    elif records:
        result["focused_queries"]["all"] = {"state": "not_built",
                                            "reason": "No verified host window; focused pivots need a bounded window"}
    result["processes"] = analysis
    result["integrity"] = integrity_evidence.analyze(records, analysis["process_creations"])
    if result["queries"].get("host_flows"):
        result["host_flows"] = flow_summary(result["queries"]["host_flows"]["rows"])
        result["host_flows"]["attribution"] = "Host IP flows; no process attribution"
    for missing in analysis["missing_parents"][:20]:
        add_gap(f"Parent {missing['parent_guid']} not found in the collected window/filters",
                f"parent:{missing['parent_guid']}", "parent_process_lookup", "not_found_in_window",
                ["process_ancestry_root"], "Search a wider verified window or the endpoint telemetry source")
    if "script_blocks" in result["queries"] and not analysis["script_blocks"]:
        add_gap("No 4104/4103 record returned in the inspected filters/window", "powershell:script-blocks",
                "host_script_block_context", "not_returned_in_filters_window", ["powershell_content_claims"],
                "Check logging policy, collection and forwarding at the source; this result does not show which applies")
    if any(row.get("username") for finding in result["queries"].values() for row in finding.get("rows", [])):
        add_gap("Account nature (service/admin/human) not established by event usernames", "identity:account-nature",
                "identity", "outside_bridge", ["account_nature"], "Consult the identity source (AD/IdP/PAM inventory)")

    if result.get("lockout", {}).get("detected"):
        add_gap("Lockout cause, caller-to-IP/process attribution and remediation not established by 4740 or nearby failures",
                "lockout:cause", "lockout_account_time_context", "unverified", ["benign_verdict"],
                "Validate the reported caller against identity/inventory and service/task/application evidence; verify remediation")
    result["host"] = host_summary(result["queries"].get("host_context", {}).get("rows", []))
    result["host"]["groups"] = event_summary(result["queries"].get("host_context", {}).get("rows", []))["groups"]
    if linux_linked["daemon_rows"]:
        result["linux"]["host_context"] = linux_evidence.analyze(result["queries"].get("host_context"), "host_context")
        for record in result["linux"]["host_context"]["accepted_root_ssh_records"]:
            moment = instant(record["provenance"]["starttime_epoch"])
            if moment and start and end:
                record["relation_to_metadata_window"] = "before" if moment < start else "after" if moment > end else "inside"
                record["seconds_before_metadata_start"] = round((start - moment).total_seconds(), 3)
                record["attribution"] = "Host context; no demonstrated link to offense or sudo session"
    if result["flows"]["dhcp_port_pattern"]:
        add_gap("Destination roles and authorized DHCP scopes/relays unverified", "dhcp:roles", "offense_linked",
                "outside_bridge", ["benign_verdict", "dhcp_pattern"], "Check DHCP scope/relay inventory")
        add_gap("Firewall anti-spoofing policy and packet-originating service unverified", "dhcp:origin",
                "offense_linked", "outside_bridge", ["benign_verdict", "dhcp_pattern"],
                "Check firewall policy and the service owning the packets")
    else:
        add_gap("Application authorization and host/process attribution not established by port/IP context",
                "attribution:host-process", "offense_linked", "outside_bridge", ["benign_verdict"],
                "Use same-record identifiers or the authorization source")
    # Context reads run after the linked Ariel collection so they cannot starve it.
    from . import qradar_context
    result["context"] = await qradar_context.collect(
        qradar, budget, offense, result["queries"].get("events", {}).get("rows", []))
    for name, finding in result["queries"].items():
        for item in query_gaps(name, finding):
            result["gaps"].append(item["summary"])
            result["gap_details"].append(item)
        if finding.get("continuation"):
            result["continuation_plan"].append({"query": name, **finding["continuation"]})
        # Keep witness rows explicitly bounded; full pages remain retrievable by search ID.
        samples = []
        rows = finding.pop("rows")
        if keep_rows:
            result.setdefault("collected_rows", {})[name] = rows  # full rows for the case store only
        # Include distinct event/log-source witnesses before filling remaining slots.
        witnesses, witness_keys = [], set()
        for index, row in enumerate(rows):
            key = (str(row.get("event_name")), str(row.get("log_source")))
            if key not in witness_keys:
                witnesses.append(index)
                witness_keys.add(key)
            if len(witnesses) == 8:
                break
        witnesses.extend(i for i in range(min(8, len(rows))) if i not in witnesses)
        for index in sorted(witnesses[:8]):
            row = rows[index]
            sample = dict(row)
            sample["result_row_index"] = index
            payload = sample.get("raw_payload")
            if isinstance(payload, str) and len(payload) > 2000:
                sample["raw_payload"] = payload[:2000]
                sample["sample_preview_truncated"] = True
                sample["observed_payload_characters"] = len(payload)
            sample["starttime_utc"] = utc(row.get("starttime"))
            sample["devicetime_utc"] = utc(row.get("devicetime"))
            samples.append(sample)
        finding["samples"] = samples
    result["gaps"] = list(dict.fromkeys(result["gaps"]))
    result["closing_reasons"] = await closure_assessment.closing_catalog(qradar, budget)
    result["budget"] = budget.describe()
    linked_complete = all(result["queries"].get(name, {}).get("result_set_complete") for name in ("events", "flows"))
    result["assessment"] = {
        "statement": ("Traffic compatible with DHCP; pending destination, anti-spoofing, CRE and host attribution validation"
                      if linked_complete and result["flows"]["dhcp_port_pattern"] else
                      "Evidence collected with unresolved gaps; no benign or malicious verdict established"),
        "confidence_in_port_pattern": "moderate" if linked_complete and result["flows"]["dhcp_port_pattern"] else "insufficient",
        "required_before_final_verdict": list(result["gaps"]),
        "prohibited_inferences": ["CLOSED/magnitude imply false positive", "4648 proves successful authentication or DHCP service",
            "zero return bytes prove nobody replied", "IP .1 proves relay", "decoded Base64 proves complete command",
            "field length plateau identifies WinCollect", "CRE event name is the full rule definition",
            "no Workbench alert proves no endpoint activity", "a file named as an argument was executed",
            "PID/IP/time proximity proves a parent/child link", "no IEX in the launch command line excludes IEX",
            "no 4104 result shows logging or forwarding was disabled", "repeated hash or vendor path proves integrity",
            "5038 proves corruption or compromise", "all queries completed proves a false positive",
            "zero INOFFENSE flows proves no communication", "missing truncated_fields proves a complete source payload",
            "Windows session ID identifies a PSM recording", "username alone shows account nature"],
        **assess(result),
    }
    result["closure_assessment"] = closure_assessment.propose(result, confirmations, **(closure_options or {}))
    return result


async def verify_offense(qradar: Any, offense_id: int, qradar_utc_offset_hours: int = -3,
                         timezone_verified: bool = False, budget: Budget | None = None,
                         confirmations: list | None = None) -> dict:
    if isinstance(offense_id, bool) or not isinstance(offense_id, int) or offense_id < 1:
        raise ValueError("offense_id must be a positive integer")
    closure_assessment.validate_confirmations(confirmations, offense_id)  # reject bad input before any query
    budget = budget or Budget()  # one deadline for metadata and every collection call
    offense = await budget.run(lambda: qradar.call("get_offense", {"offense_id": offense_id}), "offense metadata")
    if not isinstance(offense, dict) or offense.get("id") != offense_id:
        raise ValueError("Unexpected offense metadata ID")
    return await collect_offense_evidence(qradar, offense, qradar_utc_offset_hours, timezone_verified,
                                          budget=budget, confirmations=confirmations)


def _clip(text: Any, size: int = 600) -> str:
    text = str(text).replace("\n", " ")
    return text if len(text) <= size else text[:size] + " …[preview cut]"


def render_evidence(evidence: dict) -> list[str]:
    """Compact provenance and an explicitly provisional assessment for the Kiro report."""
    lines = ["", "## Offense-linked evidence (INOFFENSE)", "",
             f"Metadata interval without padding: {evidence['metadata_interval']}",
             f"Ariel linked search window: {evidence.get('linked_window')}",
             f"Observed linked-event interval (starttime, not metadata duration): {evidence['events']['observed_interval']}",
             f"Field catalogs (live AQL resources): {evidence.get('field_catalogs')}",
             f"Collection budget: {evidence.get('budget')}"]
    for name, query in evidence["queries"].items():
        lines += [f"- {name}: {query['state']}; outcome {query.get('outcome')}; search ID {query.get('search_id')}; "
                  f"rows {query['returned_rows']}; record_count {query.get('record_count')}; "
                  f"complete within query/window: {query['result_set_complete']}; "
                  f"scope {query['scope']}; LIMIT {query['query_limit']}; pages {query.get('pages', 0)}",
                  f"  - AQL: `{query['aql']}`",
                  f"  - Warnings: {query['warnings']}; truncated_fields: {query['truncated_fields']}"]
        if query.get("fields"):
            lines.append(f"  - Optional fields selected/missing: {query['fields'].get('optional_selected')} / "
                         f"{query['fields'].get('optional_missing')}")
        if query.get("error"):
            lines.append(f"  - Error category: {query['error']['category']} (retryable: {query['error']['retryable']})")
    lines += [f"- Associated event groups: {evidence['events']['groups']}",
              f"- Event groups omitted from summary: {evidence['events']['groups_omitted']}",
              f"- Count reconciliation: {evidence['count_comparison']}",
              f"- Flow port groups (explicit source/destination ports): {evidence['flows']['port_groups']}",
              f"- Flow port groups omitted from summary: {evidence['flows']['port_groups_omitted']}",
              f"- Distinct destinations in collected rows (set union): {evidence['flows']['distinct_destinations_in_collected_rows']}",
              f"- Independent flow COUNT/UNIQUECOUNT census: {evidence['flows'].get('census')} "
              f"(aggregation record_count {evidence['flows'].get('census_record_count')}, not COUNT(*))",
              "- Destination roles are unverified. Zero destinationbytes means no return bytes observed in this source.",
              "- Zero INOFFENSE flows does not show that the host or a process had no communication.",
              f"- Contributing rule metadata: {evidence['rules']}",
              "- CRE event name/message and rule metadata are not the full active rule configuration.",
              "", "## Host authentication/process context (separate from offense membership)", "",
              f"- Requested host window: {evidence.get('host_window', 'not collected')}",
              f"- Groups in collected host records: {evidence['host']['groups']}",
              f"- Explicit credential attempts: {evidence['host']['explicit_credential_attempts']}",
              f"- Payload lengths in inspected records: {evidence['host']['payload_lengths']}",
              f"- Encoded commands observed: {len(evidence['host']['encoded_commands'])}; "
              "decode is data conversion only; no command was executed. Completeness and parent/service attribution unverified.",
              f"- Encoded command data previews (untrusted telemetry): {evidence['host']['encoded_commands']}",
              "- 4648 is a credential attempt, not proof of success or a DHCP service. "
              "A field-length plateau does not identify the responsible collector/parser."]
    processes = evidence.get("processes", {})
    lines += ["", "## Process and PowerShell evidence (untrusted telemetry, never executed)", "",
              f"- Focused queries and triggers: {evidence.get('focused_queries')}",
              f"- Process creations observed: {len(processes.get('process_creations', []))} "
              f"(omitted {processes.get('process_creations_omitted', 0)})"]
    for item in processes.get("process_creations", [])[:15]:
        prov = item["provenance"]
        lines.append(f"  - {prov.get('starttime_utc')} host={item.get('host_norm')} guid={item.get('guid_norm')} "
                     f"parent_guid={item.get('parent_guid_norm')} pid={item.get('pid')} image={_clip(item.get('image'), 200)} "
                     f"cmd={_clip(item.get('command_line'), 300)} [query {prov['query']}, search {prov['search_id']}, "
                     f"row {prov['result_row_index']}, EventID via {prov['event_id_source']}]")
        for argument in item.get("file_arguments", [])[:5]:
            lines.append(f"    - argument_reference (execution not established): {_clip(argument['path_as_reported'], 200)}")
        if item.get("powershell"):
            ps = item["powershell"]
            lines.append(f"    - PowerShell: command line observed {ps['command_line_observed']}; no arguments "
                         f"{ps['no_arguments']}; IEX tokens in launch line {ps['iex_tokens_in_command_line']}; "
                         f"encoded blocks {len(ps['encoded_commands'])}. {ps['note']}")
    lines += [f"- GUID+host links: {processes.get('links')}",
              f"- Chains (child to ancestor): {processes.get('chains')}; cycles detected {processes.get('cycles_detected')}",
              f"- Parents not found in the collected window (gap, not absence): {processes.get('missing_parents')}",
              f"- Unlinked/candidate references (PID or host-less GUID only): {processes.get('unlinked_references')}",
              f"- PID reuse observed: {processes.get('pid_reuse')}",
              f"- IEX criteria: {processes.get('iex_criteria')}"]
    for block in processes.get("script_blocks", [])[:10]:
        prov = block["provenance"]
        lines.append(f"  - {block['event_id']} {prov.get('starttime_utc')} host={block['host_norm']} part={block['message_part']} "
                     f"IEX tokens={block['iex_tokens']} possibly cut={block['text_possibly_truncated_at_source_or_bridge']} "
                     f"candidates={block['candidate_processes']} text={_clip(block['text_preview'], 400)}")
    integrity = evidence.get("integrity", {})
    lines += ["", "## Code integrity and hashes", ""]
    for event in integrity.get("integrity_events", [])[:10]:
        lines.append(f"- {event['event_id']} file={_clip(event['file_as_reported'], 200)} host={event['host']}: "
                     f"{event['interpretation']} Relationship: {event['relationship_to_process_chain']}")
    lines += [f"- Repeated hashes: {integrity.get('repeated_hashes')}",
              f"- Non-comparable (abbreviated/invalid) hashes: {integrity.get('non_comparable_hashes')}",
              f"- {integrity.get('vendor_path_note')}"]
    if evidence.get("host_flows"):
        lines.append(f"- Host IP flow context (no process attribution): {evidence['host_flows']['port_groups'][:20]}")
    assessment = evidence["assessment"]
    lines += ["", "## Continuation plan", ""]
    lines.extend(f"- {item['query']}: {item['action']} ({item['reason']}); search ID {item['search_id']}; "
                 f"cursor {item['cursor']}; tools {item['tools']}" for item in evidence.get("continuation_plan", []))
    if not evidence.get("continuation_plan"):
        lines.append("- No pending job or page cursor; re-run only with a hypothesis that can change the conclusion.")
    lines += ["", "## Evidence-based assessment", "",
              f"Status: {assessment['status']}",
              assessment['statement'],
              f"Confidence in port compatibility only: {assessment['confidence_in_port_pattern']}",
              f"Collection completeness: {assessment['collection_completeness']}",
              f"Confirmed facts (observations, not causes): {assessment['confirmed_facts']}",
              f"Hypotheses: {assessment['hypotheses']}",
              f"final_benign_verdict_permitted={assessment['final_benign_verdict_permitted']}: "
              f"{assessment['final_benign_verdict_permitted_meaning']}",
              f"Reportable now: {assessment['reportable_now']}",
              "A final benign/false-positive verdict and tuning are not authorized by this collection alone.",
              "", "### Blocking gaps by conclusion", ""]
    lines.extend(f"- {conclusion}: {ids}" for conclusion, ids in assessment["blocking_gaps_by_conclusion"].items())
    lines += ["", "### Required before a final verdict", ""]
    lines.extend(f"- {gap_text}" for gap_text in assessment["required_before_final_verdict"])
    lines.extend(f"- Collection warning: {warning}" for warning in evidence["warnings"])
    linux = evidence.get("linux", {})
    if linux.get("detected"):
        lines += ["", "## Linux authentication and command census", "",
                  f"- Frozen strict window: {linux.get('strict_window')}",
                  f"- INOFFENSE sudo actors/targets: {linux['offense']['sudo_actor_counts']} / {linux['offense']['sudo_target_counts']}",
                  f"- Commands counted over all collected rows: {linux['offense']['sudo_commands']}",
                  f"- Unparsed/cut daemon records: {linux['offense']['unparsed_daemon_rows']} / {linux['offense']['truncated_payload_rows']}"]
        for name in ("ssh_window", "identity_window"):
            if name in linux:
                item = linux[name]
                lines += [f"- {name}: search {item['search_id']}; kinds {item['kind_counts']}; "
                          f"recognized census complete: {item['recognized_message_census_complete']}",
                          f"  - Accepted root SSH messages parsed: {item['accepted_root_ssh_count']}; "
                          f"negative claim for SSH query only: {item['negative_claim']}",
                          f"  - Witness records: {item['records'][:5]}"]
    lockout = evidence.get("lockout", {})
    if lockout.get("detected"):
        lines += ["", "## Account lockout evidence", "", lockout["interpretation"],
                  f"- Event IDs counted: {lockout['event_id_counts']}",
                  f"- Reported account/domain/caller groups: {lockout['groups']}",
                  f"- Authentication candidates: {lockout.get('authentication_candidates', [])}",
                  f"- Record previews omitted: {lockout['records_omitted']}; groups omitted: {lockout['groups_omitted']}",
                  f"- Correlation cap reached: {lockout.get('candidate_limit_reached', False)}; "
                  f"lockouts beyond correlation cap: {lockout.get('lockouts_not_correlated_due_to_cap', 0)}",
                  "- Cause, authorization, responsible process and remediation remain unverified."]
    context = evidence.get("context")
    if context:
        lines += ["", "## QRadar context (read only; snapshots and untrusted text)", "", f"- {context['handling']}"]
        for key, item in context.items():
            if key == "handling":
                continue
            entries = item.items() if key in ("assets", "log_sources", "qids") else [(key, item)]
            for name, read in entries:
                if isinstance(read, dict) and "state" in read:
                    lines.append(f"- {key if name == key else f'{key} {name}'}: {read['state']}; items {read.get('count', 0)}"
                                 + (f"; {read.get('error', {}).get('category')}" if read.get("error") else ""))
        for ip, nets in (context.get("network_hierarchy") or {}).get("matches", {}).items():
            lines.append(f"- network objects for {ip}: {[n['name'] + ' ' + n['cidr'] for n in nets[:3]]}")
    closing = evidence.get("closure_assessment")
    if closing:
        lines += ["", "## Closing recommendation and analyst note (draft)", "",
                  f"Recommendation: {closing['recommendation']}",
                  f"Final disposition confidence: {closing['confidence']}. {closing['confidence_explanation']}",
                  f"Live closing reason catalog: {closing['reason_catalog_state']}",
                  f"Recommended reason (live catalog): {closing.get('recommended_reason')}",
                  f"Conditional reason options: {closing['conditional_reason_options']}"]
        for item in closing.get("decision_matrix", []):
            lines.append(f"- reason {item['label']} (ID {item['id']}): {item['sufficiency']}; met {item['met']}; "
                         f"blocking {[b['id'] + ' (' + b['status'] + ')' for b in item['blocking']]}")
        lines += ["", "### Suggested note for analyst review", "", closing["suggested_note"]]
    return lines
