"""Offense-linked collection and evidence limits; never infer authorization from ports."""

from __future__ import annotations

import base64
import binascii
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

from .aql_search import run_query, search_results
from .core import address, instant

SEARCH_LIMIT = 5000
PAGE_LIMIT = 500
MAX_PAGES = 10
MAX_RULES = 20


def utc(value: Any) -> str | None:
    stamp = value.astimezone(timezone.utc) if isinstance(value, datetime) else instant(value)
    return stamp.isoformat(timespec="milliseconds").replace("+00:00", "Z") if stamp else None


def interval(rows: list[dict], key: str) -> dict:
    stamps = [stamp for row in rows if (stamp := instant(row.get(key))) is not None]
    return {"start": utc(min(stamps)) if stamps else None,
            "end": utc(max(stamps)) if stamps else None, "clock": key}


def number(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        return int(value) if str(value).lstrip("-").isdigit() else None
    except (TypeError, ValueError):
        return None


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
            "search_end_utc": utc(now), "bounds_note": "Approximate anchor; LAST is evaluated when each job starts"}
    if not verified:
        return None, {**scope, "reason": "Historical/future window requires a verified QRadar timezone"}
    begin = start - timedelta(minutes=1)
    stop = end + timedelta(minutes=1)
    if stop - begin > timedelta(hours=24):
        return None, {**scope, "reason": "Raw offense interval exceeds 24 hours; partition bounded searches"}
    local_start, local_end = begin + timedelta(hours=offset), stop + timedelta(hours=offset)
    tail = f"START '{local_start:%Y-%m-%d %H:%M:%S}' STOP '{local_end:%Y-%m-%d %H:%M:%S}'"
    return tail, {**scope, "mode": "absolute", "search_window": tail,
                  "search_start_utc": utc(begin), "search_end_utc": utc(stop)}


async def collect_query(qradar: Any, query: str, database: str, scope: str) -> dict:
    """Follow pages on one search ID, with an explicit search/page/budget ceiling."""
    finding: dict = {"aql": query, "database": database, "scope": scope,
                     "query_limit": SEARCH_LIMIT, "state": "unavailable", "rows": [],
                     "warnings": [], "truncated_fields": [], "result_set_complete": False}
    try:
        page = await run_query(qradar, query, limit=PAGE_LIMIT)
        finding.update(search_id=page.get("search_id"), state=page.get("status"),
                       record_count=page.get("record_count"), pages=0)
        while page.get("results_available"):
            if page.get("database") != database:
                raise ValueError("Ariel returned the wrong database")
            finding["pages"] += 1
            finding["rows"].extend(page["rows"])
            finding["warnings"].extend(page.get("warnings", []))
            finding["truncated_fields"].extend(
                f"page {finding['pages']}: {field}" for field in page.get("truncated_fields", []))
            if not page.get("has_more"):
                total = number(page.get("record_count"))
                finding["result_set_complete"] = (
                    total is not None and total == len(finding["rows"]) and total < SEARCH_LIMIT)
                break
            next_start = page.get("next_start")
            if (finding["pages"] >= MAX_PAGES or len(finding["rows"]) >= SEARCH_LIMIT
                    or not isinstance(next_start, int) or next_start <= page.get("start", -1)):
                finding["next_start"] = next_start
                finding["warnings"].append("Collection budget reached; continue the same search ID")
                break
            page = await search_results(qradar, finding["search_id"], next_start, PAGE_LIMIT)
        if not page.get("results_available"):
            finding["state"] = page.get("status", "unavailable")
            finding["warnings"].append(page.get("warning", "Results unavailable; not a negative search"))
        if number(finding.get("record_count")) == SEARCH_LIMIT:
            finding["warnings"].append("AQL LIMIT reached; partition/refine to include excluded rows or groups")
    except Exception as exc:
        finding["state"] = "unavailable"
        finding["result_set_complete"] = False
        finding["warnings"].append(f"Collection failed ({type(exc).__name__}); inspect upstream permissions/schema")
    finding["returned_rows"] = len(finding["rows"])
    # Earlier pages had more results; this is not an unresolved gap once they were fetched.
    finding["warnings"] = list(dict.fromkeys(w for w in finding["warnings"]
        if not (finding["result_set_complete"] and w.startswith("More results may exist"))))
    return finding


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


async def collect_offense_evidence(qradar: Any, offense: dict, offset_hours: int = -3,
                                   timezone_verified: bool = False, now: datetime | None = None) -> dict:
    """Collect linked records, flow census, rule metadata and a contextual host pivot."""
    oid = offense.get("id")
    if isinstance(oid, bool) or not isinstance(oid, int) or oid < 1:
        raise ValueError("Positive integer offense ID required")
    if isinstance(offset_hours, bool) or not isinstance(offset_hours, int) or not -12 <= offset_hours <= 14:
        raise ValueError("QRadar offset must be an integer between -12 and 14")
    if not isinstance(timezone_verified, bool):
        raise ValueError("timezone_verified must be a boolean")
    now = now or datetime.now(timezone.utc)
    start = instant(offense.get("start_time") or offense.get("first_event_flow_seen"))
    end = instant(offense.get("last_updated_time") or offense.get("last_event_flow_seen")) or start
    result: dict = {"offense_id": oid, "collected_at": utc(now),
        "metadata": {key: offense.get(key) for key in ("id", "description", "status", "magnitude",
            "severity", "credibility", "relevance", "event_count", "flow_count", "start_time",
            "last_updated_time", "close_time", "closing_reason_id", "rules", "offense_source")},
        "metadata_interval": {"start": utc(start), "end": utc(end), "padding_seconds": 0},
        "queries": {}, "rules": [], "warnings": [], "gaps": []}
    for resource in ("events", "flows"):
        try:
            await qradar.read_aql_resource(resource)
        except Exception:
            result["warnings"].append(f"{resource} field resource unavailable; canonical SELECT still requires QRadar validation")
    tail = None
    if start and end and end >= start:
        tail, result["linked_window"] = query_tail(start, end, offset_hours, timezone_verified, now)
    else:
        result["linked_window"] = {"reason": "Missing or invalid offense metadata interval"}
    if tail:
        expressions = {
            "events": "SELECT starttime, devicetime, sourceip, sourceport, destinationip, destinationport, username, qid, QIDNAME(qid) AS event_name, LOGSOURCENAME(logsourceid) AS log_source, UTF8(payload) AS raw_payload FROM events",
            "flows": "SELECT firstpackettime, lastpackettime, sourceip, sourceport, destinationip, destinationport, protocolid, sourcebytes, destinationbytes, sourcepackets, destinationpackets FROM flows",
            "flow_census": "SELECT COUNT(*) AS total_rows, UNIQUECOUNT(destinationip) AS distinct_destinations FROM flows",
        }
        for name, select in expressions.items():
            database = "events" if name == "events" else "flows"
            # INOFFENSE association, never a source-IP substitute. No local offset for recent cases.
            query = f"{select} WHERE INOFFENSE({oid}) LIMIT {SEARCH_LIMIT} {tail}"
            result["queries"][name] = await collect_query(qradar, query, database, "offense_linked")
    else:
        result["gaps"].append(result["linked_window"]["reason"])

    events = result["queries"].get("events", {}).get("rows", [])
    flows = result["queries"].get("flows", {}).get("rows", [])
    result["events"] = event_summary(events)
    result["flows"] = flow_summary(flows)
    census = result["queries"].get("flow_census", {})
    result["flows"]["census"] = census.get("rows", [])[:1]
    if census.get("result_set_complete") and len(census.get("rows", [])) == 1:
        census_row = census["rows"][0]
        result["flows"]["distinct_destinations_in_search"] = number(value(census_row, "distinct_destinations"))
        result["flows"]["total_rows_in_search"] = number(value(census_row, "total_rows"))
        if (result["queries"].get("flows", {}).get("result_set_complete") and
                (number(value(census_row, "total_rows")) != len(flows) or
                 number(value(census_row, "distinct_destinations")) != result["flows"]["distinct_destinations_in_collected_rows"])):
            result["gaps"].append("Flow census and fetched rows differ; reconcile snapshots/coverage")
    elif census:
        result["gaps"].append("Flow COUNT/UNIQUECOUNT census unavailable or invalid")
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
            result["gaps"].append(f"{database} coverage/count reconciliation unresolved")
    refs = offense.get("rules")
    if not isinstance(refs, list) or not refs:
        result["gaps"].append("Contributing rule IDs not returned in offense metadata")
        refs = []
    if len(refs) > MAX_RULES:
        result["gaps"].append("Contributing rule metadata cap reached")
    for ref in refs[:MAX_RULES]:
        if not isinstance(ref, dict) or number(ref.get("id")) is None or number(ref.get("id")) < 0:
            result["gaps"].append("Invalid contributing rule reference")
            continue
        entry = {"id": number(ref["id"]), "type": ref.get("type"), "state": "unavailable"}
        try:
            details = await qradar.call("get_rule", {"rule_id": entry["id"]})
            if not isinstance(details, dict) or number(details.get("id")) != entry["id"]:
                raise ValueError("Rule metadata ID mismatch")
            entry.update(state="collected", metadata=details)
        except Exception as exc:
            entry["reason"] = f"Rule metadata unavailable ({type(exc).__name__})"
        result["rules"].append(entry)
    result["gaps"].append("Rule metadata/event text does not establish the complete active CRE tests or responses")

    observed = result["events"]["observed_interval"]
    host_start, host_end = instant(observed["start"]), instant(observed["end"])
    ip = address(offense.get("offense_source"))
    if ip and host_start and host_end:
        host_start, host_end = host_start - timedelta(minutes=15), host_end + timedelta(minutes=15)
        requested_end = utc(host_end)
        host_end = min(host_end, now)
        host_tail, result["host_window"] = query_tail(host_start, host_end, offset_hours, timezone_verified, now)
        result["host_window"]["requested_end_utc"] = requested_end
        result["host_window"]["future_margin_not_observable"] = requested_end != utc(host_end)
        if host_tail:
            numeric = f"starttime >= {int(host_start.timestamp() * 1000)} AND starttime <= {int(host_end.timestamp() * 1000)}"
            predicate = (f"(sourceip = '{ip}' OR destinationip = '{ip}') AND {numeric} AND "
                "(QIDNAME(qid) ILIKE '%logon%' OR QIDNAME(qid) ILIKE '%authentication%' OR "
                "QIDNAME(qid) ILIKE '%credential%' OR QIDNAME(qid) ILIKE '%ticket%' OR "
                "QIDNAME(qid) ILIKE '%Process Create%' OR QIDNAME(qid) ILIKE '%ProcessCreate%' OR "
                "QIDNAME(qid) ILIKE '%ProcessAccess%')")
            query = ("SELECT starttime, devicetime, sourceip, destinationip, username, qid, "
                "QIDNAME(qid) AS event_name, LOGSOURCENAME(logsourceid) AS log_source, UTF8(payload) AS raw_payload "
                f"FROM events WHERE {predicate} ORDER BY starttime ASC LIMIT {SEARCH_LIMIT} {host_tail}")
            result["queries"]["host_context"] = await collect_query(qradar, query, "events", "host_ip_time_context")
        else:
            result["gaps"].append("Host pivot needs a verified historical timezone")
    else:
        result["gaps"].append("No offense source IP/linked event time to anchor host pivot")
    host = result["queries"].get("host_context", {})
    result["host"] = host_summary(host.get("rows", []))
    result["host"]["groups"] = event_summary(host.get("rows", []))["groups"]
    if result["flows"]["dhcp_port_pattern"]:
        result["gaps"].extend(["Destination roles and authorized DHCP scopes/relays unverified",
            "Firewall anti-spoofing policy and packet-originating service unverified"])
    else:
        result["gaps"].append("Application authorization and host/process attribution not established by port/IP context")
    for name, finding in result["queries"].items():
        if not finding["result_set_complete"]:
            result["gaps"].append(f"{name}: query coverage incomplete or unavailable")
        if finding["truncated_fields"]:
            result["gaps"].append(f"{name}: bridge truncated fields; original content unavailable in this response")
        # Keep witness rows explicitly bounded; full pages remain retrievable by search ID.
        samples = []
        rows = finding.pop("rows")
        # Include distinct event/log-source witnesses before filling remaining slots.
        witnesses, seen = [], set()
        for index, row in enumerate(rows):
            key = (str(row.get("event_name")), str(row.get("log_source")))
            if key not in seen:
                witnesses.append(index)
                seen.add(key)
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
    linked_complete = all(result["queries"].get(name, {}).get("result_set_complete") for name in ("events", "flows"))
    result["assessment"] = {
        "status": "preliminary", "final_benign_verdict_permitted": False,
        "statement": ("Traffic compatible with DHCP; pending destination, anti-spoofing, CRE and host attribution validation"
                      if linked_complete and result["flows"]["dhcp_port_pattern"] else
                      "Evidence collected with unresolved gaps; no benign or malicious verdict established"),
        "confidence_in_port_pattern": "moderate" if linked_complete and result["flows"]["dhcp_port_pattern"] else "insufficient",
        "required_before_final_verdict": list(dict.fromkeys(result["gaps"])),
        "prohibited_inferences": ["CLOSED/magnitude imply false positive", "4648 proves successful authentication or DHCP service",
            "zero return bytes prove nobody replied", "IP .1 proves relay", "decoded Base64 proves complete command",
            "field length plateau identifies WinCollect", "CRE event name is the full rule definition",
            "no Workbench alert proves no endpoint activity"],
    }
    return result


async def verify_offense(qradar: Any, offense_id: int, qradar_utc_offset_hours: int = -3,
                         timezone_verified: bool = False) -> dict:
    if isinstance(offense_id, bool) or not isinstance(offense_id, int) or offense_id < 1:
        raise ValueError("offense_id must be a positive integer")
    offense = await qradar.call("get_offense", {"offense_id": offense_id})
    if not isinstance(offense, dict) or offense.get("id") != offense_id:
        raise ValueError("Unexpected offense metadata ID")
    return await collect_offense_evidence(qradar, offense, qradar_utc_offset_hours, timezone_verified)


def render_evidence(evidence: dict) -> list[str]:
    """Compact provenance and an explicitly provisional assessment for the Kiro report."""
    lines = ["", "## Offense-linked evidence (INOFFENSE)", "",
             f"Metadata interval without padding: {evidence['metadata_interval']}",
             f"Ariel linked search window: {evidence.get('linked_window')}",
             f"Observed linked-event interval (starttime, not metadata duration): {evidence['events']['observed_interval']}"]
    for name, query in evidence["queries"].items():
        lines += [f"- {name}: {query['state']}; search ID {query.get('search_id')}; "
                  f"rows {query['returned_rows']}; complete within query/window: {query['result_set_complete']}; "
                  f"scope {query['scope']}; LIMIT {query['query_limit']}; pages {query.get('pages', 0)}",
                  f"  - AQL: `{query['aql']}`",
                  f"  - Warnings: {query['warnings']}; truncated_fields: {query['truncated_fields']}"]
    lines += [f"- Associated event groups: {evidence['events']['groups']}",
              f"- Event groups omitted from summary: {evidence['events']['groups_omitted']}",
              f"- Count reconciliation: {evidence['count_comparison']}",
              f"- Flow port groups (explicit source/destination ports): {evidence['flows']['port_groups']}",
              f"- Flow port groups omitted from summary: {evidence['flows']['port_groups_omitted']}",
              f"- Distinct destinations in collected rows (set union): {evidence['flows']['distinct_destinations_in_collected_rows']}",
              f"- Independent flow COUNT/UNIQUECOUNT census: {evidence['flows'].get('census')}",
              "- Destination roles are unverified. Zero destinationbytes means no return bytes observed in this source.",
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
              "A field-length plateau does not identify the responsible collector/parser.",
              "", "## Evidence-based assessment", "",
              f"Status: {evidence['assessment']['status']}",
              evidence['assessment']['statement'],
              f"Confidence in port compatibility only: {evidence['assessment']['confidence_in_port_pattern']}",
              "A final benign/false-positive verdict and tuning are not authorized by this collection alone.",
              "", "### Required before a final verdict", ""]
    lines.extend(f"- {gap}" for gap in evidence["assessment"]["required_before_final_verdict"])
    lines.extend(f"- Collection warning: {warning}" for warning in evidence["warnings"])
    return lines
