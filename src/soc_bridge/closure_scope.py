"""Scoped confirmations, observed-activity instances, contradictions and dispositions for closure.

An authorization is evidence only for the activity, entities, processes and window it names.
Each observed activity instance (one process creation, one script block, or one entity of
another activity) is evaluated on its own: authorizing process_execution of a named process
on host-a covers neither processes on host-b nor other commands on host-a. Instances no
record covers stay listed explicitly. Analyst records stay labelled as external and
unverified by the bridge.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from .core import address, instant, iso
from .process_chain import basename, same_host

# Activities the collection can actually demonstrate; each maps to existing analyses.
ACTIVITIES = {
    "process_execution": "process creation records (Sysmon 1 / 4688) in the collected rows",
    "script_execution": "PowerShell 4104/4103 script content records",
    "remote_authentication": "accepted SSH authentication records",
    "privilege_use": "sudo/su/PAM privilege records",
    "account_lockout": "4740 account lockout records",
    "explicit_credential_use": "4648 explicit-credential attempt records (attempt, not success)",
    "network_traffic": "offense-linked flow records",
    "code_integrity": "5038 code-integrity records",
    "offense_activity": "the offense-linked records when no more specific activity was identified",
}
SCOPED_REQUIREMENTS = {"authorization", "malicious_activity_confirmed", "detection_error"}
# Queries whose rows carry each non-process activity (entities and times per row).
ACTIVITY_QUERIES = {
    "remote_authentication": ("events", "linux_ssh_window"),
    "privilege_use": ("events", "linux_identity_window"),
    "account_lockout": ("events", "lockout_authentication"),
    "explicit_credential_use": ("host_context",),
    "network_traffic": ("flows", "host_flows"),
    "code_integrity": ("integrity",),
    "offense_activity": ("events", "flows"),
}
MAX_INSTANCES = 200
MAX_LISTED = 50
EXPLICIT_OFFSET = re.compile(r"(Z|[+-]\d{2}:?\d{2})$", re.I)


def strict_instant(value: Any, field: str) -> datetime:
    """ISO-8601 time with an explicit timezone (Z or ±hh:mm); local times are rejected, never assumed UTC."""
    if not isinstance(value, str) or "T" not in value or not EXPLICIT_OFFSET.search(value.strip()):
        raise ValueError(f"{field} must be an ISO-8601 time with an explicit timezone (for example "
                         "2026-10-09T14:00:00-03:00 or 2026-10-09T17:00:00Z); a time without timezone is not "
                         "interpreted as UTC")
    parsed = instant(value.strip())
    if parsed is None:
        raise ValueError(f"{field} is not a valid ISO-8601 time")
    return parsed


def _strings(value: Any, field: str, limit: int = 20, size: int = 500) -> list[str]:
    if (not isinstance(value, list) or not 1 <= len(value) <= limit
            or not all(isinstance(v, str) and 0 < len(v.strip()) <= size for v in value)):
        raise ValueError(f"{field} must list 1..{limit} non-empty strings")
    return sorted({_norm(v) for v in value})


def _norm(value: Any) -> str | None:
    return " ".join(value.split()).lower() if isinstance(value, str) and value.strip() else None


def validate_scope(scope: Any) -> dict:
    if not isinstance(scope, dict):
        raise ValueError("scope must be an object with activity, entities, window_start and window_end")
    activity = scope.get("activity")
    if activity not in ACTIVITIES:
        raise ValueError(f"scope.activity must be one of {sorted(ACTIVITIES)}")
    entities = scope.get("entities")
    if (not isinstance(entities, list) or not 1 <= len(entities) <= 20
            or not all(isinstance(e, str) and 0 < len(e.strip()) <= 200 for e in entities)):
        raise ValueError("scope.entities must list 1..20 entity strings (host, account, IP, application)")
    start = strict_instant(scope.get("window_start"), "scope.window_start")
    end = strict_instant(scope.get("window_end"), "scope.window_end")
    if end < start:
        raise ValueError("scope.window_end must not be before scope.window_start")
    out = {"activity": activity, "entities": sorted({e.strip().lower() for e in entities}),
           "window_start": iso(start), "window_end": iso(end)}
    if activity == "process_execution":
        if scope.get("processes") is None:
            raise ValueError("scope.processes is required for process_execution: name the authorized executables "
                             "(full path or file name); an authorization without processes covers no process")
        out["processes"] = _strings(scope["processes"], "scope.processes")
        for key in ("command_lines", "parent_processes"):
            if scope.get(key) is not None:
                out[key] = _strings(scope[key], f"scope.{key}", size=2000 if key == "command_lines" else 500)
    elif activity == "script_execution":
        if scope.get("script_block_ids") is None:
            raise ValueError("scope.script_block_ids is required for script_execution: cite the ScriptBlockId values")
        out["script_block_ids"] = _strings(scope["script_block_ids"], "scope.script_block_ids", size=100)
    else:
        unexpected = [k for k in ("processes", "command_lines", "parent_processes", "script_block_ids") if k in scope]
        if unexpected:
            raise ValueError(f"{', '.join(unexpected)} apply only to process_execution/script_execution scopes")
    return out


def _epoch_iso(value: Any) -> str | None:
    return iso(instant(value)) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _row_entities(row: dict) -> list[str]:
    out = []
    for key in ("sourceip", "destinationip"):
        value = row.get(key)
        if isinstance(value, str) and address(value):
            out.append(value.lower())
    for key in ("username", "host", "hostname"):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            out.append(value.strip().lower())
    return out


def _activities(result: dict) -> dict[str, str]:
    processes = result.get("processes", {})
    activities: dict[str, str] = {}
    if processes.get("process_creations"):
        activities["process_execution"] = f"{len(processes['process_creations'])} process creation record(s)"
    if processes.get("script_blocks"):
        activities["script_execution"] = f"{len(processes['script_blocks'])} script content record(s)"
    linux = result.get("linux", {})
    kinds = (linux.get("offense") or {}).get("kind_counts", {})
    if (linux.get("ssh_window") or {}).get("accepted_ssh_count") or kinds.get("ssh_authentication_accepted"):
        activities["remote_authentication"] = "accepted SSH record(s)"
    if kinds.get("sudo_command_record") or kinds.get("su_identity_record"):
        activities["privilege_use"] = "sudo/su record(s)"
    if (result.get("lockout") or {}).get("detected"):
        activities["account_lockout"] = "4740 record(s)"
    if (result.get("host") or {}).get("explicit_credential_attempts"):
        activities["explicit_credential_use"] = "4648 record(s) (attempt)"
    if (result.get("queries", {}).get("flows") or {}).get("returned_rows"):
        activities["network_traffic"] = "offense-linked flow record(s)"
    if (result.get("integrity") or {}).get("integrity_events"):
        activities["code_integrity"] = "5038 record(s)"
    if not activities:
        activities["offense_activity"] = "offense-linked records (no more specific activity identified)"
    return activities


def _instances(result: dict, activities: dict[str, str]) -> list[dict]:
    """One instance per process creation, per script block, and per entity of other activities."""
    out: list[dict] = []
    processes = result.get("processes", {})
    for index, item in enumerate(processes.get("process_creations", [])):
        prov = item.get("provenance") or {}
        parent = ((item.get("fields") or {}).get("ParentImage") or {}).get("value")
        out.append({"id": f"process:{item.get('guid_norm') or index}:{item.get('host_norm') or 'host?'}",
                    "activity": "process_execution",
                    "entities": [item["host_norm"]] if item.get("host_norm") else [],
                    "process": {"image": item.get("image"), "command_line": item.get("command_line"),
                                "command_line_cut": bool(item.get("command_line_preview_truncated")),
                                "parent_image": parent},
                    "time_start": prov.get("starttime_utc"), "time_end": prov.get("starttime_utc"),
                    "reference": {k: prov.get(k) for k in ("query", "search_id", "result_row_index")}})
    for index, item in enumerate(processes.get("script_blocks", [])):
        prov = item.get("provenance") or {}
        out.append({"id": f"script:{item.get('script_block_id') or index}:{item.get('host_norm') or 'host?'}",
                    "activity": "script_execution",
                    "entities": [item["host_norm"]] if item.get("host_norm") else [],
                    "process": {"script_block_id": item.get("script_block_id")},
                    "time_start": prov.get("starttime_utc"), "time_end": prov.get("starttime_utc"),
                    "reference": {k: prov.get(k) for k in ("query", "search_id", "result_row_index")}})
    rows_by_query = result.get("collected_rows") or {}
    samples = {name: q.get("samples", []) for name, q in (result.get("queries") or {}).items()}
    for activity in activities:
        if activity in ("process_execution", "script_execution"):
            continue
        groups: dict[str, dict] = {}
        for query in ACTIVITY_QUERIES.get(activity, ()):
            for index, row in enumerate(rows_by_query.get(query) or samples.get(query) or []):
                if not isinstance(row, dict):
                    continue
                moment = _epoch_iso(row.get("starttime") if row.get("starttime") is not None else row.get("firstpackettime"))
                for entity in _row_entities(row):
                    group = groups.setdefault(entity, {"times": [], "reference": {"query": query, "row_index": index}})
                    group["times"].append(moment)
        if not groups:
            source = (result.get("metadata") or {}).get("offense_source")
            observed = (result.get("events") or {}).get("observed_interval") or {}
            interval = observed if observed.get("start") else result.get("metadata_interval") or {}
            if source:
                groups[str(source).lower()] = {"times": [iso(instant(interval.get("start"))),
                                                         iso(instant(interval.get("end")))],
                                               "reference": {"source": "offense metadata",
                                                             "interval": "observed" if observed.get("start")
                                                             else "metadata"}}
        for entity, group in sorted(groups.items()):
            times = group["times"]
            known = sorted(t for t in times if t)
            out.append({"id": f"{activity}:{entity}", "activity": activity, "entities": [entity], "process": None,
                        "time_start": known[0] if known and len(known) == len(times) else None,
                        "time_end": known[-1] if known and len(known) == len(times) else None,
                        "reference": group["reference"]})
    return out


def observed_profile(result: dict) -> dict:
    """Activities, per-instance entities/processes/times and the observed window, with their source."""
    events = result.get("events", {})
    interval = events.get("observed_interval") or {}
    start = instant(interval.get("start")) or instant((result.get("metadata_interval") or {}).get("start"))
    end = instant(interval.get("end")) or instant((result.get("metadata_interval") or {}).get("end")) or start
    activities = _activities(result)
    instances = _instances(result, activities)
    entities = sorted({e for i in instances for e in i["entities"]})
    return {"activities": activities, "instances": instances[:MAX_INSTANCES],
            "instances_not_evaluated": max(0, len(instances) - MAX_INSTANCES),
            "entities": entities[:200],
            "window_start": iso(start) if start else None, "window_end": iso(end) if end else None}


def _entity_covered(entity: str, named: list[str]) -> bool:
    return any(entity == n or same_host(entity, n) for n in named)


def _process_covered(scope: dict, instance: dict) -> str | None:
    """None when the scope names this process instance; otherwise the reason it does not."""
    process = instance.get("process") or {}
    if instance["activity"] == "script_execution":
        block = _norm(process.get("script_block_id"))
        return None if block and block in scope.get("script_block_ids", []) else "script block not named in the record"
    if instance["activity"] != "process_execution":
        return None
    image = _norm(process.get("image"))
    if not image:
        return "process image not observed in the record"
    named = scope.get("processes", [])
    if not any(entry == image if ("\\" in entry or "/" in entry) else entry == basename(image) for entry in named):
        return f"process {basename(image)} not named in the record"
    if scope.get("command_lines"):
        command = _norm(process.get("command_line"))
        if not command or process.get("command_line_cut") or command not in scope["command_lines"]:
            return "command line not named in the record (or not fully observed)"
    if scope.get("parent_processes"):
        parent = _norm(process.get("parent_image"))
        if not parent or not any(entry == parent if ("\\" in entry or "/" in entry) else entry == basename(parent)
                                 for entry in scope["parent_processes"]):
            return "parent process not named in the record"
    return None


def coverage(confirmations: list[dict], profile: dict, requirement_id: str = "authorization") -> dict:
    """Which observed activity instances a scoped record covers (activity, entities, process/chain, window)."""
    records = [c for c in confirmations if c["requirement"] == requirement_id]
    unscoped = [c["reference"] for c in records if not c.get("scope")]
    covered: dict[str, str] = {}
    uncovered: list[dict] = []
    contradictions: list[dict] = []
    for inst in profile.get("instances", []):
        reasons = []
        for c in records:
            scope = c.get("scope")
            if not scope or scope["activity"] != inst["activity"]:
                continue
            if not inst["entities"]:
                reasons.append("entity not identified in the collected record")
                continue
            missing = [e for e in inst["entities"] if not _entity_covered(e, scope["entities"])]
            if missing:
                reasons.append(f"entity {', '.join(missing)} not named in {c['reference']}")
                continue
            why = _process_covered(scope, inst)
            if why:
                reasons.append(f"{why} ({c['reference']})")
                continue
            first, last = instant(inst.get("time_start")), instant(inst.get("time_end"))
            if not first or not last:
                reasons.append("instance time unknown; the window cannot be checked")
                continue
            window_start, window_end = instant(scope["window_start"]), instant(scope["window_end"])
            if first < window_start or last > window_end:
                if len(contradictions) < 20:
                    contradictions.append({
                        "id": f"window:{requirement_id}:{inst['id']}",
                        "summary": f"{inst['activity']} {inst['id']} observed {iso(first)}..{iso(last)}, outside the "
                                   f"window of record {c['reference']} ({scope['window_start']}..{scope['window_end']})",
                        "affects": [requirement_id], "status": "unresolved",
                        "evidence": {"record": c["reference"], "instance": inst["id"],
                                     "observed_window": [iso(first), iso(last)]}})
                reasons.append(f"outside the window of {c['reference']}")
                continue
            covered[inst["id"]] = c["reference"]
            break
        if inst["id"] not in covered:
            uncovered.append({"id": inst["id"], "activity": inst["activity"], "entities": inst["entities"],
                              "process": inst.get("process"), "time": [inst.get("time_start"), inst.get("time_end")],
                              "reference": inst.get("reference"),
                              "reason": "; ".join(dict.fromkeys(reasons)) or "no scoped record for this activity"})
    not_evaluated = profile.get("instances_not_evaluated", 0)
    uncovered_activities = sorted({u["activity"] for u in uncovered})
    covered_activities = sorted({i["activity"] for i in profile.get("instances", []) if i["id"] in covered})
    status = ("confirmed" if records and covered and not uncovered and not not_evaluated
              else "compatible" if records else "unverified")
    return {"status": status, "covered": covered, "covered_activities": covered_activities,
            "uncovered": uncovered[:MAX_LISTED], "uncovered_count": len(uncovered),
            "uncovered_activities": uncovered_activities, "instances_not_evaluated": not_evaluated,
            "unscoped_records": unscoped, "contradictions": contradictions}


def load_reason_definitions(known_requirements: set[str]) -> tuple[dict, list[str]]:
    """Local definitions for custom closing reasons (JSON file named by SOC_BRIDGE_CLOSING_REASONS).

    {"Reason text": {"category": "...", "requires": ["authorization", ...], "definition": "..."}}
    Only known requirement IDs are accepted; anything else makes that definition invalid."""
    path = os.environ.get("SOC_BRIDGE_CLOSING_REASONS", "").strip()
    if not path:
        return {}, []
    problems: list[str] = []
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}, ["closing-reason definitions file unreadable or not JSON"]
    out = {}
    for text, spec in (data.items() if isinstance(data, dict) else []):
        requires = spec.get("requires") if isinstance(spec, dict) else None
        if (not isinstance(text, str) or not isinstance(requires, list) or not requires
                or not set(requires) <= known_requirements or not isinstance(spec.get("definition"), str)):
            problems.append(f"definition for '{str(text)[:60]}' ignored: requires known requirement IDs and a definition")
            continue
        out[text.strip().lower()] = {"requires": requires, "definition": spec["definition"][:500],
                                     "category": str(spec.get("category") or "custom")[:60]}
    return out, problems


CATEGORIES = [
    {"id": "malicious_confirmed", "label": "atividade maliciosa confirmada",
     "requires": ["malicious_activity_confirmed"]},
    {"id": "authorized_activity", "label": "atividade legítima/autorizada que disparou a detecção",
     "requires": ["authorization", "relevant_collection_complete"], "contradicted_by": ["malicious_activity_confirmed"]},
    {"id": "detection_error", "label": "erro de detecção comprovado",
     "requires": ["detection_error", "relevant_collection_complete"], "contradicted_by": ["malicious_activity_confirmed"]},
]
CATEGORY_REASONS = {
    "malicious_confirmed": "No closing reason while remediation is pending; 'Resolved' needs remediation_verified and "
                           "'Policy Violation' needs policy_confirmed. These are separate requirements.",
    "authorized_activity": "Usually 'Non-Issue'/'Not an Issue' in the local catalog; the reason still needs its own requirements.",
    "detection_error": "Usually 'False-Positive, Tuned' only after tuning is applied and verified.",
    "inconclusive": "No disposition is sustained; an explicit administrative decision ('Unresolved') is evaluated separately.",
}


def confidence(sustained: dict | None, req: dict, contradictions: list, corroborated: bool) -> dict:
    """Level from explicit criteria, never from a numeric score.

    "corroborated" is true only when a second source demonstrates the same activity (a link
    by shared identifiers and pertinent behavior), never because any QRadar row exists."""
    basis = []
    if not sustained:
        return {"level": "low", "basis": ["no disposition has all of its requirements met"]}
    needed = [req[r] for r in sustained["met"] if r in req]
    external = [r["id"] for r in needed if str(r.get("source", "")).startswith("analyst")]
    basis.append("requirements met: " + ", ".join(sustained["met"]))
    if external:
        basis.append("relies on analyst-supplied records not verified by the bridge: " + ", ".join(external))
    if contradictions:
        basis.append(f"{len(contradictions)} contradiction(s) recorded (see contradictions)")
    if corroborated:
        basis.append("corroborated: Trend and QRadar records demonstrably describe the same activity "
                     "(shared identifiers and pertinent behavior)")
    else:
        basis.append("no demonstrated second-source corroboration")
    level = "high" if not external and corroborated else "moderate"
    return {"level": level, "basis": basis,
            "criteria": "high = bridge-demonstrated requirements corroborated by a second source that demonstrably "
                        "describes the same activity; moderate = sustained but relying on external records or a "
                        "single source; low = not sustained"}


def now_iso() -> str:
    return iso(datetime.now().astimezone())
