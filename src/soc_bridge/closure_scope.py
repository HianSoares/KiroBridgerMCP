"""Scoped confirmations, observed-activity profile, contradictions and dispositions for closure.

An authorization is evidence only for the activity, entities and window it names. A
generic "the host/account/application is authorized" does not authorize every activity the
collection observed: each observed activity must be covered by a scoped record. Analyst
records stay labelled as external and unverified by the bridge.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any

from .core import address, instant, iso

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
    start, end = instant(scope.get("window_start")), instant(scope.get("window_end"))
    if not start or not end or end < start:
        raise ValueError("scope.window_start/window_end must be ISO-8601 times with a timezone, start <= end")
    return {"activity": activity, "entities": sorted({e.strip().lower() for e in entities}),
            "window_start": iso(start), "window_end": iso(end)}


def observed_profile(result: dict) -> dict:
    """Activities, entities and observed window derived from the collection, with their source."""
    events = result.get("events", {})
    interval = events.get("observed_interval") or {}
    start = instant(interval.get("start")) or instant((result.get("metadata_interval") or {}).get("start"))
    end = instant(interval.get("end")) or instant((result.get("metadata_interval") or {}).get("end")) or start
    entities: set[str] = set()
    source = (result.get("metadata") or {}).get("offense_source")
    if source:
        entities.add(str(source).lower())
    rows = [r for rows in (result.get("collected_rows") or {}).values() for r in rows]
    rows += [s for q in (result.get("queries") or {}).values() for s in q.get("samples", [])]
    for row in rows:
        for key in ("sourceip", "destinationip", "username", "host"):
            value = row.get(key) if isinstance(row, dict) else None
            if isinstance(value, str) and value and (key != "sourceip" or address(value)):
                entities.add(value.lower())
    processes = result.get("processes", {})
    for item in processes.get("process_creations", []):
        if item.get("host_norm"):
            entities.add(str(item["host_norm"]).lower())
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
    return {"activities": activities, "entities": sorted(entities)[:200],
            "window_start": iso(start) if start else None, "window_end": iso(end) if end else None}


def coverage(confirmations: list[dict], profile: dict, requirement_id: str = "authorization") -> dict:
    """Which observed activities a scoped record covers (activity, entity overlap, window)."""
    observed_start, observed_end = instant(profile.get("window_start")), instant(profile.get("window_end"))
    entities = set(profile.get("entities", []))
    covered, uncovered, contradictions, unscoped = {}, [], [], []
    records = [c for c in confirmations if c["requirement"] == requirement_id]
    for c in records:
        if not c.get("scope"):
            unscoped.append(c["reference"])
    for activity in profile["activities"]:
        match = None
        for c in records:
            scope = c.get("scope")
            if not scope or scope["activity"] != activity:
                continue
            if not set(scope["entities"]) & entities:
                continue
            start, end = instant(scope["window_start"]), instant(scope["window_end"])
            if observed_start and observed_end and (start > observed_start or end < observed_end):
                contradictions.append({
                    "id": f"window:{requirement_id}:{activity}",
                    "summary": f"{activity} observed {iso(observed_start)}..{iso(observed_end)}, outside the window "
                               f"of record {c['reference']} ({scope['window_start']}..{scope['window_end']})",
                    "affects": [requirement_id], "status": "unresolved",
                    "evidence": {"record": c["reference"], "observed_window": [iso(observed_start), iso(observed_end)]}})
                continue
            match = c["reference"]
            break
        if match:
            covered[activity] = match
        else:
            uncovered.append(activity)
    status = ("confirmed" if records and not uncovered else "compatible" if records else "unverified")
    return {"status": status, "covered": covered, "uncovered": uncovered, "unscoped_records": unscoped,
            "contradictions": contradictions}


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
    """Level from explicit criteria, never from a numeric score."""
    basis = []
    if not sustained:
        return {"level": "low", "basis": ["no disposition has all of its requirements met"]}
    needed = [req[r] for r in sustained["met"] if r in req]
    external = [r["id"] for r in needed if str(r.get("source", "")).startswith("analyst")]
    basis.append("requirements met: " + ", ".join(sustained["met"]))
    if external:
        basis.append("relies on analyst-supplied records not verified by the bridge: " + ", ".join(external))
    if contradictions:
        basis.append(f"{len(contradictions)} resolved/irrelevant contradiction(s) recorded")
    if corroborated:
        basis.append("corroborated by an independent source (Trend and QRadar)")
    level = "high" if not external and corroborated else "moderate"
    return {"level": level, "basis": basis,
            "criteria": "high = bridge-demonstrated requirements corroborated by a second source; moderate = sustained "
                        "but relying on external records or a single source; low = not sustained"}


def now_iso() -> str:
    return iso(datetime.now().astimezone())
