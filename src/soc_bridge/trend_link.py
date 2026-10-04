"""Demonstrated link between a related Trend alert and the offense activity.

An offense-first investigation finds Workbench alerts by IP and time. That association
selects alerts to deepen; it does not show that the alert and the offense describe the same
activity. The alert's True Positive rests on specific Search records: an executed process
instance (actor or newly launched object) whose file hash carries a malicious verdict. A link
is demonstrated only when an offense-linked QRadar process record is that same execution, or
is demonstrably its parent or child, on the same endpoint:

- same execution: same host, same artifact (full hash or identical image path), and the
  same instance (equal PID, or byte-identical command line) with compatible execution times;
- chain: the QRadar process is the parent (or child) of the malicious instance, shown by the
  PID/parent PID and launch times on the same host, and described as such.

A file hash identifies an artifact, not an execution. Alert observables keep their role
(process, parent, object, unknown), source and cut flag, but a parent/object observable never
attributes the malice to a QRadar process, and hashes of one endpoint are never combined
with the hostname of another. The alert creation time is never used as an execution time.
Anything weaker stays a candidate: it neither confirms malicious activity in the offense nor
corroborates the QRadar evidence. Command lines are compared as original strings; a change
of case or spacing is not "identical".
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from .alert_assessment import _executed_roles
from .process_chain import same_host
from .structured import find_paths
from .time_anchor import parse
from .trend_records import full_hashes

TOLERANCE_SECONDS = 2.0
REQUIRED = ("an offense-linked QRadar process record that is the same execution as the Trend instance carrying the "
            "malicious verdict (same host and artifact, equal PID or identical command line, compatible execution "
            "times), or its demonstrated parent/child on the same host")


def _when(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    if len(text) >= 19 and text[10] == " " and "+" not in text[10:] and not text.endswith("Z"):
        text = text.replace(" ", "T", 1) + "Z"  # Sysmon UtcTime is UTC by definition
    return parse(text)[0]


def _iso(value: datetime | None) -> str | None:
    return value.isoformat().replace("+00:00", "Z") if value else None


def _pid(value: Any) -> int | None:
    text = str(value).strip().lower() if value is not None else ""
    try:
        return int(text, 16) if text.startswith("0x") else int(text)
    except ValueError:
        return None


def _instance(group: dict, record: dict, role: str) -> dict:
    cut = [p for p in record.get("cut_by_bridge", []) if p.lower().startswith(role)]
    return {"role": role, "image": group.get("filePath"), "command_line": group.get("cmd"),
            "command_line_cut": bool(cut), "pid": _pid(group.get("pid")),
            "instance_id": group.get("hashId") if role == "process" else group.get("processHashId"),
            "launch_time_utc": _iso(parse(group.get("launchTime"))[0]) if group.get("launchTime") else None,
            "hashes": sorted(full_hashes(group).values())}


def verdict_hashes(report: dict) -> list[str]:
    """Hashes with an existing high-risk sandbox result whose returned artifact contains the full digest."""
    reads = {**(report.get("enrichment") or {}), **(report.get("hypothesis_checks") or {})}
    out = set()
    for name, item in reads.items():
        if not (name.startswith("sandbox:") and isinstance(item, dict) and item.get("state") == "collected"):
            continue
        digest = str(item.get("queried_hash") or "").lower()
        if digest and any(isinstance(e, dict) and str(e.get("riskLevel", "")).lower() == "high"
                          and find_paths(e, digest) for e in item.get("items", [])):
            out.add(digest)
    return sorted(out)


def evidence(report: dict) -> dict:
    """Structured, persistable basis of a Trend alert verdict: re-evaluable without new calls."""
    report = report or {}
    verdicts = set(verdict_hashes(report))
    malicious = []
    for record in ((report.get("auto_pivots") or {}).get("records") or {}).get("linked", []):
        for group in _executed_roles(record):
            role = "process" if group is record.get("process") else "object"
            instance = _instance(group, record, role)
            if not verdicts & set(instance["hashes"]):
                continue
            parent = record.get("parent") or {}
            malicious.append({
                "fact_id": f"malicious_instance:{record.get('uuid') or record.get('tool')}:{role}",
                "trend_record": {"uuid": record.get("uuid"), "tool": record.get("tool"),
                                 "event_time_utc": record.get("event_time_utc"),
                                 "endpoint_host": record.get("endpoint_host"),
                                 "endpoint_guid": record.get("endpoint_guid")},
                "instance": instance,
                "parent": _instance(parent, record, "parent") if parent else None,
                "verdict_hashes": sorted(verdicts & set(instance["hashes"]))})
    observables = []
    for category, items in (((report.get("extraction") or {}).get("observables")) or {}).items():
        for item in items if isinstance(items, list) else []:
            if isinstance(item, dict):
                observables.append({"category": category, "value": item.get("value"), "role": item.get("role", "unknown"),
                                    "sources": item.get("sources", [])[:5], "cut_by_bridge": bool(item.get("cut_by_bridge"))})
    return {"malicious_instances": malicious[:20], "verdict_hashes": sorted(verdicts),
            "observables": observables[:100],
            "alert_created_utc": (report.get("alert") or {}).get("createdDateTime"),
            "note": "alert_created_utc is the alert clock, never an execution time"}


def _qradar_instances(result: dict) -> list[dict]:
    processes = result.get("processes") or {}
    items = processes.get("process_instances")
    if items is None:  # results stored by earlier versions
        items = processes.get("process_creations", [])
    out = []
    for item in items:
        prov = item.get("provenance") or {}
        if prov.get("scope") != "offense_linked":
            continue  # host-context records are near the offense, not part of it
        hashes = item.get("hashes") or {}
        hashes = {str(v.get("value") if isinstance(v, dict) else v).lower() for v in hashes.values()
                  if not isinstance(v, dict) or v.get("comparable")}
        utc = item.get("utc_time") or ((item.get("fields") or {}).get("UtcTime") or {}).get("value")
        moment = _when(utc) or _when(prov.get("devicetime_utc"))
        out.append({"host": item.get("host_norm"), "image": item.get("image"), "command_line": item.get("command_line"),
                    "command_line_cut": bool(item.get("command_line_cut") or item.get("command_line_preview_truncated")),
                    "pid": _pid(item.get("pid")), "parent_pid": _pid(item.get("parent_pid")),
                    "parent_image": item.get("parent_image") or ((item.get("fields") or {}).get("ParentImage") or {}).get("value"),
                    "hashes": hashes, "time": moment,
                    "time_basis": "Sysmon UtcTime" if _when(utc) else "QRadar devicetime" if moment else None,
                    "reference": {k: prov.get(k) for k in ("query", "search_id", "result_row_index")}})
    return out


def _same_artifact(q: dict, t: dict) -> list[str]:
    shared = []
    if q["hashes"] & set(t.get("hashes") or []):
        shared.append("file hash")
    if q["image"] and t.get("image") and q["image"] == t["image"]:
        shared.append("identical image path")
    return shared


def _close(a: datetime | None, b: datetime | None) -> bool:
    return bool(a and b and abs((a - b).total_seconds()) <= TOLERANCE_SECONDS)


def _same_execution(q: dict, t: dict) -> tuple[list[str], str | None]:
    """Instance-level identifiers shared by a QRadar process and a Trend instance; or why not."""
    artifact = _same_artifact(q, t)
    if not artifact:
        return [], "different artifact"
    launched = _when(t.get("launch_time_utc"))
    if not launched or not q["time"]:
        return [], "execution time missing on one side (the alert creation time is not an execution time)"
    if not _close(q["time"], launched):
        return [], f"execution times differ ({_iso(q['time'])} vs {_iso(launched)})"
    instance = []
    if q["pid"] is not None and q["pid"] == t.get("pid"):
        instance.append("process ID")
    if (q["command_line"] and t.get("command_line") and not q["command_line_cut"] and not t.get("command_line_cut")
            and q["command_line"] == t["command_line"]):
        instance.append("identical command line (original string)")
    if not instance:
        return [], "same artifact and time but no instance identifier in common (PID or identical command line)"
    return artifact + instance + ["compatible execution time"], None


def link(result: dict, alert_id: str, basis: dict | None, association: dict | None = None) -> dict:
    """"demonstrated" with the matching records and relation, or "candidate" with what is missing."""
    basis = basis or {}
    malicious = basis.get("malicious_instances") or []
    qradar = _qradar_instances(result)
    matches, reasons = [], []
    for fact in malicious:
        record, t, parent = fact["trend_record"], fact["instance"], fact.get("parent") or {}
        for q in qradar:
            if not q["host"] or not record.get("endpoint_host") or not same_host(q["host"], str(record["endpoint_host"]).lower()):
                reasons.append("different or unknown endpoint")
                continue
            base = {"trend_record": record, "trend_instance": t, "qradar_record": q["reference"], "host": q["host"],
                    "qradar_execution_time": _iso(q["time"]), "qradar_time_basis": q["time_basis"],
                    "fact_id": fact["fact_id"]}
            shared, why = _same_execution(q, t)
            if shared:
                matches.append({**base, "relation": "same_process_instance", "shared_identifiers": shared,
                                "description": f"the QRadar process {q['image']} (PID {q['pid']}) is the Trend instance "
                                               "that carries the malicious verdict"})
                continue
            if parent:
                shared_parent, _ = _same_execution(q, parent)
                if shared_parent and t.get("pid") is not None:
                    matches.append({**base, "relation": "parent_of_malicious_instance",
                                    "shared_identifiers": shared_parent + ["parent PID/launch time recorded by Trend"],
                                    "description": f"the QRadar process {q['image']} (PID {q['pid']}) is the parent of the "
                                                   f"malicious Trend instance {t.get('image')} (PID {t.get('pid')}); the "
                                                   "malice belongs to the child process, launched by this offense activity"})
                    continue
            launched = _when(t.get("launch_time_utc"))
            if (q["parent_pid"] is not None and q["parent_pid"] == t.get("pid") and q["parent_image"] and t.get("image")
                    and q["parent_image"] == t["image"] and launched and q["time"] and q["time"] >= launched):
                matches.append({**base, "relation": "child_of_malicious_instance",
                                "shared_identifiers": ["parent PID", "identical parent image path", "launched after the parent"],
                                "description": f"the QRadar process {q['image']} (PID {q['pid']}) was launched by the "
                                               f"malicious Trend instance {t.get('image')} (PID {t.get('pid')})"})
                continue
            reasons.append(why or "no shared execution")
    if matches:
        return {"alert_id": alert_id, "level": "demonstrated", "matches": matches[:10],
                "basis": "same execution instance or demonstrated process chain on the same endpoint"}
    if not malicious:
        missing = "the Search records that carry the malicious verdict are not available for comparison"
    elif not qradar:
        missing = "no offense-linked QRadar process creation record to compare"
    else:
        missing = "; ".join(sorted(set(reasons)))[:500]
    return {"alert_id": alert_id, "level": "candidate",
            "basis": "related only by the IP/time association used to select the alert"
                     + (f" ({', '.join(association.get('match_fields') or [])})" if association else ""),
            "why_not_demonstrated": missing, "missing": REQUIRED,
            "trend_instances_compared": len(malicious), "qradar_instances_compared": len(qradar)}
