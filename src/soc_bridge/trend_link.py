"""Demonstrated link between a related Trend alert and the offense activity.

An offense-first investigation finds Workbench alerts by IP and time. That association
selects alerts to deepen; it does not show that the alert and the offense describe the same
activity. The alert's True Positive rests on specific Search records: an executed process
instance (actor, or newly launched object) whose file hash carries a malicious verdict. A link
is demonstrated only when an offense-linked QRadar process record is that same execution, or
is demonstrably its parent or child, on the same endpoint.

Identity rules (``LINK_CRITERIA``):

- Hashes are compared per algorithm (sha256/sha1/md5) and per role/artifact, with their source.
  Each comparison is ``equal``, ``conflict`` (complete digests of the same algorithm differ),
  ``incomplete`` (present but cut or invalid), ``not_comparable`` (different algorithms) or
  ``absent``. A conflict is recorded and is never outweighed by an equal path, PID or command.
  It does not show the activity is benign; it shows this association is not demonstrated.
- Known identifiers that differ (PID, original command line, image path) are conflicts too.
- Same execution: same endpoint, compatible execution times, no conflict, and either an equal
  hash plus an equal PID or identical command line, or (hash absent/not comparable) an
  identical image path plus an equal PID.
- Parent of the malicious instance: the QRadar process is the Trend parent instance by the same
  rules (PID and launch time identify the instance; a long-lived parent stays valid). For a
  newly launched object, the parent is the actor process of that record, not the actor's parent.
- Child of the malicious instance: the QRadar child's ParentProcessGuid must point to a QRadar
  process record (INOFFENSE or host context, labelled as such) on the same endpoint that is the
  malicious instance by the same rules. A parent PID alone never identifies the parent instance
  (PID reuse). Trend instance IDs and Sysmon GUIDs are different namespaces and never compared.

The alert creation time is never an execution time. Anything weaker stays a candidate: it
neither confirms malicious activity in the offense nor corroborates the QRadar evidence.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from .alert_assessment import _executed_roles
from .process_chain import guid as normalize_guid, instance_key, same_host
from .structured import find_paths
from .time_anchor import parse

LINK_CRITERIA = "activity-v3"
BASIS_VERSION = 2
TOLERANCE_SECONDS = 2.0
ALGORITHMS = {"sha256": 64, "sha1": 40, "md5": 32}
TREND_HASH_FIELDS = {"fileHashSha256": "sha256", "fileHashSha1": "sha1", "fileHashMd5": "md5"}
REQUIRED = ("an offense-linked QRadar process record that is the same execution as the Trend instance carrying the "
            "malicious verdict (same endpoint, no conflicting hash or identifier, equal hash with equal PID or "
            "identical command line, or identical path with equal PID when no hash is comparable, compatible "
            "execution times), or its parent/child demonstrated by instance identity (ParentProcessGuid) on the "
            "same endpoint")


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


def _hex(value: Any, length: int) -> bool:
    text = str(value or "")
    return len(text) == length and all(c in "0123456789abcdefABCDEF" for c in text)


def trend_hash_states(group: dict, role: str) -> dict:
    out = {}
    for field, algo in TREND_HASH_FIELDS.items():
        value = group.get(field)
        if value in (None, ""):
            continue
        complete = _hex(value, ALGORITHMS[algo])
        out[algo] = {"state": "complete" if complete else "incomplete",
                     "value": str(value).lower() if complete else None,
                     "observed_length": len(str(value)), "source": f"Trend {role}.{field}"}
    return out


def _legacy_states(hashes: Any, source: str) -> dict:
    """Hash lists/dicts stored by earlier versions: the algorithm is inferred from a full hex length."""
    values = hashes.values() if isinstance(hashes, dict) else hashes or []
    out = {}
    for value in values:
        value = value.get("value") if isinstance(value, dict) else value
        algo = next((a for a, n in ALGORITHMS.items() if _hex(value, n)), None)
        if algo:
            out[algo] = {"state": "complete", "value": str(value).lower(), "observed_length": len(str(value)),
                         "source": source}
    return out


def compare_hashes(left: dict, right: dict) -> dict:
    """Per-algorithm comparison of two artifacts' hash states; never compares across algorithms."""
    if not left or not right:
        side = "both" if not left and not right else "QRadar" if not left else "Trend"
        return {"state": "absent", "by_algorithm": {}, "missing_on": side}
    by_algorithm = {}
    for algo in sorted(set(left) | set(right)):
        a, b = left.get(algo), right.get(algo)
        if not a or not b:
            by_algorithm[algo] = {"state": "one_side", "qradar": a, "trend": b}
        elif a["state"] != "complete" or b["state"] != "complete":
            by_algorithm[algo] = {"state": "incomplete", "qradar": a, "trend": b}
        else:
            by_algorithm[algo] = {"state": "equal" if a["value"] == b["value"] else "conflict", "qradar": a, "trend": b}
    states = {v["state"] for v in by_algorithm.values()}
    overall = ("conflict" if "conflict" in states else "equal" if "equal" in states else
               "incomplete" if "incomplete" in states else "not_comparable")
    return {"state": overall, "by_algorithm": by_algorithm}


def _instance(group: dict, record: dict, role: str) -> dict:
    cut = [p for p in record.get("cut_by_bridge", []) if p.lower().startswith(role)]
    states = trend_hash_states(group, role)
    return {"role": role, "image": group.get("filePath"), "command_line": group.get("cmd"),
            "command_line_cut": bool(cut), "pid": _pid(group.get("pid")),
            "instance_id": group.get("hashId") if role in ("process", "parent") else group.get("processHashId"),
            "instance_id_namespace": "Trend process hash ID (not a Sysmon ProcessGuid)",
            "launch_time_utc": _iso(parse(group.get("launchTime"))[0]) if group.get("launchTime") else None,
            "hash_states": states,
            "hashes": sorted(v["value"] for v in states.values() if v["state"] == "complete")}


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
            # The parent of a newly launched object is the actor of the record; the parent of an actor
            # is the record's parent group.
            parent_group, parent_role = ((record.get("process"), "process") if role == "object"
                                         else (record.get("parent"), "parent"))
            malicious.append({
                "fact_id": f"malicious_instance:{record.get('uuid') or record.get('tool')}:{role}",
                "basis_version": BASIS_VERSION,
                "trend_record": {"uuid": record.get("uuid"), "tool": record.get("tool"),
                                 "event_time_utc": record.get("event_time_utc"),
                                 "endpoint_host": record.get("endpoint_host"),
                                 "endpoint_guid": record.get("endpoint_guid")},
                "instance": instance,
                "parent": _instance(parent_group, record, parent_role) if parent_group else None,
                "parent_basis": ("actor process of the record (launched the object)" if role == "object"
                                 else "parent group of the record"),
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


def trend_states(instance: dict) -> dict:
    return instance.get("hash_states") or _legacy_states(instance.get("hashes"), "Trend (stored by an earlier version)")


def _qradar_instances(result: dict) -> list[dict]:
    processes = result.get("processes") or {}
    items = processes.get("process_instances")
    if items is None:  # results stored by earlier versions
        items = processes.get("process_creations", [])
    out = []
    for item in items:
        prov = item.get("provenance") or {}
        states = item.get("hash_states")
        if states is None:
            raw = item.get("hashes") or {}
            states = ({k.lower(): {"state": "complete" if v.get("comparable") else "incomplete",
                                   "value": str(v.get("value")).lower() if v.get("comparable") else None,
                                   "observed_length": len(str(v.get("value") or "")), "source": f"Sysmon Hashes {k}"}
                       for k, v in raw.items() if isinstance(v, dict) and k.lower() in ALGORITHMS}
                      or _legacy_states(raw, "Sysmon Hashes (stored by an earlier version)"))
        utc = item.get("utc_time") or ((item.get("fields") or {}).get("UtcTime") or {}).get("value")
        moment = _when(utc) or _when(prov.get("devicetime_utc"))
        parent_guid = item.get("parent_guid_norm") or normalize_guid(
            ((item.get("fields") or {}).get("ParentProcessGuid") or {}).get("value"))
        key = item.get("instance_key") or instance_key(item.get("host_norm"), item.get("guid_norm"), item.get("pid"),
                                                        utc, item.get("image"))
        out.append({"key": key, "host": item.get("host_norm"), "image": item.get("image"), "command_line": item.get("command_line"),
                    "command_line_cut": bool(item.get("command_line_cut") or item.get("command_line_preview_truncated")),
                    "pid": _pid(item.get("pid")), "parent_pid": _pid(item.get("parent_pid")),
                    "guid": item.get("guid_norm"), "parent_guid": parent_guid,
                    "hash_states": states, "time": moment, "scope": prov.get("scope"),
                    "time_basis": "Sysmon UtcTime" if _when(utc) else "QRadar devicetime" if moment else None,
                    "reference": {k: prov.get(k) for k in ("query", "scope", "search_id", "result_row_index")}})
    return out


def _close(a: datetime | None, b: datetime | None) -> bool:
    return bool(a and b and abs((a - b).total_seconds()) <= TOLERANCE_SECONDS)


def _same_path(a: str | None, b: str | None) -> bool | None:
    """True identical, False different (case-insensitively), None when either is unknown."""
    if not a or not b:
        return None
    return True if a == b else None if a.lower() == b.lower() else False


def same_execution(q: dict, t: dict) -> dict:
    """Whether a QRadar process record and a Trend instance are the same execution, with the basis."""
    artifact = compare_hashes(q["hash_states"], trend_states(t))
    launched = _when(t.get("launch_time_utc"))
    path = _same_path(q["image"], t.get("image"))
    pid = None if q["pid"] is None or t.get("pid") is None else q["pid"] == t["pid"]
    full = lambda c, cut: bool(c) and not cut  # noqa: E731
    command = (q["command_line"] == t["command_line"]
               if full(q["command_line"], q["command_line_cut"]) and full(t.get("command_line"), t.get("command_line_cut"))
               else None)
    conflicts = []
    if artifact["state"] == "conflict":
        conflicts.append("full " + ", ".join(a for a, v in artifact["by_algorithm"].items() if v["state"] == "conflict")
                         + " hashes differ")
    if pid is False:
        conflicts.append(f"process ID differs ({q['pid']} vs {t.get('pid')})")
    if command is False:
        conflicts.append("command lines differ (original strings)")
    if path is False:
        conflicts.append("image paths differ")
    weak = [name for name, value in (("identical image path", path), ("process ID", pid),
                                     ("identical command line (original string)", command)) if value]
    time_ok = _close(q["time"], launched)
    base = {"artifact": artifact, "weak_signals": weak, "conflicts": conflicts, "time_ok": time_ok}
    hashes = f" (hash comparison: {artifact['state']})"
    if not launched or not q["time"]:
        return {**base, "same": False,
                "reason": "execution time missing on one side (the alert creation time is not an execution time)" + hashes}
    if not time_ok:
        return {**base, "same": False,
                "reason": f"execution times differ ({_iso(q['time'])} vs {_iso(launched)})" + hashes}
    if conflicts:
        return {**base, "same": False, "reason": "; ".join(conflicts) + hashes}
    if artifact["state"] == "equal" and (pid or command):
        return {**base, "same": True, "shared": ["file hash (" + ", ".join(
            a for a, v in artifact["by_algorithm"].items() if v["state"] == "equal") + ")"] + weak
                                                + ["compatible execution time"]}
    if artifact["state"] in ("absent", "not_comparable", "incomplete") and path and pid:
        return {**base, "same": True, "shared": weak + ["compatible execution time"],
                "note": f"hash {artifact['state']}: identity rests on the identical path, PID and execution time"}
    if artifact["state"] == "equal":
        return {**base, "same": False, "reason": "same artifact and time but no instance identifier in common "
                                                 "(PID or identical command line)"}
    return {**base, "same": False,
            "reason": f"hash {artifact['state']}: needs an identical image path and an equal PID"}


def _conflict(q: dict, t: dict, record: dict, check: dict, relation: str, fact_id: str) -> dict | None:
    """A recorded contradiction when weaker signals suggest identity but a known identifier conflicts."""
    if not check["time_ok"] or not check["conflicts"] or not (check["weak_signals"] or check["artifact"]["state"] == "equal"):
        return None
    return {"relation_tested": relation, "trend_record": record.get("uuid"), "trend_role": t.get("role"),
            "fact_id": fact_id, "qradar_instance_key": q["key"],
            "qradar_record": q["reference"], "conflicts": check["conflicts"], "weak_signals": check["weak_signals"],
            "hashes": check["artifact"]["by_algorithm"],
            "meaning": "this association is not demonstrated; the conflict does not show the activity is benign"}


def link(result: dict, alert_id: str, basis: dict | None, association: dict | None = None) -> dict:
    """"demonstrated" with the matching records and relation, or "candidate" with what is missing."""
    basis = basis or {}
    malicious = basis.get("malicious_instances") or []
    every = _qradar_instances(result)
    offense = [q for q in every if q["scope"] == "offense_linked"]  # context records are near, not part of it
    matches, reasons, conflicts = [], [], []
    for fact in malicious:
        record, t = fact["trend_record"], fact["instance"]
        parent = fact.get("parent") or {}
        if not fact.get("basis_version") and t.get("role") == "object":
            parent = {}  # earlier versions stored the actor's parent here; it is not the object's parent
            reasons.append("stored basis predates the actor/object parent distinction; parent relation not evaluated")
        endpoint = str(record.get("endpoint_host") or "").lower()
        for q in offense:
            if not q["host"] or not endpoint or not same_host(q["host"], endpoint):
                reasons.append("different or unknown endpoint")
                continue
            base = {"trend_record": record, "trend_instance": t, "qradar_record": q["reference"],
                    "qradar_instance_key": q["key"], "host": q["host"],
                    "qradar_execution_time": _iso(q["time"]), "qradar_time_basis": q["time_basis"],
                    "fact_id": fact["fact_id"], "criteria": LINK_CRITERIA}
            check = same_execution(q, t)
            if check["same"]:
                matches.append({**base, "relation": "same_process_instance", "artifact": check["artifact"],
                                "shared_identifiers": check["shared"], "note": check.get("note"),
                                "description": f"the QRadar process {q['image']} (PID {q['pid']}) is the Trend instance "
                                               "that carries the malicious verdict"})
                continue
            found = _conflict(q, t, record, check, "same_process_instance", fact["fact_id"])
            if found:
                conflicts.append(found)
            reasons.append(check["reason"])
            if parent:
                up = same_execution(q, parent)
                if up["same"] and t.get("pid") is not None:
                    matches.append({**base, "relation": "parent_of_malicious_instance", "artifact": up["artifact"],
                                    "shared_identifiers": up["shared"] + [f"Trend {fact.get('parent_basis') or 'parent'}"],
                                    "description": f"the QRadar process {q['image']} (PID {q['pid']}) is the parent of the "
                                                   f"malicious Trend instance {t.get('image')} (PID {t.get('pid')}), "
                                                   f"identified as the {fact.get('parent_basis') or 'parent'}; the malice "
                                                   "belongs to the child process, launched by this offense activity"})
                    continue
                found = _conflict(q, parent, record, up, "parent_of_malicious_instance", fact["fact_id"])
                if found:
                    conflicts.append(found)
            if q["parent_pid"] is None or q["parent_pid"] != t.get("pid"):
                continue
            if not q["parent_guid"]:
                reasons.append("ParentProcessGuid not available: a parent PID alone does not identify the parent "
                               "instance (PID reuse)")
                continue
            parents = [r for r in every if r["guid"] == q["parent_guid"] and r["host"] and same_host(r["host"], q["host"])]
            if not parents:
                reasons.append(f"parent instance {q['parent_guid']} (ParentProcessGuid) not observed in the collected "
                               "records on this endpoint; a parent PID alone does not identify it")
                continue
            r = parents[0]
            up = same_execution(r, t)
            if up["same"] and q["time"] and r["time"] and q["time"] >= r["time"]:
                where = "an INOFFENSE record" if r["scope"] == "offense_linked" else f"a {r['scope']} record (not an INOFFENSE record)"
                matches.append({**base, "relation": "child_of_malicious_instance", "artifact": up["artifact"],
                                "shared_identifiers": ["ParentProcessGuid -> parent creation record on the same endpoint"]
                                + up["shared"],
                                "chain": {"child_guid": q["guid"], "parent_guid": q["parent_guid"],
                                          "parent_record": r["reference"], "parent_record_scope": r["scope"]},
                                "description": f"the QRadar process {q['image']} (PID {q['pid']}) was launched by the "
                                               f"malicious instance {t.get('image')} (PID {t.get('pid')}); the parent is "
                                               f"identified by ParentProcessGuid {q['parent_guid']} in {where}"})
                continue
            reasons.append(f"ParentProcessGuid {q['parent_guid']} identifies an instance started {_iso(r['time'])} that "
                           f"is not the malicious instance ({up.get('reason')}): PID reuse or another execution")
    if matches:
        return {"alert_id": alert_id, "level": "demonstrated", "matches": matches[:10], "conflicts": conflicts[:10],
                "criteria": LINK_CRITERIA,
                "basis": "same execution instance or process chain demonstrated by instance identity on the same endpoint"}
    if not malicious:
        missing = "the Search records that carry the malicious verdict are not available for comparison"
    elif not offense:
        missing = "no offense-linked QRadar process creation record to compare"
    else:
        missing = "; ".join(sorted(set(reasons)))[:800]
    return {"alert_id": alert_id, "level": "candidate", "conflicts": conflicts[:10], "criteria": LINK_CRITERIA,
            "basis": "related only by the IP/time association used to select the alert"
                     + (f" ({', '.join(association.get('match_fields') or [])})" if association else ""),
            "why_not_demonstrated": missing, "missing": REQUIRED,
            "trend_instances_compared": len(malicious), "qradar_instances_compared": len(offense)}


def stored_link_conflicts(match: dict, current: dict | None, computed: dict) -> list[str]:
    """Positive contradictions between a stored link and the current evidence of its own identifiers.

    A stored link stays usable only while nothing current contradicts it: a conflict found now for the
    same Trend fact and QRadar instance, a change of the Trend instance's own complete hashes, PID or
    launch time, or complete hashes recorded for the linked QRadar process that differ from the current
    Trend instance (or parent). Missing observations are not contradictions."""
    out = []
    key = (match.get("fact_id"), match.get("qradar_instance_key"))
    for conflict in computed.get("conflicts", []):
        if (conflict.get("fact_id"), conflict.get("qradar_instance_key")) == key:
            out += [f"current comparison: {c}" for c in conflict["conflicts"]]
    if not current:
        return list(dict.fromkeys(out))
    then, now = match.get("trend_instance") or {}, current.get("instance") or {}
    changed = compare_hashes(trend_states(then), trend_states(now))
    if changed["state"] == "conflict":
        out.append("Trend instance changed: full " + ", ".join(
            a for a, v in changed["by_algorithm"].items() if v["state"] == "conflict") + " hashes differ from the linked ones")
    if then.get("pid") is not None and now.get("pid") is not None and then["pid"] != now["pid"]:
        out.append(f"Trend instance changed: process ID {then['pid']} -> {now['pid']}")
    first, second = _when(then.get("launch_time_utc")), _when(now.get("launch_time_utc"))
    if first and second and not _close(first, second):
        out.append(f"Trend instance changed: launch time {_iso(first)} -> {_iso(second)}")
    target = (current.get("parent") if match.get("relation") == "parent_of_malicious_instance" else now) or {}
    linked = {a: v["qradar"] for a, v in ((match.get("artifact") or {}).get("by_algorithm") or {}).items()
              if v.get("qradar")}
    against = compare_hashes(linked, trend_states(target))
    if against["state"] == "conflict":
        out.append("full " + ", ".join(a for a, v in against["by_algorithm"].items() if v["state"] == "conflict")
                   + " hashes of the linked QRadar process differ from the current Trend instance")
    return list(dict.fromkeys(out))
