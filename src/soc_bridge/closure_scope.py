"""Scoped confirmations, observed-activity instances, contradictions and dispositions for closure.

An authorization is evidence only for the activity, entities, behavior and window it names.
Each observed activity instance (one process creation, one script block, one privileged
command or identity switch, or one entity of another activity) is evaluated on its own:
authorizing a backup script run by powershell.exe on host-a covers neither processes on
host-b nor another PowerShell command on host-a. An executable name never authorizes every
behavior of that executable; a broad authorization must be declared by the external record
and is shown as such. Instances that no record covers, and instances the engine could not
evaluate (with count, reason and next action), stay listed explicitly. Analyst records stay
labelled as external and unverified by the bridge.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
from datetime import datetime
from pathlib import Path
from typing import Any

from .core import address, instant, iso
from .process_chain import arguments, basename, guid, same_host

# Activities the collection can actually demonstrate; each maps to existing analyses.
ACTIVITIES = {
    "process_execution": "process creation records (Sysmon 1 / 4688) in the collected rows",
    "script_execution": "PowerShell 4104/4103 script content records",
    "remote_authentication": "accepted SSH authentication records",
    "privilege_use": "sudo commands and su identity switches",
    "account_lockout": "4740 account lockout records",
    "explicit_credential_use": "4648 explicit-credential attempt records (attempt, not success)",
    "network_traffic": "offense-linked flow records",
    "code_integrity": "5038 code-integrity records",
    "offense_activity": "the offense-linked records when no more specific activity was identified",
}
SCOPED_REQUIREMENTS = {"authorization", "malicious_activity_confirmed", "detection_error"}
# Queries whose rows carry each entity-level activity (entities and times per row).
ACTIVITY_QUERIES = {
    "remote_authentication": ("events", "linux_ssh_window"),
    "privilege_use": ("events", "linux_identity_window"),
    "account_lockout": ("events", "lockout_authentication"),
    "explicit_credential_use": ("host_context",),
    "network_traffic": ("flows", "host_flows"),
    "code_integrity": ("integrity",),
    "offense_activity": ("events", "flows"),
}
MAX_INSTANCES = 5000  # analysis cap per profile; beyond it instances are counted as not evaluated
MAX_LISTED = 50  # presentation cap of the uncovered list (the count is always complete)
EXPLICIT_OFFSET = re.compile(r"(Z|[+-]\d{2}:?\d{2})$", re.I)
BREADTH = "any_behavior_of_named_processes"
PRIVILEGE_BREADTH = "any_privileged_command_of_named_accounts"
# Executables whose behavior is defined by the script/code they run, not by their own binary.
INTERPRETERS = {"powershell.exe", "pwsh.exe", "powershell_ise.exe", "pwsh", "cmd.exe", "python.exe", "pythonw.exe",
                "py.exe", "python", "python3", "bash", "bash.exe", "sh", "sh.exe", "zsh", "dash", "ksh", "wscript.exe",
                "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "node.exe", "node", "perl", "perl.exe",
                "ruby", "ruby.exe", "php", "php.exe", "java.exe", "java", "javaw.exe", "wmic.exe", "msiexec.exe",
                "installutil.exe", "msbuild.exe"}
INLINE_FLAGS = {"-command", "-c", "/c", "/k", "/r", "-e", "-ec", "-en", "-enc", "-enco", "-encod", "-encode",
                "-encoded", "-encodedc", "-encodedco", "-encodedcom", "-encodedcomm", "-encodedcomma",
                "-encodedcomman", "-encodedcommand", "-m", "-r", "-x", "-eval", "-p"}
VALUE_OPTIONS = {"-executionpolicy", "-ep", "-ex", "-exec", "-windowstyle", "-w", "-version", "-v", "-psconsolefile",
                 "-configurationname", "-workingdirectory", "-wd", "-inputformat", "-if", "-outputformat", "-of",
                 "-settingsfile"}
FULL_HASH = re.compile(r"^(?:[0-9A-Fa-f]{32}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})$")


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


def _norm(value: Any) -> str | None:
    return " ".join(value.split()).lower() if isinstance(value, str) and value.strip() else None


def _strings(value: Any, field: str, limit: int = 20, size: int = 500, keep: bool = False) -> list[str]:
    """Validated list; ``keep`` preserves the original strings (only outer whitespace is removed)."""
    if (not isinstance(value, list) or not 1 <= len(value) <= limit
            or not all(isinstance(v, str) and 0 < len(v.strip()) <= size for v in value)):
        raise ValueError(f"{field} must list 1..{limit} non-empty strings of up to {size} characters")
    return sorted({v.strip() if keep else _norm(v) for v in value})


def _breadth(scope: dict, allowed: str) -> dict:
    basis = scope.get("breadth_basis")
    if scope.get("breadth") != allowed:
        raise ValueError(f"scope.breadth, when present, must be '{allowed}'")
    if not isinstance(basis, str) or not 10 <= len(basis.strip()) <= 500:
        raise ValueError("scope.breadth_basis must quote where the external record grants the broad authorization "
                         "(10..500 characters); breadth is never inferred from an executable or account name")
    return {"breadth": allowed, "breadth_basis": basis.strip()}


def _process_scope(scope: dict, out: dict) -> None:
    if scope.get("processes") is None:
        raise ValueError("scope.processes is required for process_execution: name the authorized executables "
                         "(full path or file name); an authorization without processes covers no process")
    out["processes"] = _strings(scope["processes"], "scope.processes")
    if scope.get("command_lines") is not None:
        out["command_lines"] = _strings(scope["command_lines"], "scope.command_lines", size=8192, keep=True)
    if scope.get("script_paths") is not None:
        out["script_paths"] = _strings(scope["script_paths"], "scope.script_paths", keep=True)
    if scope.get("artifact_hashes") is not None:
        hashes = _strings(scope["artifact_hashes"], "scope.artifact_hashes", size=64)
        if not all(FULL_HASH.fullmatch(h) for h in hashes):
            raise ValueError("scope.artifact_hashes must be full MD5/SHA-1/SHA-256 digests")
        out["artifact_hashes"] = hashes
    if scope.get("process_instances") is not None:
        instances = [guid(v) for v in _strings(scope["process_instances"], "scope.process_instances", size=40)]
        if not all(instances):
            raise ValueError("scope.process_instances must be ProcessGuid values")
        out["process_instances"] = sorted(instances)
    if scope.get("parent_processes") is not None:
        out["parent_processes"] = _strings(scope["parent_processes"], "scope.parent_processes")
    if scope.get("breadth") is not None or scope.get("breadth_basis") is not None:
        out.update(_breadth(scope, BREADTH))
    behavior = [k for k in ("command_lines", "script_paths", "artifact_hashes", "process_instances", "breadth") if k in out]
    if not behavior:
        raise ValueError("process_execution needs a behavior discriminator besides the executable: command_lines "
                         "(exact strings), script_paths, artifact_hashes (non-interpreters), process_instances "
                         f"(ProcessGuid) or an explicit breadth='{BREADTH}' with breadth_basis")
    interpreters = sorted(p for p in out["processes"] if basename(p) in INTERPRETERS)
    if interpreters and behavior == ["artifact_hashes"]:
        raise ValueError(f"{', '.join(interpreters)} is an interpreter: its file hash identifies the interpreter, "
                         "not the script or command it ran; cite command_lines, script_paths or process_instances")


def _privilege_scope(scope: dict, out: dict) -> None:
    if scope.get("commands") is not None:
        out["commands"] = _strings(scope["commands"], "scope.commands", size=8192, keep=True)
    if scope.get("run_as") is not None:
        out["run_as"] = _strings(scope["run_as"], "scope.run_as", size=128, keep=True)
    if scope.get("identity_switch") is not None:
        if scope["identity_switch"] is not True:
            raise ValueError("scope.identity_switch, when present, must be true")
        out["identity_switch"] = True
    if scope.get("breadth") is not None or scope.get("breadth_basis") is not None:
        out.update(_breadth(scope, PRIVILEGE_BREADTH))
    if not any(k in out for k in ("commands", "identity_switch", "breadth")):
        raise ValueError("privilege_use needs the authorized behavior: commands (exact sudo commands), "
                         f"identity_switch=true for su, or an explicit breadth='{PRIVILEGE_BREADTH}' with breadth_basis")


SPECIFIC_FIELDS = ("processes", "command_lines", "script_paths", "artifact_hashes", "process_instances",
                   "parent_processes", "script_block_ids", "commands", "run_as", "identity_switch", "breadth",
                   "breadth_basis")


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
    allowed: tuple = ()
    if activity == "process_execution":
        _process_scope(scope, out)
        allowed = ("processes", "command_lines", "script_paths", "artifact_hashes", "process_instances",
                   "parent_processes", "breadth", "breadth_basis")
    elif activity == "script_execution":
        if scope.get("script_block_ids") is None:
            raise ValueError("scope.script_block_ids is required for script_execution: cite the ScriptBlockId values")
        out["script_block_ids"] = _strings(scope["script_block_ids"], "scope.script_block_ids", size=100)
        allowed = ("script_block_ids",)
    elif activity == "privilege_use":
        _privilege_scope(scope, out)
        allowed = ("commands", "run_as", "identity_switch", "breadth", "breadth_basis")
    unexpected = [k for k in SPECIFIC_FIELDS if k in scope and k not in allowed]
    if unexpected:
        raise ValueError(f"{', '.join(unexpected)} do not apply to a {activity} scope")
    return out


def script_invocation(command_line: str | None, image: str | None) -> dict:
    """What an interpreter was asked to run: a script path, inline code, or unknown; never executed."""
    name = basename(image) or ""
    rest = arguments(command_line, image)
    if rest is None:
        return {"script": None, "inline": None, "extra_arguments": None, "basis": "command line not observed"}
    try:
        tokens = shlex.split(rest, posix=False)
    except ValueError:
        return {"script": None, "inline": None, "extra_arguments": None, "basis": "command line not tokenizable"}
    tokens = [t[1:-1] if len(t) >= 2 and t[0] == t[-1] == '"' else t for t in tokens]
    index = 0
    while index < len(tokens):
        token = tokens[index]
        lower = token.lower()
        if lower in INLINE_FLAGS:
            return {"script": None, "inline": True, "extra_arguments": None, "basis": f"inline code flag {token}"}
        if lower in ("-file", "-f"):
            script = tokens[index + 1] if index + 1 < len(tokens) else None
            return {"script": script, "inline": False, "extra_arguments": len(tokens) > index + 2,
                    "basis": f"{token} argument"}
        if lower.startswith("-") or (name == "cmd.exe" and lower.startswith("/")):
            index += 2 if lower in VALUE_OPTIONS else 1
            continue
        if name in ("powershell.exe", "powershell_ise.exe"):
            # Windows PowerShell treats bare arguments as -Command text.
            return {"script": None, "inline": True, "extra_arguments": None, "basis": "bare argument runs as -Command"}
        return {"script": token, "inline": False, "extra_arguments": len(tokens) > index + 1,
                "basis": "first non-option argument"}
    return {"script": None, "inline": False, "extra_arguments": False, "basis": "no script argument"}


def _same_path(left: str | None, right: str | None) -> bool:
    if not left or not right:
        return False
    windows = bool(re.match(r"^[A-Za-z]:\\|^\\\\", left) or re.match(r"^[A-Za-z]:\\|^\\\\", right))
    return left.lower() == right.lower() if windows else left == right


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
    creations = processes.get("process_instances", processes.get("process_creations"))
    if creations:
        total = len(creations) + processes.get("process_instances_not_analyzed", 0)
        activities["process_execution"] = f"{total} process creation record(s)"
    blocks = processes.get("script_block_instances", processes.get("script_blocks"))
    if blocks:
        activities["script_execution"] = f"{len(blocks)} script content record(s)"
    linux = result.get("linux", {})
    kinds = (linux.get("offense") or {}).get("kind_counts", {})
    if (linux.get("ssh_window") or {}).get("accepted_ssh_count") or kinds.get("ssh_authentication_accepted"):
        activities["remote_authentication"] = "accepted SSH record(s)"
    if kinds.get("sudo_command_record") or kinds.get("su_identity_record") or any(
            (linux.get(p) or {}).get("kind_counts", {}).get(k) for p in ("identity_window",)
            for k in ("sudo_command_record", "su_identity_record")):
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


def _not_evaluated(gaps: dict, activity: str, count: int, reason: str, action: str) -> None:
    if count <= 0:
        return
    entry = gaps.setdefault(activity, {"count": 0, "reasons": [], "next_actions": []})
    entry["count"] += count
    entry["reasons"].append(f"{count}: {reason}")
    entry["next_actions"].append(action)


RERUN = ("run investigate_offense_case again on the same case: completed queries are reused from the case and "
         "re-analyzed without new searches")
NARROW = "narrow the window or partition the offense query (qradar_run_aql) so each part stays under the analysis cap"


def _process_instances(result: dict, gaps: dict) -> list[dict]:
    processes = result.get("processes", {})
    out = []
    if "process_instances" in processes:
        items = processes["process_instances"]
        _not_evaluated(gaps, "process_execution", processes.get("process_instances_not_analyzed", 0),
                       "process creations beyond the analysis cap", NARROW)
    else:
        items = processes.get("process_creations", [])
        _not_evaluated(gaps, "process_execution", processes.get("process_creations_omitted", 0),
                       "only the presentation list (first 100 creations) is available in this result", RERUN)
    for index, item in enumerate(items):
        prov = item.get("provenance") or {}
        image = item.get("image")
        command = item.get("command_line")
        cut = bool(item.get("command_line_cut") or item.get("command_line_preview_truncated"))
        parent = item.get("parent_image") or ((item.get("fields") or {}).get("ParentImage") or {}).get("value")
        hashes = item.get("hashes") or {}
        hashes = {k: (v.get("value") if isinstance(v, dict) else v) for k, v in hashes.items()
                  if not isinstance(v, dict) or v.get("comparable")}
        out.append({"id": f"process:{item.get('guid_norm') or index}:{item.get('host_norm') or 'host?'}",
                    "activity": "process_execution",
                    "entities": [item["host_norm"]] if item.get("host_norm") else [],
                    "process": {"image": image, "command_line": command, "command_line_cut": cut,
                                "parent_image": parent, "guid": item.get("guid_norm"),
                                "hashes": {k: str(v).lower() for k, v in hashes.items() if v},
                                "invocation": script_invocation(command, image) if basename(image) in INTERPRETERS else None},
                    "time_start": prov.get("starttime_utc"), "time_end": prov.get("starttime_utc"),
                    "reference": {k: prov.get(k) for k in ("query", "search_id", "result_row_index")}})
    return out


def _script_instances(result: dict, gaps: dict) -> list[dict]:
    processes = result.get("processes", {})
    if "script_block_instances" in processes:
        items = processes["script_block_instances"]
        _not_evaluated(gaps, "script_execution", processes.get("script_block_instances_not_analyzed", 0),
                       "script blocks beyond the analysis cap", NARROW)
    else:
        items = processes.get("script_blocks", [])
        _not_evaluated(gaps, "script_execution", processes.get("script_blocks_omitted", 0),
                       "only the presentation list (first 100 script blocks) is available in this result", RERUN)
    out = []
    for index, item in enumerate(items):
        prov = item.get("provenance") or {}
        out.append({"id": f"script:{item.get('script_block_id') or index}:{item.get('host_norm') or 'host?'}",
                    "activity": "script_execution",
                    "entities": [item["host_norm"]] if item.get("host_norm") else [],
                    "process": {"script_block_id": item.get("script_block_id")},
                    "time_start": prov.get("starttime_utc"), "time_end": prov.get("starttime_utc"),
                    "reference": {k: prov.get(k) for k in ("query", "search_id", "result_row_index")}})
    return out


def _privilege_instances(result: dict, gaps: dict) -> list[dict] | None:
    linux = result.get("linux") or {}
    parts = [linux.get(p) or {} for p in ("offense", "identity_window")]
    if not any("privilege_instances" in part for part in parts):
        return None
    merged: dict[tuple, dict] = {}
    for part in parts:
        _not_evaluated(gaps, "privilege_use", part.get("privilege_instances_not_analyzed", 0),
                       "privileged commands beyond the analysis cap", NARROW)
        for item in part.get("privilege_instances", []):
            key = (item["kind"], item.get("host"), item.get("actor"), item.get("run_as"), item.get("command"))
            entry = merged.setdefault(key, {**item, "references": []})
            for bound, pick in (("first_starttime", min), ("last_starttime", max)):
                values = [v for v in (entry.get(bound), item.get(bound)) if v is not None]
                entry[bound] = pick(values) if values else None
            entry["time_missing"] = entry.get("time_missing") or item.get("time_missing")
            entry["references"] = (entry["references"] + item.get("references", []))[:5]
    out = []
    for (kind, host, actor, run_as, command), item in merged.items():
        known = not item.get("time_missing")
        out.append({"id": f"privilege:{kind}:{host or 'host?'}:{actor}:{run_as}:{hashlib.sha256((command or '').encode('utf-8')).hexdigest()[:12]}",
                    "activity": "privilege_use",
                    "entities": [e.lower() for e in (host, actor) if e],
                    "process": {"kind": kind, "command": command, "run_as": run_as,
                                "command_cut": bool(item.get("command_cut_by_bridge"))},
                    "time_start": _epoch_iso(item.get("first_starttime")) if known else None,
                    "time_end": _epoch_iso(item.get("last_starttime")) if known else None,
                    "reference": item["references"][:1]})
    return out


def _entity_instances(result: dict, activity: str, gaps: dict) -> list[dict]:
    rows_by_query = result.get("collected_rows") or {}
    queries = result.get("queries") or {}
    groups: dict[str, dict] = {}
    for query in ACTIVITY_QUERIES.get(activity, ()):
        finding = queries.get(query) or {}
        rows = rows_by_query.get(query)
        if rows is None:
            rows = finding.get("samples", [])
            source = "witness samples"
        else:
            source = "stored rows"
        returned = finding.get("returned_rows")
        if isinstance(returned, int) and returned > len(rows):
            _not_evaluated(gaps, activity, returned - len(rows),
                           f"{query}: {returned} rows returned but only {len(rows)} {source} available for analysis",
                           RERUN if source == "witness samples" else NARROW)
        for index, row in enumerate(rows):
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
            groups[str(source).lower()] = {"times": [iso(instant(interval.get("start"))), iso(instant(interval.get("end")))],
                                           "reference": {"source": "offense metadata",
                                                         "interval": "observed" if observed.get("start") else "metadata"}}
    out = []
    for entity, group in sorted(groups.items()):
        times = group["times"]
        known = sorted(t for t in times if t)
        out.append({"id": f"{activity}:{entity}", "activity": activity, "entities": [entity], "process": None,
                    "time_start": known[0] if known and len(known) == len(times) else None,
                    "time_end": known[-1] if known and len(known) == len(times) else None,
                    "reference": group["reference"]})
    return out


def _instances(result: dict, activities: dict[str, str], gaps: dict) -> list[dict]:
    out: list[dict] = []
    for activity in activities:
        if activity == "process_execution":
            out += _process_instances(result, gaps)
        elif activity == "script_execution":
            out += _script_instances(result, gaps)
        elif activity == "privilege_use":
            privileged = _privilege_instances(result, gaps)
            if privileged is None:
                # Older stored results lack per-command instances: entity instances that only an explicit
                # breadth can cover (the command of each record is unknown to the engine).
                privileged = [{**i, "process": {"kind": "unknown", "command": None, "run_as": None, "command_cut": False}}
                              for i in _entity_instances(result, activity, gaps)]
            out += privileged
        else:
            out += _entity_instances(result, activity, gaps)
    return out


def observed_profile(result: dict) -> dict:
    """Activities, per-instance entities/behavior/times, the instances not evaluated and the observed window."""
    events = result.get("events", {})
    interval = events.get("observed_interval") or {}
    start = instant(interval.get("start")) or instant((result.get("metadata_interval") or {}).get("start"))
    end = instant(interval.get("end")) or instant((result.get("metadata_interval") or {}).get("end")) or start
    activities = _activities(result)
    gaps: dict[str, dict] = {}
    instances = _instances(result, activities, gaps)
    if len(instances) > MAX_INSTANCES:
        for inst in instances[MAX_INSTANCES:]:
            _not_evaluated(gaps, inst["activity"], 1, "instances beyond the decision cap", NARROW)
        instances = instances[:MAX_INSTANCES]
    for entry in gaps.values():
        entry["reason"] = "; ".join(dict.fromkeys(entry.pop("reasons")))
        entry["next_action"] = "; ".join(dict.fromkeys(entry.pop("next_actions")))
    entities = sorted({e for i in instances for e in i["entities"]})
    return {"activities": activities, "instances": instances, "instances_not_evaluated": gaps,
            "entities": entities[:200],
            "window_start": iso(start) if start else None, "window_end": iso(end) if end else None}


def summarize_profile(profile: dict, listed: int = 100) -> dict:
    """Presentation view of a profile: counts are complete, the instance list is capped."""
    return {**{k: v for k, v in profile.items() if k != "instances"},
            "instances": profile["instances"][:listed], "instance_count": len(profile["instances"]),
            "instances_listed": min(listed, len(profile["instances"]))}


def _entity_covered(entity: str, named: list[str]) -> bool:
    return any(entity == n or same_host(entity, n) for n in named)


def _named(entries: list[str], path: str | None) -> bool:
    value = _norm(path)
    return bool(value) and any(entry == value if ("\\" in entry or "/" in entry) else entry == basename(value)
                               for entry in entries)


def _behavior_covered(scope: dict, instance: dict) -> str | None:
    """None when the scope names this instance's behavior; otherwise the reason it does not."""
    process = instance.get("process") or {}
    if instance["activity"] == "script_execution":
        block = _norm(process.get("script_block_id"))
        return None if block and block in scope.get("script_block_ids", []) else "script block not named in the record"
    if instance["activity"] == "privilege_use":
        if scope.get("run_as") and process.get("run_as") not in scope["run_as"]:
            return f"run-as account {process.get('run_as')} not named in the record"
        if scope.get("breadth"):
            return None
        if process.get("kind") == "su_identity_record":
            return None if scope.get("identity_switch") else "su identity switch not authorized by the record"
        command = process.get("command")
        if not command or process.get("command_cut"):
            return "privileged command not fully observed"
        return None if command.strip() in scope.get("commands", []) else "privileged command not named in the record"
    if instance["activity"] != "process_execution":
        return None
    image = process.get("image")
    if not _norm(image):
        return "process image not observed in the record"
    if not _named(scope.get("processes", []), image):
        return f"process {basename(image)} not named in the record"
    if scope.get("parent_processes") and not _named(scope["parent_processes"], process.get("parent_image")):
        return "parent process not named in the record"
    if scope.get("process_instances") and process.get("guid") not in scope["process_instances"]:
        return "process instance (ProcessGuid) not named in the record"
    if scope.get("artifact_hashes") and not set(scope["artifact_hashes"]) & set((process.get("hashes") or {}).values()):
        return "artifact hash not named in the record (or not observed)"
    if scope.get("command_lines"):
        command = process.get("command_line")
        if not command or process.get("command_line_cut") or command.strip() not in scope["command_lines"]:
            return "command line not identical to one named in the record (or not fully observed)"
    if scope.get("script_paths"):
        invocation = process.get("invocation") or script_invocation(process.get("command_line"), image)
        if invocation.get("inline") or not invocation.get("script"):
            return f"no script file executed ({invocation.get('basis')})"
        if not any(_same_path(invocation["script"], path) for path in scope["script_paths"]):
            return f"script {invocation['script']} not named in the record"
        if invocation.get("extra_arguments"):
            return "script run with additional arguments; cite the exact command line"
    return None


def coverage(confirmations: list[dict], profile: dict, requirement_id: str = "authorization") -> dict:
    """Which observed instances a scoped record covers (activity, entities, behavior/chain, window)."""
    records = [c for c in confirmations if c["requirement"] == requirement_id]
    unscoped = [c["reference"] for c in records if not c.get("scope")]
    covered: dict[str, str] = {}
    uncovered: list[dict] = []
    contradictions: list[dict] = []
    broad: dict[str, dict] = {}
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
            why = _behavior_covered(scope, inst)
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
            if scope.get("breadth"):
                entry = broad.setdefault(c["reference"], {
                    "reference": c["reference"], "activity": scope["activity"], "breadth": scope["breadth"],
                    "declared": [f"broad authorization declared by the external record {c['reference']}: "
                                 f"{scope['breadth_basis']}"], "instances_covered": 0})
                entry["instances_covered"] += 1
            break
        if inst["id"] not in covered:
            uncovered.append({"id": inst["id"], "activity": inst["activity"], "entities": inst["entities"],
                              "process": inst.get("process"), "time": [inst.get("time_start"), inst.get("time_end")],
                              "reference": inst.get("reference"),
                              "reason": "; ".join(dict.fromkeys(reasons)) or "no scoped record for this activity"})
    not_evaluated = profile.get("instances_not_evaluated") or {}
    if isinstance(not_evaluated, int):  # profiles stored by earlier versions
        not_evaluated = {"unknown": {"count": not_evaluated, "reason": "beyond the earlier cap",
                                     "next_action": RERUN}} if not_evaluated else {}
    uncovered_activities = sorted({u["activity"] for u in uncovered} | set(not_evaluated))
    covered_activities = sorted({i["activity"] for i in profile.get("instances", []) if i["id"] in covered})
    status = ("confirmed" if records and covered and not uncovered and not not_evaluated
              else "compatible" if records else "unverified")
    return {"status": status, "covered": covered, "covered_activities": covered_activities,
            "uncovered": uncovered[:MAX_LISTED], "uncovered_count": len(uncovered),
            "uncovered_activities": uncovered_activities, "instances_not_evaluated": not_evaluated,
            "broad_authorizations": list(broad.values()),
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
    by execution instance or demonstrated chain), never because any QRadar row exists."""
    basis = []
    if not sustained:
        return {"level": "low", "basis": ["no disposition has all of its requirements met"]}
    needed = [req[r] for r in sustained["met"] if r in req]
    external = [r["id"] for r in needed if str(r.get("source", "")).startswith("analyst")]
    basis.append("requirements met: " + ", ".join(sustained["met"]))
    if external:
        basis.append("relies on analyst-supplied records not verified by the bridge: " + ", ".join(external))
    broad = [b for r in needed for b in ((r.get("evidence") or {}).get("broad_authorizations") or [])
             if isinstance(r.get("evidence"), dict)]
    if broad:
        basis.append("relies on a broad authorization declared by the external record: "
                     + ", ".join(b["reference"] for b in broad))
    if contradictions:
        basis.append(f"{len(contradictions)} contradiction(s) recorded (see contradictions)")
    if corroborated:
        basis.append("corroborated: Trend and QRadar records demonstrably describe the same activity "
                     "(same execution instance or a demonstrated process chain)")
    else:
        basis.append("no demonstrated second-source corroboration")
    level = "high" if not external and corroborated else "moderate"
    return {"level": level, "basis": basis,
            "criteria": "high = bridge-demonstrated requirements corroborated by a second source that demonstrably "
                        "describes the same activity; moderate = sustained but relying on external records or a "
                        "single source; low = not sustained"}


def now_iso() -> str:
    return iso(datetime.now().astimezone())
