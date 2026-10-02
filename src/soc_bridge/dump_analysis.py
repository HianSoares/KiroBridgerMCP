"""Dual-use memory-dump tools (ProcDump): intent, execution, dump file and target, kept apart.

The command line shows intent. A record of the dump process acting shows execution.
A .dmp file event attributed to that instance shows a file operation. The target is
identified from the PID only together with the same endpoint, an earlier start and,
when present, the process-instance ID; PID reuse makes a target ambiguous.
Nothing here concludes credential dumping, and a non-LSASS target is not benign.
"""

from __future__ import annotations

import re
from datetime import timedelta
from typing import Any

from . import vision_search
from .alert_discovery import endpoint_clause, term
from .ariel_collection import Budget
from .time_anchor import parse
from .trend_records import endpoint_identity, preview, same_endpoint

DUMP_TOOLS = {"procdump.exe", "procdump64.exe", "procdump64a.exe"}
DUMP_TYPES = {"-ma": "full memory", "-mp": "MiniPlus", "-mm": "mini", "-mt": "triage", "-mk": "kernel"}
VALUE_OPTIONS = {"-n", "-s", "-c", "-cl", "-m", "-ml", "-p", "-pl", "-f", "-fx", "-at", "-l", "-g"}
TOKEN = re.compile(r'"[^"]*"|\S+')
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,119}$")
ARCHIVERS = {"7z.exe", "7za.exe", "rar.exe", "winrar.exe", "tar.exe", "makecab.exe", "compact.exe"}
COPIERS = {"robocopy.exe", "xcopy.exe", "esentutl.exe"}
TRANSFER_TOOLS = {"curl.exe", "bitsadmin.exe", "ftp.exe", "rclone.exe", "pscp.exe", "scp.exe", "certutil.exe"}
CREDENTIAL_STORES = {"lsass.exe"}


def base(path: Any) -> str:
    return str(path or "").replace("/", "\\").rstrip("\\").rsplit("\\", 1)[-1].lower()


def parse_command(command: str) -> dict:
    """ProcDump arguments as written; quoting is honoured, nothing is executed."""
    tokens = [t.strip('"') for t in TOKEN.findall(command or "")]
    args = tokens[1:] if tokens and base(tokens[0]) in DUMP_TOOLS | {"procdump"} else tokens
    options, positional, skip = [], [], False
    for token in args:
        if skip:
            skip = False
            continue
        if token[:1] in "-/" and len(token) > 1:
            option = "-" + token[1:].lower()
            options.append(option)
            skip = option in VALUE_OPTIONS
        else:
            positional.append(token)
    target = positional[0] if positional else None
    destination = positional[1] if len(positional) > 1 else None
    return {"options": options, "dump_types": [DUMP_TYPES[o] for o in options if o in DUMP_TYPES],
            "target_as_written": target, "target_is_pid": bool(target and target.isdigit()),
            "destination_as_written": destination,
            "accepts_eula_flag": "-accepteula" in options}


def _dump_launches(records: list[dict]) -> list[dict]:
    """One entry per dump-tool instance (launch, access and write records of it are merged)."""
    found: dict[Any, dict] = {}
    for record in sorted(records, key=lambda r: str(r.get("event_time_utc") or "")):
        process, obj = record.get("process", {}), record.get("object", {})
        if base(process.get("filePath")) in DUMP_TOOLS and process.get("cmd"):
            item = {"record": record, "actor": "dump tool acting", "command": process["cmd"],
                    "instance": process.get("hashId"), "pid": process.get("pid"),
                    "parent_path": record.get("parent", {}).get("filePath")}
        elif base(obj.get("filePath")) in DUMP_TOOLS and obj.get("cmd"):
            item = {"record": record, "actor": "dump tool launched by another process",
                    "command": obj["cmd"], "instance": obj.get("processHashId"), "pid": obj.get("pid"),
                    "parent_path": process.get("filePath")}
        else:
            continue
        item["launch_time"] = (process if item["actor"] == "dump tool acting" else obj).get("launchTime")
        # Never merge unknown instances by PID/command (PID reuse), or across endpoints.
        key = ((endpoint_identity(record), item["instance"]) if endpoint_identity(record) and item["instance"] else
               ("record", record.get("uuid"), record.get("event_time_raw"), item["command"], item["pid"]))
        if key in found:
            if (item["launch_time"] and not found[key]["launch_time"]) or (
                    item["actor"] == "dump tool launched by another process" and
                    found[key]["actor"] == "dump tool acting" and not found[key]["launch_time"]):
                existing_records = found[key]["records"]
                found[key] = item | {"records": existing_records}
            found[key]["parent_path"] = found[key]["parent_path"] or item["parent_path"]
            found[key].setdefault("records", []).append(record.get("uuid"))
        else:
            found[key] = item | {"records": [record.get("uuid")]}
    return list(found.values())


def _target(launch: dict, records: list[dict]) -> dict:
    parsed = launch["parsed"]
    record = launch["record"]
    when = _launch_instant(launch)
    if not parsed["target_as_written"]:
        return {"status": "not identified", "reason": "no target in the command line"}
    if not parsed["target_is_pid"]:
        return {"status": "named in command line", "image_as_written": parsed["target_as_written"],
                "reason": "process name argument; instance not resolved"}
    pid = parsed["target_as_written"]
    candidates = []
    for other in records:
        for role in ("process", "object", "parent"):
            group = other.get(role, {})
            if str(group.get("pid")) != pid or not same_endpoint(other, record):
                continue
            start = parse(group.get("launchTime"))[0]
            if not start or not when or start > when:
                continue
            candidates.append({"image": group.get("filePath"), "instance": group.get("hashId") or group.get("processHashId"),
                               "launch_time": group.get("launchTime"), "role": role, "record_uuid": other.get("uuid")})
    unique = {((c["image"] or "").lower(), c["instance"], c["launch_time"]): c for c in candidates}
    access = [r for r in records if _actor_relation(launch, r) == "instance_match"
              and str(r.get("object", {}).get("pid")) == pid and r.get("object", {}).get("processHashId")]
    accessed_instances = {r["object"]["processHashId"] for r in access}
    matches = {c["instance"]: c for c in candidates if c["instance"] in accessed_instances}
    if len(accessed_instances) == len(matches) == 1:
        instance, match = next(iter(matches.items()))
        return {"status": "confirmed by process-instance ID", "pid": pid, "image": match["image"],
                "instance": instance, "basis": "same endpoint and time: dump-tool instance referenced the target instance",
                "memory_access_operation": "unverified (event taxonomy not decoded)"}
    if len(unique) == 1:
        only = next(iter(unique.values()))
        return {"status": "candidate (PID + endpoint + earlier start)", "pid": pid, "image": only["image"],
                "instance": only["instance"], "basis": "same endpoint, PID equal, started before the dump"}
    if len(unique) > 1:
        return {"status": "ambiguous (PID reuse)", "pid": pid,
                "images": sorted({key[0] for key in unique})[:10],
                "basis": "several process identities/launches used this PID on the endpoint"}
    return {"status": "not resolved in collected records", "pid": pid,
            "reason": "no record with this PID on the same endpoint in the inspected window"}


def _actor_relation(launch: dict, record: dict) -> str | None:
    """Instance proof or a PID/time candidate, always scoped to endpoint and time."""
    when = _launch_instant(launch)
    event_time = parse(record.get("event_time_raw"))[0]
    if not same_endpoint(launch["record"], record) or not when or not event_time or not when <= event_time <= when + timedelta(hours=6):
        return None
    group = record.get("process", {})
    if base(group.get("filePath")) not in DUMP_TOOLS:
        return None
    if launch["instance"]:
        return "instance_match" if group.get("hashId") == launch["instance"] else None
    # Even an exact PID/launch match without an instance ID remains a candidate.
    started = parse(group.get("launchTime"))[0]
    launch_started = parse(launch.get("launch_time"))[0]
    if (group.get("pid") is not None and launch["pid"] is not None
            and str(group["pid"]) == str(launch["pid"]) and started and launch_started
            and started == launch_started and started <= when):
        return "candidate_pid_launch_time"
    return None


def _launch_instant(launch: dict):
    return parse(launch.get("launch_time"))[0] or parse(launch["record"].get("event_time_raw"))[0]


def _activity_kind(record: dict) -> str:
    actor = base(record.get("process", {}).get("filePath"))
    cmd = str(record.get("process", {}).get("cmd") or "").lower()
    if actor in DUMP_TOOLS:
        return "dump-tool file reference (operation unverified)"
    if actor in ARCHIVERS or "compress-archive" in cmd:
        return "compression candidate"
    if actor in COPIERS or re.search(r"\b(?:copy|move)\b", cmd):
        return "copy/move candidate"
    if re.search(r"\b(?:del|erase)\b|remove-item", cmd):
        return "deletion candidate"
    if actor in TRANSFER_TOOLS:
        return "transfer-tool access candidate"
    return "access by another process (operation as reported)"


async def analyze(vision: Any, budget: Budget, records: list[dict], endpoints: list[dict]) -> dict:
    launches = _dump_launches(records)
    if not launches:
        return {"applicable": False}
    results = []
    seen: dict = {}
    for launch in launches[:5]:
        launch["parsed"] = parse_command(launch["command"])
        record = launch["record"]
        when = _launch_instant(launch)
        acted = any(_actor_relation(launch, r) == "instance_match" for r in records)
        references = [r for r in records if str(r.get("object", {}).get("filePath") or "").lower().endswith(".dmp")
                      and _actor_relation(launch, r)]
        dump_files = [r for r in references if _actor_relation(launch, r) == "instance_match"]
        item: dict[str, Any] = {
            "command": preview(launch["command"]), "arguments": launch["parsed"], "parent_path": launch["parent_path"],
            "intent": (f"command line requests a {', '.join(launch['parsed']['dump_types']) or 'process'} dump of "
                       f"{launch['parsed']['target_as_written'] or 'an unstated target'}"),
            "execution": ("observed: records of the dump-tool instance acting" if acted else
                          "process reference observed; execution by an identified dump-tool instance is not established"),
            "dump_file": ({"status": "file reference attributed to dump-tool instance", "paths": sorted({r["object"]["filePath"] for r in dump_files})[:5],
                           "operations_as_reported": sorted({str(r.get("event", {}).get("eventSubId")) for r in dump_files})[:10]}
                          if dump_files else {"status": "no .dmp file reference attributed to a dump-tool instance"}),
            "target": _target(launch, records), "followups": [], "connections": []}
        item["dump_file"].update(creation_confirmed=False, operation="unverified: eventId/eventSubId taxonomy not decoded",
                                 candidates=[{"path": r["object"]["filePath"], "uuid": r.get("uuid"),
                                              "relation": _actor_relation(launch, r)} for r in references if r not in dump_files][:10])
        paths = item["dump_file"].get("paths", [])
        names = {base(p) for p in paths} | (
            {base(launch["parsed"]["destination_as_written"])} if launch["parsed"]["destination_as_written"] and
            base(launch["parsed"]["destination_as_written"]).endswith(".dmp") else set())
        if when:
            for name in sorted(n for n in names if SAFE_NAME.fullmatch(n))[:2]:
                scoped_endpoints = [{"guid": record.get("endpoint_guid"), "name": record.get("endpoint_host"),
                                     "ips": record.get("endpoint_ips", [])}]
                for endpoint in scoped_endpoints:
                    clause = endpoint_clause(endpoint)[0]
                    if not clause:
                        continue
                    finding = await vision_search.search(
                        vision, budget, "search_endpoint_activities_list", f"{clause} and {term('objectFilePath', name)}",
                        when, when + timedelta(hours=6), purpose="later activity on the dump file", seen=seen)
                    activity = [{"time_utc": r.get("event_time_utc"), "actor": r.get("process", {}).get("filePath"),
                                 "actor_instance": r.get("process", {}).get("hashId"), "kind": _activity_kind(r),
                                 "event": r.get("event", {}), "file_relation": (
                                     "exact path (artifact continuity unverified)" if str(r.get("object", {}).get("filePath") or "").lower()
                                     in {p.lower() for p in paths} else "basename only (candidate)"),
                                 "operation": "unverified", "uuid": r.get("uuid")} for r in finding["records"]
                                if base(r.get("object", {}).get("filePath")) == name and same_endpoint(record, r)
                                and parse(r.get("event_time_raw"))[0] and when <= parse(r["event_time_raw"])[0] <= when + timedelta(hours=6)]
                    item["followups"].append({"file": name, "state": finding["state"], "records": activity[:20],
                                              "continuation": finding["continuation"]})
        actors = {launch["instance"]: when} if launch["instance"] else {}
        for f in item["followups"]:
            for a in f["records"]:
                if a["actor_instance"] and a["file_relation"].startswith("exact path"):
                    at = parse(a["time_utc"])[0]
                    actors[a["actor_instance"]] = min(actors.get(a["actor_instance"]) or at, at)
        for r in records:
            net = r.get("network", {})
            at = parse(r.get("event_time_raw"))[0]
            actor_start = actors.get(r.get("process", {}).get("hashId"))
            if (actor_start and at and actor_start <= at <= actor_start + timedelta(hours=6)
                    and same_endpoint(record, r) and (net.get("dst") or net.get("request"))):
                item["connections"].append({"time_utc": r.get("event_time_utc"), "actor": r["process"].get("filePath"),
                                            "dst": net.get("dst"), "dpt": net.get("dpt"), "request": net.get("request"),
                                            "basis": "same endpoint and process instance, after the dump/file reference",
                                            "dump_transfer_confirmed": False})
        target_image = base(item["target"].get("image"))
        item["hypotheses"] = [
            {"id": "operational_diagnostics", "needs": "authorization or vendor support record for this dump "
             "(ticket/change), the dump's purpose and its disposition; signature, vendor path, SYSTEM or 'No Findings' do not prove authorization"},
            {"id": "malicious_collection", "needs": "target identity, later access/compression/transfer of the dump "
             "and the launching chain; " + ("target is a credential store: credential access must be assessed (T1003.001 candidate)"
                                            if target_image in CREDENTIAL_STORES else
                                            "a non-LSASS target does not make the activity benign (application memory can hold secrets)")}]
        item["not_proven"] = ["credential extraction (ProcDump or MITRE tags alone do not show it)",
                              "authorization (signature, vendor path, SYSTEM account, 'No Findings' are not authorization)"]
        item["not_proven"].extend(["dump creation/write (file reference and event code are not decoded operation proof)",
                                  "transfer of the dump (a connection alone does not identify transferred content)"])
        item["request"] = "Obtain the authorization/diagnostic source (ticket, change, vendor case) and the dump's custody"
        results.append(item)
    return {"applicable": True, "dumps": results}
