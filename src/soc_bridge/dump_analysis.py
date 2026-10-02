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
from .trend_records import preview

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
        key = item["instance"] or (record.get("endpoint_guid") or record.get("endpoint_host"), item["command"], item["pid"])
        if key in found:
            found[key]["parent_path"] = found[key]["parent_path"] or item["parent_path"]
            found[key].setdefault("records", []).append(record.get("uuid"))
        else:
            found[key] = item | {"records": [record.get("uuid")]}
    return list(found.values())


def _target(launch: dict, records: list[dict]) -> dict:
    parsed = launch["parsed"]
    record = launch["record"]
    when = parse(record.get("event_time_raw"))[0]
    endpoint = (record.get("endpoint_guid") or record.get("endpoint_host") or "").lower()
    if not parsed["target_as_written"]:
        return {"status": "not identified", "reason": "no target in the command line"}
    if not parsed["target_is_pid"]:
        return {"status": "named in command line", "image_as_written": parsed["target_as_written"],
                "reason": "process name argument; instance not resolved"}
    pid = parsed["target_as_written"]
    candidates = []
    for other in records:
        same_endpoint = (other.get("endpoint_guid") or other.get("endpoint_host") or "").lower() == endpoint
        for role in ("process", "object", "parent"):
            group = other.get(role, {})
            if str(group.get("pid")) != pid or not same_endpoint:
                continue
            start = parse(group.get("launchTime"))[0]
            if start and when and start > when:
                continue
            candidates.append({"image": group.get("filePath"), "instance": group.get("hashId") or group.get("processHashId"),
                               "launch_time": group.get("launchTime"), "role": role, "record_uuid": other.get("uuid")})
    unique = {(c["image"] or "").lower(): c for c in candidates}
    access = [r for r in records if launch["instance"] and r.get("process", {}).get("hashId") == launch["instance"]
              and str(r.get("object", {}).get("pid")) == pid]
    if access and access[0].get("object", {}).get("processHashId"):
        instance = access[0]["object"]["processHashId"]
        match = next((c for c in candidates if c["instance"] == instance), None)
        if match:
            return {"status": "confirmed by process-instance ID", "pid": pid, "image": match["image"],
                    "instance": instance, "basis": "dump-tool instance accessed object PID whose instance ID matches"}
    if len(unique) == 1:
        only = next(iter(unique.values()))
        return {"status": "candidate (PID + endpoint + earlier start)", "pid": pid, "image": only["image"],
                "instance": only["instance"], "basis": "same endpoint, PID equal, started before the dump"}
    if len(unique) > 1:
        return {"status": "ambiguous (PID reuse)", "pid": pid, "images": sorted(unique)[:10],
                "basis": "several images used this PID on the endpoint"}
    return {"status": "not resolved in collected records", "pid": pid,
            "reason": "no record with this PID on the same endpoint in the inspected window"}


def _activity_kind(record: dict) -> str:
    actor = base(record.get("process", {}).get("filePath"))
    cmd = str(record.get("process", {}).get("cmd") or "").lower()
    if actor in DUMP_TOOLS:
        return "written by the dump tool (as reported)"
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
        when = parse(record.get("event_time_raw"))[0]
        acted = any(r.get("process", {}).get("hashId") == launch["instance"] and base(r.get("process", {}).get("filePath")) in DUMP_TOOLS
                    for r in records) if launch["instance"] else launch["actor"] == "dump tool acting"
        dump_files = [r for r in records if str(r.get("object", {}).get("filePath") or "").lower().endswith(".dmp")
                      and (not launch["instance"] or r.get("process", {}).get("hashId") == launch["instance"])]
        item: dict[str, Any] = {
            "command": preview(launch["command"]), "arguments": launch["parsed"], "parent_path": launch["parent_path"],
            "intent": (f"command line requests a {', '.join(launch['parsed']['dump_types']) or 'process'} dump of "
                       f"{launch['parsed']['target_as_written'] or 'an unstated target'}"),
            "execution": ("observed: records of the dump-tool instance acting" if acted else
                          "launch observed; the dump-tool instance acting was not observed in collected records"),
            "dump_file": ({"status": "file operation in telemetry", "paths": sorted({r["object"]["filePath"] for r in dump_files})[:5],
                           "operations_as_reported": sorted({str(r.get("event", {}).get("eventSubId")) for r in dump_files})[:10]}
                          if dump_files else {"status": "no .dmp file operation in collected records"}),
            "target": _target(launch, records), "followups": [], "connections": []}
        names = {base(p) for p in item["dump_file"].get("paths", [])} | (
            {base(launch["parsed"]["destination_as_written"])} if launch["parsed"]["destination_as_written"] and
            base(launch["parsed"]["destination_as_written"]).endswith(".dmp") else set())
        if when:
            for name in sorted(n for n in names if SAFE_NAME.fullmatch(n))[:2]:
                for endpoint in endpoints[:2]:
                    clause = endpoint_clause(endpoint)[0]
                    if not clause:
                        continue
                    finding = await vision_search.search(
                        vision, budget, "search_endpoint_activities_list", f"{clause} and {term('objectFilePath', name)}",
                        when, when + timedelta(hours=6), purpose="later activity on the dump file", seen=seen)
                    activity = [{"time_utc": r.get("event_time_utc"), "actor": r.get("process", {}).get("filePath"),
                                 "actor_instance": r.get("process", {}).get("hashId"), "kind": _activity_kind(r),
                                 "event": r.get("event", {})} for r in finding["records"]
                                if base(r.get("object", {}).get("filePath")) == name]
                    item["followups"].append({"file": name, "state": finding["state"], "records": activity[:20],
                                              "continuation": finding["continuation"]})
        actors = {launch["instance"]} | {a["actor_instance"] for f in item["followups"] for a in f["records"]}
        for r in records:
            net = r.get("network", {})
            if r.get("process", {}).get("hashId") in actors - {None} and (net.get("dst") or net.get("request")):
                item["connections"].append({"time_utc": r.get("event_time_utc"), "actor": r["process"].get("filePath"),
                                            "dst": net.get("dst"), "dpt": net.get("dpt"), "request": net.get("request"),
                                            "basis": "same process-instance ID as the dump tool or a dump-file actor"})
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
        if not item["connections"]:
            item["not_proven"].append("transfer of the dump (no attributable connection in collected records)")
        item["request"] = "Obtain the authorization/diagnostic source (ticket, change, vendor case) and the dump's custody"
        results.append(item)
    return {"applicable": True, "dumps": results}
