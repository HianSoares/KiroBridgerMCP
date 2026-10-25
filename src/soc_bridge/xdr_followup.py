"""Explicit XDR Data Explorer phase after one Workbench investigation, and a digest of direct Search records.

The Workbench investigation runs once. Its report then carries ``xdr_followup``:

- seeds: endpoints (name/GUID/IP), users, hashes, process instances, commands and times, each with the
  source it came from, so no host or IP has to be asked of the analyst when a source already gave it;
- phases: deduplicated ``trend_search_data`` parameter sets for the pertinent sources, built only from
  validated seeds and from fields the audited Search contract documents (read the live resource first);
- transfer: for backup/sync/transfer tools, the questions and the evidence that answers each stage
  (binary present, configuration accessed, command started, connection attributed, traffic observed and
  operation completed are different stages);
- volume_sources: where byte counters could exist and what each one can prove;
- assessment_scope: the alert assessment covers the initial collection only.

``digest`` summarizes the records ``trend_search_data`` returned, with provenance per occurrence: actors
(one execution only when processHashId identifies it), image aggregates labelled as such, commands with
each endpoint/role/instance occurrence, file objects, connections and metrics. Only fields with verified
network-counter semantics for the source are counters; other numeric metrics stay unclassified with their
native values. Nothing is summed. File size, event counts and ports are not bytes transferred.
"""

from __future__ import annotations

import re
from datetime import timedelta
from typing import Any

from .alert_discovery import GUID, HASH, HOST, INSTANCE_ID, endpoint_clause, term
from .core import address
from .time_anchor import parse
from .trend_records import endpoint_identity, full_hashes, normalize

MAX_LIST = 40
TRANSFER_TOOLS = ("rclone", "restic", "robocopy", "azcopy", "rsync", "winscp", "pscp", "scp", "sftp", "megacmd",
                  "megasync", "gsutil", "rclone.conf", "veeam", "duplicati", "s3", "ftp")
TRANSFER_WORDS = re.compile(r"(?i)\b(rclone|restic|robocopy|azcopy|rsync|winscp|pscp|megacmd|megasync|gsutil|duplicati|"
                            r"veeam|backup|exfiltrat\w*|data transfer|cloud storage|sync)\b")
TOOL_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$")
# Network counters with verified semantics, by (Search tool, native field) -> unit and direction. The
# audited Vision One Search contracts document no byte or packet field for any source, so this table is
# empty: counter-like fields stay unclassified metrics until a field is verified (contract or product
# documentation) and added here with its unit and direction.
NETWORK_COUNTERS: dict[tuple[str, str], dict[str, str]] = {}
NOT_VOLUME = re.compile(r"(?i)(filesize|size$|port$|^dpt$|^spt$|eventcount)")
METRIC_LIKE = re.compile(r"(?i)(byte|octet|packet|size|count|rate|loss|duration|bandwidth|throughput)")
SCOPE_NOTE = ("This assessment covers the initial collection of investigate_vision_alert only (phases listed in "
              "completed_phases). Results of trend_search_data, upstream_query or QRadar queries made afterwards are "
              "not part of it: present them as a separate agent opinion and never as this assessment re-evaluated.")


def _value(value: Any) -> Any:
    return value.get("value") if isinstance(value, dict) and "value" in value else value


def _add(bucket: dict, key: Any, item: dict, source: str) -> None:
    entry = bucket.setdefault(key, {**item, "sources": []})
    if source not in entry["sources"] and len(entry["sources"]) < 6:
        entry["sources"].append(source)


def seeds(report: dict, records: list[dict]) -> dict:
    """Identifiers already known after the initial collection, each with provenance."""
    ex = report.get("extraction") or {}
    endpoints: dict = {}
    users: dict = {}
    hashes: dict = {}
    instances: dict = {}
    commands: dict = {}
    for endpoint in ex.get("endpoints", []):
        key = (endpoint.get("guid") or "").lower() or (endpoint.get("name") or "").lower()
        if key:
            for source in endpoint.get("sources", ["alert detail"])[:3]:
                _add(endpoints, key, {"name": endpoint.get("name"), "guid": endpoint.get("guid"),
                                      "ips": list(endpoint.get("ips", []))}, f"Workbench {source}")
    observables = ex.get("observables") or {}
    for item in observables.get("user", []):
        _add(users, item["value"].lower(), {"value": item["value"]}, f"Workbench {item['sources'][0]}")
    for item in observables.get("hash", []):
        if HASH.fullmatch(item["value"]):
            _add(hashes, item["value"].lower(), {"value": item["value"].lower(), "role": item.get("role")},
                 f"Workbench {item['sources'][0]}")
    for item in observables.get("command", []):
        _add(commands, item["value"], {"value": item["value"], "role": item.get("role")}, f"Workbench {item['sources'][0]}")
    for record in records:
        label = (record.get("relation") or {}).get("label")
        if label not in ("linked", "identifier_match"):
            continue
        source = f"Search {record.get('tool')} uuid={record.get('uuid')} ({label})"
        ident = endpoint_identity(record)
        if ident:
            key = (record.get("endpoint_guid") or "").lower().strip("{}") or (record.get("endpoint_host") or "").lower()
            _add(endpoints, key, {"name": record.get("endpoint_host"), "guid": record.get("endpoint_guid"),
                                  "ips": list(record.get("endpoint_ips", []))}, source)
            entry = endpoints[key]
            entry["ips"] = sorted(set(entry["ips"]) | set(record.get("endpoint_ips", [])))
            entry["name"] = entry.get("name") or record.get("endpoint_host")
            entry["guid"] = entry.get("guid") or record.get("endpoint_guid")
        for user in (record.get("logon", {}).get("user"), record.get("process", {}).get("user"),
                     record.get("object", {}).get("user")):
            if isinstance(user, str) and user:
                _add(users, user.lower(), {"value": user}, source)
        for role in ("process", "object", "parent"):
            group = record.get(role) or {}
            for value in full_hashes(group).values():
                _add(hashes, value, {"value": value, "role": role}, source)
            cmd = _value(group.get("cmd"))
            if isinstance(cmd, str) and cmd:
                _add(commands, cmd, {"value": cmd, "role": role}, source)
        for role, field in (("process", "hashId"), ("object", "processHashId")):
            group = record.get(role) or {}
            hash_id = group.get(field)
            if isinstance(hash_id, str) and INSTANCE_ID.fullmatch(hash_id) and ident:
                _add(instances, (ident, hash_id), {
                    "id": hash_id, "role": role, "endpoint": {"guid": record.get("endpoint_guid"),
                                                              "name": record.get("endpoint_host")},
                    "image": _value(group.get("filePath")), "pid": group.get("pid"),
                    "launch_time": group.get("launchTime"), "event_time": record.get("event_time_utc")}, source)
    anchor = report.get("anchor") or {}
    return {
        "endpoints": list(endpoints.values())[:MAX_LIST], "users": list(users.values())[:MAX_LIST],
        "hashes": list(hashes.values())[:MAX_LIST], "instances": list(instances.values())[:MAX_LIST],
        "commands": list(commands.values())[:MAX_LIST],
        "times": {"anchor": anchor.get("time_utc"), "anchor_basis": anchor.get("basis"),
                  "anchor_provisional": anchor.get("provisional"),
                  "alert_clocks": (report.get("clocks") or {}).get("alert")},
        "identifiers": _identifiers(endpoints.values(), users.values(), hashes.values(), instances.values(),
                                    commands.values(), []),
        "note": "Each value lists its sources. Workbench values and Search records linked by uuid are facts of the "
                "alert; identifier matches are candidates. Hosts/IPs here are not asked of the analyst again."}


def _identifiers(endpoints, users, hashes, instances, commands, destinations) -> dict:
    return {"hosts": sorted({(e.get("name") or "").lower() for e in endpoints if e.get("name")}),
            "guids": sorted({(e.get("guid") or "").lower().strip("{}") for e in endpoints if e.get("guid")}),
            "ips": sorted({ip for e in endpoints for ip in e.get("ips", [])}),
            "users": sorted({u["value"].lower() for u in users}),
            "hashes": sorted({h["value"].lower() for h in hashes}),
            "instances": sorted({i["id"] for i in instances}),
            "commands": sorted({c["value"] for c in commands})[:MAX_LIST],
            "destinations": sorted(set(destinations))[:MAX_LIST]}


def _iso(value) -> str:
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def _transfer_terms(report: dict, found: dict) -> list[str]:
    alert = report.get("alert") or {}
    text = " ".join(str(alert.get(k) or "") for k in ("name", "model", "description"))
    text += " " + " ".join(c["value"] for c in found["commands"])
    text += " " + " ".join(str(o.get("value")) for o in ((report.get("extraction") or {}).get("observables") or {})
                           .get("path", []))
    return sorted({m.lower() for m in TRANSFER_WORDS.findall(text)})


def phases(report: dict, found: dict) -> list[dict]:
    """Deduplicated trend_search_data calls; queries use validated seeds and audited field names only."""
    when = parse(found["times"]["anchor"])[0]
    if not when:
        return []
    before = timedelta(minutes=60 if found["times"]["anchor_provisional"] else 30)
    out: list[dict] = []
    seen: set = set()

    def add(kind: str, source: str, query: str, start, end, purpose: str, answers: list[str], hypothesis: str = "") -> None:
        key = (source, query, _iso(start), _iso(end))
        if key in seen:
            return
        seen.add(key)
        out.append({"id": f"xdr-{len(out) + 1}", "kind": kind, "hypothesis": hypothesis or None,
                    "tool": "trend_search_data",
                    "parameters": {"source": source, "query": query, "start_date_time": _iso(start),
                                   "end_date_time": _iso(end), "select": "", "top": 500, "limit": 1000,
                                   "max_calls": 12},
                    "purpose": purpose, "answers": answers})

    endpoints = found["endpoints"][:5]
    for endpoint in endpoints:
        clause, basis = endpoint_clause(endpoint)
        det_clause, _ = endpoint_clause(endpoint, detections=True)
        if not clause:
            continue
        add("command_series", "endpoint", clause, when - before, when + timedelta(minutes=60),
            f"process/command series on the alert endpoint by {basis}",
            ["command line", "parent process", "user", "process instance (processHashId, PID, launch time)"])
        add("posterior_activity", "endpoint", clause, when, when + timedelta(hours=6),
            "activity after the alert time on the same endpoint (files, child processes, connections)",
            ["later file activity", "connections", "child processes"])
        add("detections", "detections", det_clause, when - before, when + timedelta(hours=6),
            f"other detections on the alert endpoint by {basis}", ["related detections"])
        name = endpoint.get("name") or ""
        guid = GUID.fullmatch(endpoint.get("guid") or "")
        net_clause = term("endpointGuid", guid[1].lower()) if guid else term("endpointHostName", name) if HOST.fullmatch(name) else None
        if net_clause:
            add("network_source", "network", net_clause, when - before, when + timedelta(hours=6),
                "Network Activity Data (secure access/proxy) for the endpoint; may be empty without that integration",
                ["remote destination", "request/URL", "action/result"])
    for instance in found["instances"][:6]:
        scope, _ = endpoint_clause({"guid": instance["endpoint"].get("guid"), "name": instance["endpoint"].get("name"),
                                    "ips": []})
        start = parse(instance.get("launch_time"))[0] or parse(instance.get("event_time"))[0] or when
        if scope:
            add("instance_activity", "endpoint", f"{scope} and {term('processHashId', instance['id'])}",
                start - timedelta(minutes=1), start + timedelta(hours=6),
                f"activity of process instance {instance['id']} (files, network events, children)",
                ["files read/written by the instance", "connections attributable to the instance", "child processes"])
            add("instance_children", "endpoint", f"{scope} and {term('objectProcessHashId', instance['id'])}",
                start - timedelta(minutes=1), start + timedelta(hours=6),
                f"events where instance {instance['id']} is the object (who launched or touched it)",
                ["parent/launcher", "access by other processes"])
    terms = _transfer_terms(report, found)
    if terms:
        tools = [t for t in terms if t in TRANSFER_TOOLS and TOOL_TOKEN.fullmatch(t)]
        for endpoint in endpoints:
            clause, _ = endpoint_clause(endpoint)
            if not clause:
                continue
            for tool in tools[:4]:
                add("transfer_command", "endpoint", f"{clause} and {term('processCmd', tool)}", when - timedelta(hours=6),
                    when + timedelta(hours=6), f"command lines of {tool} on the endpoint (copy/sync/move, remote, --config)",
                    ["command and arguments", "source and remote destination", "parent and user"], "transfer")
                add("transfer_launch", "endpoint", f"{clause} and {term('objectCmd', tool)}", when - timedelta(hours=6),
                    when + timedelta(hours=6), f"processes that launched {tool} (launcher command and user)",
                    ["launcher", "scheduled task or service", "user"], "transfer")
            if "rclone" in tools:
                add("transfer_config", "endpoint", f"{clause} and {term('objectFilePath', 'rclone.conf')}",
                    when - timedelta(hours=6), when + timedelta(hours=6),
                    "access to rclone.conf (configuration access is not a transfer)",
                    ["which process read/wrote the configuration", "when"], "transfer")
    return out


TRANSFER_STAGES = [
    {"stage": "binary_present", "established_by": "file event or detection of the tool on the endpoint",
     "does_not_establish": "execution, configuration or transfer"},
    {"stage": "configuration_accessed", "established_by": "file event on the configuration (for example rclone.conf) "
                                                          "with the actor instance",
     "does_not_establish": "a remote connection or transfer; the remote type is in the file content, which is not read"},
    {"stage": "command_started", "established_by": "process launch with command line, parent, user and instance",
     "does_not_establish": "a successful connection or any data moved"},
    {"stage": "connection_attributed", "established_by": "network event whose actor is the same process instance "
                                                         "(processHashId), with destination and port",
     "does_not_establish": "bytes moved or completion"},
    {"stage": "traffic_observed", "established_by": "verified byte/packet counters of that attributed session (for "
                                                    "example QRadar flows with the same tuple and time)",
     "does_not_establish": "that the job finished, that every file arrived or that the destination kept the data"},
    {"stage": "operation_completed", "established_by": "an application result tied to the same execution (tool log, "
                                                       "exit status or completion message of that instance) or a "
                                                       "confirmation at the destination",
     "does_not_establish": "authorization: that needs an external record (change, backup policy, owner)"}]


def transfer(report: dict, found: dict) -> dict | None:
    terms = _transfer_terms(report, found)
    if not terms:
        return None
    return {"applies_because": f"transfer/backup terms found in the alert or collected commands: {terms}",
            "questions": ["command, parent process, user and instance", "source files and remote destination",
                          "activity after the execution", "connections attributable to the process instance",
                          "remote destination, result and transfer indicators"],
            "stages": TRANSFER_STAGES,
            "rule": "Binary present, configuration accessed, command started, connection attributed, traffic "
                    "observed and operation completed are different stages; counters alone never reach "
                    "operation_completed. Report the last stage the evidence reaches and the source for the next."}


def volume_sources(found: dict) -> list[dict]:
    ips = sorted({ip for e in found["endpoints"] for ip in e.get("ips", []) if address(ip) and ":" not in ip})
    out = [{"source": "Vision One Search records (endpoint, network)",
            "how": "trend_search_data evidence_digest: transfer_counters holds only fields with verified counter "
                   "semantics; unclassified_metrics keeps every other numeric metric with its native value",
            "proves": "for a verified counter, the bytes/packets of that record and session in its verified direction",
            "limit": "no byte or packet field of these sources is verified in the audited contracts, so counter-like "
                     "fields stay unclassified and do not establish transferred volume"}]
    qradar = {"source": "QRadar flows (Ariel)", "how": "qradar_read_aql_resource('flows') to confirm the byte/packet "
              "fields of this deployment, then qradar_run_aql over the host IP and window",
              "proves": "traffic observed per flow (byte/packet counters with direction) for the flow's IP/port "
                        "tuple; not that the operation completed",
              "limit": "a flow is attributed to the process only when its tuple matches a process connection record "
                       "(same source port and time); a shared/NAT IP and time alone keep it a candidate",
              "requires": "flow collection covering the host's network segment; verified QRadar timezone"}
    if ips:
        qradar["host_ips"] = ips
    else:
        qradar["host_ips"] = []
        qradar["note"] = "no host IP yet: take endpointIp from the command_series records before querying flows"
    out.append(qradar)
    return out


def followup(report: dict, records: list[dict]) -> dict:
    found = seeds(report, records)
    planned = phases(report, found)
    return {"seeds": found, "phases": planned, "transfer": transfer(report, found),
            "volume_sources": volume_sources(found),
            "procedure": ["Read trend_read_search_resource for each source before the first query; keep fields the live "
                          "schema and the returned records actually contain.",
                          "Run each phase once; follow continuation_plan windows and refine_filters for full leaves; "
                          "never repeat identical parameters that cannot make progress.",
                          "Compare evidence_digest.identifiers with seeds.identifiers to state what the XDR phase added.",
                          "Keep the alert assessment as the assessment of the initial collection; give the agent "
                          "opinion with the complementary evidence separately."],
            "state": "planned" if planned else "not_planned: no time anchor or no validated endpoint scope",
            "assessment_scope": SCOPE_NOTE}


# ------------------------------------------------------------------ digest of direct Search records

def _flat(row: dict, prefix: str = "") -> list[tuple[str, Any]]:
    out = []
    for key, value in row.items():
        path = f"{prefix}{key}"
        if isinstance(value, dict):
            out += _flat(value, f"{path}.")
        else:
            out.append((path, value))
    return out


def _metric(field: str, value: Any, tool: str) -> tuple[str, dict] | None:
    """Classify one numeric field: verified network counter, known non-volume, or unclassified metric."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    leaf = field.rsplit(".", 1)[-1]
    verified = NETWORK_COUNTERS.get((tool, leaf))
    if verified:
        return "counter", verified
    if NOT_VOLUME.search(leaf):
        return "not_transfer_volume", {}
    if METRIC_LIKE.search(leaf):
        return "unclassified", {}
    return None


def _ref(index: int, row: dict) -> dict:
    return {"record_index": index, "uuid": row.get("uuid"), "time_utc": row.get("event_time_utc")}


def digest(records: list[dict], tool: str, query: str, complete: bool, pending: int) -> dict:
    """Actors, commands, files, connections and metrics in returned records, with provenance per occurrence."""
    instances: dict = {}
    executions: list[dict] = []
    aggregates: dict = {}
    commands: dict = {}
    files: list[dict] = []
    connections: list[dict] = []
    counters: list[dict] = []
    unclassified: list[dict] = []
    not_volume: list[dict] = []
    users: set[str] = set()
    hosts: list[dict] = []
    sessions: dict = {}
    for index, record in enumerate(records):
        data = record.get("data") if isinstance(record.get("data"), dict) else {}
        row = normalize(data, tool, query)
        ref = _ref(index, row)
        endpoint = {"host": row.get("endpoint_host"), "guid": row.get("endpoint_guid"), "ips": row.get("endpoint_ips")}
        if endpoint["host"] or endpoint["guid"]:
            hosts.append(endpoint)
        process, parent, obj, net = (row.get(k) or {} for k in ("process", "parent", "object", "network"))
        logon_user = (row.get("logon") or {}).get("user")
        for user in (logon_user, process.get("user"), obj.get("user")):
            if isinstance(user, str) and user:
                users.add(user)
        if process.get("hashId") or process.get("filePath"):
            observation = {"pid": process.get("pid"), "user": process.get("user") or logon_user,
                           "launch_time": process.get("launchTime"), "cmd": process.get("cmd"),
                           "parent": {"image": parent.get("filePath"), "cmd": parent.get("cmd"),
                                      "pid": parent.get("pid")} if parent else None, **ref}
            scope = endpoint["guid"] or endpoint["host"]
            if process.get("hashId") and scope:
                # processHashId on an identified endpoint identifies one execution.
                actor = instances.setdefault((scope, process["hashId"]), {
                    "identity": "process instance (processHashId on the same endpoint)", "endpoint": endpoint,
                    "instance": process["hashId"], "image": process.get("filePath"), "hashes": full_hashes(process),
                    "observations": []})
                actor["observations"].append(observation)
            else:
                executions.append({"identity": "unidentified execution: no processHashId on an identified endpoint; "
                                               "kept as a separate observation",
                                   "endpoint": endpoint, "instance": None, "image": process.get("filePath"),
                                   "hashes": full_hashes(process), "observations": [observation]})
            if process.get("filePath"):
                group = aggregates.setdefault((scope, process["filePath"]), {
                    "aggregate": "by image on one endpoint; not a single execution", "endpoint": endpoint,
                    "image": process["filePath"], "pids": [], "users": [], "instances": [], "records": []})
                for key, value in (("pids", process.get("pid")), ("users", observation["user"]),
                                   ("instances", process.get("hashId"))):
                    if value is not None and value not in group[key]:
                        group[key].append(value)
                group["records"].append(ref)
        for role, group in (("process", process), ("parent", parent), ("object", obj)):
            cmd = group.get("cmd")
            if isinstance(cmd, str) and cmd:
                entry = commands.setdefault(cmd, {"cmd": cmd, "occurrences": []})
                entry["occurrences"].append({"endpoint": endpoint, "role": role,
                                             "instance": group.get("hashId") or group.get("processHashId"),
                                             "pid": group.get("pid"), **ref})
        if obj.get("filePath"):
            files.append({"actor_instance": process.get("hashId"), "actor": process.get("filePath"),
                          "actor_pid": process.get("pid"), "object": obj.get("filePath"), "endpoint": endpoint,
                          "event": (row.get("event") or {}).get("eventSubId") or (row.get("event") or {}).get("eventName"),
                          **ref})
        dst = net.get("dst") or net.get("serverIp") or obj.get("ip") or net.get("request")
        if dst:
            attributed = bool(process.get("hashId"))
            connections.append({"src": net.get("src") or net.get("clientIp"), "spt": net.get("spt") or net.get("clientPort"),
                                "dst": dst, "dpt": net.get("dpt") or net.get("serverPort") or obj.get("port"),
                                "request": net.get("request"), "actor_instance": process.get("hashId"),
                                "actor": process.get("filePath"), "actor_pid": process.get("pid"), "endpoint": endpoint,
                                "attribution": "same record: the process instance is the event actor" if attributed else
                                "record without a process instance: not attributable to one execution", **ref})
        session = (net.get("src") or net.get("clientIp"), net.get("spt") or net.get("clientPort"), dst,
                   net.get("dpt") or net.get("serverPort"), data.get("flowId"))
        for field, value in _flat(data):
            found = _metric(field, value, tool)
            if not found:
                continue
            kind, semantics = found
            if kind == "counter":
                sessions.setdefault((session, field), []).append(value)
                counters.append({"field": field, "value": value, **semantics,
                                 "session": dict(zip(("src", "spt", "dst", "dpt", "flowId"), session)),
                                 "actor_instance": process.get("hashId"), **ref})
            else:
                (not_volume if kind == "not_transfer_volume" else unclassified).append(
                    {"field": field, "value": value, **ref})
    repeated = [{"field": field, "session": dict(zip(("src", "spt", "dst", "dpt", "flowId"), session)),
                 "readings": len(values)} for (session, field), values in sessions.items() if len(values) > 1]
    destinations = sorted({str(c["dst"]) for c in connections})
    actors = list(instances.values()) + executions
    for actor in actors:
        pids = {o["pid"] for o in actor["observations"] if o["pid"] is not None}
        actor["pids"] = sorted(pids, key=str)
        actor["users"] = sorted({o["user"] for o in actor["observations"] if o["user"]})
        if actor["instance"] and len(pids) > 1:
            actor["conflict"] = "one processHashId with different PIDs: verify before treating it as one execution"
    volume = {"total": None,
              "state": "verified_counters_returned" if counters else "no_verified_counter_fields",
              "fields_checked": f"every field of {len(records)} returned record(s)",
              "coverage": ("complete in the queried window" if complete else
                           f"partial: {pending} window(s)/refinement(s) pending; counters may be missing"),
              "repeated_sessions": repeated[:MAX_LIST],
              "rule": "No total is computed. Only fields with verified network-counter semantics for this source are "
                      "counters, each kept with its record, session, unit and direction; repeated readings of one "
                      "session may be cumulative and are never added. Other numeric metrics stay unclassified with "
                      "their native values. Traffic observed for a session does not show the operation completed."}
    if not counters:
        volume["missing"] = ("no field with verified network-counter semantics for this source in the returned "
                             "records; transferred volume is not established by this query")
    return {"actors": actors[:MAX_LIST], "actors_total": len(actors),
            "image_aggregates": list(aggregates.values())[:MAX_LIST],
            "commands": list(commands.values())[:MAX_LIST], "commands_total": len(commands),
            "file_objects": files[:MAX_LIST], "file_objects_total": len(files),
            "connections": connections[:MAX_LIST], "connections_total": len(connections),
            "transfer_counters": counters[:MAX_LIST], "transfer_counters_total": len(counters),
            "unclassified_metrics": unclassified[:MAX_LIST], "unclassified_metrics_total": len(unclassified),
            "not_transfer_volume": not_volume[:MAX_LIST], "volume": volume,
            "identifiers": _identifiers(
                [{"name": h["host"], "guid": h["guid"], "ips": h.get("ips") or []} for h in hosts],
                [{"value": u} for u in users],
                [{"value": v} for a in actors for v in a["hashes"].values()],
                [{"id": a["instance"]} for a in actors if a.get("instance")],
                [{"value": c} for c in commands], destinations),
            "note": "Derived from the returned records only, with record_index/uuid provenance per occurrence. Actors "
                    "are one execution only when processHashId identifies it; image_aggregates group observations "
                    "and are not executions. Compare identifiers with xdr_followup.seeds.identifiers."}
