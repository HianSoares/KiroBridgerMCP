"""Linux daemon messages as observations, with a census over every collected row.

The parser never executes commands, guesses the year/timezone of syslog text,
or assigns an SSH session from an IP, PID or nearby timestamp alone.
"""
from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timezone

from .core import address, instant

PREFIX = re.compile(
    r"^(?:<\d{1,3}>)?(?:(?:[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|"
    r"\d{4}-\d{2}-\d{2}T\S+)\s+)?(?:(?P<host>[A-Za-z0-9_.-]+)\s+)?"
    r"(?P<daemon>sudo|sshd|su)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$", re.S)
RFC5424 = re.compile(
    r"^<\d{1,3}>1\s+\S+\s+(?P<host>\S+)\s+(?P<daemon>sudo|sshd|su)\s+"
    r"(?P<pid>\d+|-)\s+\S+\s+-\s+(?P<message>.*)$", re.S)
SUDO = re.compile(r"^\s*(?P<actor>[^\s:;]{1,128})\s*:\s*TTY=(?P<tty>[^;]*)\s*;\s*"
                  r"PWD=(?P<pwd>[^;]*)\s*;\s*USER=(?P<target>[^;]*)\s*;\s*COMMAND=(?P<command>.+)$", re.S)
ACCEPTED = re.compile(r"^Accepted (?P<method>\S+) for (?P<target>\S+) from (?P<peer>\S+) port (?P<port>\d+)\b")
FAILED = re.compile(r"^Failed (?P<method>\S+) for (?:invalid user )?(?P<target>\S+) from (?P<peer>\S+) port (?P<port>\d+)\b")
SU = re.compile(r"^\(to (?P<target>[^)]+)\)\s+(?P<actor>\S+)\s+on\s+(?P<terminal>.*)$")
PAM = re.compile(r"^pam_\w+\((?P<module>sshd|su|sudo):session\): session "
                 r"(?P<operation>opened|closed) for user (?P<target>[^\s(]+)(?P<remainder>.*)$")


def stamp(value) -> str | None:
    dt = value if isinstance(value, datetime) else instant(value)
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z") if dt else None


def parse(payload: str | None) -> dict | None:
    if not isinstance(payload, str):
        return None
    match = PREFIX.fullmatch(payload.strip()) or RFC5424.fullmatch(payload.strip())
    if not match:
        return None
    data = match.groupdict()
    if data["host"] == "-":
        data["host"] = None
    message = data.pop("message")
    data.update(kind="unparsed_daemon_message", outcome="not_established")
    if data["daemon"] == "sudo" and (item := SUDO.fullmatch(message)):
        data.update(kind="sudo_command_record", **{k: v.strip() for k, v in item.groupdict().items()})
        data["meaning"] = "sudo recorded an invocation; command exit status, authorization and account nature unverified"
    elif data["daemon"] == "sshd" and (item := ACCEPTED.match(message)):
        peer, port = address(item["peer"]), int(item["port"])
        if peer and 0 < port <= 65535:
            data.update(kind="ssh_authentication_accepted", outcome="accepted_as_logged",
                        target=item["target"], method=item["method"], peer=peer, peer_port=port)
    elif data["daemon"] == "sshd" and (item := FAILED.match(message)):
        peer, port = address(item["peer"]), int(item["port"])
        if peer and 0 < port <= 65535:
            data.update(kind="ssh_authentication_failed", outcome="failed_as_logged",
                        target=item["target"], method=item["method"], peer=peer, peer_port=port)
    elif (item := PAM.match(message)):
        data.update(kind="pam_session_record", **item.groupdict())
        data["meaning"] = "PAM session message for this module/user; not a proven link to another process or session"
    elif data["daemon"] == "su" and (item := SU.fullmatch(message)):
        data.update(kind="su_identity_record", **item.groupdict())
        data["meaning"] = "su recorded this identity switch; purpose and authorization unverified"
    elif data["daemon"] == "sshd" and "[preauth]" in message:
        data.update(kind="ssh_preauth_record", meaning="sshd pre-authentication message; not an accepted login")
    return data


ANALYSIS_CAP = 5000  # privilege instances evaluated by decisions (presentation keeps 100 groups)


def analyze(finding: dict | None, query_name: str, bounds: tuple[int, int] | None = None) -> dict:
    finding = finding or {}
    rows = finding.get("rows", [])
    counts, commands, targets, actors = Counter(), Counter(), Counter(), Counter()
    privilege: dict[tuple, dict] = {}
    parsed, daemon_rows, unparsed, cut, records = 0, 0, 0, 0, []
    outside, missing_time, unrecognized = 0, 0, 0
    root_accepted, accepted = [], []
    for index, row in enumerate(rows):
        if bounds is not None:
            dt = instant(row.get("starttime"))
            if dt is None:
                missing_time += 1
                continue
            if not bounds[0] <= int(dt.timestamp() * 1000) <= bounds[1]:
                outside += 1
                continue
        item = parse(row.get("raw_payload"))
        if item is None:
            unrecognized += 1
            continue
        daemon_rows += 1
        if item["kind"] == "unparsed_daemon_message":
            unparsed += 1
        else:
            parsed += 1
        truncated = "raw_payload" in finding.get("truncated_rows", {}).get(str(index), [])
        cut += truncated
        counts[item["kind"]] += 1
        provenance = {"query": query_name, "search_id": finding.get("search_id"), "result_row_index": index,
                      "starttime_epoch": row.get("starttime"), "starttime_utc": stamp(row.get("starttime")),
                      "devicetime_utc": stamp(row.get("devicetime")), "log_source": row.get("log_source"),
                      "payload_truncated_by_bridge": truncated}
        if item["kind"] == "sudo_command_record":
            key = (item.get("host"), item["actor"], item["target"], item["command"], truncated)
            commands[key] += 1
            actors[item["actor"]] += 1
            targets[item["target"]] += 1
        if item["kind"] in ("sudo_command_record", "su_identity_record"):
            # One instance per host/actor/run-as/command (sudo) or identity switch (su), with its times.
            pkey = (item["kind"], item.get("host"), item.get("actor"), item.get("target"), item.get("command"))
            entry = privilege.setdefault(pkey, {
                "kind": item["kind"], "host": item.get("host"), "actor": item.get("actor"), "run_as": item.get("target"),
                "command": item.get("command"), "command_cut_by_bridge": False, "rows": 0, "first_starttime": None,
                "last_starttime": None, "references": []})
            entry["rows"] += 1
            entry["command_cut_by_bridge"] = entry["command_cut_by_bridge"] or truncated
            moment = row.get("starttime")
            if isinstance(moment, (int, float)) and not isinstance(moment, bool):
                entry["first_starttime"] = moment if entry["first_starttime"] is None else min(entry["first_starttime"], moment)
                entry["last_starttime"] = moment if entry["last_starttime"] is None else max(entry["last_starttime"], moment)
            else:
                entry["time_missing"] = True
            if len(entry["references"]) < 5:
                entry["references"].append({"query": query_name, "search_id": finding.get("search_id"),
                                            "result_row_index": index})
        if item["kind"] == "ssh_authentication_accepted":
            accepted.append({**item, "provenance": provenance})
            if item["target"] == "root":
                root_accepted.append({**item, "provenance": provenance})
        if len(records) < 20:
            # Commands in a response are previews; grouping above used the complete collected value.
            preview = dict(item)
            for key in ("command", "remainder", "meaning"):
                if isinstance(preview.get(key), str) and len(preview[key]) > 2000:
                    preview[key] = preview[key][:2000]
                    preview[f"{key}_preview_truncated"] = True
            records.append({**preview, "provenance": provenance})
    ordered = commands.most_common(100)
    complete = bool(finding.get("result_set_complete")) and not unparsed and not cut and not outside and not missing_time
    if bounds is not None:
        complete = complete and not unrecognized
    return {"scope": finding.get("scope"), "search_id": finding.get("search_id"),
            "collected_rows": len(rows), "daemon_rows": daemon_rows, "parsed_rows": parsed,
            "unparsed_daemon_rows": unparsed, "truncated_payload_rows": cut,
            "unrecognized_rows": unrecognized, "outside_window_rows": outside, "missing_time_rows": missing_time,
            "query_result_complete": bool(finding.get("result_set_complete")),
            "recognized_message_census_complete": complete,
            "kind_counts": dict(counts), "sudo_actor_counts": dict(actors), "sudo_target_counts": dict(targets),
            "sudo_commands": [{"host": h, "actor": a, "target": t, "command_preview": cmd[:2000],
                               "command_preview_truncated": len(cmd) > 2000,
                               "payload_truncated_by_bridge": truncated, "rows": count}
                              for (h, a, t, cmd, truncated), count in ordered],
            "sudo_command_groups": len(commands), "sudo_command_groups_omitted": max(0, len(commands) - 100),
            "privilege_instances": list(privilege.values())[:ANALYSIS_CAP],
            "privilege_instances_not_analyzed": max(0, len(privilege) - ANALYSIS_CAP),
            "accepted_ssh_count": len(accepted), "accepted_root_ssh_count": len(root_accepted),
            "accepted_root_ssh_records": root_accepted[:20],
            "accepted_root_ssh_records_omitted": max(0, len(root_accepted) - 20), "records": records,
            "negative_claim": ("No accepted root SSH message parsed in these sources/filters/window"
                               if complete and not root_accepted and query_name in ("linux_ssh_window", "ssh") else None),
            "limitations": ["Census covers collected rows, not endpoint logging completeness",
                            "QIDNAME alone is not proof of SSH authentication, sudo success or user target",
                            "Equal normalized IPs and zero ports do not prove loopback or a local connection",
                            "A user name does not establish account nature or authorization",
                            "PID/time/host proximity does not establish a shared SSH/sudo/su session",
                            "Syslog header time is kept as text; UTC comes from epochs without offset guesses"]}
