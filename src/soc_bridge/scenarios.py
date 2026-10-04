"""Scenario interpretation built only from analyses the bridge already performs.

Each scenario separates what the records show from what they do not establish, and lists the
evidence that would discriminate the competing hypotheses. No new event taxonomy is created:
every statement maps to an existing parser (process_chain, linux_evidence, lockout_evidence,
integrity_evidence, flow_summary, dump_analysis) and keeps its provenance.
"""

from __future__ import annotations

from typing import Any


def _windows(result: dict) -> dict:
    processes = result.get("processes", {})
    attempts = (result.get("host") or {}).get("explicit_credential_attempts", [])
    creations, blocks = processes.get("process_creations", []), processes.get("script_blocks", [])
    if not (creations or blocks or attempts):
        return {"detected": False}
    observed = []
    if creations:
        observed.append(f"{len(creations)} process creation record(s) with GUID/host; "
                        f"{len(processes.get('links', []))} parent/child link(s) by GUID+host")
    if processes.get("powershell_processes"):
        observed.append(f"{len(processes['powershell_processes'])} PowerShell process creation(s)")
    if blocks:
        observed.append(f"{len(blocks)} PowerShell 4104/4103 content record(s)")
    if attempts:
        observed.append(f"{len(attempts)} EventID 4648 record(s): explicit-credential attempt as logged")
    return {"detected": True, "observed": observed,
            "not_established": ["4648 does not show a successful logon or the service used",
                                "a QID/rule name is not the EventID or the payload content",
                                "PID or time proximity is not a parent/child link without GUID+host",
                                "missing 4104 results do not show logging or forwarding was disabled"],
            "gaps": [f"parent {m.get('parent_guid')} not found in the window" for m in processes.get("missing_parents", [])[:5]],
            "discriminating_evidence": ["full command line and script content of the chain",
                                        "user/session of each process (from the same record)",
                                        "collection reach: sources, window and pages of the queries"]}


def _linux(result: dict) -> dict:
    linux = result.get("linux", {})
    offense = linux.get("offense", {})
    kinds = offense.get("kind_counts", {})
    if not linux.get("detected"):
        return {"detected": False}
    observed = []
    if kinds.get("ssh_authentication_accepted"):
        observed.append(f"{kinds['ssh_authentication_accepted']} accepted SSH authentication record(s) (as logged)")
    if kinds.get("sudo_command_record"):
        observed.append(f"{kinds['sudo_command_record']} sudo record(s); actors {offense.get('sudo_actor_counts')}, "
                        f"targets {offense.get('sudo_target_counts')}")
    if kinds.get("su_identity_record"):
        observed.append(f"{kinds['su_identity_record']} su identity record(s) (origin -> target)")
    if kinds.get("pam_session_record"):
        observed.append(f"{kinds['pam_session_record']} PAM session record(s)")
    return {"detected": True, "observed": observed,
            "not_established": ["SSH authentication, sudo, su and a PAM session are different events",
                                "a sudo record shows the invoked command, not its result",
                                "origin user, target user and invoked command are separate fields; none implies the other"],
            "gaps": ["unparsed daemon records present"] if offense.get("unparsed_daemon_rows") else [],
            "discriminating_evidence": ["SSH session preceding the sudo/su on the same host and time",
                                        "command result in the host or application logs"]}


def _lockout(result: dict) -> dict:
    lockout = result.get("lockout", {})
    if not lockout.get("detected"):
        return {"detected": False}
    groups = lockout.get("groups", [])[:5]
    observed = [f"locked account {g.get('target_domain')}\\{g.get('target_user')}; CallerComputerName "
                f"{g.get('caller_computer')}; recording source {g.get('log_source')}; {g.get('rows')} 4740 record(s)"
                for g in groups]
    return {"detected": True, "observed": observed,
            "not_established": ["the recording DC is not the origin of the failures",
                                "CallerComputerName is the reported caller, not the responsible process",
                                "4740 is a lockout, not an authentication"],
            "candidates": f"{len(lockout.get('authentication_candidates', []))} 4625/4771/4776 failure(s) correlated by "
                          "account and time (candidates)",
            "discriminating_evidence": ["4625 on the caller host with the process name",
                                        "service/task/application using the account"]}


def _network(result: dict) -> dict:
    flows = result.get("flows", {})
    if not flows.get("port_groups"):
        return {"detected": False}
    return {"detected": True,
            "observed": [f"{len(flows['port_groups'])} protocol/port group(s); "
                         f"{flows.get('distinct_destinations_in_collected_rows')} destination(s) in collected rows",
                         "DHCP-compatible port pattern" if flows.get("dhcp_port_pattern") else "no DHCP-only pattern"],
            "not_established": ["a port pattern is compatibility, not the destination role",
                                "equal private IPs and zero ports do not prove loopback",
                                "flows do not attribute traffic to a process"],
            "discriminating_evidence": ["destination roles (DHCP/IPAM inventory)", "firewall policy for the interfaces",
                                        "process attribution from endpoint telemetry with the same 5-tuple and time"]}


def _integrity(result: dict) -> dict:
    events = (result.get("integrity") or {}).get("integrity_events", [])
    if not events:
        return {"detected": False}
    linked = [e for e in events if isinstance(e.get("relationship_to_process_chain"), list)]
    return {"detected": True,
            "observed": [f"{len(events)} code-integrity record(s); {len(linked)} with a candidate link to an observed "
                         "process path on the same host"],
            "not_established": ["time proximity does not relate the file to the chain",
                                "5038 alone does not show tampering or compromise"],
            "discriminating_evidence": ["same file identity (volume, version, hash) in the process chain"]}


def _dumping(trend: dict | None) -> dict:
    dumps = []
    for item in (trend or {}).get("investigations", []):
        for dump in ((item.get("report") or {}).get("dump_analysis") or {}).get("dumps", []):
            dumps.append((item["alert_id"], dump))
    if not dumps:
        return {"detected": False}
    observed = [f"alert {alert}: intent {d['intent']}; execution {d['execution']}; dump file {d['dump_file']['status']}; "
                f"target {d['target'].get('status')}; later activity {len(d.get('followups', []))} followup(s); "
                f"connections {len(d.get('connections', []))}" for alert, d in dumps[:5]]
    return {"detected": True, "observed": observed,
            "not_established": ["process access, heuristic detection, execution, dump creation, later read and "
                                "transfer are separate stages; each needs its own record",
                                "the alert name does not establish credential theft"],
            "discriminating_evidence": ["dump file creation and later read by another process",
                                        "transfer of that file (network record attributed to the reader)",
                                        "authorization/diagnostic record for the dump tool"]}


def interpret(result: dict, trend: dict | None = None) -> dict:
    scenarios = {"windows_powershell": _windows(result), "linux": _linux(result), "lockout": _lockout(result),
                 "credential_dumping": _dumping(trend), "network_dhcp": _network(result),
                 "integrity": _integrity(result)}
    rules = [r.get("metadata", {}).get("name") for r in result.get("rules", []) if r.get("state") == "collected"]
    return {"scenarios": {k: v for k, v in scenarios.items() if v.get("detected")},
            "rule_names": [r for r in rules if r],
            "behavior_vs_label": "Rule and offense names describe why QRadar alerted; observed behavior comes only "
                                 "from the records listed in each scenario."}


def hypotheses(result: dict, closure: dict, trend: dict | None, scenarios: dict) -> list[dict]:
    req = closure.get("requirements", {})

    def status(rid: str) -> str:
        return (req.get(rid) or {}).get("status", "unverified")

    tests: dict[str, list[str]] = {k: [] for k in ("malicious", "authorized", "detection_error", "misattribution")}
    for name, finding in (result.get("queries") or {}).items():
        tests["detection_error"].append(f"{name}: {finding.get('outcome')}")
    for item in (trend or {}).get("investigations", []):
        if item.get("state") == "collected":
            tests["malicious"].append(f"Trend alert {item['alert_id']}: {item['report']['assessment']['classification']} "
                                      f"(link to the offense: {(item.get('link') or {}).get('level', 'not evaluated')})")
    discriminators = [d for s in scenarios.get("scenarios", {}).values() for d in s.get("discriminating_evidence", [])]
    return [
        {"id": "malicious", "status": status("malicious_activity_confirmed"), "tests": tests["malicious"],
         "would_confirm": "malicious use tied to the observed activity (linked records, verdict tied to execution)",
         "discriminating_evidence": discriminators[:6]},
        {"id": "authorized_or_operational", "status": status("authorization"),
         "tests": [f"scoped records: {(req.get('authorization') or {}).get('evidence')}"],
         "would_confirm": "a scoped record covering activity, entities and window of every observed activity"},
        {"id": "detection_error", "status": status("detection_error"), "tests": tests["detection_error"],
         "would_confirm": "positive evidence that the rule matched something else; absence in queries is not enough"},
        {"id": "misattribution", "status": "unverified", "tests": [],
         "would_confirm": "identifiers showing the records belong to another host/account/process"},
    ]
