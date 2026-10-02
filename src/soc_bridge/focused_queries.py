"""Evidence-triggered AQL. Every literal comes from a validated IP, host name, GUID or epoch."""

from __future__ import annotations

from typing import Any

from .aql_fields import FLOW_COLUMNS, SelectPlan
from .core import address
from .process_chain import GUID, HOST

SCRIPT_MARKERS = ("%scriptblock%", "%<EventID>4103</EventID>%", "%<EventID>4104</EventID>%",
                  "%EventID=4103%", "%EventID=4104%", "%EventCode=4103%", "%EventCode=4104%",
                  "%CommandInvocation(%")
INTEGRITY_MARKERS = ("%code integrity%", "%<EventID>5038</EventID>%", "%<EventID>6281</EventID>%",
                     "%EventID=5038%", "%EventID=6281%", "%EventCode=5038%", "%EventCode=6281%")
LINUX_SSH_MARKERS = ("%sshd[%", "%sshd:%", "% sshd %", "%pam_unix(sshd:%", "%pam_sss(sshd:%")
LINUX_IDENTITY_MARKERS = ("%su[%", "%su:%", "% su %", "%pam_unix(su:%", "%pam_sss(su:%")
LINUX_CONTEXT_MARKERS = LINUX_SSH_MARKERS + LINUX_IDENTITY_MARKERS + ("%sudo[%", "%sudo:%", "% sudo %")


def _any_payload(markers: tuple[str, ...]) -> str:
    return "(" + " OR ".join(f"UTF8(payload) ILIKE '{marker}'" for marker in markers) + ")"


def host_predicate(ip: str | None, hosts: list[str]) -> str | None:
    """IP and up to three host names; anything failing validation is dropped, never escaped."""
    parts = []
    ip = address(ip) if ip else None
    if ip:
        parts.append(f"(sourceip = '{ip}' OR destinationip = '{ip}')")
    for name in [h for h in hosts if isinstance(h, str) and HOST.fullmatch(h)][:3]:
        parts.append(f"UTF8(payload) ILIKE '%{name}%'")
    return "(" + " OR ".join(parts) + ")" if parts else None


def epoch_predicate(column: str, start_ms: int, end_ms: int) -> str:
    if not all(isinstance(v, int) and not isinstance(v, bool) and v >= 0 for v in (start_ms, end_ms)):
        raise ValueError("Epoch bounds must be nonnegative integers")
    return f"{column} >= {start_ms} AND {column} <= {end_ms}"


def _events(plan: SelectPlan, where: str, limit: int, tail: str) -> tuple[str, str | None]:
    query = f"{plan.select()} FROM events WHERE {where} ORDER BY starttime ASC LIMIT {limit} {tail}"
    fallback = f"{plan.select(False)} FROM events WHERE {where} ORDER BY starttime ASC LIMIT {limit} {tail}"
    return query, (fallback if plan.optional else None)


def script_blocks(plan: SelectPlan, tail: str, start_ms: int, end_ms: int, ip: str | None,
                  hosts: list[str]) -> dict | str:
    scope = host_predicate(ip, hosts)
    if not scope:
        return "No validated host IP/name to scope a script-block search"
    where = f"{scope} AND {epoch_predicate('starttime', start_ms, end_ms)} AND {_any_payload(SCRIPT_MARKERS)}"
    query, fallback = _events(plan, where, 500, tail)
    return {"database": "events", "query": query, "fallback": fallback, "scope": "host_script_block_context",
            "criteria": ("Payload markers for 4104/4103 (XML/key=value EventID, 'scriptblock', module-logging "
                         "'CommandInvocation('); EventID is then confirmed by parsing, not by QIDNAME.")}


def integrity(plan: SelectPlan, tail: str, start_ms: int, end_ms: int, ip: str | None,
              hosts: list[str]) -> dict | str:
    scope = host_predicate(ip, hosts)
    if not scope:
        return "No validated host IP/name to scope a code-integrity search"
    where = f"{scope} AND {epoch_predicate('starttime', start_ms, end_ms)} AND {_any_payload(INTEGRITY_MARKERS)}"
    query, fallback = _events(plan, where, 200, tail)
    return {"database": "events", "query": query, "fallback": fallback, "scope": "host_integrity_context",
            "criteria": "Payload markers for 5038/6281 or 'code integrity'; EventID confirmed by parsing."}


def parent_lookup(plan: SelectPlan, tail: str, start_ms: int, end_ms: int, parent_guid: str) -> dict | str:
    match = GUID.fullmatch(parent_guid or "")
    if not match:
        return "Parent GUID failed validation; not used in AQL"
    where = f"{epoch_predicate('starttime', start_ms, end_ms)} AND UTF8(payload) ILIKE '%{match[1].lower()}%'"
    query, fallback = _events(plan, where, 50, tail)
    return {"database": "events", "query": query, "fallback": fallback, "scope": "parent_process_lookup",
            "criteria": "Validated parent GUID in payload within the host window; host equality checked after parsing."}


def host_flows(tail: str, start_ms: int, end_ms: int, ip: str | None) -> dict | str:
    ip = address(ip) if ip else None
    if not ip:
        return "No validated host IP for a flow context search"
    columns = ", ".join(expression for expression, _ in FLOW_COLUMNS)
    query = (f"SELECT {columns} FROM flows WHERE (sourceip = '{ip}' OR destinationip = '{ip}') AND "
             f"{epoch_predicate('firstpackettime', start_ms, end_ms)} LIMIT 1000 {tail}")
    return {"database": "flows", "query": query, "fallback": None, "scope": "host_network_context",
            "criteria": "Host IP flows in the observed window; flows carry no process attribution."}


def linux_auth(plan: SelectPlan, tail: str, start_ms: int, end_ms: int,
               ip: str | None, hosts: list[str], identity: bool = False) -> dict | str:
    """Separate sshd from su/PAM noise; epoch bounds are the frozen metadata snapshot."""
    scope = host_predicate(ip, hosts)
    if not scope:
        return "No validated host IP/name for Linux authentication context"
    markers = LINUX_IDENTITY_MARKERS if identity else LINUX_SSH_MARKERS
    where = f"{scope} AND {epoch_predicate('starttime', start_ms, end_ms)} AND {_any_payload(markers)}"
    query, fallback = _events(plan, where, 5000, tail)
    return {"database": "events", "query": query, "fallback": fallback,
            "scope": "linux_identity_strict_window" if identity else "linux_ssh_strict_window",
            "criteria": "Linux daemon payload markers, not fixed QIDs; exact starttime epoch bounds plus bounded LAST/START/STOP"}


def describe(spec: dict | str, trigger: str) -> dict[str, Any]:
    if isinstance(spec, str):
        return {"trigger": trigger, "state": "not_built", "reason": spec}
    return {"trigger": trigger, "scope": spec["scope"], "criteria": spec["criteria"]}
