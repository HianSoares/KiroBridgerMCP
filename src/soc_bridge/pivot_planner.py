"""Turn investigable gaps into structured next pivots, and refuse repeats without a new reason.

Every pivot names the hypothesis/requirement it tests, the evidence that motivated it, the
source/entity/filters/window, its expected cost, which results would support or contradict
the hypothesis and when to stop. Priority follows the trigger records first, then strong
identifiers, process/session, and broad context last. Deterministic failures
(requires_resolution) are never retried automatically; transient ones are retried once.
Evidence that depends on a source the bridge cannot read is requested precisely instead of
being replaced by a supposedly equivalent query.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

PRIORITY = {"trigger_records": 1, "strong_identifier": 2, "process_session": 3, "context": 4, "external": 5}

# Gap ids whose evidence lives outside the bridge: data, source and validation to request.
EXTERNAL = {
    "rules:cre-definition": ("active CRE tests and responses of the contributing rules", "QRadar rule editor",
                             "compare each test with the triggering offense-linked events"),
    "attribution:host-process": ("application/owner authorization for the observed host and process",
                                 "change/asset owner records", "match activity, entity and window to the record"),
    "identity:account-nature": ("account type (service, admin, human) and owner", "AD/IdP/PAM inventory",
                                "match the exact account and domain"),
    "dhcp:roles": ("authorized DHCP scopes/relays and destination roles", "DHCP/IPAM inventory",
                   "match destination IPs and scopes"),
    "dhcp:origin": ("firewall anti-spoofing policy and the service owning the packets", "firewall policy",
                    "match interfaces and policy IDs"),
    "lockout:cause": ("service/task/application that used the locked account", "host/application owner, 4625 on the caller",
                      "match account, caller and time"),
}


def _key(action: str, params: dict) -> str:
    return hashlib.sha256(json.dumps([action, params], sort_keys=True, default=str).encode()).hexdigest()[:16]


def pivot(action: str, hypothesis: str, motivated_by: str, source: str, params: dict, priority: str,
          cost: dict, supports_if: str, contradicts_if: str, stop: str, status: str = "planned",
          reason: str = "", tool: str = "") -> dict:
    return {"id": _key(action, params), "action": action, "tool": tool, "hypothesis": hypothesis,
            "motivated_by": motivated_by, "source": source, "params": params, "priority": PRIORITY[priority],
            "priority_class": priority, "cost": cost, "supports_if": supports_if, "contradicts_if": contradicts_if,
            "stop_criterion": stop, "status": status, "reason": reason}


def plan(result: dict, trend: dict | None = None, previous: list[dict] | None = None, budget_hint: dict | None = None) -> list[dict]:
    out: list[dict] = []
    for name, finding in (result.get("queries") or {}).items():
        outcome = finding.get("outcome")
        error = finding.get("error") or {}
        cont = finding.get("continuation") or {}
        scope = finding.get("scope", name)
        klass = ("trigger_records" if scope == "offense_linked" else
                 "process_session" if "process" in str(scope) or "script" in str(scope) else "context")
        base = {"query": name, "search_id": finding.get("search_id"), "window_clause": finding.get("aql", "")[-80:]}
        if outcome == "creation_uncertain" or (finding.get("resume") or {}).get("action") == "requires_resolution":
            out.append(pivot("verify_uncertain_creation", f"coverage of {name}", f"query {name}: creation_uncertain",
                             "QRadar Ariel searches", base, klass, {"queries": 0, "calls": 0},
                             "an existing job with this AQL is found and its results are read",
                             "no job exists; then rerun this query explicitly",
                             "stop once the job is found or the analyst requests rerun_queries=[name]",
                             status="requires_resolution",
                             reason="search ID unknown: the bridge never recreates an uncertain job on its own"))
        elif cont.get("action") in ("poll_same_search", "fetch_next_page"):
            out.append(pivot("resume_same_search", f"coverage of {name}", f"query {name}: {outcome}",
                             "QRadar Ariel", {**base, "cursor": cont.get("cursor")}, klass,
                             {"queries": 0, "calls": 2}, "remaining pages add records relevant to the hypotheses",
                             "remaining pages are empty or irrelevant", "stop at result_set_complete or job error",
                             tool="investigate_offense_case (same case)"))
        elif cont.get("action") == "start_planned_query":
            retry = error.get("retryable", True) and not error.get("requires_resolution")
            out.append(pivot("start_planned_query", f"coverage of {name}", f"query {name}: {outcome}",
                             "QRadar Ariel", base, klass, {"queries": 1, "calls": 3},
                             "the query returns records that discriminate the hypotheses",
                             "the query completes empty in a complete window",
                             "stop after one completed job", status="planned" if retry else "requires_resolution",
                             reason="" if retry else error.get("next_action", "deterministic failure"),
                             tool="investigate_offense_case (same case)"))
        elif cont.get("action") == "new_partitioned_query":
            out.append(pivot("partition_query", f"records excluded by LIMIT in {name}", f"query {name}: limited",
                             "QRadar Ariel", base, klass, {"queries": 2, "calls": 6},
                             "the excluded window/groups contain trigger records",
                             "the partitions add no relevant records",
                             "stop when every partition is complete", status="proposed",
                             reason="needs a new validated AQL per partition (qradar_run_aql); not automatic",
                             tool="qradar_run_aql"))
        elif error and not error.get("retryable") and outcome not in ("complete_in_window", "empty"):
            out.append(pivot("resolve_query_failure", f"coverage of {name}", f"{name}: {error.get('category')}",
                             "QRadar", base, klass, {"queries": 0, "calls": 0}, "", "",
                             "stop: repeating the same request cannot succeed", status="requires_resolution",
                             reason=error.get("next_action", "")))
    for gap in result.get("gap_details", []):
        if gap["id"] in EXTERNAL:
            data, source, check = EXTERNAL[gap["id"]]
            out.append(pivot("request_external_evidence", ", ".join(gap.get("relevance", {}).get("blocks", [])),
                             f"gap {gap['id']}", source, {"data": data, "validation": check}, "external",
                             {"queries": 0, "calls": 0}, "the record covers the activity, entity and window",
                             "the record is missing, out of scope or contradicts the observed activity",
                             "stop when the analyst cites the record or states it does not exist",
                             status="requires_analyst", reason="the bridge cannot read this source"))
    for item in (trend or {}).get("not_deepened", []):
        out.append(pivot("investigate_related_alert", "same incident observed by Trend", f"alert {item['alert_id']}",
                         "Vision One Workbench", {"alert_id": item["alert_id"]}, "strong_identifier",
                         {"calls": 40}, "linked Search records on the offense entities",
                         "the alert concerns another host/time", "stop after one alert-first investigation",
                         status="proposed", reason=item.get("reason", ""), tool="investigate_vision_alert"))
    executed = {p["id"]: p for p in previous or [] if p.get("status") in ("executed", "completed")}
    for item in out:
        prior = executed.get(item["id"])
        if prior and prior.get("motivated_by") == item["motivated_by"]:
            item.update(status="skipped_repeat", reason="already executed with the same motivation; needs a new reason")
    out.sort(key=lambda p: (p["priority"], p["action"]))
    return out


def next_action(pivots: list[dict]) -> dict | None:
    for status in ("planned", "requires_resolution", "requires_analyst", "proposed"):
        for item in pivots:
            if item["status"] == status:
                return item
    return None
