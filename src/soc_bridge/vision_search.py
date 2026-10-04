"""Budgeted Vision One Search and OAT collection with the continuity the upstream really supports.

The official MCP Search handlers forward only startDateTime, endDateTime, top, mode,
select and the TMV1-Query header: there is no continuation token, so a full page is
split into time partitions. OAT forwards nextBatchToken, so it is paged by token.
countOnly is an independent count for the same query/window at call time.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from .aql_errors import classify_failure
from .ariel_collection import Budget, BudgetExhausted
from .core import records
from .time_anchor import utc_ms
from .trend_records import identity, normalize

TOP_VALUES = ("50", "100", "500", "1000", "5000")
MIN_PARTITION = timedelta(seconds=60)
SEARCH_TOOLS = {"search_endpoint_activities_list", "search_detections_list", "search_network_activities_list",
                "search_identity_activities_list", "search_email_activities_list"}
COUNT_SEMANTICS = ("countOnly result for the same query and full window at call time: an independent measure, not "
                   "proof that every row was fetched (ingestion delay and partition boundaries can differ).")


def _iso(dt: datetime) -> str:
    return utc_ms(dt)


def _count(response: Any) -> int | None:
    if isinstance(response, dict):
        for key in ("totalCount", "count", "total"):
            value = response.get(key)
            if isinstance(value, int) and not isinstance(value, bool):
                return value
    return None


async def _call(vision: Any, budget: Budget, tool: str, args: dict, stage: str) -> Any:
    budget.calls_made += 1
    return await budget.run(lambda: vision.call(tool, args), stage)


async def search(vision: Any, budget: Budget, tool: str, query: str, start: datetime, end: datetime,
                 top: str = "500", purpose: str = "", count: bool = False,
                 seen: dict | None = None) -> dict:
    """Collect one query over [start, end] with time partitions; never claims more than was read."""
    if tool not in SEARCH_TOOLS or top not in TOP_VALUES or not isinstance(query, str) or not query:
        raise ValueError("Unsupported Search tool, top value or empty query")
    if end <= start:
        raise ValueError("Search window must be positive")
    seen = {} if seen is None else seen
    finding: dict = {"tool": tool, "query": query, "purpose": purpose, "window": {"start": _iso(start), "end": _iso(end)},
                     "top": top, "partitions": [], "records": [], "state": "not_started", "continuation": [],
                     "continuation_supported_by_upstream": False, "count_only": None, "errors": []}
    queue = [(start, end)]
    capped_minimum = False
    while queue:
        part_start, part_end = queue.pop(0)
        reason = budget.blocked("call") or budget.blocked("partition") or budget.blocked("record")
        if reason:
            finding["continuation"].append({"action": "search_partition", "tool": tool, "query": query,
                                            "start": _iso(part_start), "end": _iso(part_end), "reason": reason})
            continue
        budget.partitions_used += 1
        args = {"query": query, "startDateTime": _iso(part_start), "endDateTime": _iso(part_end), "top": top}
        part = {"start": args["startDateTime"], "end": args["endDateTime"], "state": "not_started", "rows": 0}
        finding["partitions"].append(part)
        try:
            response = await _call(vision, budget, tool, args, f"{tool} partition")
            rows = records(response)
        except BudgetExhausted as exc:
            part["state"] = "not_started" if not exc.started else "interrupted"
            finding["continuation"].append({"action": "search_partition", "tool": tool, "query": query,
                                            "start": part["start"], "end": part["end"], "reason": str(exc)})
            continue
        except Exception as exc:
            error = classify_failure(exc)
            part["state"] = error["outcome"]
            part["error"] = error["category"]
            finding["errors"].append({"partition": [part["start"], part["end"]], **error})
            continue
        has_next = isinstance(response, dict) and bool(response.get("nextLink") or response.get("next"))
        part.update(state="completed", rows=len(rows), upstream_signalled_more=has_next)
        budget.observe_rows(len(rows))
        for row in rows:
            if not isinstance(row, dict):
                continue
            record = normalize(row, tool, query, {"start": part["start"], "end": part["end"]})
            key = identity(record)
            if key in seen:
                seen[key].setdefault("also_returned_by", []).append({"tool": tool, "query": query,
                                                                    "partition": [part["start"], part["end"]]})
                continue
            seen[key] = record
            finding["records"].append(record)
        if len(rows) >= int(top) or has_next:
            part["state"] = "page_full"
            if part_end - part_start > MIN_PARTITION * 2:
                middle = part_start + (part_end - part_start) / 2
                queue[:0] = [(part_start, middle), (middle, part_end)]
                part["note"] = "Search has no continuation token in the MCP handler; window split in halves"
            else:
                capped_minimum = True
                part["note"] = "Minimum partition still full: refine filters (more specific query)"
                finding["continuation"].append({"action": "refine_filters", "tool": tool, "query": query,
                                                "start": part["start"], "end": part["end"],
                                                "reason": "page full at the minimum partition size"})
    if count and not budget.blocked("call"):
        try:
            response = await _call(vision, budget, tool, {"query": query, "startDateTime": _iso(start),
                                                          "endDateTime": _iso(end), "mode": "countOnly"},
                                   f"{tool} countOnly")
            value = _count(response)
            finding["count_only"] = {"state": "collected" if value is not None else "unrecognized_format",
                                     "value": value, "semantics": COUNT_SEMANTICS}
        except Exception as exc:
            error = classify_failure(exc) if not isinstance(exc, BudgetExhausted) else {"category": "time_budget"}
            finding["count_only"] = {"state": "unavailable", "error": error["category"], "semantics": COUNT_SEMANTICS}
    states = [p["state"] for p in finding["partitions"]]
    delivered = any(s in ("completed", "page_full") for s in states)
    if finding["continuation"] and any(c["action"] == "search_partition" for c in finding["continuation"]):
        finding["state"] = "partial" if delivered else "not_started"
    elif capped_minimum:
        finding["state"] = "limited"
    elif finding["errors"] and not delivered:
        finding["state"] = "unavailable"
    elif finding["errors"]:
        finding["state"] = "partial"
    elif not finding["records"]:
        finding["state"] = "empty"
    else:
        finding["state"] = "complete_in_window"
    finding["records_fetched"] = len(finding["records"])
    finding["coverage_note"] = ("complete_in_window means every partition returned less than a full page; it says "
                                "nothing about whether the endpoint logged everything (sensor, policy, retention).")
    return finding


async def oat(vision: Any, budget: Budget, filter_expr: str, start: datetime, end: datetime,
              top: str = "200", max_batches: int = 5, next_batch_token: str | None = None) -> dict:
    """OAT detections paged by nextBatchToken (the token the upstream handler forwards)."""
    finding: dict = {"tool": "workbench_observed_attack_techniques_list", "filter": filter_expr,
                     "window": {"start": _iso(start), "end": _iso(end)}, "items": [], "batches": 0,
                     "state": "not_started", "continuation": None, "errors": []}
    token = next_batch_token
    seen_tokens: set[str] = set()

    def resume(reason: str) -> dict:
        return {"action": "oat_next_batch" if token else "start_oat", "tool": finding["tool"],
                "filter": filter_expr, "detectedStartDateTime": _iso(start), "detectedEndDateTime": _iso(end),
                "top": top, "nextBatchToken": token, "nextBatchToken_present": bool(token), "reason": reason}

    finding["resumed"] = bool(next_batch_token)
    finding["coverage_note"] = "Coverage is for the requested batches; a resumed call does not include earlier batches"
    while True:
        reason = budget.blocked("call") or budget.blocked("record")
        if reason or finding["batches"] >= max_batches:
            finding["continuation"] = resume(reason or "batch cap reached")
            break
        args = {"filter": filter_expr, "detectedStartDateTime": _iso(start), "detectedEndDateTime": _iso(end), "top": top}
        if token:
            args["nextBatchToken"] = token
        try:
            response = await _call(vision, budget, finding["tool"], args, "OAT batch")
            rows = records(response)
        except BudgetExhausted as exc:
            finding["errors"].append({"category": "time_budget", "message": str(exc)})
            finding["continuation"] = resume(str(exc))
            break
        except Exception as exc:
            finding["errors"].append(classify_failure(exc))
            finding["continuation"] = resume("batch failed; retain the failed batch token and collected items")
            break
        finding["batches"] += 1
        budget.observe_rows(len(rows))
        for row in rows:
            if isinstance(row, dict):
                finding["items"].append(normalize_oat(row))
        token = response.get("nextBatchToken") if isinstance(response, dict) else None
        if not token:
            break
        if token in seen_tokens:
            finding["errors"].append({"category": "response_format", "message": "OAT repeated a continuation token"})
            finding["continuation"] = resume("repeated token; inspect upstream before resuming")
            break
        seen_tokens.add(token)
    if finding["errors"] and not finding["batches"]:
        finding["state"] = "unavailable"
    elif finding["continuation"] or finding["errors"]:
        finding["state"] = "partial" if finding["batches"] else "not_started"
    elif finding["items"]:
        finding["state"] = "complete_in_window"
    elif finding["batches"]:
        finding["state"] = "empty"
    return finding


def normalize_oat(row: dict) -> dict:
    filters = row.get("filters") if isinstance(row.get("filters"), list) else []
    endpoint = row.get("endpoint") if isinstance(row.get("endpoint"), dict) else {}
    detail = row.get("detail") if isinstance(row.get("detail"), dict) else {}
    return {"uuid": row.get("uuid"), "detected_date_time": row.get("detectedDateTime"),
            "ingested_date_time": row.get("ingestedDateTime"), "source": row.get("source"),
            "filters": [{"id": f.get("id"), "name": f.get("name"), "risk_level": f.get("riskLevel"),
                         "mitre_tactic_ids": f.get("mitreTacticIds") or [],
                         "mitre_technique_ids": f.get("mitreTechniqueIds") or []} for f in filters if isinstance(f, dict)],
            "endpoint": {"name": endpoint.get("endpointName"), "agent_guid": endpoint.get("agentGuid"),
                         "ips": endpoint.get("ips") or []},
            "detail": normalize(detail, "oat_detail", "") if detail else None}
