"""Bounded Workbench discovery through the official read-only MCP list handler.

That handler forwards filter/orderBy/time bounds, but no paging token or URL.
Never follow nextLink directly with the API key or pretend to have fetched it.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import re
from typing import Any

from .aql_errors import ResponseFormatError, classify_failure
from .ariel_collection import Budget
from .time_anchor import utc_ms

TOOL = "workbench_alerts_list"
STATUSES = {"OPEN": ("Open", "In Progress"), "NEW": ("Open",),
            "IN_PROGRESS": ("In Progress",), "CLOSED": ("Closed",), "ALL": ()}
SEVERITIES = {"critical", "high", "medium", "low"}
ALERT_ID = re.compile(r"WB-[A-Za-z0-9-]{1,100}\Z")


def parameters(status: str = "OPEN", severity: str = "", start_date_time: str = "",
               end_date_time: str = "", limit: int = 50, now: datetime | None = None) -> dict:
    if not isinstance(status, str) or status not in STATUSES:
        raise ValueError("status must be OPEN, NEW, IN_PROGRESS, CLOSED or ALL")
    if not isinstance(severity, str) or severity not in SEVERITIES | {""}:
        raise ValueError("severity must be critical, high, medium, low or empty")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 200:
        raise ValueError("limit must be an integer from 1 to 200")

    def stamp(value: str) -> datetime:
        if not isinstance(value, str) or len(value) > 40:
            raise ValueError("time bounds must be ISO timestamps with an explicit offset")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError("time bounds must be ISO timestamps with an explicit offset") from None
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("time bounds require Z or an explicit UTC offset")
        return parsed.astimezone(timezone.utc)

    if not isinstance(start_date_time, str) or not isinstance(end_date_time, str):
        raise ValueError("time bounds must be strings")
    if bool(start_date_time) != bool(end_date_time):
        raise ValueError("provide both time bounds or neither")
    default_window = not start_date_time
    end = stamp(end_date_time) if end_date_time else now or datetime.now(timezone.utc)
    start = stamp(start_date_time) if start_date_time else end - timedelta(days=1)
    if not timedelta(0) < end - start <= timedelta(days=30):
        raise ValueError("window must be positive and no longer than 30 days")
    clauses = []
    states = STATUSES[status]
    if states:
        clauses.append("(" + " or ".join(f"status eq '{state}'" for state in states) + ")")
    if severity:
        clauses.append(f"severity eq '{severity}'")
    return {"status": status, "severity": severity, "limit": limit, "default_window": default_window,
            "start_date_time": utc_ms(start), "end_date_time": utc_ms(end),
            "filter": " and ".join(clauses)}


def failed(stage: str, exc: BaseException) -> dict:
    error = classify_failure(exc)
    # The common classifier predates Trend discovery: keep its categories while
    # avoiding QRadar-specific instructions and raw upstream exception messages.
    error["next_action"] = error["next_action"].replace("QRadar", "Vision One")
    if not isinstance(exc, ResponseFormatError):
        error["message"] = "Vision One discovery failed; inspect local MCP logs and API permissions"
    return {"outcome": "unavailable", "alerts": [], "returned_alerts": 0,
            "result_set_complete": False, "any_matching_alert": None,
            "diagnostic_stage": stage, "error": error}


async def find_alerts(vision: Any, status: str = "OPEN", severity: str = "",
                      start_date_time: str = "", end_date_time: str = "", limit: int = 50,
                      budget: Budget | None = None) -> dict:
    selection = parameters(status, severity, start_date_time, end_date_time, limit)
    budget = budget or Budget(max_seconds=30, max_calls=1)
    result = {"selection": selection, "source": "Vision One Workbench",
              "window_semantics": "Workbench API retrieval range; not the time of every underlying endpoint event",
              "open_semantics": "OPEN includes status Open and In Progress; investigationResult is separate",
              "continuation_supported_by_upstream": False,
              "coverage_note": "Coverage is limited to this API page, time range and account permissions. "
                               "The default range is the last 24 hours, not all historical open alerts."}
    attempted = False
    try:
        if hasattr(vision, "available") and TOOL not in vision.available:
            raise RuntimeError(f"Optional MCP tool unavailable: {TOOL}")
        def call():
            nonlocal attempted
            attempted = True
            budget.calls_made += 1
            return vision.call(TOOL, {"filter": selection["filter"], "orderBy": "createdDateTime desc",
                                     "startDateTime": selection["start_date_time"],
                                     "endDateTime": selection["end_date_time"]})
        response = await budget.run(call, "Vision One Workbench listing")
    except Exception as exc:
        return {**result, **failed("upstream_tool_call" if attempted else "before_tool_call", exc),
                "mcp_tool_call_attempted": attempted, "budget": budget.describe()}
    try:
        if not isinstance(response, dict) or not isinstance(response.get("items"), list):
            raise ResponseFormatError("Workbench listing must contain an items array")
        rows = response["items"]
        if len(rows) > 5000 or any(not isinstance(row, dict) for row in rows):
            raise ResponseFormatError("Workbench listing has invalid or oversized items")
        next_link = response.get("nextLink")
        if next_link is not None and not isinstance(next_link, str):
            raise ResponseFormatError("Workbench nextLink must be a string")
        count = response.get("totalCount")
        if count is not None and (isinstance(count, bool) or not isinstance(count, int) or count < len(rows)):
            raise ResponseFormatError("Workbench totalCount is inconsistent")
        ids = set()
        summaries = []
        cuts = []
        summary_chars = 0
        response_budget_reached = False
        for index, row in enumerate(rows):
            alert_id = row.get("id")
            if not isinstance(alert_id, str) or not ALERT_ID.fullmatch(alert_id) or alert_id in ids:
                raise ResponseFormatError("Workbench listing has missing, invalid or duplicate alert IDs")
            ids.add(alert_id)
            state = row.get("status")
            if selection["status"] != "ALL" and state not in STATUSES[selection["status"]]:
                raise ResponseFormatError("Workbench response did not establish the requested lifecycle status")
            if severity and row.get("severity") != severity:
                raise ResponseFormatError("Workbench response did not honor the severity filter")
            if index >= limit:
                continue
            summary = {"id": alert_id}
            for key in ("name", "model", "modelId", "status", "investigationStatus", "investigationResult",
                        "severity", "score", "createdDateTime", "updatedDateTime", "caseId"):
                value = row.get(key)
                if value is not None and not isinstance(value, (str, int, float, bool)):
                    raise ResponseFormatError("Workbench summary field has an unexpected type")
                if isinstance(value, str) and len(value) > 1000:
                    value = value[:1000]
                    cuts.append(f"alerts[{index}].{key}")
                summary[key] = value
            summary["investigation_tool"] = {"tool": "investigate_vision_alert", "parameters": {"alert_id": alert_id}}
            size = len(json.dumps(summary, ensure_ascii=False))
            if summary_chars + size > 180000:
                response_budget_reached = True
                continue
            summary_chars += size
            summaries.append(summary)
        more = bool(next_link) or (count is not None and count > len(rows))
        locally_capped = len(rows) > len(summaries)
        complete = not more and not locally_capped
        result.update(outcome=("complete_in_window" if summaries else "empty") if complete else "partial",
                      alerts=summaries, returned_alerts=len(summaries), upstream_rows=len(rows),
                      upstream_total_count=count, next_link_present=bool(next_link),
                      local_limit_reached=locally_capped, result_set_complete=complete,
                      response_budget_reached=response_budget_reached,
                      any_matching_alert=True if summaries else False if complete else None,
                      truncated_fields=cuts, diagnostic_stage="page_collected", continuation_plan=[])
        if locally_capped and len(rows) <= 200 and not response_budget_reached:
            result["continuation_plan"].append({"action": "read_larger_first_page", "tool": "trend_find_alerts",
                "parameters": {k: selection[k] for k in ("status", "severity", "start_date_time", "end_date_time")}
                              | {"limit": len(rows)},
                "note": "This repeats the first page; retain seen IDs. It is not an upstream cursor."})
        if more or (locally_capped and len(rows) > 200) or response_budget_reached:
            result["continuation_plan"].append({"action": "refine_filters_or_time_range",
                "tool": "trend_find_alerts", "requires_refinement": True,
                "note": "The official MCP handler does not accept nextLink/skipToken. Narrow the explicit "
                        "time range or severity and retain seen IDs, or inspect remaining pages in the console. "
                        "Refinement does not guarantee completeness for alerts sharing the same timestamp."})
        budget.records_seen += len(rows)
        return {**result, "mcp_tool_call_attempted": attempted, "budget": budget.describe()}
    except ResponseFormatError as exc:
        return {**result, **failed("response_validation", exc), "mcp_tool_call_attempted": attempted,
                "budget": budget.describe()}
