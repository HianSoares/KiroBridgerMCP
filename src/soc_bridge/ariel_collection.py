"""One Ariel job per query: poll and page the same search ID inside an explicit budget."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from .aql_errors import AQLPolicyError, AQLValidationError, ResponseFormatError, classify_failure
from .aql_search import check_query, search_results, search_status, start_query

# Outcomes are mutually exclusive descriptions of one query, not of the incident.
OUTCOMES = ("not_started", "pending", "error", "unavailable", "empty",
            "complete_in_window", "limited", "partial")
TRUNCATED_PATH = re.compile(r"^rows\[(\d+)\]\.?(.*)$")


def number(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        return int(value) if str(value).lstrip("-").isdigit() else None
    except (TypeError, ValueError):
        return None


@dataclass
class Budget:
    """Shared ceiling for one collection: wall time, jobs created, polls and pages."""
    max_seconds: float = 60.0
    max_queries: int = 12
    max_pages: int = 40
    max_polls: int = 60
    page_size: int = 500
    poll_wait_seconds: int = 3
    clock: Callable[[], float] = time.monotonic
    queries_started: int = 0
    pages_fetched: int = 0
    polls: int = 0
    validation_retries: int = 0
    started: float = field(init=False)

    def __post_init__(self) -> None:
        for name in ("max_queries", "max_pages", "max_polls", "page_size", "poll_wait_seconds"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"Budget {name} must be a nonnegative integer")
        if not 1 <= self.page_size <= 500 or not 0 <= self.poll_wait_seconds <= 10:
            raise ValueError("Budget page_size must be 1..500 and poll_wait_seconds 0..10")
        if isinstance(self.max_seconds, bool) or not isinstance(self.max_seconds, (int, float)) or self.max_seconds <= 0:
            raise ValueError("Budget max_seconds must be positive")
        self.started = self.clock()

    def remaining_seconds(self) -> float:
        return self.max_seconds - (self.clock() - self.started)

    def blocked(self, kind: str) -> str | None:
        if self.remaining_seconds() <= 0:
            return "time budget exhausted"
        limits = {"query": (self.queries_started, self.max_queries, "query budget exhausted"),
                  "page": (self.pages_fetched, self.max_pages, "page budget exhausted"),
                  "poll": (self.polls, self.max_polls, "status polling budget exhausted")}
        used, ceiling, reason = limits[kind]
        return reason if used >= ceiling else None

    def wait(self) -> int:
        return max(0, min(self.poll_wait_seconds, int(self.remaining_seconds())))

    def describe(self) -> dict:
        return {"max_seconds": self.max_seconds, "elapsed_seconds": round(self.clock() - self.started, 3),
                "max_queries": self.max_queries, "queries_started": self.queries_started,
                "max_pages": self.max_pages, "pages_fetched": self.pages_fetched,
                "max_polls": self.max_polls, "polls": self.polls, "page_size": self.page_size,
                "validation_retries_without_optional_fields": self.validation_retries}


TOOLS = {"poll_same_search": ["qradar_get_search_status", "qradar_get_search_results"],
         "fetch_next_page": ["qradar_get_search_results"],
         "new_partitioned_query": ["qradar_read_aql_resource", "qradar_run_aql"],
         "start_planned_query": ["qradar_run_aql"]}


def continuation(finding: dict, action: str, reason: str, cursor: int | None = None) -> dict:
    plan = {"action": action, "reason": reason, "scope": finding["scope"],
            "database": finding["database"], "aql": finding["aql"],
            "search_id": finding.get("search_id") if action in ("poll_same_search", "fetch_next_page") else None,
            "cursor": cursor, "tools": TOOLS[action]}
    if action == "new_partitioned_query":
        plan["note"] = ("LIMIT excluded rows/groups from this job; paging the same search ID cannot "
                        "return them. Split the window or refine filters in a new validated query.")
    elif action in ("poll_same_search", "fetch_next_page"):
        plan["note"] = "Resume this search ID; do not recreate the query to obtain these results."
    return plan


async def collect_query(qradar: Any, query: str, database: str, scope: str,
                        budget: Budget | None = None, fallback_query: str | None = None,
                        plan: Any = None) -> dict:
    """Validate, create once, poll and page; classify the outcome and keep a resume cursor."""
    budget = budget or Budget()
    finding: dict = {"aql": query, "database": database, "scope": scope, "query_limit": None,
                     "state": "not started", "outcome": "not_started", "rows": [], "warnings": [],
                     "truncated_fields": [], "truncated_rows": {}, "result_set_complete": False,
                     "pages": 0, "polls": 0, "record_count": None}
    if plan is not None:
        finding["fields"] = plan.describe()
    try:
        policy = check_query(query)
    except AQLPolicyError as exc:
        return _failed(finding, exc)
    finding["query_limit"] = policy["query_limit"]
    finding["record_count_semantics"] = ("groups/rows returned by the aggregation; not the value of COUNT(*)"
                                         if policy["aggregated"] else "rows in the Ariel result set")
    reason = budget.blocked("query")
    if reason:
        finding["warnings"].append(f"Query not started: {reason}")
        finding["continuation"] = continuation(finding, "start_planned_query", reason)
        return finding
    try:
        try:
            created = await start_query(qradar, query)
        except AQLValidationError:
            if not fallback_query or fallback_query == query:
                raise
            # Optional live properties made QRadar reject the query; keep the required collection.
            budget.validation_retries += 1
            if plan is not None:
                plan.optional_rejected_by_validation = True
                finding["fields"] = plan.describe()
            finding["aql"] = fallback_query
            finding["warnings"].append("QRadar rejected optional fields; collected without them (culprit not isolated)")
            created = await start_query(qradar, fallback_query)
        budget.queries_started += 1
        sid = created["search_id"]
        finding.update(search_id=sid, state=str(created.get("status") or "WAIT").upper())
        while finding["state"] != "COMPLETED":
            if finding["state"] in {"ERROR", "CANCELED"}:
                finding["outcome"] = "error"
                finding["error"] = {"category": "job_failed", "outcome": "error", "retryable": False,
                                    "message": f"Ariel job ended with {finding['state']}",
                                    "next_action": "Inspect the query/window; this is not an empty completed search"}
                finding["warnings"].append("Ariel job failed or was canceled; this is not an empty completed search")
                return _finish(finding)
            reason = budget.blocked("poll")
            if reason:
                finding["outcome"] = "pending"
                finding["warnings"].append(f"Search still {finding['state']}: {reason}; resume the same search ID")
                finding["continuation"] = continuation(finding, "poll_same_search", reason, 0)
                return _finish(finding)
            status = await search_status(qradar, sid, budget.wait())
            budget.polls += 1
            finding["polls"] += 1
            finding.update(state=status["status"], record_count=status.get("record_count"))
        start = 0
        while True:
            reason = budget.blocked("page")
            if reason:
                finding["warnings"].append(f"Pages remain: {reason}; continue the same search ID")
                finding["continuation"] = continuation(finding, "fetch_next_page", reason, start)
                break
            page = await search_results(qradar, sid, start, budget.page_size)
            budget.pages_fetched += 1
            if not page.get("results_available"):
                finding.update(state=page.get("status", "unavailable"), outcome="pending")
                finding["warnings"].append(page.get("warning", "Results unavailable; not a negative search"))
                finding["continuation"] = continuation(finding, "poll_same_search", "results not available", start)
                break
            if page.get("database") != database:
                raise ResponseFormatError("Ariel returned the wrong database")
            finding["pages"] += 1
            finding["record_count"] = page.get("record_count", finding["record_count"])
            for path in page.get("truncated_fields", []):
                finding["truncated_fields"].append(f"page {finding['pages']}: {path}")
                match = TRUNCATED_PATH.match(path)
                if match:
                    index = str(start + int(match[1]))
                    finding["truncated_rows"].setdefault(index, []).append(match[2])
            finding["rows"].extend(page["rows"])
            finding["warnings"].extend(w for w in page.get("warnings", [])
                                       if not w.startswith("More results may exist"))
            if not page.get("has_more"):
                break
            next_start = page.get("next_start")
            if not isinstance(next_start, int) or next_start <= start:
                finding["warnings"].append("Non-advancing page cursor; stopped without claiming completeness")
                finding["continuation"] = continuation(finding, "fetch_next_page", "non-advancing cursor", start)
                break
            start = next_start
    except Exception as exc:
        return _failed(finding, exc)
    return _finish(finding)


def _failed(finding: dict, exc: BaseException) -> dict:
    error = classify_failure(exc)
    finding["error"] = error
    finding["outcome"] = error["outcome"]
    # "rejected" = refused before any job existed; "unavailable" = could not be read.
    finding["state"] = "rejected" if error["category"] in ("local_policy", "upstream_validation") else "unavailable"
    finding["result_set_complete"] = False
    finding["warnings"].append(f"{error['category']}: {error['message']}. {error['next_action']}")
    if finding.get("search_id") and error["retryable"]:
        finding["continuation"] = continuation(finding, "poll_same_search", error["category"], 0)
    return _finish(finding)


def _finish(finding: dict) -> dict:
    """Outcome from counts already observed; never fill numbers that were not returned."""
    rows = len(finding["rows"])
    total = number(finding.get("record_count"))
    limit = finding.get("query_limit")
    if finding["outcome"] == "not_started" and finding.get("search_id"):
        if finding.get("continuation"):
            finding["outcome"] = "partial"
        elif total is None:
            finding["outcome"] = "partial"
            finding["warnings"].append("record_count unavailable; completeness not established")
        elif limit is not None and total >= limit:
            finding["outcome"] = "limited"
            finding["warnings"].append("AQL LIMIT reached; partition/refine to include excluded rows or groups")
            finding["continuation"] = continuation(finding, "new_partitioned_query", "AQL LIMIT reached")
        elif total == 0 and rows == 0:
            finding["outcome"] = "empty"
        elif total == rows:
            finding["outcome"] = "complete_in_window"
        else:
            finding["outcome"] = "partial"
            finding["warnings"].append("Fetched rows differ from record_count; completeness not established")
    finding["result_set_complete"] = finding["outcome"] in ("empty", "complete_in_window")
    finding["returned_rows"] = rows
    if finding.get("continuation", {}).get("cursor") is not None:
        finding["next_start"] = finding["continuation"]["cursor"]
    finding["warnings"] = list(dict.fromkeys(finding["warnings"]))
    return finding
