"""One Ariel job per query: poll and page the same search ID inside an explicit budget."""

from __future__ import annotations

import asyncio
import re
import time
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from .aql_errors import AQLPolicyError, AQLValidationError, ResponseFormatError, classify_failure
from .aql_search import check_query, create_search, search_results, search_status, validate_query

# Outcomes are mutually exclusive descriptions of one query, not of the incident.
OUTCOMES = ("not_started", "pending", "error", "unavailable", "empty",
            "complete_in_window", "limited", "partial", "creation_uncertain")
TRUNCATED_PATH = re.compile(r"^rows\[(\d+)\]\.?(.*)$")
ACTIVE_READ_BUDGET = ContextVar("active_read_budget", default=None)
# Creation failures where QRadar demonstrably did not create a job; any other
# creation failure leaves the job's existence uncertain.
NOT_CREATED = {"permission", "tool_unavailable"}


class CheckpointFailed(RuntimeError):
    """Persisting collection progress failed; the collection stops instead of continuing unsaved."""


Progress = Callable[[dict, str], None]


def snapshot(finding: dict, stage: str, cursor: int | None = None) -> dict:
    """Resumable copy of an in-flight finding.

    "creating" is written before the creation call: if the run stops during that call QRadar
    may have created the job without returning its ID, so the saved state is
    creation_uncertain. Later stages carry the known search ID, the rows already fetched and
    the cursor of the next page to read."""
    snap = {k: (list(v) if isinstance(v, list) else dict(v) if isinstance(v, dict) else v)
            for k, v in finding.items()}
    snap["result_set_complete"] = False
    snap["checkpoint"] = stage
    if stage == "creating":
        snap.update(outcome="creation_uncertain", state="creation_uncertain")
        snap["continuation"] = continuation(finding, "verify_creation_before_retry",
                                            "run stopped while the job was being created")
    else:
        rows = len(snap.get("rows", []))
        snap["outcome"] = "partial" if rows else "pending"
        snap["next_start"] = cursor if cursor is not None else rows
        snap["continuation"] = continuation(finding, "fetch_next_page" if rows else "poll_same_search",
                                            f"checkpoint {stage}", snap["next_start"])
    snap["returned_rows"] = len(snap.get("rows", []))
    return snap


def _notify(progress: Progress | None, finding: dict, stage: str, cursor: int | None = None) -> None:
    if progress is None:
        return
    try:
        progress(snapshot(finding, stage, cursor), stage)
    except Exception as exc:
        raise CheckpointFailed(f"checkpoint {stage} not saved: {type(exc).__name__}") from exc


class BudgetExhausted(TimeoutError):
    """The shared collection deadline ended before or during an upstream call."""

    def __init__(self, stage: str, started: bool, reason: str = "time budget exhausted"):
        self.stage = stage
        self.started = started
        super().__init__(f"{reason} {'during' if started else 'before'} {stage}")


def number(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        return int(value) if str(value).lstrip("-").isdigit() else None
    except (TypeError, ValueError):
        return None


@dataclass
class Budget:
    """Shared ceiling for one collection: wall time, jobs, polls, pages, Trend calls, records, partitions."""
    max_seconds: float = 60.0
    max_queries: int = 12
    max_pages: int = 40
    max_polls: int = 60
    page_size: int = 500
    poll_wait_seconds: int = 3
    clock: Callable[[], float] = time.monotonic
    max_calls: int = 40
    max_records: int = 5000
    max_partitions: int = 12
    queries_started: int = 0
    pages_fetched: int = 0
    polls: int = 0
    validation_retries: int = 0
    calls_made: int = 0
    reused_reads: int = 0
    reused_records: int = 0
    reused_partitions: int = 0
    last_read_reused: bool = False
    records_seen: int = 0
    partitions_used: int = 0
    phase: str = "primary"
    reservations: dict = field(default_factory=dict)
    phase_log: list = field(default_factory=list)
    started: float = field(init=False)
    # A call cut by the deadline ends the time of its phase, whatever the budget clock reads:
    # asyncio may fire a timeout up to one clock resolution early (15.6 ms with GetTickCount64
    # on Windows before Python 3.13), and recomputing "start + allowed - elapsed" in floating
    # point can leave a positive residue of ~1e-14 s. Both used to let the next call start.
    # The cut is therefore recorded as state, not derived from arithmetic: the phase is closed
    # (later phases keep their reservations) and, without reservations, the whole budget is.
    deadline_floor: float = field(init=False)
    cut_phases: set = field(init=False)
    expired: bool = field(init=False)

    def __post_init__(self) -> None:
        for name in ("max_queries", "max_pages", "max_polls", "page_size", "poll_wait_seconds",
                     "max_calls", "max_records", "max_partitions"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"Budget {name} must be a nonnegative integer")
        if not 1 <= self.page_size <= 500 or not 0 <= self.poll_wait_seconds <= 10:
            raise ValueError("Budget page_size must be 1..500 and poll_wait_seconds 0..10")
        if isinstance(self.max_seconds, bool) or not isinstance(self.max_seconds, (int, float)) or self.max_seconds <= 0:
            raise ValueError("Budget max_seconds must be positive")
        self.started = self.clock()
        self.deadline_floor = self.started
        self.cut_phases = set()
        self.expired = False

    def now(self) -> float:
        return max(self.clock(), self.deadline_floor)

    def remaining_seconds(self) -> float:
        remaining = self.max_seconds - (self.now() - self.started)
        return min(remaining, 0.0) if self.expired else remaining

    # Reservations keep part of the budget for later phases (for example the Trend<->QRadar
    # correlation) so that broad or optional reads cannot consume it first. A phase gets its
    # reservation back when it is entered; a skipped phase releases it explicitly.
    def reserve(self, phase: str, calls: int = 0, seconds: float = 0.0, queries: int = 0) -> None:
        if phase == self.phase or min(calls, seconds, queries) < 0:
            raise ValueError("Reservations are for later phases and must be nonnegative")
        self.reservations[phase] = {"calls": calls, "seconds": float(seconds), "queries": queries}

    def enter(self, phase: str) -> None:
        self.reservations.pop(phase, None)
        self.phase_log.append({"phase": phase, "entered_at_seconds": round(self.now() - self.started, 3),
                               "calls_made": self.calls_made, "queries_started": self.queries_started})
        self.phase = phase

    def release(self, phase: str, reason: str) -> None:
        if self.reservations.pop(phase, None) is not None:
            self.phase_log.append({"phase": phase, "released": reason})

    def _held(self, key: str) -> float:
        return sum(r[key] for r in self.reservations.values())

    def _held_by(self) -> str:
        return ", ".join(sorted(self.reservations)) or "none"

    def available_seconds(self) -> float:
        """Time this phase may use: the deadline minus what later phases hold."""
        available = self.remaining_seconds() - self._held("seconds")
        return min(available, 0.0) if self.phase in self.cut_phases else available

    def blocked(self, kind: str) -> str | None:
        if self.remaining_seconds() <= 0:
            return "time budget exhausted"
        if self.available_seconds() <= 0:
            return f"remaining time reserved for later phase(s): {self._held_by()}"
        limits = {"query": (self.queries_started, self.max_queries, "query budget exhausted", "queries"),
                  "page": (self.pages_fetched, self.max_pages, "page budget exhausted", None),
                  "poll": (self.polls, self.max_polls, "status polling budget exhausted", None),
                  "call": (self.calls_made, self.max_calls, "upstream call budget exhausted", "calls"),
                  "record": (self.records_seen, self.max_records, "record budget exhausted", None),
                  "partition": (self.partitions_used, self.max_partitions, "time-partition budget exhausted", None)}
        used, ceiling, reason, held_key = limits[kind]
        if used >= ceiling:
            return reason
        if held_key and used >= ceiling - self._held(held_key):
            return f"remaining {held_key} reserved for later phase(s): {self._held_by()}"
        return None

    def wait(self) -> int:
        return max(0, min(self.poll_wait_seconds, int(self.available_seconds())))

    async def run(self, operation: Callable[[], Awaitable[Any]], stage: str) -> Any:
        """Run one upstream call under the shared deadline; never start it after the deadline
        or inside time that a later phase holds."""
        remaining = self.available_seconds()
        if remaining <= 0:
            reason = ("time budget exhausted" if self.remaining_seconds() <= 0 else
                      f"time reserved for later phase(s) {self._held_by()}")
            raise BudgetExhausted(stage, started=False, reason=reason)
        begun = self.now()
        self.last_read_reused = False
        context = ACTIVE_READ_BUDGET.set((self, stage))
        try:
            return await asyncio.wait_for(operation(), timeout=remaining)
        except asyncio.TimeoutError:
            # The timer marks the end of the time this phase may use, whatever the budget clock
            # reads now: later phases keep their reservations, this phase has none left.
            self.deadline_floor = max(self.deadline_floor, begun + remaining)
            self.cut_phases.add(self.phase)
            if self._held("seconds") <= 0:
                self.expired = True
            raise BudgetExhausted(stage, started=True) from None
        finally:
            ACTIVE_READ_BUDGET.reset(context)

    def reuse_read(self, stage: str) -> None:
        """Refund the charged read/partition when no upstream call was made."""
        self.last_read_reused = True
        self.calls_made = max(0, self.calls_made - 1)
        self.reused_reads += 1
        if stage.endswith(" partition"):
            self.partitions_used = max(0, self.partitions_used - 1)
            self.reused_partitions += 1

    def observe_rows(self, count: int) -> None:
        if self.last_read_reused:
            self.reused_records += count
        else:
            self.records_seen += count

    def describe(self) -> dict:
        return {"max_seconds": self.max_seconds, "elapsed_seconds": round(self.now() - self.started, 3),
                "max_queries": self.max_queries, "queries_started": self.queries_started,
                "max_pages": self.max_pages, "pages_fetched": self.pages_fetched,
                "max_polls": self.max_polls, "polls": self.polls, "page_size": self.page_size,
                "validation_retries_without_optional_fields": self.validation_retries,
                "max_calls": self.max_calls, "calls_made": self.calls_made,
                "reused_reads": self.reused_reads, "reused_records": self.reused_records,
                "reused_partitions": self.reused_partitions,
                "max_records": self.max_records, "records_seen": self.records_seen,
                "max_partitions": self.max_partitions, "partitions_used": self.partitions_used,
                "phase": self.phase, "pending_reservations": dict(self.reservations), "phase_log": list(self.phase_log)}


TOOLS = {"poll_same_search": ["qradar_get_search_status", "qradar_get_search_results"],
         "fetch_next_page": ["qradar_get_search_results"],
         "new_partitioned_query": ["qradar_read_aql_resource", "qradar_run_aql"],
         "start_planned_query": ["qradar_run_aql"],
         "verify_creation_before_retry": []}


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
    elif action == "verify_creation_before_retry":
        plan["note"] = ("Creation did not complete in time: QRadar may or may not have created this job and its "
                        "search ID is unknown. The bridge did not recreate it. Check the Ariel searches for this "
                        "AQL before running it again, to avoid a duplicate job.")
    return plan


async def collect_query(qradar: Any, query: str, database: str, scope: str,
                        budget: Budget | None = None, fallback_query: str | None = None,
                        plan: Any = None, resume: dict | None = None, progress: Progress | None = None) -> dict:
    """Validate, create once, poll and page; classify the outcome and keep a resume cursor.

    With ``resume`` (a saved finding that has a search ID), the same job is continued from its
    saved cursor: no validation, no creation, rows already collected are kept. ``progress``
    receives a resumable snapshot before creation, when the search ID arrives and after
    every page, so a cancelled run keeps the job ID, cursor and rows."""
    budget = budget or Budget()
    if resume is not None:
        return await _resume(qradar, resume, budget, progress)
    finding: dict = {"aql": query, "database": database, "scope": scope, "query_limit": None,
                     "state": "not started", "outcome": "not_started", "rows": [], "warnings": [],
                     "truncated_fields": [], "truncated_rows": {}, "result_set_complete": False,
                     "pages": 0, "polls": 0, "record_count": None}
    if plan is not None:
        finding["fields"] = plan.describe()
    try:
        policy = check_query(query)
    except AQLPolicyError as exc:
        return _failed(finding, exc, "policy", 0)
    finding["query_limit"] = policy["query_limit"]
    finding["record_count_semantics"] = ("groups/rows returned by the aggregation; not the value of COUNT(*)"
                                         if policy["aggregated"] else "rows in the Ariel result set")
    reason = budget.blocked("query")
    if reason:
        return _not_started(finding, reason)
    stage, start = "validation", 0
    try:
        try:
            await budget.run(lambda: validate_query(qradar, query), "validation")
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
            await budget.run(lambda: validate_query(qradar, fallback_query), "validation")
        # Validation may consume the budget: check again so no job is created after the deadline.
        reason = budget.blocked("query")
        if reason:
            return _not_started(finding, f"{reason} after validation")
        stage = "creation"
        aql = finding["aql"]
        budget.queries_started += 1
        _notify(progress, finding, "creating")
        created = await budget.run(lambda: create_search(qradar, aql), "creation")
        sid = created["search_id"]
        finding.update(search_id=sid, state=str(created.get("status") or "WAIT").upper())
        _notify(progress, finding, "created", 0)
        return await _drive(qradar, finding, budget, database, 0, progress)
    except CheckpointFailed:
        raise
    except Exception as exc:
        return _failed(finding, exc, stage, start)


async def _drive(qradar: Any, finding: dict, budget: Budget, database: str, start: int,
                 progress: Progress | None = None) -> dict:
    """Poll the known job and page from ``start``; never creates or recreates a search."""
    sid = finding["search_id"]
    stage = "polling"
    try:
        while finding["state"] != "COMPLETED":
            if finding["state"] in {"ERROR", "CANCELED"}:
                finding["outcome"] = "error"
                finding["error"] = {"category": "job_failed", "outcome": "error", "retryable": False, "stage": stage,
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
            status = await budget.run(lambda: search_status(qradar, sid, budget.wait()), "polling")
            budget.polls += 1
            finding["polls"] += 1
            finding.update(state=status["status"], record_count=status.get("record_count"))
        stage = "results"
        while True:
            reason = budget.blocked("page")
            if reason:
                finding["warnings"].append(f"Pages remain: {reason}; continue the same search ID")
                finding["continuation"] = continuation(finding, "fetch_next_page", reason, start)
                break
            page = await budget.run(lambda: search_results(qradar, sid, start, budget.page_size), "results")
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
            _notify(progress, finding, "page", start)
    except CheckpointFailed:
        raise
    except Exception as exc:
        return _failed(finding, exc, stage, start)
    return _finish(finding)


FINAL = ("complete_in_window", "empty")


async def _resume(qradar: Any, saved: dict, budget: Budget, progress: Progress | None = None) -> dict:
    """Continue a saved finding. Complete results are reused; an uncertain creation is never
    recreated; a known job is polled/paged from its saved cursor and rows are appended."""
    finding = {k: (list(v) if isinstance(v, list) else dict(v) if isinstance(v, dict) else v)
               for k, v in saved.items()}
    finding.setdefault("rows", [])
    finding.setdefault("truncated_fields", [])
    finding.setdefault("truncated_rows", {})
    previous = saved.get("outcome")
    if previous in FINAL:
        finding["resume"] = {"action": "reused", "reason": "result set already complete; no upstream call"}
        return finding
    if not saved.get("search_id"):
        finding["resume"] = {"action": "requires_resolution" if previous == "creation_uncertain" else "not_resumable",
                             "reason": ("creation was uncertain and the search ID is unknown: the bridge does not "
                                        "recreate the job; confirm in QRadar whether it exists first"
                                        if previous == "creation_uncertain" else
                                        "no job exists for this query; start it as a planned query")}
        return finding
    cursor = saved.get("next_start")
    if not isinstance(cursor, int) or cursor < 0:
        cursor = len(finding["rows"])
    finding.update(outcome="not_started", warnings=[], result_set_complete=False)
    finding.pop("continuation", None)
    finding.pop("error", None)
    finding.pop("checkpoint", None)
    finding["resume"] = {"action": "continued_same_search", "search_id": saved["search_id"], "cursor": cursor,
                         "previous_outcome": previous, "rows_kept": len(finding["rows"])}
    if str(finding.get("state", "")).upper() != "COMPLETED":
        finding["state"] = str(finding.get("state") or "WAIT").upper()
    return await _drive(qradar, finding, budget, finding["database"], cursor, progress)


def _not_started(finding: dict, reason: str) -> dict:
    """No job exists for this query; the plan is to start it, never to resume something."""
    finding["warnings"].append(f"Query not started: {reason}")
    finding["continuation"] = continuation(finding, "start_planned_query", reason)
    return _finish(finding)


def _uncertain(finding: dict, error: dict) -> dict:
    finding.update(outcome="creation_uncertain", state="creation_uncertain", error=error)
    finding["warnings"].append("Job creation did not complete: QRadar may have created it, search ID unknown; "
                               "not recreated automatically")
    finding["continuation"] = continuation(finding, "verify_creation_before_retry", error["category"])
    return _finish(finding)


def _failed(finding: dict, exc: BaseException, stage: str, cursor: int) -> dict:
    """Classify by job existence first, then stage: a known job is always resumed, never restarted."""
    if isinstance(exc, BudgetExhausted):
        if not finding.get("search_id"):
            if stage == "creation" and exc.started:
                return _uncertain(finding, {
                    "category": "creation_timeout", "outcome": "creation_uncertain", "retryable": False,
                    "stage": stage, "message": str(exc),
                    "next_action": "Check the Ariel searches for this AQL before running it again"})
            # Validation, or creation that never began: no job can exist.
            return _not_started(finding, str(exc))
        # The job exists whether the deadline hit before or during this call: keep its ID and cursor.
        error = {"category": "time_budget", "outcome": "unavailable", "retryable": True, "stage": stage,
                 "message": str(exc), "next_action": "Resume the same search ID within a new budget"}
        finding["error"] = error
    else:
        error = {**classify_failure(exc), "stage": stage}
        finding["error"] = error
        if stage == "creation" and not (error["category"] in NOT_CREATED or (
                error["category"] == "connection" and "cannot connect" in error["message"])):
            return _uncertain(finding, error)
        finding["outcome"] = error["outcome"]
        # "rejected" = refused before any job existed; "unavailable" = could not be read.
        finding["state"] = ("rejected" if error["category"] in ("local_policy", "upstream_validation")
                            else "unavailable")
    finding["warnings"].append(f"{stage} {error['category']}: {error['message']}. {error['next_action']}")
    if stage == "polling":
        finding["outcome"] = "pending" if error["category"] == "time_budget" else finding["outcome"]
        finding["continuation"] = continuation(finding, "poll_same_search", f"{stage}: {error['category']}", 0)
    elif stage == "results":
        # Rows from earlier pages stay; coverage is partial from the page that failed onward.
        finding["outcome"] = "partial"
        finding["warnings"].append(f"Rows before cursor {cursor} kept; the page at {cursor} was not read")
        finding["continuation"] = continuation(finding, "fetch_next_page", f"{stage}: {error['category']}", cursor)
    elif finding.get("search_id"):
        # Defensive: any other failure with a known job resumes it rather than planning a new search.
        finding["continuation"] = continuation(finding, "poll_same_search", f"{stage}: {error['category']}", cursor)
    elif error["retryable"]:
        finding["continuation"] = continuation(finding, "start_planned_query", f"{stage}: {error['category']}")
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
