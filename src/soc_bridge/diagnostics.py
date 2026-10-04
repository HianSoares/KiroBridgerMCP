"""Bounded MCP failure diagnostics; never include raw exception messages or telemetry."""

from __future__ import annotations


class InvestigationUnavailable(RuntimeError):
    """A collection stage failed; no completed investigation report exists."""


class MCPToolFailure(RuntimeError):
    def __init__(self, source: str, tool: str, reason: str):
        self.source = source
        self.tool = tool
        self.reason = reason
        super().__init__(f"{source} {tool}: {reason}")


def _leaves(error: BaseException) -> list[BaseException]:
    if isinstance(error, BaseExceptionGroup):
        return [leaf for child in error.exceptions for leaf in _leaves(child)]
    return [error]


def failure_reason(error: BaseException) -> str:
    """Use types and status codes only; URL, response text and exception args may be sensitive."""
    failures = _leaves(error)
    for item in failures:
        if isinstance(item, MCPToolFailure):
            return f"{item.source} tool {item.tool}: {item.reason}"
    for item in failures:
        response = getattr(item, "response", None)
        status = getattr(response, "status_code", None)
        if isinstance(status, int) and 100 <= status <= 599:
            if status == 401:
                return "HTTP 401: access token missing, expired or not accepted"
            if status == 403:
                return "HTTP 403: account or API key lacks permission"
            return f"HTTP {status} from upstream MCP"
    for item in failures:
        kind = type(item).__name__
        if kind in {"ConnectError", "ConnectTimeout", "ConnectionRefusedError"}:
            return "cannot connect to local MCP; check Docker/QRadar MCP status"
        if kind in {"ReadTimeout", "TimeoutError"}:
            return "upstream MCP timed out"
        if kind == "FileNotFoundError":
            return "Docker executable not found in Kiro environment"
        if kind in {"EndOfStream", "BrokenResourceError", "ClosedResourceError"}:
            return "upstream MCP connection closed unexpectedly"
        if kind in {"RuntimeError", "ValueError"}:
            return f"{kind} during MCP operation; inspect local service logs"
    kinds = ", ".join(dict.fromkeys(type(item).__name__ for item in failures))
    return f"{kinds or 'UnknownError'} during MCP operation; inspect local service logs"


def unavailable(stage: str, error: BaseException) -> InvestigationUnavailable:
    return InvestigationUnavailable(
        f"Collection failed at {stage}: {failure_reason(error)}. "
        "No complete investigation report was produced; do not infer absent alerts or offenses. "
        "Check the named local connection/permissions, then rerun investigate_case with the same ID."
    )


def collection_failure(stage: str, error: BaseException) -> dict:
    """Structured phase failure; the source is named only when supplied by the client."""
    from .aql_errors import ResponseFormatError, classify_failure
    leaves = _leaves(error)
    known = next((e for e in leaves if isinstance(e, MCPToolFailure)), None)
    reason = failure_reason(error)
    categorized = known or error
    if known is None and any(hint in reason for hint in ("HTTP ", "connection closed", "cannot connect", "timed out")):
        categorized = MCPToolFailure("not identified", stage, reason)
    elif known is None and isinstance(error, ValueError):
        # This is a failure inside an active phase, not evidence of pre-call validation.
        categorized = ResponseFormatError()
    classified = classify_failure(categorized)
    return {"stage": stage, "source": known.source if known else "not identified",
            "category": classified["category"], "retryable": classified["retryable"],
            "requires_resolution": classified["requires_resolution"],
            "reason": reason,
            "next_action": ("Resume only the failed/pending read with its saved search ID/cursor; "
                            "do not repeat completed collection. Check permissions/parameters or local MCP logs "
                            "for non-retryable failures.")}
