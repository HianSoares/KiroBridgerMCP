"""Typed AQL failures and safe classification; messages never echo upstream text."""

from __future__ import annotations

from .diagnostics import MCPToolFailure


class AQLPolicyError(ValueError):
    """Rejected locally by the bridge policy before QRadar was asked; not transient."""


class AQLValidationError(ValueError):
    """QRadar did not confirm the AQL as valid; no search job was created."""


class ResponseFormatError(ValueError):
    """An upstream response had an unexpected shape; data was not interpreted."""


# Category -> (outcome, retryable, next step). Messages are fixed bridge text.
CATEGORIES = {
    "local_policy": ("error", False, "Fix the query shape (single SELECT, LIMIT, LAST or START/STOP); QRadar was not contacted"),
    "upstream_validation": ("error", False, "Check field/function names against the live AQL resources; no job was created"),
    "permission": ("unavailable", False, "Fix the QRadar account/token permission; retrying will not help"),
    "connection": ("unavailable", True, "Check the local QRadar MCP service, then retry once"),
    "timeout": ("unavailable", True, "Upstream timed out; retry once or narrow the window"),
    "tool_unavailable": ("unavailable", False, "The upstream MCP does not expose this read-only tool"),
    "upstream_tool_error": ("unavailable", False, "Inspect local QRadar MCP logs; the tool reported an error"),
    "response_format": ("unavailable", False, "Upstream response shape was unexpected; inspect versions/logs"),
    "invalid_argument": ("error", False, "A bridge argument was rejected before any upstream call"),
    "unknown": ("unavailable", False, "Inspect local service logs"),
}


def classify_failure(exc: BaseException) -> dict:
    """Map an exception to a category without copying response bodies, URLs or tokens."""
    message = None
    if isinstance(exc, AQLPolicyError):
        category, message = "local_policy", str(exc)
    elif isinstance(exc, AQLValidationError):
        category, message = "upstream_validation", str(exc)
    elif isinstance(exc, ResponseFormatError):
        category, message = "response_format", str(exc)
    elif isinstance(exc, MCPToolFailure):
        reason = exc.reason
        if "HTTP 401" in reason or "HTTP 403" in reason:
            category = "permission"
        elif "timed out" in reason:
            category = "timeout"
        elif "cannot connect" in reason or "connection closed" in reason:
            category = "connection"
        else:
            category = "upstream_tool_error"
        # MCPToolFailure reasons are already built from status codes/types only.
        message = f"{exc.source} {exc.tool}: {reason}"
    elif isinstance(exc, RuntimeError) and str(exc).startswith("Optional MCP tool unavailable"):
        category, message = "tool_unavailable", str(exc)
    elif isinstance(exc, TimeoutError):
        category = "timeout"
    elif isinstance(exc, ValueError):
        category = "invalid_argument"
    else:
        category = "unknown"
    outcome, retryable, action = CATEGORIES[category]
    return {"category": category, "outcome": outcome, "retryable": retryable,
            "message": message or f"{type(exc).__name__} during QRadar collection",
            "next_action": action}
