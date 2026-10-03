"""Typed AQL failures and safe classification; messages never echo upstream text."""

from __future__ import annotations

import re

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
    "license_or_integration": ("unavailable", False, "Check the product license, entitlement or connected integration"),
    "not_found": ("unavailable", False, "Upstream did not find the identifier; this is not proof that no activity exists"),
    "rate_limited": ("unavailable", True, "Upstream rate limit reached; resume later"),
    "request_rejected": ("error", False, "Upstream rejected the request parameters or query syntax"),
    "upstream_error": ("unavailable", True, "Upstream service error; retry once later"),
    "availability_unknown": ("unavailable", False, "tools/list discovery was incomplete; rerun diagnostics before concluding the tool is absent"),
    "unknown": ("unavailable", False, "Inspect local service logs"),
}
# Deterministic failures: repeating the same request cannot succeed until someone resolves the cause.
REQUIRES_RESOLUTION = {"local_policy", "upstream_validation", "permission", "tool_unavailable", "response_format",
                       "invalid_argument", "license_or_integration", "request_rejected", "availability_unknown"}


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
        status = re.search(r"HTTP (\d{3})", reason)
        code = int(status[1]) if status else None
        if "license/integration" in reason:
            category = "license_or_integration"
        elif code in (401, 403):
            category = "permission"
        elif code == 404:
            category = "not_found"
        elif code == 429:
            category = "rate_limited"
        elif code in (400, 422) or "upstream rejected request parameters" in reason:
            category = "request_rejected"
        elif code is not None and code >= 500:
            category = "upstream_error"
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
    elif isinstance(exc, RuntimeError) and str(exc).startswith("Optional MCP tool availability unknown"):
        category, message = "availability_unknown", str(exc)
    elif isinstance(exc, TimeoutError):
        category = "timeout"
    elif isinstance(exc, ValueError):
        category = "invalid_argument"
    else:
        category = "unknown"
    outcome, retryable, action = CATEGORIES[category]
    return {"category": category, "outcome": outcome, "retryable": retryable,
            "requires_resolution": category in REQUIRES_RESOLUTION,
            "message": message or f"{type(exc).__name__} during QRadar collection",
            "next_action": action}
