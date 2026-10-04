"""Central capability discovery: paginated tools/list, availability states and call outcomes.

A tool advertised by an upstream is not a tool the bridge may call (allowlist), and neither
is proof of permission, license or data access: only a successful call shows that. A
partial discovery (repeated cursor, invalid page, page cap, deadline) never allows the
claim that a tool is absent; its availability is "unknown".
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Callable

MAX_PAGES = 20
STATES = {
    "available_allowed": "advertised by the upstream and allowed by the bridge allowlist",
    "advertised_blocked": "advertised by the upstream but not allowed by the bridge (mutation or not integrated)",
    "absent": "not advertised after a complete tools/list discovery",
    "unknown": "tools/list discovery was incomplete; availability cannot be stated",
}
CALL_OUTCOMES = {
    "tested_ok": "at least one call returned a usable response",
    "reused_read": "a successful read from this alert snapshot was reused; no new upstream call",
    "rejected": "the upstream rejected the request (arguments, query or validation)",
    "permission": "the account/key lacks permission",
    "license_or_integration": "license, entitlement or integration not available",
    "unavailable": "connection, timeout, rate limit or upstream error",
    "format_incompatible": "the response shape was not usable",
    "not_found": "the identifier was not found upstream",
}


class Discovery:
    """Result of one paginated tools/list walk; names never include a partial-page guess."""

    def __init__(self, source: str):
        self.source = source
        self.names: set[str] = set()
        self.pages = 0
        self.complete = False
        self.stop_reason = "not started"
        self.server: dict[str, Any] = {}

    def state(self, tool: str, allowed: set[str]) -> str:
        if tool in self.names:
            return "available_allowed" if tool in allowed else "advertised_blocked"
        return "absent" if self.complete else "unknown"

    def describe(self, allowed: set[str]) -> dict:
        blocked = sorted(self.names - allowed)
        allowed_present = sorted(self.names & allowed)
        missing = sorted(allowed - self.names)
        return {"source": self.source, "complete": self.complete, "pages": self.pages,
                "stop_reason": self.stop_reason, "server": self.server,
                "advertised": len(self.names), "available_allowed": allowed_present,
                "advertised_blocked_count": len(blocked),
                ("absent" if self.complete else "availability_unknown"): missing,
                "meaning": STATES}


class ToolSet(set):
    """Set of advertised names that also carries how they were discovered."""
    discovery: Discovery


async def discover(session: Any, source: str, max_pages: int = MAX_PAGES, deadline_seconds: float = 30.0,
                   clock: Callable[[], float] = time.monotonic) -> Discovery:
    """Walk every tools/list page; stop safely on a repeated cursor, invalid page, cap or deadline."""
    found = Discovery(source)
    started = clock()
    cursor: str | None = None
    seen: set[str] = set()
    while True:
        remaining = deadline_seconds - (clock() - started)
        if remaining <= 0:
            found.stop_reason = "deadline reached before the last page"
            return found
        if found.pages >= max_pages:
            found.stop_reason = f"page cap of {max_pages} reached with a cursor still pending"
            return found
        try:
            result = await asyncio.wait_for(session.list_tools(cursor) if cursor else session.list_tools(),
                                            timeout=remaining)
        except asyncio.TimeoutError:
            found.stop_reason = "deadline reached while reading a page"
            return found
        except Exception as exc:  # category only; upstream text may contain secrets
            found.stop_reason = f"tools/list page failed ({type(exc).__name__})"
            return found
        tools = getattr(result, "tools", None)
        if not isinstance(tools, list) or not all(isinstance(getattr(t, "name", None), str) for t in tools):
            found.stop_reason = "invalid tools/list page"
            return found
        found.pages += 1
        found.names.update(t.name for t in tools)
        cursor = getattr(result, "nextCursor", None)
        if not cursor:
            found.complete = True
            found.stop_reason = "last page reached"
            return found
        if not isinstance(cursor, str) or cursor in seen:
            found.stop_reason = "repeated or invalid cursor"
            return found
        seen.add(cursor)


async def tool_names(session: Any, source: str, initialize_result: Any = None) -> ToolSet:
    discovery = await discover(session, source)
    info = getattr(initialize_result, "serverInfo", None)
    if info is not None:
        discovery.server = {"name": getattr(info, "name", None), "version": getattr(info, "version", None)}
    names = ToolSet(discovery.names)
    names.discovery = discovery
    return names


def absence_state(client: Any, tool: str) -> str | None:
    """None when the tool may be called; otherwise tool_absent or availability_unknown."""
    available = getattr(client, "available", None)
    if available is None or tool in available:
        return None
    discovery = getattr(available, "discovery", None)
    return "availability_unknown" if discovery is not None and not discovery.complete else "tool_absent"


def outcome_for(category: str) -> str:
    return {"request_rejected": "rejected", "upstream_validation": "rejected", "invalid_argument": "rejected",
            "local_policy": "rejected", "permission": "permission", "license_or_integration": "license_or_integration",
            "response_format": "format_incompatible", "not_found": "not_found"}.get(category, "unavailable")


class Ledger:
    """Per-tool call outcomes observed in this process; categories only, never upstream text."""

    def __init__(self) -> None:
        self.calls: dict[str, dict[str, int]] = {}

    def record(self, tool: str, outcome: str) -> None:
        bucket = self.calls.setdefault(tool, {})
        bucket[outcome] = bucket.get(outcome, 0) + 1

    def describe(self) -> dict:
        return {"calls": {tool: dict(sorted(v.items())) for tool, v in sorted(self.calls.items())},
                "meaning": CALL_OUTCOMES,
                "note": "A successful call shows access for that call only; it is not a permission audit."}


# Bridge tools that write only the local case store (never an upstream object).
LOCAL_WRITE_TOOLS = frozenset({"investigate_offense_case", "reassess_case"})

# Outcomes observed by this bridge process since it started (shown by diagnostics).
GLOBAL_LEDGER = Ledger()


async def public_tools() -> dict[str, dict]:
    """Single source for the bridge's own MCP tools (names, read-only hint, local writes)."""
    from .kiro_server import mcp
    tools = await mcp.list_tools()
    return {t.name: {"read_only": bool(t.annotations and t.annotations.readOnlyHint),
                     "destructive": bool(t.annotations and t.annotations.destructiveHint)} for t in tools}
