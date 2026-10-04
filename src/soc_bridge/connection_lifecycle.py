"""Close each MCP resource without discarding an already returned investigation.

Resources are entered/exited in the calling task (SDK cancel scopes require this).
Only ordinary cleanup errors after collection are recoverable. Cancellation and
errors from the body still propagate; diagnostics never copy exception messages.
"""

import asyncio
from contextlib import AsyncExitStack
from typing import Any

from .diagnostics import MCPToolFailure, failure_reason


class _Resource:
    def __init__(self, scope: "InvestigationConnections", context: Any, source: str, component: str):
        self.scope, self.context = scope, context
        self.source, self.component = source, component

    async def __aenter__(self):
        return await self.context.__aenter__()

    async def __aexit__(self, kind, error, traceback):
        try:
            # Run in this task: wait_for/create_task would break AnyIO cancel scopes.
            async with asyncio.timeout(self.scope.CLEANUP_SECONDS):
                return await self.context.__aexit__(kind, error, traceback)
        except Exception as exc:
            diagnostic = {"source": self.source, "component": self.component,
                          "stage": "shutdown", "reason": failure_reason(exc)}
            self.scope.errors.append(diagnostic)
            # A cleanup failure must not replace an earlier collection error/cancellation.
            if error is not None:
                return False
            if self.scope.completed:
                return False
            raise MCPToolFailure(self.source, self.component + " shutdown", diagnostic["reason"]) from None


class InvestigationConnections(AsyncExitStack):
    CLEANUP_SECONDS = 10

    def __init__(self):
        super().__init__()
        self.completed = False
        self.errors: list[dict] = []

    async def enter(self, context: Any, source: str, component: str):
        return await self.enter_async_context(_Resource(self, context, source, component))

    def collected(self, report: Any) -> Any:
        self.completed = True
        return report

    def deliver(self, report: Any) -> Any:
        if not self.errors:
            return report
        warning = ("Collection returned a report; connection shutdown failed. Collected evidence and query "
                   "coverage are preserved. Do not rerun completed searches because of this cleanup error.")
        if isinstance(report, dict):
            report["connection_lifecycle"] = {"report_preserved": True, "shutdown_errors": self.errors,
                                              "retry_collection": False}
            report.setdefault("warnings", []).append(warning)
            for item in self.errors:
                report["warnings"].append(f"{item['source']} {item['component']} shutdown: {item['reason']}")
        elif isinstance(report, str):
            report += "\n\n## Connection shutdown warning\n\n" + warning + "\n"
            report += "\n".join(f"- {e['source']} {e['component']}: {e['reason']}" for e in self.errors)
        return report
