"""soc-bridge-change: separate MCP server for upstream tools that change state or send data out.

Disabled by default in three independent ways: Kiro's entry is written with "disabled": true and no
autoApprove; execution needs SOC_BRIDGE_ENABLE_CHANGES=1 plus a human-maintained policy file listing
each allowed platform/tool; and every request needs an out-of-band approval typed by a person in a
terminal (soc-bridge change approve <id>). soc-bridge-readonly never imports this module.
"""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

mcp = FastMCP("SOC Bridge Change Control")


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
async def change_operations(platform: str = "", query: str = "", effect: str = "", offset: int = 0,
                            limit: int = 40) -> dict:
    """List upstream tools that change state or send data out (access="change"), with the current
    change policy of this server (enabled or not, allowed tools). Nothing is executed."""
    from .change_control import policy
    from .upstream_access import Refused, search
    try:
        found = search(platform, query, effect, "", "change", offset, limit)
    except Refused as refused:
        return refused.describe()
    return {**found, "policy": policy()}


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False,
                                      openWorldHint=False))
async def change_request(platform: str, tool: str, arguments: dict[str, Any] | None, justification: str) -> dict:
    """Propose one change with validated arguments and a justification. Writes a local request only;
    it does not run anything. A person must approve it in a terminal with
    `soc-bridge change approve <id>`; nothing in the conversation approves it."""
    from .change_control import propose
    from .upstream_access import Refused
    try:
        return propose(platform, tool, arguments, justification)
    except Refused as refused:
        return refused.describe()


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
async def change_request_status(request_id: str) -> dict:
    """Show a change request: arguments, justification, approval state, history and result summary."""
    from .change_control import load, summary
    from .upstream_access import Refused
    try:
        return summary(load(request_id))
    except Refused as refused:
        return refused.describe()


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False,
                                      openWorldHint=True))
async def change_execute(request_id: str, timeout_seconds: int = 120) -> dict:
    """Execute an approved change request once. Refused unless changes are enabled for this server,
    the policy file lists the tool, a person approved this exact request in a terminal and the
    approval is valid and unexpired. A timeout leaves the outcome uncertain; it is never retried."""
    from .change_control import execute
    from .upstream_access import Refused
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or not 5 <= timeout_seconds <= 300:
        return Refused("invalid_arguments", "timeout_seconds must be 5..300").describe()
    try:
        return await execute(request_id, timeout_seconds)
    except Refused as refused:
        return {**refused.describe(), "request_id": request_id}


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
