"""Synthetic stdio MCP Workbench server; no network or product credentials."""
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

mcp = FastMCP("Synthetic Trend")


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
async def workbench_alerts_list(filter: str = "", orderBy: str = "",
                                startDateTime: str = "", endDateTime: str = "") -> dict:
    assert filter == "(status eq 'Open' or status eq 'In Progress')"
    assert orderBy == "createdDateTime desc"
    assert startDateTime.endswith("Z") and endDateTime.endswith("Z")
    return {"items": [{"id": "WB-DEMO-0001", "status": "Open", "severity": "high",
                       "name": "Synthetic alert"}], "totalCount": 1}


if __name__ == "__main__":
    mcp.run(transport="stdio")
