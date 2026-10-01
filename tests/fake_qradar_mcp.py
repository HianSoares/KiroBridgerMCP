"""Loopback-only synthetic IBM response shapes for the transport integration test."""

import json
import sys
from uuid import uuid4

from mcp.server.fastmcp import FastMCP


mcp = FastMCP("Synthetic QRadar", host="127.0.0.1", port=int(sys.argv[1]), stateless_http=True)
jobs = {}


@mcp.resource("qradar://aql/events/fields")
def event_fields() -> str:
    return json.dumps({"fields": [{"name": "payload"}, {"name": "devicetime"}]})


@mcp.resource("qradar://aql/flows/fields")
def flow_fields() -> str:
    return json.dumps({"fields": [{"name": "sourceip"}]})


@mcp.resource("qradar://aql/functions")
def functions() -> str:
    return json.dumps({"functions": [{"name": "UTF8"}]})


@mcp.resource("qradar://aql/guide")
def guide() -> str:
    return "# Synthetic AQL Guide"


@mcp.tool()
def validate_aql(query_expression: str) -> str:
    return "✓ AQL query is valid\n\nQuery: " + query_expression


@mcp.tool()
def create_ariel_search(query_expression: str) -> dict:
    sid = str(uuid4())
    table = "flows" if "FROM flows" in query_expression else "events"
    jobs[sid] = {"database": table, "rows": [{"RawPayload": "synthetic event", "devicetime": 1790255701000},
                                               {"RawPayload": "second synthetic event", "devicetime": 1790255702000}]}
    return {"search_id": sid, "status": "WAIT"}


@mcp.tool()
def get_ariel_search_status(search_id: str, wait_seconds: int = 0) -> dict:
    return {"status": "COMPLETED", "record_count": len(jobs[search_id]["rows"])}


@mcp.tool()
def get_ariel_search_results(search_id: str, start: int = 0, limit: int = 100) -> dict:
    job = jobs[search_id]
    return {job["database"]: job["rows"][start:start + limit]}


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
