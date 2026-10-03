"""Loopback-only synthetic IBM response shapes for the transport integration test."""

import json
import sys
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from mcp.server.fastmcp import FastMCP


mcp = FastMCP("Synthetic QRadar", host="127.0.0.1", port=int(sys.argv[1]), stateless_http=True)
jobs = {}
epoch = int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp() * 1000)


@mcp.tool()
def get_offense(offense_id: int) -> dict:
    return {"id": offense_id, "description": "Synthetic matching offenses", "status": "OPEN", "offense_source": "192.0.2.10", "event_count": 2,
            "flow_count": 1, "start_time": epoch, "last_updated_time": epoch + 60000,
            "rules": [{"id": 12, "type": "CRE_RULE"}],
            "magnitude": 10 if offense_id == 12347 else 5, "severity": 6,
            "credibility": 4, "relevance": 5}


@mcp.tool()
def list_offenses(filter: str = "", sort: str = "+id", fields: str = "", limit: int = 50,
                  offset: int = 0, format_output: bool = False) -> str:
    # Mimic IBM's JSON text through a FastMCP string wrapper.
    if 'status = "HIDDEN"' in filter:
        return "Tool execution failed: synthetic private-error-body"
    assert not format_output and sort == "+id"
    assert 'description' not in filter
    rows = [dict(get_offense(i), description="Other synthetic offense") for i in (12340, 12341)]
    rows += [get_offense(i) for i in (12345, 12346, 12347)]
    return json.dumps({"offenses": rows[offset:offset + limit], "total_count": len(rows)})


@mcp.tool()
def get_rule(rule_id: int) -> str:
    # IBM returns formatted text, including when FastMCP wraps strings in structuredContent.result.
    return 'Rule ID: ' + str(rule_id) + '\n\nFull JSON:\n' + json.dumps(
        {"id": rule_id, "name": "Synthetic DHCP rule", "enabled": True})


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
    if "UNIQUECOUNT" in query_expression:
        jobs[sid]["rows"] = [{"total_rows": 1, "distinct_destinations": 1}]
    elif "INOFFENSE" in query_expression and table == "flows":
        jobs[sid]["rows"] = [{"sourceip": "192.0.2.10", "destinationip": "198.51.100.1",
            "sourceport": 67, "destinationport": 68, "protocolid": 17, "firstpackettime": epoch,
            "sourcebytes": 100, "destinationbytes": 0}]
    elif "INOFFENSE" in query_expression:
        jobs[sid]["rows"] = [{"starttime": epoch, "event_name": "Synthetic firewall", "raw_payload": "Drop"},
            {"starttime": epoch + 60000, "event_name": "Synthetic CRE", "raw_payload": "Synthetic DHCP rule"}]
    elif "ORDER BY starttime" in query_expression:
        jobs[sid]["rows"] = [{"starttime": epoch, "event_name": "Success using explicit credentials",
            "raw_payload": "EventID=4648 ProcessName=svchost.exe"}]
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
