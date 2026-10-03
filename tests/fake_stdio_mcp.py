"""Synthetic stdio MCP server with deliberate faults for the WSL preflight probe tests.

Usage: fake_stdio_mcp.py <mode>. Every value here is fabricated.
"""

import json
import sys
import time

SECRET = "synthetic-secret-value-7f3a"
MODE = sys.argv[1]
TOOL = {"name": "investigate_demo", "inputSchema": {"type": "object", "properties": {}},
        "annotations": {"readOnlyHint": True}}


def send(message: dict) -> None:
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()


def initialize_result() -> dict:
    if MODE == "bad_initialize":
        return {"protocolVersion": "2025-06-18", "capabilities": {}}  # no serverInfo, no tools capability
    return {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
            "serverInfo": {"name": "fake", "version": "0"}}


def tools_response(request_id: int) -> dict:
    if MODE == "tools_error":
        return {"jsonrpc": "2.0", "id": request_id,
                "error": {"code": -32603, "message": f"upstream failure token={SECRET}"}}
    if MODE == "tools_not_list":
        return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": {"name": "x"}}}
    if MODE == "tool_without_schema":
        return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": [{"name": "x"}]}}
    if MODE == "not_readonly":
        return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": [{**TOOL, "annotations": {}}]}}
    if MODE == "other_surface":
        return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": [{**TOOL, "name": f"tool_{SECRET}"}]}}
    return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": [TOOL]}}


if MODE == "secret_stdout":
    sys.stdout.write(f"QRADAR_MCP_TOKEN={SECRET}\n")
    sys.stdout.flush()
if MODE == "secret_stderr":
    sys.stderr.write(f"SOC Bridge via wsl.exe (fake): QRADAR_MCP_TOKEN={SECRET}\n")
    sys.stderr.flush()
if MODE == "huge_line":
    sys.stdout.write("x" * (2 << 20))
    sys.stdout.flush()
    time.sleep(30)

for line in sys.stdin:
    request = json.loads(line)
    if request.get("method") == "initialize":
        send({"jsonrpc": "2.0", "id": request["id"], "result": initialize_result()})
    elif request.get("method") == "tools/list":
        if MODE == "notifications":
            # Never answer; keep the stream busy forever with valid notifications.
            while True:
                send({"jsonrpc": "2.0", "method": "notifications/message",
                      "params": {"level": "info", "data": "busy"}})
                time.sleep(0.01)
        send(tools_response(request["id"]))
