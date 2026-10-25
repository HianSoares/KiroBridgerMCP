"""Synthetic Trend Search server returning raw JSON text with large integer identifiers; no product data.

Like the official handler (mark3labs mcp-go, NewToolResultText), the API body is returned as one text
block without structuredContent, so identifiers arrive as JSON integers in text. The values are beyond
2**53 and collide pairwise if converted to float; logonUser is a list, as in Endpoint Activity Data.
"""
import asyncio
import json

from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

POSITIVE = (2 ** 60 + 1, 2 ** 60 + 3)            # both become 2**60 as float
NEGATIVE = (-(2 ** 62) - 5, -(2 ** 62) - 7)      # both become -(2**62) as float
HOST = "ws-bigint.example.test"
TOOL = "search_endpoint_activities_list"


def rows():
    out = []
    for n, value in enumerate(POSITIVE + NEGATIVE):
        out.append({"uuid": f"synthetic-bigint-{n}", "eventTime": 1790000000000 + n, "endpointHostName": HOST,
                    "logonUser": [f"EXAMPLE\\user{n}"], "processHashId": value, "processPid": 5000 + n,
                    "processFilePath": "C:\\Tools\\tool.exe", "processCmd": "tool.exe --sync",
                    "objectProcessHashId": -value, "objectFilePath": f"C:\\Data\\file{n}.txt"})
    return out


def main() -> None:
    server = Server("synthetic-trend-search-bigint")

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        return [types.Tool(name=TOOL, description="Synthetic endpoint activity",
                           inputSchema={"type": "object", "properties": {
                               "query": {"type": "string"}, "startDateTime": {"type": "string"},
                               "endDateTime": {"type": "string"}, "top": {"type": "string"},
                               "mode": {"type": "string"}, "select": {"type": "string"}}, "required": ["query"]},
                           annotations=types.ToolAnnotations(readOnlyHint=True))]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
        if arguments.get("mode") == "countOnly":
            body = {"totalCount": len(rows()), "progressRate": 100}
        else:
            body = {"items": rows()}
        return [types.TextContent(type="text", text=json.dumps(body))]

    async def serve() -> None:
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())

    asyncio.run(serve())


if __name__ == "__main__":
    main()
