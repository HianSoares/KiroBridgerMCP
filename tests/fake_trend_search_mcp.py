"""Synthetic Trend Search server; no network, credentials, or product data."""
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from typing import Annotated
from pydantic import Field

mcp = FastMCP('Synthetic Trend Search')

@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
async def search_endpoint_activities_list(query: Annotated[str, Field(description='endpointHostName, processPid, objectPid, processCmd')], startDateTime: str = '', endDateTime: str = '',
                                          top: str = '500', mode: str = 'default', select: str = '') -> dict:
    """Query supports endpointHostName, processPid, objectPid and processCmd in this synthetic server."""
    assert query and startDateTime.endswith('Z') and endDateTime.endswith('Z')
    assert top in {'50', '100', '500', '1000', '5000'}
    if mode == 'countOnly':
        return {'totalCount': 0, 'progressRate': 100}
    return {'items': [{'uuid': 'synthetic-event', 'endpointHostName': 'host.example.test',
                       'processPid': 4242, 'objectPid': 4567, 'processCmd': 'diagnostic.exe --target 4567',
                       'processHashId': 'synthetic-instance', 'nativeUnknownField': {'value': 'preserved'}}]}

if __name__ == '__main__':
    mcp.run(transport='stdio')
