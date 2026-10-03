"""Decode IBM offense listings, including error text whose FastMCP adapter lost isError."""
from __future__ import annotations

import json
import re
from typing import Any

from .aql_errors import ResponseFormatError
from .diagnostics import MCPToolFailure

ERROR_PREFIX = re.compile(r'^(?:Error\s+executing\s+list_offenses\s*:|Tool execution failed\s*:|'
                          r'Invalid (?:filter|sort) expression\s*:)', re.I)
HTTP_CODE = re.compile(r'\b(?:HTTP(?:\s+status(?:\s+code)?)?\s*[:=]?\s*|status(?:\s+code)?\s*[:=]\s*)([45]\d\d)\b|'
                       r'\b([45]\d\d)\s+(?:Bad Request|Unauthorized|Forbidden|Not Found|Too Many Requests|Internal Server Error)\b', re.I)


def upstream_error(text: str, source: str) -> MCPToolFailure:
    """Only coarse facts from a recognized error envelope; never echo message bodies/URLs/tokens."""
    code = HTTP_CODE.search(text[:20000])
    reason = f'upstream returned HTTP {next(g for g in code.groups() if g)}' if code else 'upstream returned a tool error'
    if ('filtering is unsupported on the field: description' in text.lower() or
            text.lower().startswith(('invalid filter expression:', 'invalid sort expression:'))):
        reason += '; upstream rejected request parameters'
    return MCPToolFailure(source, 'list_offenses', reason + '; inspect local QRadar MCP logs')


def decode_listing(result: Any, source: str = 'QRadar') -> dict:
    """Accept bounded documented JSON envelopes; reject tables and malformed text as response errors."""
    if getattr(result, 'isError', False):
        raw = ' '.join(getattr(b, 'text', '') for b in (result.content or []))
        raise upstream_error(raw, source)
    data = getattr(result, 'structuredContent', None)
    if data is None:
        blocks = [getattr(b, 'text', None) for b in (getattr(result, 'content', None) or [])]
        blocks = [b for b in blocks if isinstance(b, str) and b.strip()]
        if len(blocks) != 1:
            raise ResponseFormatError('Offense listing returned no single JSON document')
        data = blocks[0]
    for _ in range(5):
        if isinstance(data, dict):
            if data.get('isError') is True:
                contents = data.get('content', [])
                raw = ' '.join(b.get('text', '') for b in contents if isinstance(b, dict))
                raise upstream_error(raw, source)
            if isinstance(data.get('offenses'), list):
                return data
            if 'result' in data:
                data = data['result']
                continue
            if isinstance(data.get('content'), list):
                blocks = data['content']
                if len(blocks) == 1 and isinstance(blocks[0], dict) and isinstance(blocks[0].get('text'), str):
                    data = blocks[0]['text']
                    continue
            raise ResponseFormatError('Offense listing JSON has no offenses array')
        if isinstance(data, list):
            # Older upstreams can return the REST array without list wrapper/total_count.
            return {'offenses': data, 'count': len(data)}
        if isinstance(data, str):
            if ERROR_PREFIX.match(data.strip()):
                raise upstream_error(data.strip(), source)
            try:
                data = json.loads(data)
            except ValueError:
                raise ResponseFormatError('Offense listing returned non-JSON text; inspect upstream logs') from None
            continue
        raise ResponseFormatError('Offense listing returned an unsupported value type')
    raise ResponseFormatError('Offense listing has too many response envelopes')
