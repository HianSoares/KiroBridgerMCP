"""Regression for IBM FastMCP errors returned as text with isError=False."""
import asyncio
import json
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock
from mcp.types import CallToolResult, TextContent
from soc_bridge.offense_response import decode_listing
from soc_bridge.offense_batch import find_offenses, investigate_offenses
from soc_bridge.transports import RestrictedMCP, QRADAR_TOOLS
from soc_bridge.aql_errors import ResponseFormatError
from soc_bridge.ariel_collection import Budget
from soc_bridge.diagnostics import MCPToolFailure


def content(text):
    return CallToolResult(content=[TextContent(type='text', text=text)], isError=False)


def client(result):
    session = SimpleNamespace(call_tool=AsyncMock(return_value=result))
    return RestrictedMCP(session, QRADAR_TOOLS, {'list_offenses', 'get_offense'}, {'list_offenses'}), session


class ResponseTests(unittest.TestCase):
    def test_documented_json_text_and_structured_envelopes(self):
        data = {'offenses': [], 'count': 0}
        variants = [content(json.dumps(data)), CallToolResult(content=[], structuredContent=data),
                    CallToolResult(content=[], structuredContent={'result': json.dumps(data)}),
                    CallToolResult(content=[], structuredContent={'result': data}),
                    content(json.dumps({'content': [{'type': 'text', 'text': json.dumps(data)}]})),
                    content(json.dumps(json.dumps(data)))]
        for result in variants:
            with self.subTest(result=result):
                self.assertEqual(decode_listing(result), data)

    def test_rest_array_supported_without_total(self):
        self.assertEqual(decode_listing(content('[]')), {'offenses': [], 'count': 0})

    def test_error_flag_lost_text_is_upstream_failure_not_invalid_argument(self):
        for text in ('Tool execution failed: private-example-secret',
                     'Error executing list_offenses: private-example-secret'):
            with self.subTest(text=text), self.assertRaises(MCPToolFailure) as caught:
                decode_listing(content(text))
            self.assertNotIn('private-example-secret', str(caught.exception))

    def test_status_code_kept_body_and_url_not_exposed(self):
        text = 'Error executing list_offenses: 403 Forbidden for https://example.invalid/?token=private-example-secret'
        with self.assertRaises(MCPToolFailure) as caught:
            decode_listing(content(text))
        self.assertIn('HTTP 403', caught.exception.reason)
        self.assertNotIn('token', str(caught.exception))
        self.assertNotIn('https', str(caught.exception))

    def test_malformed_text_and_tables_are_response_errors(self):
        for text in ('invalid json', '{broken', 'ID STATUS DESCRIPTION\n1 OPEN synthetic'):
            with self.subTest(text=text), self.assertRaises(ResponseFormatError):
                decode_listing(content(text))

    def test_nested_error_flag_recognized(self):
        result = CallToolResult(content=[], structuredContent={'result': {'isError': True,
                     'content': [{'text': 'Error executing list_offenses: HTTP 401 private-example-secret'}]}})
        with self.assertRaises(MCPToolFailure) as caught:
            decode_listing(result)
        self.assertIn('HTTP 401', caught.exception.reason)
        self.assertNotIn('private-example-secret', str(caught.exception))

    def test_too_many_envelopes_stop(self):
        data = []
        for _ in range(8):
            data = {'result': data}
        with self.assertRaises(ResponseFormatError):
            decode_listing(CallToolResult(content=[], structuredContent=data))


class DiscoveryDiagnosticTests(unittest.IsolatedAsyncioTestCase):
    async def test_upstream_failure_counts_call_and_never_claims_local_rejection(self):
        qr, session = client(content('Tool execution failed: private-example-secret'))
        result = await find_offenses(qr, 'Synthetic description: with spaces')
        session.call_tool.assert_awaited_once()
        self.assertTrue(result['mcp_tool_call_attempted'])
        self.assertEqual(result['budget']['calls_made'], 1)
        self.assertEqual(result['error']['category'], 'upstream_tool_error')
        self.assertFalse(result['discovery_exhausted'])
        self.assertNotIn('private-example-secret', json.dumps(result))

    async def test_malformed_response_points_to_decoding_stage(self):
        qr, _ = client(content('{invalid'))
        result = await find_offenses(qr, 'Synthetic description')
        self.assertEqual(result['error']['category'], 'response_format')
        self.assertEqual(result['error']['stage'], 'upstream_response_decoding')
        self.assertTrue(result['error']['mcp_tool_call_attempted'])

    async def test_upstream_permission_and_validation_not_local_input(self):
        for text, category in [('Error executing list_offenses: HTTP 403 Forbidden private-example-secret', 'permission'),
                               ('Invalid filter expression: private-example-secret', 'request_rejected')]:
            qr, _ = client(content(text))
            result = await find_offenses(qr, 'Synthetic description')
            self.assertEqual(result['error']['category'], category)
            self.assertTrue(result['mcp_tool_call_attempted'])
            self.assertNotIn('private-example-secret', json.dumps(result))

    async def test_unexpected_valueerror_after_call_not_local_rejection(self):
        qr = SimpleNamespace(call=AsyncMock(side_effect=ValueError('private-example-secret')))
        result = await find_offenses(qr, 'Synthetic description')
        self.assertEqual(result['error']['category'], 'upstream_client')
        self.assertTrue(result['mcp_tool_call_attempted'])
        self.assertNotIn('private-example-secret', json.dumps(result))

    async def test_valid_arguments_colons_and_contains_reach_upstream(self):
        qr, session = client(content('{"offenses": []}'))
        for match in ('exact', 'contains'):
            result = await find_offenses(qr, 'Synthetic: Multiple lockout containing audit', match=match)
            self.assertTrue(result['page_complete'])
            self.assertTrue(result['decoded_response_returned'])
        self.assertEqual(session.call_tool.await_count, 2)

    async def test_invalid_argument_makes_no_tool_call(self):
        qr, session = client(content('{"offenses": []}'))
        with self.assertRaises(ValueError):
            await find_offenses(qr, 'Synthetic description', limit=0)
        session.call_tool.assert_not_awaited()

    async def test_expired_or_call_budget_makes_no_tool_call(self):
        for budget in (Budget(max_calls=0), Budget(max_seconds=1, clock=lambda: 0)):
            if budget.max_calls != 0:
                budget.clock = lambda: 2
            qr, session = client(content('{"offenses": []}'))
            result = await find_offenses(qr, 'Synthetic description', budget=budget)
            session.call_tool.assert_not_awaited()
            self.assertFalse(result['mcp_tool_call_attempted'])
            self.assertEqual(result['budget']['calls_made'], 0)

    async def test_batch_propagates_discovery_call_count(self):
        qr, _ = client(content('Tool execution failed: private-example-secret'))
        result = await investigate_offenses(qr, description='Synthetic description')
        self.assertEqual(result['outcome'], 'discovery_unavailable')
        self.assertEqual(result['budget']['calls_made'], 1)
        self.assertTrue(result['discovery']['mcp_tool_call_attempted'])
