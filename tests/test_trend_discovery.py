"""Workbench discovery contracts, conservative coverage and real stdio transport."""
import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from mcp import StdioServerParameters
from mcp.types import CallToolResult, TextContent
from soc_bridge.ariel_collection import Budget
from soc_bridge.diagnostics import MCPToolFailure
from soc_bridge.trend_discovery import find_alerts, parameters
from soc_bridge.transports import RestrictedMCP, live_trend_discovery


def row(number=1, **extra):
    return {"id": f"WB-DEMO-{number:04}", "status": "Open", "severity": "high", **extra}


def vision(response):
    return SimpleNamespace(call=AsyncMock(return_value=response))


class ParameterTests(unittest.TestCase):
    def test_default_day_and_current_status_filter(self):
        result = parameters(now=datetime(2026, 1, 2, tzinfo=timezone.utc))
        self.assertEqual(result['start_date_time'], '2026-01-01T00:00:00.000Z')
        self.assertEqual(result['filter'], "(status eq 'Open' or status eq 'In Progress')")
        self.assertNotIn('investigationStatus', result['filter'])

    def test_each_lifecycle_and_severity(self):
        for status, fragment in [('NEW', "status eq 'Open'"), ('IN_PROGRESS', "status eq 'In Progress'"),
                                 ('CLOSED', "status eq 'Closed'"), ('ALL', '')]:
            with self.subTest(status=status):
                self.assertIn(fragment, parameters(status=status)['filter'])
        self.assertEqual(parameters(status='ALL', severity='critical')['filter'], "severity eq 'critical'")

    def test_offsets_normalized_to_utc(self):
        result = parameters(start_date_time='2026-01-01T09:00:00-03:00', end_date_time='2026-01-01T10:00:00-03:00')
        self.assertEqual(result['start_date_time'], '2026-01-01T12:00:00.000Z')

    def test_invalid_parameters_fail_before_transport(self):
        for kwargs in ({'status': []}, {'status': "Open' or true"}, {'severity': 'urgent'}, {'limit': True},
                       {'limit': 201}, {'start_date_time': '2026-01-01T00:00:00Z'},
                       {'start_date_time': '2026-01-01', 'end_date_time': '2026-01-02'},
                       {'start_date_time': '2026-01-02T00:00:00Z', 'end_date_time': '2026-01-01T00:00:00Z'},
                       {'start_date_time': '2026-01-01T00:00:00Z', 'end_date_time': '2026-03-01T00:00:00Z'}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                parameters(**kwargs)


class DiscoveryTests(unittest.IsolatedAsyncioTestCase):
    async def test_open_and_in_progress_found_with_investigation_ids(self):
        client = vision({'items': [row(), row(2, status='In Progress', investigationResult='True Positive')]})
        result = await find_alerts(client)
        self.assertTrue(result['any_matching_alert'])
        self.assertTrue(result['result_set_complete'])
        self.assertEqual(result['alerts'][1]['investigationResult'], 'True Positive')
        self.assertEqual(result['alerts'][0]['investigation_tool']['parameters'], {'alert_id': 'WB-DEMO-0001'})
        args = client.call.call_args.args[1]
        self.assertEqual(set(args), {'filter', 'orderBy', 'startDateTime', 'endDateTime'})

    async def test_empty_is_only_in_window(self):
        result = await find_alerts(vision({'items': []}))
        self.assertEqual(result['outcome'], 'empty')
        self.assertFalse(result['any_matching_alert'])
        self.assertIn('not all historical', result['coverage_note'])

    async def test_next_link_is_partial_and_never_fetched_or_exposed(self):
        client = vision({'items': [row()], 'nextLink': 'https://example.invalid/?token=synthetic-secret'})
        result = await find_alerts(client)
        self.assertEqual(result['outcome'], 'partial')
        self.assertFalse(result['result_set_complete'])
        client.call.assert_awaited_once()
        self.assertNotIn('synthetic-secret', json.dumps(result))
        self.assertEqual(result['continuation_plan'][0]['action'], 'refine_filters_or_time_range')

    async def test_empty_with_next_page_is_not_negative(self):
        result = await find_alerts(vision({'items': [], 'nextLink': 'opaque'}))
        self.assertIsNone(result['any_matching_alert'])
        self.assertEqual(result['outcome'], 'partial')

    async def test_count_larger_than_page_is_partial_even_without_link(self):
        result = await find_alerts(vision({'items': [row()], 'totalCount': 4}))
        self.assertFalse(result['result_set_complete'])

    async def test_local_cap_reports_repeat_first_page_not_fake_cursor(self):
        result = await find_alerts(vision({'items': [row(1), row(2)]}), limit=1)
        self.assertEqual(result['returned_alerts'], 1)
        plan = result['continuation_plan'][0]
        self.assertEqual(plan['parameters']['limit'], 2)
        self.assertIn('not an upstream cursor', plan['note'])

    async def test_bad_shapes_and_ignored_filters_are_not_empty(self):
        for response in ([], {}, {'items': [None]}, {'items': [row(status='Closed')]},
                         {'items': [row(status=None)]}, {'items': [row(id='bad')]},
                         {'items': [row(), row()]}, {'items': [], 'nextLink': 12},
                         {'items': [row()], 'totalCount': 0}, {'items': [], 'totalCount': True}):
            with self.subTest(response=response):
                result = await find_alerts(vision(response))
                self.assertEqual(result['error']['category'], 'response_format')
                self.assertIsNone(result['any_matching_alert'])
                self.assertTrue(result['mcp_tool_call_attempted'])

    async def test_severity_filter_enforced(self):
        result = await find_alerts(vision({'items': [row()]}), severity='low')
        self.assertEqual(result['error']['category'], 'response_format')

    async def test_errors_are_sanitized_and_not_local_argument_errors(self):
        for code, category in [(403, 'permission'), (429, 'rate_limited'), (500, 'upstream_error')]:
            client = vision(None)
            client.call.side_effect = MCPToolFailure('Vision One', 'workbench_alerts_list', f'upstream returned HTTP {code}')
            result = await find_alerts(client)
            self.assertEqual(result['error']['category'], category)
            self.assertIsNone(result['any_matching_alert'])
            self.assertNotIn('QRadar', json.dumps(result))

    async def test_missing_tool_and_nonjson_text(self):
        session = SimpleNamespace(call_tool=AsyncMock())
        client = RestrictedMCP(session, {'workbench_alerts_list'}, set(), set(), 'Vision One')
        result = await find_alerts(client)
        self.assertEqual(result['error']['category'], 'tool_unavailable')
        self.assertFalse(result['mcp_tool_call_attempted'])
        self.assertEqual(result['budget']['calls_made'], 0)
        session.call_tool.assert_not_awaited()
        session.call_tool.return_value = CallToolResult(content=[TextContent(type='text', text='private-synthetic-body')])
        client.available.add('workbench_alerts_list')
        result = await find_alerts(client)
        self.assertEqual(result['error']['category'], 'response_format')
        self.assertNotIn('private-synthetic-body', json.dumps(result))

    async def test_deadline_preserves_attempt_state(self):
        client = vision({'items': []})
        expired = Budget(clock=lambda: 0)
        expired.clock = lambda: 100
        result = await find_alerts(client, budget=expired)
        self.assertFalse(result['mcp_tool_call_attempted'])
        client.call.assert_not_awaited()
        async def slow(*args):
            await asyncio.sleep(1)
        client.call.side_effect = slow
        result = await find_alerts(client, budget=Budget(max_seconds=.01))
        self.assertTrue(result['mcp_tool_call_attempted'])
        self.assertEqual(result['error']['category'], 'timeout')

    async def test_long_fields_are_cut_and_response_has_global_budget(self):
        rows = [row(i, **{key: 'x' * 2000 for key in ('name', 'model', 'modelId', 'investigationResult',
            'createdDateTime', 'updatedDateTime', 'caseId')}) for i in range(1, 201)]
        result = await find_alerts(vision({'items': rows}), limit=200)
        self.assertTrue(result['response_budget_reached'])
        self.assertFalse(result['result_set_complete'])
        self.assertLess(len(json.dumps(result)), 220000)
        self.assertTrue(result['truncated_fields'])

    async def test_real_stdio_session_is_trend_only_and_readonly(self):
        def synthetic_params(**kwargs):
            self.assertIn('-readonly=true', kwargs['args'])
            self.assertIn('-toolsets=workbench', kwargs['args'])
            self.assertNotIn('synthetic-key', kwargs['args'])
            return StdioServerParameters(command=sys.executable,
                args=[str(Path(__file__).with_name('fake_trend_mcp.py'))])
        with patch('mcp.StdioServerParameters', side_effect=synthetic_params), \
             patch('soc_bridge.transports.live_qradar_query', side_effect=AssertionError('QRadar must not connect')):
            result = await live_trend_discovery({}, 'synthetic-key', 'us')
        self.assertEqual(result['alerts'][0]['id'], 'WB-DEMO-0001')
        self.assertTrue(result['selection']['default_window'])

    async def test_startup_failure_not_empty_and_invalid_args_do_not_start_docker(self):
        with patch('mcp.client.stdio.stdio_client', side_effect=FileNotFoundError('synthetic-secret')) as start:
            result = await live_trend_discovery({}, 'synthetic-key', 'us')
            self.assertEqual(result['outcome'], 'unavailable')
            self.assertFalse(result['mcp_tool_call_attempted'])
            self.assertNotIn('synthetic-secret', json.dumps(result))
            start.reset_mock()
            with self.assertRaises(ValueError):
                await live_trend_discovery({'limit': 0}, 'synthetic-key', 'us')
            start.assert_not_called()

    async def test_public_tool_uses_existing_trend_environment_only(self):
        from soc_bridge.kiro_server import trend_find_alerts, mcp
        import os
        with patch.dict(os.environ, {'TREND_VISION_ONE_API_KEY': 'synthetic-key', 'TREND_VISION_ONE_REGION': 'eu'}), \
             patch('soc_bridge.kiro_server.live_trend_discovery', AsyncMock(return_value={'outcome': 'empty'})) as run:
            self.assertEqual(await trend_find_alerts(severity='high'), {'outcome': 'empty'})
        self.assertEqual(run.call_args.args[1:], ('synthetic-key', 'eu'))
        self.assertEqual(run.call_args.args[0]['severity'], 'high')
        tools = {t.name: t for t in await mcp.list_tools()}
        self.assertEqual(len(tools), 26)
        self.assertTrue(tools['trend_find_alerts'].annotations.readOnlyHint)
        self.assertEqual(set(tools['trend_find_alerts'].inputSchema['properties']),
                         {'status', 'severity', 'start_date_time', 'end_date_time', 'limit'})

    async def test_missing_credentials_and_unknown_region_fail_before_startup(self):
        with patch('mcp.client.stdio.stdio_client') as start:
            for key, region in [('', 'us'), ('synthetic-key', 'unknown')]:
                with self.assertRaises(ValueError):
                    await live_trend_discovery({}, key, region)
            start.assert_not_called()
