"""Independent Search: native evidence, bounded coverage, real MCP and pack contracts."""
import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from mcp import StdioServerParameters
from soc_bridge.ariel_collection import Budget
from soc_bridge.capabilities import Discovery, ToolSet
from soc_bridge.diagnostics import MCPToolFailure
from soc_bridge.trend_search import SOURCES, collect, parameters, resource
from soc_bridge.transports import RestrictedMCP, live_trend_search

ROOT = Path(__file__).resolve().parents[1]
BOUNDS = {'start_date_time': '2026-01-01T12:00:00Z', 'end_date_time': '2026-01-01T12:10:00Z'}

def selection(**kwargs):
    return parameters(query='endpointHostName:"host.example.test"', **{**BOUNDS, **kwargs})

def client(response):
    return SimpleNamespace(call=AsyncMock(return_value=response))

def row(n=1, **extra):
    return {'uuid': f'synthetic-{n}', 'endpointHostName': 'host.example.test', 'processPid': 4242,
            'processCmd': 'diagnostic.exe --target 4567', **extra}

class ParametersTests(unittest.TestCase):
    def test_defaults_are_explicit_and_offsets_absolute(self):
        s = parameters('processPid:4242', now=datetime(2026, 1, 2, tzinfo=timezone.utc))
        self.assertEqual(s['start_date_time'], '2026-01-01T00:00:00.000Z')
        self.assertTrue(s['default_window'])
        s = parameters('processPid:4242', start_date_time='2026-01-01T09:00:00-03:00',
                       end_date_time='2026-01-01T10:00:00-03:00')
        self.assertEqual(s['start_date_time'], '2026-01-01T12:00:00.000Z')
        self.assertFalse(s['default_window'])

    def test_invalid_input_is_rejected_before_any_read(self):
        cases = [{'source': 'sql'}, {'query': ''}, {'query': 'x\nsecret'}, {'query': 'x' * 4097},
                 {'query': None}, {'select': 'a,a'}, {'select': 'a,,b'}, {'select': 'a;DROP'},
                 {'select': 'x' * 2001}, {'select': 4}, {'top': 25}, {'top': True},
                 {'limit': 0}, {'limit': 5001}, {'limit': True}, {'max_calls': 25},
                 {'max_calls': 0}, {'count_only': 1}, {'start_date_time': '', 'end_date_time': BOUNDS['end_date_time']},
                 {'start_date_time': '2026-01-01T12:00:00', 'end_date_time': '2026-01-01T12:10:00'},
                 {'end_date_time': '2025-01-01T12:10:00Z'}, {'end_date_time': '2026-03-01T12:10:00Z'}]
        for overrides in cases:
            with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                args = {'query': 'processPid:4242', **BOUNDS, **overrides}
                parameters(**args)

    def test_native_expression_is_not_mistaken_for_offense_description(self):
        expression = '(endpointHostName:"host.example.test") and (processPid:4242 or objectPid:4242)'
        self.assertEqual(parameters(expression)['query'], expression)
        self.assertEqual(parameters(expression, select=' processCmd, objectCmd ')['select'], 'processCmd,objectCmd')

class SearchTests(unittest.IsolatedAsyncioTestCase):
    async def test_all_sources_forward_their_own_tool_and_types(self):
        for source, tool in SOURCES.items():
            with self.subTest(source=source):
                c = client({'items': [row()]})
                r = await collect(c, selection(source=source, top=100, select='processCmd'))
                self.assertTrue(r['result_set_complete'])
                args = c.call.call_args.args
                self.assertEqual(args[0], tool)
                self.assertEqual(args[1]['top'], '100')
                self.assertEqual(args[1]['select'], 'processCmd')
                self.assertEqual(args[1]['mode'], 'default')
                self.assertNotIn('skipToken', args[1])
                self.assertNotIn('alert_id', args[1])

    async def test_native_evidence_roles_and_unknown_fields_are_preserved(self):
        native = row(processCmd='x' * 5000, processFileHashSha256='a' * 64, objectPid=4567,
                     objectProcessHashId='different-instance', processHashId='actor-instance',
                     unknownNative={'relationship': ['keep', 'these']})
        r = await collect(client({'items': [native]}), selection())
        self.assertEqual(r['records'][0]['data'], native)
        self.assertTrue(r['evidence_fields_complete'])
        self.assertEqual(r['records'][0]['provenance'][0]['query_reference'], 'selection.query')
        self.assertNotIn('assessment', r)  # a query does not automatically prove malicious/benign

    async def test_empty_is_negative_only_with_completed_coverage(self):
        r = await collect(client({'items': []}), selection())
        self.assertEqual(r['outcome'], 'empty')
        self.assertIs(r['any_matching_record'], False)
        self.assertIn('logging', r['coverage_note'])

    async def test_count_zero_does_not_claim_complete_logs(self):
        c = client({'totalCount': 0, 'progressRate': 100})
        r = await collect(c, selection(count_only=True, select='processCmd'))
        self.assertEqual(r['count_only']['value'], 0)
        self.assertEqual(r['outcome'], 'counted')
        self.assertFalse(r['result_set_complete'])
        self.assertIsNone(r['any_matching_record'])
        self.assertNotIn('select', c.call.call_args.args[1])
        self.assertEqual(c.call.call_args.args[1]['mode'], 'countOnly')

    async def test_incomplete_count_is_partial(self):
        r = await collect(client({'count': 5, 'progressRate': 10}), selection(count_only=True))
        self.assertEqual(r['outcome'], 'partial')
        self.assertEqual(r['count_only']['state'], 'partial')
        self.assertIsNone(r['any_matching_record'])

    async def test_response_format_failures_are_not_empty(self):
        cases = [[], {}, {'items': 'bad'}, {'items': [None]}, {'items': [{}]},
                 {'items': [], 'nextLink': 1}, {'items': [row()], 'totalCount': 0},
                 {'items': [], 'totalCount': True}, {'items': [], 'totalCount': -1},
                 {'items': [], 'progressRate': -1}, {'items': [], 'progressRate': True},
                 {'items': [], 'progressRate': float('nan')}, {'items': [row(i) for i in range(51)]}]
        for response in cases:
            with self.subTest(response=response):
                r = await collect(client(response), selection(top=50))
                self.assertEqual(r['errors'][0]['category'], 'response_format')
                self.assertIsNone(r['any_matching_record'])
                self.assertFalse(r['result_set_complete'])
        r = await collect(client({'items': []}), selection(count_only=True))
        self.assertEqual(r['errors'][0]['category'], 'response_format')

    async def test_errors_are_classified_and_sanitized(self):
        for code, category in ((401, 'permission'), (403, 'permission'), (400, 'request_rejected'),
                               (429, 'rate_limited'), (500, 'upstream_error')):
            c = client(None)
            c.call.side_effect = MCPToolFailure('Vision One', 'Search', f'upstream returned HTTP {code}')
            r = await collect(c, selection())
            with self.subTest(code=code):
                self.assertEqual(r['errors'][0]['category'], category)
                self.assertIsNone(r['any_matching_record'])
                self.assertTrue(r['mcp_tool_call_attempted'])
        c.call.side_effect = RuntimeError('synthetic-secret')
        r = await collect(c, selection())
        self.assertNotIn('synthetic-secret', json.dumps(r))

    async def test_full_page_is_partitioned_and_native_uuid_deduplicates(self):
        c = client(None)
        c.call.side_effect = [{'items': [row(i) for i in range(50)]},
                              {'items': [row(0), row(100)]}, {'items': [row(1), row(101)]}]
        r = await collect(c, selection(top=50))
        self.assertEqual(c.call.await_count, 3)
        self.assertEqual(r['returned_records'], 52)
        self.assertEqual(r['partitions'][0]['state'], 'page_full')
        self.assertEqual(len(r['records'][0]['provenance']), 2)
        self.assertTrue(r['result_set_complete'])
        calls = c.call.call_args_list
        self.assertEqual(calls[1].args[1]['endDateTime'], calls[2].args[1]['startDateTime'])

    async def test_budget_continuation_contains_executable_pending_windows(self):
        c = client({'items': [row(i) for i in range(50)]})
        r = await collect(c, selection(top=50, max_calls=1, select='processCmd'))
        self.assertFalse(r['result_set_complete'])
        self.assertEqual(len(r['continuation_plan']), 2)
        plan = r['continuation_plan'][0]
        self.assertEqual(plan['action'], 'search_partition')
        self.assertEqual(plan['parameters']['select'], 'processCmd')
        resumed = parameters(**plan['parameters'])
        self.assertNotEqual(resumed['end_date_time'], selection()['end_date_time'])
        c = client({'items': []})
        r2 = await collect(c, resumed)
        self.assertEqual(c.call.await_count, 1)
        self.assertTrue(r2['result_set_complete'])
        self.assertIn('retain previous', plan['note'])

    async def test_dense_leaf_requires_refinement_never_follows_url(self):
        r = await collect(client({'items': [], 'nextLink': 'https://example.invalid/?secret=synthetic-secret'}),
                          selection(end_date_time='2026-01-01T12:00:01Z'))
        self.assertEqual(r['continuation_plan'][0]['action'], 'refine_filters')
        self.assertIsNone(r['any_matching_record'])
        self.assertNotIn('synthetic-secret', json.dumps(r))

    async def test_partial_error_keeps_rows_and_pending_sibling_without_retry_loop(self):
        c = client(None)
        c.call.side_effect = [{'items': [row(i) for i in range(50)]},
                             MCPToolFailure('Vision One', 'Search', 'upstream returned HTTP 403')]
        r = await collect(c, selection(top=50))
        self.assertEqual(r['outcome'], 'partial')
        self.assertEqual(r['returned_records'], 50)
        self.assertTrue(r['any_matching_record'])
        self.assertEqual(c.call.await_count, 2)
        self.assertTrue(all(p['action'] == 'resolve_error' for p in r['continuation_plan']))

    async def test_incomplete_progress_is_not_complete_even_when_empty(self):
        for rows in ([], [row()]):
            r = await collect(client({'items': rows, 'progressRate': 30}), selection())
            self.assertEqual(r['outcome'], 'partial')
            self.assertFalse(r['result_set_complete'])
            self.assertEqual(r['any_matching_record'], True if rows else None)

    async def test_local_record_cap_marks_unreturned_rows(self):
        r = await collect(client({'items': [row(), row(2)]}), selection(limit=1))
        self.assertEqual(r['returned_records'], 1)
        self.assertEqual(r['continuation_plan'][0]['action'], 'refine_filters')
        self.assertFalse(r['result_set_complete'])

    async def test_field_cuts_and_global_output_cap_are_explicit(self):
        r = await collect(client({'items': [row(processCmd='x' * 20000)]}), selection())
        self.assertFalse(r['evidence_fields_complete'])
        self.assertEqual(len(r['records'][0]['data']['processCmd']), 16384)
        self.assertTrue(r['result_set_complete'])  # row coverage != field preservation
        rows = [row(i, **{f'field{k}': 'x' * 16000 for k in range(5)}) for i in range(50)]
        r = await collect(client({'items': rows}), selection(top=100))
        self.assertFalse(r['result_set_complete'])
        self.assertLess(len(json.dumps(r)), 530000)
        self.assertEqual(r['continuation_plan'][0]['action'], 'refine_filters')

    async def test_pid_reuse_and_uuid_with_changed_content_are_not_merged(self):
        a = row(); b = row(processHashId='new-instance'); c = row(); c.pop('uuid')
        r = await collect(client({'items': [a, b, c, dict(c)]}), selection())
        self.assertEqual(r['returned_records'], 4)

    async def test_duplicate_provenance_is_also_bounded(self):
        from soc_bridge import trend_search
        c = client(None)
        c.call.side_effect = [{'items': [row()], 'nextLink': 'opaque'},
                             {'items': [row()]}, {'items': [row()]}]
        # A response budget just large enough for the first record must also apply
        # to duplicate provenance; no unbounded query/body repetition is allowed.
        first = await collect(client({'items': [row()]}), selection())
        size = len(json.dumps(first['records'][0], ensure_ascii=False))
        with patch.object(trend_search, 'MAX_RESPONSE_CHARS', size + 15):
            r = await collect(c, selection())
        self.assertTrue(r['result_set_complete'])
        self.assertEqual(r['records'][0]['provenance_omitted'], 2)
        self.assertEqual(len(r['records'][0]['provenance']), 1)

    async def test_source_contract_matches_versioned_official_handler_catalog(self):
        snapshot = json.loads((ROOT / 'docs/coverage/vision-one-mcp-tools.json').read_text(encoding='utf-8'))
        catalog = {tool['name']: tool for tool in snapshot['tools']}
        for tool in SOURCES.values():
            self.assertEqual(catalog[tool]['registered_as'], 'read')
            self.assertIn('top', catalog[tool]['declared'])
            self.assertNotIn('skipToken', catalog[tool]['declared'])
            self.assertFalse(catalog[tool]['not_forwarded'])

    async def test_missing_tool_vs_incomplete_discovery(self):
        session = SimpleNamespace(call_tool=AsyncMock())
        for complete, category in ((True, 'tool_absent'), (False, 'availability_unknown')):
            discovery = Discovery('Vision One'); discovery.complete = complete
            names = ToolSet(); names.discovery = discovery
            restricted = RestrictedMCP(session, set(SOURCES.values()), names, set(), 'Vision One')
            r = await collect(restricted, selection())
            with self.subTest(complete=complete):
                self.assertEqual(r['errors'][0]['category'], category)
                self.assertFalse(r['mcp_tool_call_attempted'])
        session.call_tool.assert_not_awaited()

    async def test_catalog_retains_live_schema_and_unknown_is_not_absence(self):
        d = Discovery('Vision One'); names = ToolSet(); names.discovery = d
        r = resource('endpoint', names)
        self.assertEqual(r['availability'], 'unknown')
        d.names.add(SOURCES['endpoint']); d.complete = True
        d.schemas[SOURCES['endpoint']] = {'properties': {'query': {'description': 'processPid / objectPid'}}}
        r = resource('endpoint', names)
        self.assertEqual(r['availability'], 'available_allowed')
        self.assertEqual(r['input_schema']['properties']['query']['description'], 'processPid / objectPid')

    async def test_deadline_no_attempt_vs_inflight_and_cancellation(self):
        c = client({'items': []}); b = Budget(clock=lambda: 0); b.clock = lambda: 100
        r = await collect(c, selection(), budget=b)
        self.assertFalse(r['mcp_tool_call_attempted']); c.call.assert_not_awaited()
        async def slow(*args):
            await asyncio.sleep(10)
        c.call.side_effect = slow
        r = await collect(c, selection(), budget=Budget(max_seconds=.01))
        self.assertEqual(r['errors'][0]['category'], 'timeout')
        self.assertTrue(r['mcp_tool_call_attempted'])
        task = asyncio.create_task(collect(c, selection()))
        await asyncio.sleep(0); task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task

class TransportTests(unittest.IsolatedAsyncioTestCase):
    def synthetic(self, **kwargs):
        self.assertIn('-readonly=true', kwargs['args'])
        self.assertIn('-toolsets=search', kwargs['args'])
        self.assertNotIn('synthetic-key', kwargs['args'])
        self.assertEqual(kwargs['env']['TREND_VISION_ONE_API_KEY'], 'synthetic-key')
        return StdioServerParameters(command=sys.executable, args=[str(ROOT / 'tests/fake_trend_search_mcp.py')])

    async def test_real_sdk_search_without_qradar_or_alert(self):
        with patch('mcp.StdioServerParameters', side_effect=self.synthetic), \
             patch('mcp.client.streamable_http.streamablehttp_client', side_effect=AssertionError('QRadar must not connect')):
            r = await live_trend_search('search', {'query': 'processPid:4242', **BOUNDS}, 'synthetic-key', 'us')
        self.assertEqual(r['records'][0]['data']['objectPid'], 4567)
        self.assertTrue(r['result_set_complete'])
        self.assertEqual(r['call_outcomes']['scope'], 'this Trend Search call only')
        self.assertNotIn('connection_lifecycle', r)  # no cleanup failure

    async def test_real_sdk_catalog_and_absent_source(self):
        with patch('mcp.StdioServerParameters', side_effect=self.synthetic):
            r = await live_trend_search('resource', {}, 'synthetic-key', 'us')
            missing = await live_trend_search('search', {'query': 'native:query', 'source': 'cloud'}, 'synthetic-key', 'us')
        self.assertEqual(r['schema_origin'], 'live MCP tools/list')
        self.assertIn('processPid', json.dumps(r['input_schema']))
        self.assertEqual(missing['errors'][0]['category'], 'tool_absent')
        self.assertFalse(missing['mcp_tool_call_attempted'])

    async def test_startup_failure_and_invalid_arguments(self):
        with patch('mcp.client.stdio.stdio_client', side_effect=FileNotFoundError('synthetic-secret')) as start:
            r = await live_trend_search('search', {'query': 'processPid:4242'}, 'synthetic-key', 'us')
            self.assertEqual(r['outcome'], 'unavailable')
            self.assertNotIn('synthetic-secret', json.dumps(r))
            start.reset_mock()
            for operation, args, key, region in [('bad', {}, 'synthetic-key', 'us'),
                  ('search', {'query': ''}, 'synthetic-key', 'us'), ('resource', {'source': 'bad'}, 'synthetic-key', 'us'),
                  ('resource', {}, '', 'us'), ('resource', {}, 'synthetic-key', 'bad')]:
                with self.assertRaises(ValueError):
                    await live_trend_search(operation, args, key, region)
            start.assert_not_called()

    async def test_cleanup_failure_preserves_search_evidence(self):
        from mcp.client.stdio import stdio_client as real_stdio
        @asynccontextmanager
        async def broken_exit(*args, **kwargs):
            async with real_stdio(*args, **kwargs) as streams:
                yield streams
            raise RuntimeError('synthetic-secret')
        with patch('mcp.StdioServerParameters', side_effect=self.synthetic), \
             patch('mcp.client.stdio.stdio_client', side_effect=broken_exit):
            r = await live_trend_search('search', {'query': 'processPid:4242'}, 'synthetic-key', 'us')
        self.assertEqual(r['records'][0]['data']['processPid'], 4242)
        self.assertTrue(r['result_set_complete'])
        self.assertTrue(r['connection_lifecycle']['shutdown_errors'])
        self.assertTrue(r['connection_lifecycle']['report_preserved'])
        self.assertNotIn('synthetic-secret', json.dumps(r))

    async def test_public_schemas_are_additive_and_only_trend_env_used(self):
        import os
        from soc_bridge.kiro_server import mcp, trend_search_data, trend_read_search_resource
        with patch.dict(os.environ, {'TREND_VISION_ONE_API_KEY': 'synthetic-key', 'TREND_VISION_ONE_REGION': 'eu'}), \
             patch('soc_bridge.kiro_server.live_trend_search', AsyncMock(return_value={'outcome': 'empty'})) as call:
            await trend_search_data('processPid:4242', **BOUNDS)
            self.assertEqual(call.call_args.args[0], 'search')
            self.assertEqual(call.call_args.args[2:], ('synthetic-key', 'eu'))
            await trend_read_search_resource('cloud')
            self.assertEqual(call.call_args.args[:2], ('resource', {'source': 'cloud'}))
        tools = {t.name: t for t in await mcp.list_tools()}
        self.assertEqual(len(tools), 28)
        for name in ('trend_search_data', 'trend_read_search_resource'):
            self.assertTrue(tools[name].annotations.readOnlyHint)
        for agent in ('case-investigator', 'threat-hunter'):
            text = (ROOT / f'.kiro/agents/{agent}.md').read_text(encoding='utf-8')
            for tool in ('trend_search_data', 'trend_read_search_resource'):
                self.assertIn(f'@soc-bridge-readonly/{tool}', text)
            self.assertIn('trend-search-conventions.md', text)

if __name__ == '__main__':
    unittest.main()
