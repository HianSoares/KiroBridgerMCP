"""QRadar returns description but rejects using it in the REST filter."""
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from mcp.types import CallToolResult, TextContent
from soc_bridge.offense_batch import find_offenses, investigate_offenses
from soc_bridge.ariel_collection import Budget
from soc_bridge.transports import RestrictedMCP, QRADAR_TOOLS
from soc_bridge.diagnostics import MCPToolFailure

DESC = 'Synthetic: multiple locks containing account event'


class API:
    def __init__(self, size=220, matching=(2, 107, 150, 153), total=True):
        self.rows = [dict(id=i, description=DESC if i in matching else 'Other synthetic offense', status='OPEN')
                     for i in range(1, size + 1)]
        self.calls, self.total = [], total
    async def call(self, name, args):
        self.calls.append((name, dict(args)))
        if 'description' in args.get('filter', ''):
            raise MCPToolFailure('QRadar', 'list_offenses', 'upstream returned HTTP 422; description filtering unsupported')
        data = {'offenses': self.rows[args['offset']:args['offset'] + args['limit']]}
        if self.total:
            data['total_count'] = len(self.rows)
        return data


def report(oid):
    return dict(offense_id=oid, metadata={'id': oid, 'description': DESC}, continuation_plan=[],
                queries={'events': {'result_set_complete': True}, 'flows': {'result_set_complete': True}},
                closure_assessment={'ready_to_close': False})


class LocalMatchingTests(unittest.IsolatedAsyncioTestCase):
    async def test_server_rejects_description_filter_but_discovery_succeeds(self):
        api = API()
        result = await find_offenses(api, DESC, limit=2)
        self.assertEqual([r['id'] for r in result['offenses']], [2, 107])
        self.assertEqual(result['next_offset'], 107)
        self.assertEqual(result['upstream_rows_scanned'], 107)
        self.assertEqual(result['upstream_pages_read'], 2)
        self.assertEqual(result['upstream_total_count'], 220)
        self.assertIsNone(result['total_count'])  # 220 is not the number matching the description
        self.assertTrue(all('description' not in a['filter'] for _, a in api.calls))

    async def test_resume_middle_of_raw_page_does_not_skip_remaining_matches(self):
        api = API()
        first = await find_offenses(api, DESC, limit=2)
        second = await find_offenses(api, **first['continuation_plan'][0]['parameters'])
        self.assertEqual([r['id'] for r in second['offenses']], [150, 153])
        self.assertEqual(second['next_offset'], 153)
        third = await find_offenses(api, **second['continuation_plan'][0]['parameters'])
        self.assertEqual(third['offenses'], [])
        self.assertTrue(third['discovery_exhausted'])
        self.assertIsNone(third['total_count'])  # later suffix is not a global matching total

    async def test_nonmatching_first_pages_do_not_end_scan(self):
        result = await find_offenses(API(matching=(220,)), DESC, limit=3)
        self.assertEqual([r['id'] for r in result['offenses']], [220])
        self.assertEqual(result['upstream_pages_read'], 3)
        self.assertTrue(result['discovery_exhausted'])
        self.assertEqual(result['total_count'], 1)

    async def test_budget_without_matches_is_partial_not_empty(self):
        result = await find_offenses(API(matching=(220,)), DESC, budget=Budget(max_calls=1))
        self.assertFalse(result['discovery_exhausted'])
        self.assertEqual(result['outcome'], 'partial')
        self.assertEqual(result['next_offset'], 100)
        self.assertEqual(result['offenses'], [])
        self.assertEqual(result['continuation_plan'][0]['parameters']['offset'], 100)

    async def test_budget_partial_matches_are_kept(self):
        result = await find_offenses(API(), DESC, limit=5, budget=Budget(max_calls=1))
        self.assertEqual([r['id'] for r in result['offenses']], [2])
        self.assertEqual(result['outcome'], 'partial')
        self.assertEqual(result['next_offset'], 100)

    async def test_record_budget_stops_at_scanned_cursor(self):
        result = await find_offenses(API(), DESC, limit=5, budget=Budget(max_records=3))
        self.assertEqual(result['next_offset'], 3)
        self.assertEqual(result['budget']['records_seen'], 3)
        self.assertFalse(result['discovery_exhausted'])

    async def test_literal_contains_percent_underscore_backslash(self):
        api = API(size=1, matching=())
        api.rows[0]['description'] = 'Literal %_\\ fragment'
        result = await find_offenses(api, '%_\\', match='contains')
        self.assertEqual(result['returned_count'], 1)
        self.assertEqual(api.calls[0][1]['filter'], 'status = "OPEN"')

    async def test_exact_does_not_treat_substrings_as_equal(self):
        result = await find_offenses(API(), 'multiple locks', match='exact')
        self.assertEqual(result['offenses'], [])
        self.assertTrue(result['discovery_exhausted'])
        self.assertEqual(result['total_count'], 0)

    async def test_error_on_later_page_preserves_matches_and_cursor(self):
        api = API()
        original = api.call
        async def fail(name, args):
            if args['offset'] >= 100:
                raise MCPToolFailure('QRadar', 'list_offenses', 'upstream returned HTTP 403')
            return await original(name, args)
        api.call = fail
        result = await find_offenses(api, DESC, limit=5)
        self.assertEqual(result['outcome'], 'partial')
        self.assertEqual([r['id'] for r in result['offenses']], [2])
        self.assertEqual(result['next_offset'], 100)
        self.assertTrue(result['continuation_plan'][0]['requires_resolution'])

    async def test_batch_uses_raw_cursor_and_investigates_all_matching_ids(self):
        api = API()
        verifier = AsyncMock(side_effect=lambda q, oid, *a, **kw: report(oid))
        with patch('soc_bridge.offense_batch.verify_offense', verifier):
            first = await investigate_offenses(api, description=DESC, max_offenses=2)
            cursor = first['continuation_plan'][0]['parameters']
            self.assertEqual(cursor['offset'], 107)
            second = await investigate_offenses(api, **cursor)
            third = await investigate_offenses(api, **second['continuation_plan'][0]['parameters'])
        self.assertEqual([c.args[1] for c in verifier.call_args_list], [2, 107, 150, 153])
        self.assertTrue(third['discovery']['discovery_exhausted'])
        self.assertFalse(first['all_matching_offenses_investigated'])

    async def test_batch_with_partial_empty_scan_returns_next_cursor(self):
        # A bounded scan can return zero matches with more population left.
        partial = await find_offenses(API(matching=(220,)), DESC, budget=Budget(max_calls=1))
        with patch('soc_bridge.offense_batch.find_offenses', AsyncMock(return_value=partial)):
            result = await investigate_offenses(API(), description=DESC)
        self.assertEqual(result['reports'], [])
        self.assertFalse(result['collection_complete'])
        self.assertEqual(result['continuation_plan'][0]['parameters']['offset'], 100)

    async def test_lost_iserror_unsupported_description_filter_is_request_rejected(self):
        response = CallToolResult(content=[TextContent(type='text', text=
            'Error executing list_offenses: Filtering is unsupported on the field: description')], isError=False)
        session = SimpleNamespace(call_tool=AsyncMock(return_value=response))
        qr = RestrictedMCP(session, QRADAR_TOOLS, {'list_offenses'}, {'list_offenses'})
        result = await find_offenses(qr, DESC)
        self.assertEqual(result['error']['category'], 'request_rejected')
        self.assertNotIn('Filtering is unsupported', result['error']['message'])  # response body not copied
