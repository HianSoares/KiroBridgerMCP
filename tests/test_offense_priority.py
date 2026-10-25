"""Synthetic queue triage: no description, no invented scores, no lost page IDs."""
import asyncio
import json
from pathlib import Path
import unittest

from soc_bridge.capabilities import LOCAL_WRITE_TOOLS
from unittest.mock import AsyncMock, patch

from soc_bridge.ariel_collection import Budget
from soc_bridge.kiro_server import mcp, qradar_list_offenses
from soc_bridge.offense_batch import find_offenses
from soc_bridge.offense_priority import list_offenses, rank_offenses

EPOCH = 1791014400000


def offense(oid, **extra):
    row = dict(id=oid, description=f'Synthetic offense {oid}', status='OPEN',
                start_time=EPOCH, last_updated_time=EPOCH, magnitude=5, severity=5,
                credibility=5, relevance=5)
    return {**row, **extra}


class API:
    def __init__(self, rows=None, total=True):
        self.rows = [offense(1), offense(2)] if rows is None else rows
        self.total = total
        self.calls = []

    async def call(self, name, args):
        self.calls.append((name, dict(args)))
        if name != 'list_offenses':
            raise AssertionError('Listing must never investigate cases or create Ariel jobs')
        data = {'offenses': self.rows[args['offset']:args['offset'] + args['limit']]}
        if self.total:
            data['total_count'] = len(self.rows)
        return data


class PriorityTests(unittest.IsolatedAsyncioTestCase):
    async def test_default_lists_all_descriptions_and_only_calls_listing(self):
        api = API([offense(1), offense(2, description='Another unrelated description', magnitude=10)])
        result = await list_offenses(api)
        self.assertEqual([row['id'] for row in result['offenses']], [2, 1])
        self.assertTrue(result['all_open_offenses_listed'])
        self.assertTrue(result['ranking']['complete_selection_ranked'])
        self.assertEqual(result['description_matching'], 'not applied')
        self.assertNotIn('description', result['scope'])
        self.assertEqual(result['total_count'], 2)
        args = api.calls[0][1]
        self.assertEqual(args['filter'], 'status = "OPEN"')
        self.assertEqual(args['sort'], '+id')
        self.assertIn('credibility', args['fields'])
        self.assertIn('relevance', args['fields'])
        self.assertFalse(args['format_output'])
        self.assertEqual(result['investigations_started'], 0)
        self.assertEqual(result['executed_actions'], [])

    async def test_late_high_priority_survives_cursor_and_global_rerank(self):
        api = API([offense(1), offense(2, magnitude=1), offense(3, magnitude=10)])
        first = await list_offenses(api, limit=2)
        self.assertEqual(first['next_offset'], 2)  # NOT the last ranked offense ID
        self.assertEqual(first['ranking']['scope'], 'returned_set_only')
        self.assertFalse(first['all_open_offenses_listed'])
        plan = first['continuation_plan'][0]
        self.assertEqual(plan['tool'], 'qradar_list_offenses')
        self.assertNotIn('description', plan['parameters'])
        self.assertNotIn('match', plan['parameters'])
        second = await list_offenses(api, **plan['parameters'])
        self.assertEqual([row['id'] for row in second['offenses']], [3])
        self.assertTrue(second['discovery_exhausted'])
        self.assertFalse(second['ranking']['complete_selection_ranked'])  # a suffix alone is not global
        combined = rank_offenses(first['offenses'] + second['offenses'])
        self.assertEqual([row['id'] for row in combined], [3, 1, 2])

    async def test_scan_multiple_raw_pages_and_resume_without_dropping_unread_rows(self):
        rows = [offense(i, magnitude=10 if i == 107 else 2) for i in range(1, 131)]
        api = API(rows)
        first = await list_offenses(api, limit=115)
        self.assertEqual(first['returned_count'], 115)
        self.assertEqual(first['offenses'][0]['id'], 107)
        self.assertEqual(first['next_offset'], 115)
        self.assertEqual(first['upstream_pages_read'], 2)
        second = await list_offenses(api, **first['continuation_plan'][0]['parameters'])
        self.assertEqual({r['id'] for r in first['offenses'] + second['offenses']}, set(range(1, 131)))
        self.assertTrue(second['discovery_exhausted'])

    async def test_unknown_total_exact_page_requires_another_read(self):
        api = API([offense(i) for i in range(1, 101)], total=False)
        first = await list_offenses(api)
        self.assertFalse(first['discovery_exhausted'])
        second = await list_offenses(api, **first['continuation_plan'][0]['parameters'])
        self.assertTrue(second['discovery_exhausted'])
        self.assertIsNone(second['total_count'])

    async def test_complete_empty_is_different_from_failure(self):
        empty = await list_offenses(API([]))
        self.assertEqual(empty['outcome'], 'empty')
        self.assertTrue(empty['discovery_exhausted'])
        api = API()
        api.call = AsyncMock(side_effect=RuntimeError('Optional MCP tool unavailable: list_offenses'))
        failed = await list_offenses(api)
        self.assertEqual(failed['outcome'], 'unavailable')
        self.assertFalse(failed['ranking']['complete_selection_ranked'])
        self.assertEqual(failed['continuation_plan'][0]['parameters']['offset'], 0)
        self.assertTrue(failed['continuation_plan'][0]['requires_resolution'])

    async def test_budget_failure_keeps_partial_rows_and_unread_cursor(self):
        result = await list_offenses(API([offense(i) for i in range(1, 151)]), limit=150,
                                     budget=Budget(max_calls=1))
        self.assertEqual(result['outcome'], 'partial')
        self.assertEqual(result['returned_count'], 100)
        self.assertEqual(result['next_offset'], 100)
        self.assertFalse(result['ranking']['complete_selection_ranked'])

    async def test_second_page_error_keeps_previous_entries(self):
        api = API([offense(i) for i in range(1, 151)])
        original = api.call
        async def failing(name, args):
            if args['offset']:
                raise RuntimeError('Optional MCP tool unavailable: list_offenses')
            return await original(name, args)
        api.call = failing
        result = await list_offenses(api, limit=150)
        self.assertEqual(result['returned_count'], 100)
        self.assertEqual(result['outcome'], 'partial')
        self.assertEqual(result['continuation_plan'][0]['parameters']['offset'], 100)

    async def test_timeout_preserves_same_cursor(self):
        api = API()
        async def slow(*args):
            await asyncio.sleep(.1)
        api.call = slow
        result = await list_offenses(api, offset=4, budget=Budget(max_seconds=.01))
        self.assertEqual(result['next_offset'], 4)
        self.assertFalse(result['all_open_offenses_listed'])

    async def test_status_all_and_bounds_use_epochs_without_timezone_or_aql(self):
        api = API([offense(1, status='CLOSED')])
        result = await list_offenses(api, status='ALL', start_time_from=EPOCH, start_time_to=EPOCH)
        self.assertEqual(api.calls[0][1]['filter'], f'start_time >= {EPOCH} and start_time <= {EPOCH}')
        self.assertTrue(result['ranking']['complete_selection_ranked'])
        self.assertFalse(result['all_open_offenses_listed'])

    async def test_wrong_status_out_of_window_and_duplicate_ids_fail(self):
        for rows, kwargs in (([offense(1, status='CLOSED')], {}),
                             ([offense(1), offense(1)], {}),
                             ([offense(2), offense(1)], {}),
                             ([offense(1)], {'start_time_from': EPOCH + 1})):
            with self.subTest(rows=rows):
                result = await list_offenses(API(rows), **kwargs)
                self.assertEqual(result['error']['category'], 'response_format')
                self.assertFalse(result['ranking']['complete_selection_ranked'])

    async def test_invalid_arguments_never_call_upstream_and_old_wildcard_stays_invalid(self):
        for kwargs in ({'status': 'unknown'}, {'offset': -1}, {'offset': True},
                       {'limit': 0}, {'limit': 501}, {'limit': True},
                       {'start_time_from': 10, 'start_time_to': 9}, {'start_time_from': '10'}):
            api = API()
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                await list_offenses(api, **kwargs)
            self.assertEqual(api.calls, [])
        with self.assertRaises(ValueError):
            await find_offenses(API(), 'Synthetic', match='any')

    async def test_public_tool_dispatches_status_only_operation(self):
        handler = AsyncMock(return_value={'synthetic': True})
        with patch('soc_bridge.kiro_server._qradar_query', handler):
            self.assertEqual(await qradar_list_offenses(), {'synthetic': True})
        handler.assert_awaited_once_with('list_offenses', status='OPEN', offset=0, limit=100,
                                        start_time_from=None, start_time_to=None)


class RankingTests(unittest.TestCase):
    def test_lexicographic_order_all_tie_breakers(self):
        rows = [offense(1), offense(2, last_updated_time=EPOCH + 1), offense(3, relevance=6),
                offense(4, credibility=6), offense(5, severity=6), offense(6, magnitude=6), offense(7)]
        self.assertEqual([r['id'] for r in rank_offenses(list(reversed(rows)))], [6, 5, 4, 3, 2, 1, 7])

    def test_unknown_is_not_zero_and_no_numeric_risk_score_is_created(self):
        rows = [offense(1, magnitude=None), offense(2, magnitude=0), offense(3, magnitude=True),
                offense(4, magnitude=11), offense(5, magnitude='10'), offense(6, magnitude=-1)]
        result = rank_offenses(rows)
        self.assertEqual(result[0]['id'], 2)
        for row in result[1:]:
            self.assertIsNone(row['priority']['inputs']['magnitude'])
            self.assertIn('magnitude', row['priority']['missing_or_invalid_fields'])
            self.assertIn('não disponível', row['priority']['rationale'])
        self.assertTrue(all('score' not in row['priority'] for row in result))
        self.assertNotIn('priority', rows[0])  # original metadata is not mutated

    def test_description_does_not_invent_higher_priority_or_a_verdict(self):
        result = rank_offenses([offense(1, description='Synthetic harmless'),
                                offense(2, description='Synthetic Critical Credential Dumping')])
        self.assertEqual([r['id'] for r in result], [1, 2])
        self.assertTrue(all('verdict' not in row['priority'] for row in result))

    def test_all_twenty_existing_schemas_stay_unchanged_and_read_only(self):
        tools = {t.name: t for t in asyncio.run(mcp.list_tools())}
        fixture_dir = Path(__file__).parent / 'fixtures'
        before = json.loads((fixture_dir / 'tool_schemas_master.json').read_text(encoding='utf-8'))
        before.update(json.loads((fixture_dir / 'tool_schemas_context_closure.json').read_text(encoding='utf-8')))
        self.assertEqual(len(before), 20)
        for name, schema in before.items():
            self.assertEqual(tools[name].inputSchema, schema, name)
        self.assertEqual(set(tools) - set(before), {'trend_search_data', 'trend_read_search_resource', 'qradar_list_offenses', 'investigate_offense_case', 'reassess_case', 'list_cases', 'get_case', 'bridge_diagnostics'})
        self.assertTrue(all((t.annotations.readOnlyHint or t.name in LOCAL_WRITE_TOOLS) and not t.annotations.destructiveHint for t in tools.values()))
        self.assertNotIn('description', tools['qradar_list_offenses'].inputSchema['properties'])


if __name__ == '__main__':
    unittest.main()
