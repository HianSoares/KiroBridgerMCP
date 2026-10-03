"""Synthetic discovery, continuation, isolation and account-role regressions."""
import asyncio
import json
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch
from soc_bridge.offense_batch import find_offenses, investigate_offenses, consolidate
from soc_bridge.lockout_evidence import analyze, correlate, fields, pivot
from soc_bridge.ariel_collection import Budget
from soc_bridge.aql_fields import FieldCatalog, EVENT_COLUMNS, plan_select
from soc_bridge.kiro_server import mcp
from soc_bridge.transports import QRADAR_TOOLS, RestrictedMCP

DESC = 'Synthetic: Multiple Lockout containing Account Lockout'
MS = int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp() * 1000)


def offense(oid):
    return dict(id=oid, description=DESC, status='OPEN', start_time=MS, last_updated_time=MS + 10000,
                event_count=1, flow_count=0, rules=[], offense_source='192.0.2.4')


class ListClient:
    def __init__(self, rows=None, total=None):
        self.rows = [offense(1), offense(2), offense(3)] if rows is None else rows
        self.total, self.calls = total, []
    async def call(self, name, args):
        self.calls.append((name, args))
        assert name == 'list_offenses'
        data = dict(offenses=self.rows[args['offset']:args['offset'] + args['limit']])
        if self.total is not None:
            data['total_count'] = self.total
        return data


def report(oid, plans=None):
    return dict(offense_id=oid, metadata=offense(oid), continuation_plan=plans or [], queries={},
                closure_assessment=dict(recommendation='Manter aberta', ready_to_close=False, confidence='Insuficiente',
                                        suggested_note=f'Offense {oid}: causa não comprovada'))


def xml_row(eid=4740, user='acct_test', domain='EXAMPLE'):
    payload = (f'<Event><System><EventID>{eid}</EventID><Computer>DC-DEMO</Computer></System>'
               '<EventData><Data Name="SubjectUserName">DC-DEMO$</Data>'
               f'<Data Name="TargetUserName">{user}</Data><Data Name="TargetDomainName">{domain}</Data>'
               '<Data Name="CallerComputerName">CLIENT-DEMO</Data><Data Name="Status">0xC000006A</Data>'
               '<Data Name="IpAddress">192.0.2.7</Data></EventData></Event>')
    return dict(raw_payload=payload, starttime=MS, devicetime=MS - 1000, username='DC-DEMO$', log_source='DC-DEMO')


def finding(rows):
    return dict(rows=rows, search_id='demo-search', result_set_complete=True, truncated_rows={})


class DiscoveryTests(unittest.IsolatedAsyncioTestCase):
    async def test_literal_filter_raw_json_and_cursor(self):
        client = ListClient()
        data = await find_offenses(client, DESC, limit=2)
        args = client.calls[0][1]
        self.assertEqual(args['filter'], 'status = "OPEN"')
        self.assertNotIn('description', args['filter'])
        self.assertFalse(args['format_output'])
        self.assertEqual(args['sort'], '+id')
        self.assertFalse(data['discovery_exhausted'])
        page = await find_offenses(client, **data['continuation_plan'][0]['parameters'])
        self.assertEqual([r['id'] for r in page['offenses']], [3])
        self.assertTrue(page['discovery_exhausted'])

    async def test_known_total_full_last_page_exhausted(self):
        self.assertTrue((await find_offenses(ListClient(total=3), DESC, offset=1, limit=2))['discovery_exhausted'])

    async def test_description_quotes_remain_literal(self):
        desc = 'Synthetic "quoted" or status="CLOSED"'
        client = ListClient([dict(offense(1), description=desc)])
        await find_offenses(client, desc)
        self.assertEqual(client.calls[0][1]['filter'], 'status = "OPEN"')

    async def test_contains_all_and_epoch_bounds(self):
        client = ListClient([offense(1)])
        data = await find_offenses(client, 'Multiple Lockout', status='ALL', match='contains', start_time_from=MS, start_time_to=MS)
        self.assertTrue(data['page_complete'])
        self.assertNotIn('description', client.calls[0][1]['filter'])
        self.assertNotIn('status =', client.calls[0][1]['filter'])
        self.assertIn(f'start_time >= {MS}', client.calls[0][1]['filter'])

    async def test_invalid_input_never_calls_upstream(self):
        for params in (dict(description=''), dict(description=DESC, limit=True), dict(description=DESC, offset=-1),
                       dict(description=DESC, status='other'), dict(description=DESC, match='bad'),
                       dict(description=DESC, start_time_from=10, start_time_to=1)):
            client = ListClient()
            with self.subTest(params=params), self.assertRaises(ValueError):
                await find_offenses(client, **params)
            self.assertEqual(client.calls, [])

    async def test_duplicate_wrong_scope_and_order_not_empty_success(self):
        for rows in ([offense(1), offense(1)], [dict(offense(1), status='CLOSED')], [dict(offense(1), id=True)], [offense(2), offense(1)]):
            with self.subTest(rows=rows):
                data = await find_offenses(ListClient(rows), DESC)
                self.assertFalse(data['page_complete'])
                self.assertEqual(data['error']['category'], 'response_format')

    async def test_unavailable_not_empty(self):
        client = ListClient()
        client.call = AsyncMock(side_effect=RuntimeError('Optional MCP tool unavailable: list_offenses'))
        data = await find_offenses(client, DESC)
        self.assertEqual(data['error']['category'], 'tool_unavailable')
        self.assertFalse(data['discovery_exhausted'])

    async def test_empty_before_known_total_rejected(self):
        self.assertFalse((await find_offenses(ListClient([], total=10), DESC))['page_complete'])

    async def test_timeout_same_cursor(self):
        client = ListClient()
        async def slow(*args):
            await asyncio.sleep(.1)
        client.call = slow
        data = await find_offenses(client, DESC, offset=5, budget=Budget(max_seconds=.01))
        self.assertFalse(data['page_complete'])
        self.assertEqual(data['continuation_plan'][0]['parameters']['offset'], 5)


class BatchTests(unittest.IsolatedAsyncioTestCase):
    async def test_description_batches_distinct_ids(self):
        client = ListClient(total=3)
        verifier = AsyncMock(side_effect=lambda q, oid, *a, **kw: report(oid))
        with patch('soc_bridge.offense_batch.verify_offense', verifier):
            first = await investigate_offenses(client, description=DESC, max_offenses=2)
            second = await investigate_offenses(client, **first['continuation_plan'][0]['parameters'])
        self.assertEqual([c.args[1] for c in verifier.call_args_list], [1, 2, 3])
        self.assertFalse(first['all_matching_offenses_investigated'])
        self.assertFalse(second['all_matching_offenses_investigated'])

    async def test_explicit_ids_deduplicated_pending_preserved(self):
        verifier = AsyncMock(side_effect=lambda q, oid, *a, **kw: report(oid))
        with patch('soc_bridge.offense_batch.verify_offense', verifier):
            data = await investigate_offenses(ListClient(), offense_ids=[1, 1, 2, 3], max_offenses=2)
        self.assertEqual([r['offense_id'] for r in data['reports']], [1, 2])
        self.assertEqual(data['continuation_plan'][0]['parameters']['offense_ids'], [3])

    async def test_failure_does_not_abort_later_offenses(self):
        async def verify(q, oid, *args, **kwargs):
            if oid == 1:
                raise RuntimeError('synthetic failure')
            return report(oid)
        with patch('soc_bridge.offense_batch.verify_offense', verify):
            data = await investigate_offenses(ListClient(), offense_ids=[1, 2])
        self.assertEqual(data['failures'][0]['offense_id'], 1)
        self.assertEqual(data['reports'][0]['offense_id'], 2)
        self.assertFalse(data['collection_complete'])

    async def test_partial_ariel_keeps_search_id(self):
        plan = dict(action='fetch_next_page', search_id='existing-demo-job', cursor=500,
                    tools=['qradar_get_search_results'])
        with patch('soc_bridge.offense_batch.verify_offense', AsyncMock(return_value=report(1, [plan]))):
            data = await investigate_offenses(ListClient(), offense_ids=[1])
        self.assertEqual(data['continuation_plan'][0]['search_id'], 'existing-demo-job')
        self.assertFalse(data['collection_complete'])
        self.assertNotIn('parameters', data['continuation_plan'][0])

    async def test_cases_share_deadline(self):
        budgets = []
        async def verify(q, oid, *args, **kwargs):
            budgets.append(kwargs['budget'].max_seconds)
            return report(oid)
        with patch('soc_bridge.offense_batch.verify_offense', verify):
            await investigate_offenses(ListClient(), offense_ids=[1, 2, 3], budget=Budget(max_seconds=30))
        for value, ceiling in zip(budgets, [10, 15, 30]):
            self.assertLessEqual(value, ceiling)

    async def test_expired_budget_preserves_unstarted_ids(self):
        budget = Budget(max_seconds=1, clock=lambda: 0)
        budget.clock = lambda: 2
        with patch('soc_bridge.offense_batch.verify_offense', AsyncMock()) as verify:
            data = await investigate_offenses(ListClient(), offense_ids=[1, 2], budget=budget)
        verify.assert_not_called()
        self.assertEqual(set(data['pending_offense_ids']), {1, 2})

    async def test_invalid_ids_and_ambiguous_selection(self):
        for params in (dict(offense_ids=[]), dict(offense_ids=[True]), dict(description=DESC, offense_ids=[1]),
                       dict(offense_ids=[1], max_offenses=6), dict(description=DESC, timezone_verified='yes')):
            with self.subTest(params=params), self.assertRaises(ValueError):
                await investigate_offenses(ListClient(), **params)


class LockoutTests(unittest.TestCase):
    def test_target_caller_and_recording_dc_separate(self):
        record = analyze(finding([xml_row()]), 'events')['records'][0]
        self.assertEqual(record['target_user'], 'acct_test')
        self.assertEqual(record['caller_computer'], 'CLIENT-DEMO')
        self.assertEqual(record['recording_computer'], 'DC-DEMO')

    def test_text_sections_do_not_use_subject(self):
        payload = ('Subject: Account Name: DC-DEMO$ Account Domain: EXAMPLE\n'
                   'Account That Was Locked Out: Account Name: acct_test Account Domain: EXAMPLE\n'
                   'Additional Information: Caller Computer Name: CLIENT-DEMO')
        self.assertEqual(fields(payload)['TargetUserName'], 'acct_test')
        self.assertEqual(fields(payload)['CallerComputerName'], 'CLIENT-DEMO')

    def test_conflicts_withheld_qid_not_eventid(self):
        self.assertNotIn('TargetUserName', fields('<Data Name="TargetUserName">a</Data><Data Name="TargetUserName">b</Data>'))
        result = analyze(finding([dict(event_name='Account locked out', username='someone')]), 'events')
        self.assertFalse(result['detected'])
        self.assertEqual(result['unparsed_lockout_named_rows'], 1)

    def test_candidate_exact_account_no_domain_conflict(self):
        lock = analyze(finding([xml_row()]), 'events')
        auth = analyze(finding([xml_row(4625), xml_row(4771, user='acct_test2'), xml_row(4776, domain='OTHER')]), 'auth')
        links = correlate(lock, auth)
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0]['relation'], 'candidate')
        self.assertEqual(links[0]['status'], '0xC000006A')

    def test_outside_time_not_linked(self):
        row = dict(xml_row(4625), starttime=MS - 901000)
        self.assertEqual(correlate(analyze(finding([xml_row()]), 'events'), analyze(finding([row]), 'auth')), [])

    def test_safe_pivot_and_epoch_bounds(self):
        plan = plan_select(EVENT_COLUMNS, FieldCatalog('events', 'unavailable'))
        spec = pivot(plan, 'LAST 24 HOURS', MS - 900000, MS + 900000, analyze(finding([xml_row()]), 'events'))
        self.assertIn("username = 'acct_test'", spec['query'])
        self.assertIn(f'starttime >= {MS - 900000}', spec['query'])
        self.assertIsInstance(pivot(plan, 'LAST 24 HOURS', MS, MS + 1,
                                   analyze(finding([xml_row(user="a' OR 1=1")]), 'events')), str)

    def test_recurrence_does_not_merge_unknown_domain(self):
        reports = []
        for oid, domain in ((1, 'EXAMPLE'), (2, 'example'), (3, None)):
            item = report(oid)
            item['lockout'] = dict(groups=[dict(target_user='acct_test', target_domain=domain, caller_computer='CLIENT-DEMO')])
            reports.append(item)
        data = consolidate(reports)
        self.assertEqual(data['recurring_lockout_identities'][0]['offenses'], [1, 2])
        self.assertTrue(all(not d['ready_to_close'] for d in data['per_offense_decisions']))


class ExposureTests(unittest.IsolatedAsyncioTestCase):
    async def test_new_tools_readonly_mutations_denied(self):
        tools = {t.name: t for t in await mcp.list_tools()}
        self.assertEqual(len(tools), 20)
        for name in ('qradar_find_offenses', 'qradar_investigate_offenses'):
            self.assertTrue(tools[name].annotations.readOnlyHint)
        client = RestrictedMCP(object(), QRADAR_TOOLS, {'list_offenses'}, {'list_offenses'})
        for name in ('set_offense_status', 'add_offense_note', 'assign_offense'):
            with self.assertRaises(ValueError):
                await client.call(name, {})


class AdditionalRegressions(unittest.IsolatedAsyncioTestCase):
    async def test_failed_query_without_continuation_not_complete(self):
        data = report(1)
        data['queries'] = {'events': {'result_set_complete': False, 'outcome': 'error'},
                           'flows': {'result_set_complete': True}}
        with patch('soc_bridge.offense_batch.verify_offense', AsyncMock(return_value=data)):
            result = await investigate_offenses(ListClient(), offense_ids=[1])
        self.assertFalse(result['collection_complete'])

    async def test_expired_discovery_retains_description_scope(self):
        budget = Budget(max_seconds=1, clock=lambda: 0)
        budget.clock = lambda: 2
        data = await investigate_offenses(ListClient(), description=DESC, offset=5, budget=budget)
        self.assertFalse(data['collection_complete'])
        params = data['continuation_plan'][0]['parameters']
        self.assertEqual(params['description'], DESC)
        self.assertEqual(params['offset'], 5)

    async def test_real_verifier_lockout_pivot_before_flows_and_note(self):
        from test_offense_evidence import QRadar
        from soc_bridge.offense_evidence import collect_offense_evidence
        class LockClient(QRadar):
            async def call(self, name, args):
                data = await super().call(name, args)
                if name == 'create_ariel_search':
                    query = args['query_expression']
                    if 'FROM events' in query:
                        rows = [xml_row()] if 'INOFFENSE' in query else [xml_row(4625)]
                        self.jobs[data['search_id']] = ('events', rows)
                return data
        client = LockClient(metadata=offense(1))
        result = await collect_offense_evidence(client, offense(1))
        self.assertTrue(result['lockout']['detected'])
        self.assertEqual(result['lockout']['event_id_counts'][4740], 1)
        self.assertEqual(result['lockout']['authentication_candidates'][0]['relation'], 'candidate')
        self.assertNotIn('records_for_analysis', result['lockout'])
        jobs = [args['query_expression'] for name, args in client.calls if name == 'create_ariel_search']
        self.assertIn("username = 'acct_test'", jobs[1])
        self.assertIn('FROM flows', jobs[2])
        self.assertIn('4740', result['closure_assessment']['suggested_note'])
        self.assertIn('acct_test', result['closure_assessment']['suggested_note'])
        self.assertIn('CLIENT-DEMO', result['closure_assessment']['suggested_note'])
        self.assertEqual(result['lockout']['root_cause_assessment']['state'], 'unverified')
        self.assertFalse(result['closure_assessment']['ready_to_close'])

    async def test_4776_success_and_unknown_status_are_not_failures(self):
        success = xml_row(4776)
        success['raw_payload'] = success['raw_payload'].replace('0xC000006A', '0x0')
        unknown = xml_row(4776)
        unknown['raw_payload'] = unknown['raw_payload'].replace('0xC000006A', '-')
        context = analyze(finding([success, unknown]), 'auth')
        self.assertEqual(context['records'][0]['authentication_outcome'], 'success')
        self.assertEqual(correlate(analyze(finding([xml_row()]), 'events'), context), [])

    async def test_truncated_payload_does_not_make_link(self):
        context = finding([xml_row(4625)])
        context['truncated_rows'] = {'0': ['raw_payload']}
        self.assertEqual(correlate(analyze(finding([xml_row()]), 'events'), analyze(context, 'auth')), [])

    async def test_json_target_fields_and_full_group_census_before_preview(self):
        row = dict(xml_row(), raw_payload=json.dumps(dict(EventID=4740, SubjectUserName='DC-DEMO$',
                   TargetUserName='acct_test', TargetDomainName='EXAMPLE', CallerComputerName='CLIENT-DEMO')))
        data = analyze(finding([row] * 125), 'events')
        self.assertEqual(data['event_id_counts'][4740], 125)
        self.assertEqual(data['groups'][0]['rows'], 125)
        self.assertEqual(data['records_omitted'], 25)
        self.assertEqual(len(data['records']), 100)
