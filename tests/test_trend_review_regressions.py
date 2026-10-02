"""Synthetic regressions for false completeness, process attribution and dispositions."""
import asyncio
import copy
import unittest
from datetime import timedelta

from soc_bridge.alert_assessment import assess
from soc_bridge.alert_discovery import discover
from soc_bridge.ariel_collection import Budget
from soc_bridge.dump_analysis import analyze
from soc_bridge.time_anchor import build_clocks
from soc_bridge.trend_qradar import relate
from soc_bridge.trend_records import normalize
from soc_bridge.vision_search import oat
from soc_bridge.workbench_extract import parse_alert
from trend_fixtures import ALERT, APP_LAUNCH, GUID, HOST, PD, PD_ACCESS, PD_LAUNCH, PD_WRITE, T0, FakeVision, rec, z


def run(coro):
    return asyncio.run(coro)


def norm(*rows):
    return [normalize(row, 'search_endpoint_activities_list', 'q') for row in rows]


def base_report(**extra):
    return {'alert_id': 'WB-SYNTH-REVIEW', 'alert': {}, 'clocks': {'anchor': {'provisional': False}},
            'auto_pivots': {'record_counts': {'linked': 1}, 'continuation': []},
            'dump_analysis': {'dumps': []}, 'enrichment': {}, 'qradar_correlation': {}, **extra}


class AssessmentRegressionTests(unittest.TestCase):
    def test_ordinary_connection_does_not_establish_malice_or_dump_transfer(self):
        dump = {'intent': 'application dump', 'execution': 'observed: records',
                'dump_file': {'status': 'file reference', 'paths': ['C:\\app.dmp']},
                'target': {'status': 'candidate', 'image': 'vendor.exe'},
                'connections': [{'dst': '192.0.2.10', 'dpt': 443}]}
        result = assess(base_report(dump_analysis={'dumps': [dump]}))
        self.assertEqual(result['classification'], 'Inconclusive')
        self.assertFalse(result['malicious_discriminators'])
        self.assertIn('transferred content is not established', ' '.join(result['facts']))

    def test_risk_label_alone_does_not_establish_malicious_use(self):
        result = assess(base_report(enrichment={'suspicious_objects:abc': {
            'state': 'collected', 'items': [{'riskLevel': 'high'}]}}))
        self.assertEqual(result['classification'], 'Inconclusive')
        self.assertTrue(result['suspicious_indicators'])

    def test_oat_failure_and_search_failure_remain_blocking_without_continuation(self):
        for kind in ('oat', 'pivots'):
            with self.subTest(kind=kind):
                result = assess(base_report(auto_pivots={'record_counts': {'linked': 1},
                    'continuation': [], kind: [{'state': 'partial', 'tool': 'synthetic'}]}))
                self.assertTrue(any('coverage partial' in s for s in result['blocking']))


class OATRegressionTests(unittest.TestCase):
    def vision(self, first=None):
        class V:
            calls = []
            async def call(self, tool, args):
                self.calls.append(dict(args))
                if args.get('nextBatchToken'):
                    raise RuntimeError('synthetic second-batch failure')
                return {'items': first if first is not None else [{'uuid': 'first'}], 'nextBatchToken': 'resume-first'}
        v = V()
        v.calls = []
        return v

    def test_second_batch_failure_preserves_rows_and_exact_resume_parameters(self):
        v = self.vision()
        result = run(oat(v, Budget(), "agentGuid eq 'synthetic'", T0, T0 + timedelta(hours=1)))
        self.assertEqual(result['state'], 'partial')
        self.assertEqual([r['uuid'] for r in result['items']], ['first'])
        resume = result['continuation']
        self.assertEqual(resume['nextBatchToken'], 'resume-first')
        self.assertEqual(resume['filter'], "agentGuid eq 'synthetic'")
        self.assertEqual(resume['detectedStartDateTime'], z(T0))
        self.assertEqual(resume['detectedEndDateTime'], z(T0 + timedelta(hours=1)))
        self.assertEqual(resume['top'], '200')

    def test_empty_first_batch_with_more_and_failed_second_is_not_empty_complete(self):
        result = run(oat(self.vision([]), Budget(), 'q', T0, T0 + timedelta(hours=1)))
        self.assertEqual(result['state'], 'partial')
        self.assertTrue(result['continuation'])

    def test_resume_starts_at_retained_token_not_first_page(self):
        async def call(tool, args):
            self.assertEqual(args['nextBatchToken'], 'resume-first')
            return {'items': [{'uuid': 'second'}]}
        v = type('V', (), {'call': staticmethod(call)})()
        result = run(oat(v, Budget(), 'q', T0, T0 + timedelta(hours=1), next_batch_token='resume-first'))
        self.assertEqual(result['state'], 'complete_in_window')
        self.assertTrue(result['resumed'])
        self.assertIn('does not include earlier batches', result['coverage_note'])
        self.assertEqual([r['uuid'] for r in result['items']], ['second'])

    def test_budget_before_first_batch_retains_start_plan_and_calls_nothing(self):
        v = self.vision()
        result = run(oat(v, Budget(max_calls=0), 'q', T0, T0 + timedelta(hours=1)))
        self.assertEqual(result['state'], 'not_started')
        self.assertEqual(result['continuation']['action'], 'start_oat')
        self.assertEqual(v.calls, [])

    def test_repeated_token_cannot_claim_complete_or_loop_forever(self):
        async def call(tool, args):
            return {'items': [{'uuid': 'same'}], 'nextBatchToken': 'loop-token'}
        v = type('V', (), {'call': staticmethod(call)})()
        result = run(oat(v, Budget(), 'q', T0, T0 + timedelta(hours=1)))
        self.assertEqual(result['state'], 'partial')
        self.assertEqual(result['batches'], 2)
        self.assertTrue(result['errors'])


class CorrelationRegressionTests(unittest.TestCase):
    def trend(self, **extra):
        return normalize({**PD_LAUNCH, "objectLaunchTime": z(T0 + timedelta(seconds=1)), **extra},
                         'search_endpoint_activities_list', 'q')

    def qr(self, **extra):
        return {'event_id': 1, 'computer': HOST, 'image': PD, 'command': PD_LAUNCH['objectCmd'],
                'pid': 6000, 'utc_time': z(T0 + timedelta(seconds=1)), 'sha256': 'cd' * 32,
                'provenance': {'search_id': 'synthetic'}, **extra}

    def test_same_binary_and_command_on_another_date_is_only_candidate(self):
        result = relate(self.trend(), self.qr(utc_time=z(T0 - timedelta(days=1))))
        self.assertEqual(result['label'], 'candidate')
        self.assertFalse(result['execution_match']['compatible_creation'])

    def test_positive_creation_matches_endpoint_pid_launch_and_same_role_content(self):
        result = relate(self.trend(), self.qr())
        self.assertEqual(result['label'], 'confirmed')
        self.assertEqual(result['trend_role'], 'object')
        self.assertTrue(result['execution_match']['compatible_creation'])

    def test_file_identity_without_launch_or_pid_never_confirms_execution(self):
        launch = dict(PD_LAUNCH)
        launch.pop('objectLaunchTime')
        trend = norm(launch)[0]
        self.assertEqual(relate(trend, self.qr())['label'], 'candidate')
        self.assertEqual(relate(self.trend(), self.qr(pid=None))['label'], 'candidate')

    def test_other_sysmon_event_type_or_truncated_payload_stays_candidate(self):
        for qr in (self.qr(event_id=10), self.qr(payload_truncated_by_bridge=True)):
            with self.subTest(qr=qr):
                self.assertEqual(relate(self.trend(), qr)['label'], 'candidate')

    def test_launch_after_observed_event_cannot_confirm(self):
        future = z(T0 + timedelta(seconds=30))
        self.assertEqual(relate(self.trend(objectLaunchTime=future), self.qr(utc_time=future))['label'], 'candidate')

    def test_matching_content_and_pid_must_be_in_same_role(self):
        trend = self.trend(processPid=6000, processLaunchTime=z(T0 + timedelta(seconds=1)),
                           objectPid=9000)
        self.assertNotEqual(relate(trend, self.qr())['label'], 'confirmed')


class DiscoveryRegressionTests(unittest.TestCase):
    def test_object_process_is_followed_even_when_first_search_only_finds_launch(self):
        def search(tool, args):
            if 'processHashId:"inst-pd"' in args['query']:
                return [PD_WRITE]
            return [PD_LAUNCH] if tool == 'search_endpoint_activities_list' else []
        v = FakeVision(search=search)
        parsed = parse_alert(ALERT)
        result = run(discover(v, Budget(max_calls=100, max_partitions=100), parsed,
                              build_clocks(ALERT, parsed)['anchor']))
        pivots = result['instance_followups']
        child = next(p for p in pivots if p['process_hash_id'] == 'inst-pd')
        self.assertEqual(child['source_roles'], ['object'])
        self.assertIn(GUID, child['query'])
        self.assertTrue(any(r['uuid'] == PD_WRITE['uuid'] for r in result['records_all']))

    def test_same_instance_string_on_two_endpoints_is_not_merged(self):
        other_guid = 'ffffffff-1111-4222-8333-444444444444'
        alert = copy.deepcopy(ALERT)
        alert['impactScope']['entities'].append({'entityType': 'host', 'entityId': other_guid,
            'entityValue': {'guid': other_guid, 'name': 'other.example.test'}})
        other = dict(PD_LAUNCH, uuid='other-launch', endpointGuid=other_guid, endpointHostName='other.example.test')
        v = FakeVision(search=lambda tool, args: [PD_LAUNCH, other] if tool == 'search_endpoint_activities_list' else [])
        parsed = parse_alert(alert)
        result = run(discover(v, Budget(max_calls=100, max_partitions=100), parsed, build_clocks(alert, parsed)['anchor']))
        children = [p for p in result['instance_followups'] if p['process_hash_id'] == 'inst-pd']
        self.assertEqual(len(children), 2)
        self.assertEqual(len({p['query'] for p in children}), 2)


class DumpRegressionTests(unittest.TestCase):
    def analyze(self, rows, vision=None):
        return run(analyze(vision or FakeVision(), Budget(max_calls=10), norm(*rows),
                           [{'guid': GUID, 'name': HOST, 'ips': []}]))['dumps']

    def test_missing_instance_does_not_attribute_unrelated_dump(self):
        launch = dict(PD_LAUNCH)
        launch.pop('objectProcessHashId')
        unrelated = dict(PD_WRITE, endpointGuid='ffffffff-1111-4222-8333-444444444444', endpointHostName='other.example.test')
        result = self.analyze([launch, unrelated])[0]
        self.assertFalse(result['dump_file'].get('paths'))
        self.assertFalse(result['dump_file']['candidates'])

    def test_matching_pid_and_launch_without_instance_remain_candidate(self):
        launch, write = dict(PD_LAUNCH), dict(PD_WRITE)
        launch.pop('objectProcessHashId')
        write.pop('processHashId')
        write['processLaunchTime'] = launch['objectLaunchTime']
        result = self.analyze([launch, write])[0]['dump_file']
        self.assertFalse(result.get('paths'))
        self.assertTrue(result['candidates'])
        self.assertEqual(result['candidates'][0]['relation'], 'candidate_pid_launch_time')

    def test_missing_pid_cannot_form_pid_launch_candidate(self):
        launch, write = dict(PD_LAUNCH), dict(PD_WRITE)
        for key in ('objectProcessHashId', 'objectPid'):
            launch.pop(key)
        for key in ('processHashId', 'processPid'):
            write.pop(key)
        write['processLaunchTime'] = launch['objectLaunchTime']
        result = self.analyze([launch, write])[0]['dump_file']
        self.assertFalse(result.get('paths'))
        self.assertFalse(result['candidates'])

    def test_no_endpoint_identity_is_not_a_shared_endpoint(self):
        launch, write = dict(PD_LAUNCH), dict(PD_WRITE)
        for r in (launch, write):
            r.pop('endpointGuid')
            r.pop('endpointHostName')
        self.assertFalse(self.analyze([launch, write])[0]['dump_file'].get('paths'))

    def test_positive_same_endpoint_instance_attributes_reference_but_not_creation(self):
        dump = self.analyze([APP_LAUNCH, PD_LAUNCH, PD_ACCESS, PD_WRITE])[0]
        self.assertEqual(dump['dump_file']['paths'], [PD_WRITE['objectFilePath']])
        self.assertFalse(dump['dump_file']['creation_confirmed'])
        self.assertEqual(dump['target']['status'], 'confirmed by process-instance ID')
        self.assertTrue(dump['execution'].startswith('observed'))

    def test_reference_before_launch_or_on_other_endpoint_is_excluded(self):
        early = dict(PD_WRITE, eventTime=z(T0 - timedelta(minutes=1)))
        other = dict(PD_WRITE, endpointGuid='ffffffff-1111-4222-8333-444444444444')
        for bad in (early, other):
            with self.subTest(bad=bad):
                self.assertFalse(self.analyze([PD_LAUNCH, bad])[0]['dump_file'].get('paths'))

    def test_pid_reuse_by_same_image_is_still_ambiguous(self):
        reused = dict(APP_LAUNCH, uuid='older-app', processHashId='older-instance',
                      processLaunchTime=z(T0 - timedelta(hours=2)))
        no_target_instance = dict(PD_ACCESS)
        no_target_instance.pop('objectProcessHashId')
        target = self.analyze([reused, APP_LAUNCH, PD_LAUNCH, no_target_instance, PD_WRITE])[0]['target']
        self.assertEqual(target['status'], 'ambiguous (PID reuse)')

    def test_connection_before_dump_or_on_other_host_is_not_attributed(self):
        for r in (rec('early-net', -60, processHashId='inst-pd', dst='192.0.2.10'),
                  dict(rec('other-net', 10, processHashId='inst-pd', dst='192.0.2.10'),
                       endpointGuid='ffffffff-1111-4222-8333-444444444444')):
            with self.subTest(r=r):
                self.assertFalse(self.analyze([PD_LAUNCH, PD_WRITE, r])[0]['connections'])

    def test_positive_connection_is_kept_as_observation_without_transfer_claim(self):
        network = rec('network', 10, processFilePath=PD, processHashId='inst-pd', dst='192.0.2.10', dpt=443)
        dump = self.analyze([PD_LAUNCH, PD_WRITE, network])[0]
        self.assertEqual(len(dump['connections']), 1)
        self.assertFalse(dump['connections'][0]['dump_transfer_confirmed'])
        self.assertTrue(any('connection alone' in p for p in dump['not_proven']))

    def test_basename_match_in_another_directory_is_only_candidate(self):
        other = dict(PD_WRITE, uuid='other-path', eventTime=z(T0 + timedelta(minutes=10)),
                     processFilePath='C:\\Tools\\other.exe', processHashId='other-actor',
                     objectFilePath='C:\\Unrelated\\app_4321.dmp')
        v = FakeVision(search=lambda tool, args: [other])
        dump = self.analyze([PD_LAUNCH, PD_WRITE], v)[0]
        follow = dump['followups'][0]['records'][0]
        self.assertEqual(follow['file_relation'], 'basename only (candidate)')
        self.assertEqual(follow['operation'], 'unverified')


if __name__ == '__main__':
    unittest.main()
