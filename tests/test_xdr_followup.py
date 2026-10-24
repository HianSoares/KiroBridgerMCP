"""Workbench alert + XDR Data Explorer: seeds with provenance, planned Search phases, record digest,
volume without fabrication, partitioned continuation and the initial-assessment scope. Synthetic data only."""

import asyncio
import json
import unittest
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

from soc_bridge.alert_investigation import investigate_vision_alert, render_alert_markdown
from soc_bridge.trend_search import collect, parameters

from trend_fixtures import ALERT_ID, GUID, HOST, NOW, OAT_ITEM, T0, FakeVision, procdump_search, z

RC_ID = "WB-SYNTH-RCLONE-0001"
RC = "C:\\Users\\Public\\rc\\rclone.exe"
RC_CMD = "rclone.exe copy C:\\Finance\\Reports remote:archive-bucket --config C:\\Users\\Public\\rc\\rclone.conf"
SPARSE = {"id": RC_ID, "model": "Synthetic RClone Detection", "severity": "medium",
          "createdDateTime": z(T0 + timedelta(minutes=8)),
          "impactScope": {"entities": [{"entityType": "host", "entityId": GUID,
                                        "entityValue": {"name": HOST, "guid": GUID}, "provenance": ["Alert"]}]},
          "matchedRules": [{"id": "r1", "name": "Synthetic cloud sync tool", "matchedFilters": [
              {"id": "f1", "name": "Sync utility launched", "matchedDateTime": z(T0 + timedelta(seconds=2)),
               "matchedEvents": [{"uuid": "ev-rc-launch", "matchedDateTime": z(T0), "type": "TELEMETRY_PROCESS"}]}]}]}


def native(uuid, seconds, **fields):
    return {"uuid": uuid, "eventTime": z(T0 + timedelta(seconds=seconds)), "endpointGuid": GUID,
            "endpointHostName": HOST, "endpointIp": ["192.0.2.60"], **fields}


LAUNCH = native("ev-rc-launch", 0, processFilePath="C:\\Windows\\System32\\cmd.exe", processHashId="inst-cmd",
                processCmd="cmd.exe /c sync.cmd", processPid=3100, logonUser="EXAMPLE\\backup.synth",
                parentFilePath="C:\\Windows\\System32\\svchost.exe", parentCmd="svchost.exe -k netsvcs",
                objectFilePath=RC, objectCmd=RC_CMD, objectPid=3200, objectProcessHashId="inst-rc",
                eventId=1, eventSubId=2)
READ = native("ev-rc-read", 30, processFilePath=RC, processCmd=RC_CMD, processHashId="inst-rc", processPid=3200,
              processUser="EXAMPLE\\backup.synth", objectFilePath="C:\\Finance\\Reports\\q3.xlsx",
              objectFileSize=482133, eventId=3, eventSubId=102)
CONNECT = native("ev-rc-net", 31, processFilePath=RC, processCmd=RC_CMD, processHashId="inst-rc", processPid=3200,
                 src="192.0.2.60", spt=50123, dst="198.51.100.77", dpt=443, eventId=4, eventSubId=401)


def client(rows_for):
    return SimpleNamespace(call=AsyncMock(side_effect=lambda tool, args: {"items": rows_for(tool, args)}))


def run(coro):
    return asyncio.run(coro)


class NoQRadar:
    async def call(self, name, args):
        raise AssertionError("QRadar is not used in this scenario")


class SparseWorkbenchTests(unittest.TestCase):
    def setUp(self):
        # Workbench gives only host/GUID and a matched event; the alert's own pivots return nothing.
        self.vision = FakeVision(alert=SPARSE, search=lambda tool, args: [])
        self.report = run(investigate_vision_alert(NoQRadar(), self.vision, RC_ID, enable_vision_search=True,
                                                   qradar_correlation=False, now=NOW))
        self.follow = self.report["xdr_followup"]

    def test_initial_investigation_runs_once_and_seeds_keep_provenance(self):
        self.assertEqual([c for c in self.vision.calls if c[0] == "workbench_alert_detail_get"],
                         [("workbench_alert_detail_get", {"alertId": RC_ID})])
        seeds = self.follow["seeds"]
        self.assertEqual(seeds["identifiers"]["guids"], [GUID])
        self.assertEqual(seeds["identifiers"]["hosts"], [HOST.lower()])
        self.assertTrue(all(e["sources"] for e in seeds["endpoints"]))
        self.assertEqual(seeds["times"]["anchor_provisional"], False)

    def test_phases_cover_pertinent_sources_without_asking_for_ip_or_host(self):
        phases = self.follow["phases"]
        kinds = {p["kind"] for p in phases}
        self.assertTrue({"command_series", "posterior_activity", "detections", "network_source",
                         "transfer_command", "transfer_launch", "transfer_config"} <= kinds)
        for phase in phases:
            parameters(**phase["parameters"])  # every phase is a valid trend_search_data call as planned
            self.assertIn(GUID, phase["parameters"]["query"].lower())
        keys = [(p["parameters"]["source"], p["parameters"]["query"], p["parameters"]["start_date_time"],
                 p["parameters"]["end_date_time"]) for p in phases]
        self.assertEqual(len(keys), len(set(keys)))  # no identical call planned twice
        self.assertEqual(self.follow["transfer"]["stages"][0]["stage"], "binary_present")
        qradar = self.follow["volume_sources"][1]
        self.assertEqual(qradar["host_ips"], [])
        self.assertIn("endpointIp", qradar["note"])  # obtained from Search records, not from the analyst

    def test_direct_search_adds_command_instance_and_connections(self):
        phase = next(p for p in self.follow["phases"] if p["kind"] == "command_series")
        result = run(collect(client(lambda tool, args: [LAUNCH, READ, CONNECT]), parameters(**phase["parameters"])))
        digest = result["evidence_digest"]
        self.assertIn(RC_CMD, [c["cmd"] for c in digest["commands"]])
        rclone = next(a for a in digest["actors"] if a["instance"] == "inst-rc")
        self.assertEqual((rclone["user"], rclone["image"]), ("EXAMPLE\\backup.synth", RC))
        launcher = next(a for a in digest["actors"] if a["instance"] == "inst-cmd")
        self.assertEqual(launcher["parent"]["image"], "C:\\Windows\\System32\\svchost.exe")
        connection = digest["connections"][0]
        self.assertEqual((connection["dst"], connection["dpt"], connection["actor_instance"]),
                         ("198.51.100.77", 443, "inst-rc"))
        self.assertIn("same record", connection["attribution"])
        self.assertEqual(digest["file_objects"][1]["object"], "C:\\Finance\\Reports\\q3.xlsx")
        seeds = self.follow["seeds"]["identifiers"]
        added = {k: sorted(set(v) - set(seeds[k])) for k, v in digest["identifiers"].items()}
        self.assertEqual(added["instances"], ["inst-cmd", "inst-rc"])
        self.assertEqual(added["destinations"], ["198.51.100.77"])
        self.assertEqual(added["users"], ["example\\backup.synth"])
        self.assertEqual(added["ips"], ["192.0.2.60"])

    def test_absent_byte_counters_produce_no_volume(self):
        result = run(collect(client(lambda tool, args: [LAUNCH, READ, CONNECT]),
                             parameters(**self.follow["phases"][0]["parameters"])))
        volume = result["evidence_digest"]["volume"]
        self.assertIsNone(volume["total"])
        self.assertEqual(volume["state"], "no_counter_fields_in_returned_records")
        self.assertIn("not established", volume["missing"])
        self.assertIn("objectFileSize", volume["not_transfer_volume"])  # file size is not transferred bytes
        self.assertIn("dpt", volume["not_transfer_volume"])
        self.assertEqual(result["evidence_digest"]["transfer_counters"], [])

    def test_counters_keep_session_and_direction_and_are_never_summed(self):
        flow = dict(CONNECT, flowId="flow-9", bytesSent=1000, bytesReceived=200)
        later = dict(flow, uuid="ev-rc-net-2", bytesSent=5000)  # same session read again: possibly cumulative
        result = run(collect(client(lambda tool, args: [flow, later]), parameters(**self.follow["phases"][0]["parameters"])))
        digest = result["evidence_digest"]
        self.assertEqual(sorted(c["value"] for c in digest["transfer_counters"]), [200, 200, 1000, 5000])
        sent = [c for c in digest["transfer_counters"] if c["field"] == "bytesSent"]
        self.assertIn("outbound", sent[0]["direction"])
        self.assertEqual(sent[0]["session"]["flowId"], "flow-9")
        self.assertIsNone(digest["volume"]["total"])
        self.assertTrue(any(r["field"] == "bytesSent" and r["readings"] == 2 for r in digest["volume"]["repeated_sessions"]))
        self.assertNotIn("6000", json.dumps(digest))  # no sum of repeated readings anywhere

    def test_report_renders_the_plan_and_the_assessment_scope(self):
        text = render_alert_markdown(self.report)
        self.assertIn("## XDR Data Explorer follow-up", text)
        self.assertIn("## Assessment of the initial collection", text)
        self.assertIn('"source": "endpoint"', text)
        asm = self.report["assessment"]
        self.assertIn("trend_search_data", asm["scope"]["excludes"])
        self.assertIn("coleta inicial", asm["note_pt"])


class PartitionedSearchTests(unittest.TestCase):
    def test_large_result_is_partitioned_with_continuation_and_partial_digest(self):
        def full(tool, args):
            return [native(f"bulk-{args['startDateTime']}-{i}", 0, processHashId=f"inst-{i}",
                           processFilePath=RC, processCmd=RC_CMD) for i in range(50)]
        selection = parameters('endpointGuid:"' + GUID + '"', start_date_time=z(T0), end_date_time=z(T0 + timedelta(hours=2)),
                               top=50, max_calls=3, limit=5000)
        result = run(collect(client(full), selection))
        self.assertFalse(result["result_set_complete"])
        plans = result["continuation_plan"]
        self.assertTrue(plans)
        windows = {(p["parameters"]["start_date_time"], p["parameters"]["end_date_time"]) for p in plans}
        self.assertNotIn((selection["start_date_time"], selection["end_date_time"]), windows)  # no identical retry
        self.assertIn("partial", result["evidence_digest"]["volume"]["coverage"])
        nxt = plans[0]["parameters"]
        follow = run(collect(client(lambda tool, args: [LAUNCH]), parameters(**nxt)))
        self.assertTrue(follow["result_set_complete"])


class AuthorizationPendingTests(unittest.TestCase):
    def test_pending_authorization_keeps_technical_facts_and_blocks_benign_true_positive(self):
        vision = FakeVision(search=procdump_search, oat=lambda a: {"items": [OAT_ITEM]})
        report = run(investigate_vision_alert(NoQRadar(), vision, ALERT_ID, enable_vision_search=True,
                                              qradar_correlation=False, now=NOW))
        asm = report["assessment"]
        self.assertEqual(asm["requirements"]["execution_observed"]["status"], "confirmed")
        self.assertTrue(asm["authorization"]["pending"])
        self.assertNotEqual(asm["classification"], "Benign True Positive")
        self.assertTrue(asm["facts"])
        self.assertIn("Autorização externa pendente", asm["note_pt"])
        self.assertIn(asm["facts"][0][:40], asm["note_pt"])
        instances = report["xdr_followup"]["seeds"]["identifiers"]["instances"]
        self.assertIn("inst-pd", instances)
        kinds = {p["kind"] for p in report["xdr_followup"]["phases"]}
        self.assertIn("instance_activity", kinds)
        self.assertIsNone(report["xdr_followup"]["transfer"])  # a dump alert is not a transfer hypothesis


if __name__ == "__main__":
    unittest.main()
