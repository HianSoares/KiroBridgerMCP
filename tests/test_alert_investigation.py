"""Alert-first investigation end to end with synthetic Workbench, Search, OAT and QRadar data."""

import asyncio
import unittest
from datetime import timedelta

from soc_bridge.alert_investigation import alert_entities, alert_ips, investigate_vision_alert, render_alert_markdown
from soc_bridge.ariel_collection import Budget
from soc_bridge.transports import ALERT_VISION_TOOLS

from synthetic_lab import Lab
from trend_fixtures import (ALERT, ALERT_ID, CMD, GUID, HOST, IP4, IP6, NOW, PD, FakeVision, procdump_search,
                            sysmon_payload, z, T0, OAT_ITEM)

LEGACY = {"id": "WB-TEST-20260924-00001", "name": "Synthetic legacy alert", "createdDateTime": "2026-09-24T12:00:00Z",
          "impactScope": [{"entityType": "ip", "entityValue": "198.51.100.24"}],
          "indicators": [{"indicatorValue": "192.0.2.8"}], "endpointName": "DEMO-PC", "processName": "tool.exe",
          "description": "contacted 203.0.113.5; narrative only"}


class QRadar(Lab):
    def __init__(self, routes=None, offenses=None):
        super().__init__(routes or {}, offenses=offenses or {71: {"id": 71, "description": "Synthetic offense",
                                                                    "magnitude": 5, "start_time": z(T0),
                                                                    "last_updated_time": z(NOW)}})

    async def call(self, name, args):
        if name == "list_source_addresses":
            self.calls.append((name, args))
            return [{"source_ip": IP4, "offense_ids": [71]}] if IP4 in args["filter"] else []
        if name == "list_local_destination_addresses":
            self.calls.append((name, args))
            return [{"local_destination_ip": "203.0.113.10", "offense_ids": [999]}]
        return await super().call(name, args)


def qradar_with_sysmon():
    row = {"starttime": int((T0.timestamp() + 2) * 1000), "devicetime": int((T0.timestamp() + 1) * 1000),
           "sourceip": IP4, "event_name": "Process Create", "log_source": "Synthetic Sysmon",
           "raw_payload": sysmon_payload(PD, CMD, 6000, 1)}
    other_host = dict(row, raw_payload=sysmon_payload(PD, CMD, 6000, 1, host="ws-other.example.test"))
    return QRadar({"FROM flows": ("flows", [], None), "FROM events WHERE (sourceip": ("events", [row, other_host], None)})


def run(coro):
    return asyncio.run(coro)


class ProcDumpScenarioTests(unittest.TestCase):
    def investigate(self, vision=None, qradar=None, **kwargs):
        vision = vision or FakeVision(search=procdump_search, oat=lambda a: {"items": [OAT_ITEM]})
        return run(investigate_vision_alert(qradar or qradar_with_sysmon(), vision, ALERT_ID, enable_vision_search=True,
                                            ariel_offset_hours=-3, now=NOW, **kwargs)), vision

    def test_dump_chain_separates_intent_execution_file_and_target(self):
        report, _ = self.investigate()
        self.assertEqual(len(report["dump_analysis"]["dumps"]), 1)  # launch, access and write: one instance
        dump = report["dump_analysis"]["dumps"][0]
        self.assertIn("full memory dump of 4321", dump["intent"])
        self.assertTrue(dump["execution"].startswith("observed"))
        self.assertEqual(dump["dump_file"]["status"], "file reference attributed to dump-tool instance")
        self.assertFalse(dump["dump_file"]["creation_confirmed"])
        self.assertEqual(dump["target"]["status"], "confirmed by process-instance ID")
        self.assertTrue(dump["target"]["image"].endswith("VendorApp.exe"))
        kinds = {r["kind"] for f in dump["followups"] for r in f["records"]}
        self.assertIn("compression candidate", kinds)
        self.assertTrue(any("credential extraction" in n for n in dump["not_proven"]))
        self.assertTrue(any("non-LSASS target does not make the activity benign" in h["needs"] for h in dump["hypotheses"]))
        self.assertTrue(any("signature, vendor path, SYSTEM" in h["needs"] for h in dump["hypotheses"]))

    def test_no_automatic_credential_dumping_or_benign_verdict(self):
        report, _ = self.investigate()
        assessment = report["assessment"]
        self.assertEqual(assessment["classification"], "Inconclusive")
        self.assertIn("authorization", assessment["justification"])
        self.assertIn("Inconclusivo", assessment["note_pt"])
        self.assertIn("não publicada", assessment["note_pt"])
        self.assertIn("not a QRadar closing reason", assessment["qradar_closure_note"])

    def test_anchor_prefers_linked_event_time_and_keeps_clocks_apart(self):
        report, _ = self.investigate()
        self.assertEqual(report["anchor"]["time_utc"], z(T0.replace(second=1)))
        self.assertFalse(report["anchor"]["provisional"])
        clocks = report["clocks"]
        self.assertEqual(clocks["alert"]["created"]["time_utc"], ALERT["createdDateTime"])
        self.assertTrue(any(e["kind"] == "OAT ingestion" for e in clocks["detection_or_ingestion"]))
        self.assertEqual(report["auto_pivots"]["record_counts"]["linked"], 1)

    def test_trend_qradar_relation_needs_host_and_identifiers(self):
        report, _ = self.investigate()
        relations = report["qradar_correlation"]["relations"]
        confirmed = [r for r in relations if r["label"] == "confirmed"]
        self.assertTrue(confirmed)
        self.assertTrue(all(r["same_host"] for r in confirmed))
        self.assertTrue(any("command line equal" in r["identifiers_equal"] for r in confirmed))
        self.assertIn("not compared", confirmed[0]["criteria"])
        self.assertFalse(any(r["label"] == "confirmed" and not r["same_host"] for r in relations))
        query = next(q for k, q in report["qradar_correlation"]["queries"].items() if ":events:" in k)
        self.assertIn("starttime >=", query["aql"])
        self.assertIn("LAST 24 HOURS", query["aql"])
        self.assertTrue(query["search_id"])
        ips = {e["ip"]: e for e in report["qradar_correlation"]["ips"]}
        self.assertIn(IP6, ips)
        self.assertTrue(any("IPv6" in n for n in report["qradar_correlation"]["notes"]))

    def test_offense_leads_stay_leads(self):
        report, _ = self.investigate()
        self.assertEqual([o["offense_id"] for o in report["offenses"]], [71])
        self.assertIn("not a process link", report["offenses"][0]["relation"])

    def test_only_allowlisted_read_tools_are_called_and_model_name_never_queried(self):
        report, vision = self.investigate()
        self.assertTrue({tool for tool, _ in vision.calls} <= ALERT_VISION_TOOLS)
        queries = [a.get("query", "") + a.get("filter", "") for _, a in vision.calls]
        self.assertFalse(any("Synthetic Memory Dump" in q or "malName" in q for q in queries))
        markdown = render_alert_markdown(report)
        self.assertIn("Nota sugerida", markdown)
        self.assertIn("Nothing was executed, closed, isolated, posted or submitted", markdown)

    def test_historical_alert_without_verified_timezone_plans_instead_of_guessing(self):
        report, _ = self.investigate(qradar=qradar_with_sysmon())
        late = run(investigate_vision_alert(qradar_with_sysmon(), FakeVision(search=procdump_search), ALERT_ID,
                                            enable_vision_search=True, ariel_offset_hours=-3,
                                            now=NOW + timedelta(days=3)))
        stage = late["qradar_correlation"]["stages"][0]
        self.assertEqual(stage["state"], "not_run")
        self.assertEqual(late["qradar_correlation"]["plan"][0]["action"], "run_with_verified_timezone")
        self.assertIn("starttime >=", late["qradar_correlation"]["plan"][0]["epoch_predicate"])
        self.assertNotIn("not_run", [s.get("state") for s in report["qradar_correlation"]["stages"]])


class GenericDiscoveryTests(unittest.TestCase):
    def test_other_model_uses_entities_not_model_name(self):
        alert = dict(ALERT, model="Any Synthetic Model", name="Any Synthetic Model")
        vision = FakeVision(alert=alert, search=procdump_search)
        report = run(investigate_vision_alert(QRadar(), vision, ALERT_ID, enable_vision_search=True, now=NOW))
        self.assertEqual(report["auto_pivots"]["logic"], "alert-entities-v3")
        self.assertGreater(report["auto_pivots"]["search_calls"], 0)
        self.assertFalse(any("Any Synthetic Model" in a.get("query", "") for _, a in vision.calls))

    def test_multiple_endpoints_are_all_searched(self):
        second = {"entityType": "host", "entityId": "ffffffff-1111-4222-8333-444444444444",
                  "entityValue": {"name": "ws-synth-02.example.test", "guid": "ffffffff-1111-4222-8333-444444444444",
                                  "ips": ["198.51.100.20"]}}
        alert = dict(ALERT, impactScope={"entities": ALERT["impactScope"]["entities"] + [second]})
        vision = FakeVision(alert=alert, search=lambda tool, args: [])
        report = run(investigate_vision_alert(QRadar(), vision, ALERT_ID, enable_vision_search=True, now=NOW))
        queried = " ".join(a.get("query", "") for _, a in vision.calls)
        self.assertIn(GUID, queried)
        self.assertIn("ffffffff-1111-4222-8333-444444444444", queried)
        self.assertEqual(report["auto_pivots"]["host"], "")
        self.assertTrue(any("none was chosen silently" in w for w in report["warnings"]))

    def test_alert_without_identifiers_does_not_search(self):
        alert = {"id": ALERT_ID, "model": "Synthetic", "createdDateTime": z(T0)}
        vision = FakeVision(alert=alert)
        report = run(investigate_vision_alert(QRadar(), vision, ALERT_ID, enable_vision_search=True, now=NOW))
        self.assertEqual(report["auto_pivots"]["discovery_status"], "no identifiers in the alert detail to search with")
        self.assertFalse([t for t, _ in vision.calls if t.startswith("search_")])
        self.assertTrue(report["anchor"]["provisional"])
        self.assertIn("No entity extracted", report["extraction"]["extraction_note"])

    def test_optional_enrichment_failures_do_not_break_collection(self):
        from soc_bridge.diagnostics import MCPToolFailure
        failures = {"endpoint_security_endpoint_get": MCPToolFailure("Vision One", "endpoint_security_endpoint_get",
                                                                    "upstream returned HTTP 403; check API permissions"),
                    "dmm_models_list": MCPToolFailure("Vision One", "dmm_models_list",
                                                      "upstream returned HTTP 403; response mentions license/integration availability"),
                    "workbench_alert_notes_list": ValueError("Unexpected shape")}
        available = ALERT_VISION_TOOLS - {"crem_attack_surface_devices_list"}
        vision = FakeVision(search=procdump_search, failures=failures, available=available)
        report = run(investigate_vision_alert(QRadar(), vision, ALERT_ID, enable_vision_search=True, now=NOW))
        enrichment = report["enrichment"]
        self.assertEqual(enrichment[f"inventory:{GUID}"]["state"], "permission")
        self.assertEqual(enrichment["dmm_model"]["state"], "license_or_integration")
        self.assertEqual(enrichment[f"crem_device:{HOST}"]["state"], "tool_absent")
        self.assertEqual(enrichment["workbench_notes"]["state"], "unavailable")
        self.assertEqual(report["auto_pivots"]["record_counts"]["linked"], 1)
        # No insight ID and no listed insight references the alert: a WB ID is never used as an insight ID.
        self.assertEqual(report["insights"]["state"], "no_related_insight_found")
        self.assertFalse(any(t.startswith("workbench_insight_") and a.get("id", "").startswith("WB-")
                             for t, a in vision.calls))
        self.assertIn("not universal reputation", next(v["purpose"] for k, v in report["hypothesis_checks"].items()
                                                       if k.startswith("suspicious_objects")))


class LegacyCompatibilityTests(unittest.TestCase):
    def test_legacy_shapes_still_parse_without_free_text(self):
        self.assertEqual(alert_ips(LEGACY), ["192.0.2.8", "198.51.100.24"])
        entities = alert_entities(LEGACY)
        self.assertEqual(entities["processes"], ["tool.exe"])
        self.assertEqual(entities["hosts"], ["DEMO-PC"])
        self.assertNotIn("203.0.113.5", str(entities))

    def test_address_index_leads_and_manual_event(self):
        class V(FakeVision):
            pass
        vision = V(alert=dict(LEGACY, id=ALERT_ID))
        report = run(investigate_vision_alert(QRadar(), vision, ALERT_ID, now=NOW, event_evidence={
            "endpoint_ip": IP4, "event_time": z(T0), "endpoint_host": "DEMO-PC"}))
        self.assertEqual(report["searched_ips"][0], IP4)
        self.assertEqual(report["offenses"][0]["offense_id"], 71)
        self.assertEqual(report["anchor"]["basis"], "analyst-supplied View event time (unverified by the bridge)")
        self.assertIn("analyst-supplied", render_alert_markdown(report).lower())

    def test_rejects_bad_inputs_before_queries(self):
        qr = QRadar()
        for bad in ("WB-", "not-an-id", "WB-x';drop"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                run(investigate_vision_alert(qr, FakeVision(), bad))
        with self.assertRaises(ValueError):
            run(investigate_vision_alert(qr, FakeVision(), ALERT_ID, event_evidence={"endpoint_ip": "x", "event_time": z(T0)}))
        wrong = FakeVision(alert=dict(ALERT, id="WB-OTHER-1"))
        with self.assertRaises(ValueError):
            run(investigate_vision_alert(qr, wrong, ALERT_ID))
        self.assertEqual(qr.calls, [])

    def test_budget_exhaustion_preserves_progress(self):
        vision = FakeVision(search=procdump_search)
        report = run(investigate_vision_alert(QRadar(), vision, ALERT_ID, enable_vision_search=True, now=NOW,
                                              budget=Budget(max_calls=3)))
        self.assertTrue(report["auto_pivots"]["continuation"])
        self.assertTrue(all(c["action"] in ("search_partition", "refine_filters") for c in report["auto_pivots"]["continuation"]))
        self.assertIn("Trend search partition(s) pending", " ".join(report["assessment"]["blocking"]))


if __name__ == "__main__":
    unittest.main()
