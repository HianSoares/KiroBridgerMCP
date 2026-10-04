"""Capability discovery, diagnostics, case persistence/resume, consolidation, pivots and scoped decisions.

All data is synthetic. No QRadar or Vision One is contacted.
"""

import asyncio
import json
import os
import tempfile
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Thread
from types import SimpleNamespace
from unittest import mock

from soc_bridge import closure_assessment, pivot_planner
from soc_bridge.ariel_collection import Budget
from soc_bridge.capabilities import LOCAL_WRITE_TOOLS, ToolSet, absence_state, discover
from soc_bridge.case_investigation import investigate_offense_case, reassess_case
from soc_bridge.case_store import CaseConflict, CaseStore, SecretInCase, merge_query, scrub
from soc_bridge.diagnose import diagnose
from soc_bridge.kiro_server import mcp
from soc_bridge.transports import RestrictedMCP

from synthetic_lab import HOST, IP, MS, NOW, Lab, offense

ROOT = Path(__file__).resolve().parents[1]
SECRET = "synthetic-secret-value-55aa77"


def run(coro):
    return asyncio.run(coro)


def tool(name):
    return SimpleNamespace(name=name)


class Pages:
    """Fake MCP session with scripted tools/list pages."""

    def __init__(self, pages, slow=False):
        self.pages, self.slow, self.calls = pages, slow, []

    async def list_tools(self, cursor=None):
        self.calls.append(cursor)
        if self.slow:
            await asyncio.sleep(1)
        page = self.pages[cursor]
        if isinstance(page, Exception):
            raise page
        return page


def page(names, cursor=None):
    return SimpleNamespace(tools=[tool(n) for n in names], nextCursor=cursor)


class DiscoveryTests(unittest.TestCase):
    def test_all_pages_are_read(self):
        session = Pages({None: page(["get_offense"], "c1"), "c1": page(["get_rule"], "c2"), "c2": page(["validate_aql"])})
        found = run(discover(session, "QRadar"))
        self.assertTrue(found.complete)
        self.assertEqual(found.names, {"get_offense", "get_rule", "validate_aql"})
        self.assertEqual(found.state("set_offense_status", {"get_offense"}), "absent")
        self.assertEqual(found.state("get_rule", {"get_offense"}), "advertised_blocked")

    def test_repeated_cursor_invalid_page_cap_and_deadline_are_partial(self):
        cases = {
            "repeated": Pages({None: page(["a"], "c1"), "c1": page(["b"], "c1")}),
            "invalid": Pages({None: SimpleNamespace(tools="not-a-list", nextCursor=None)}),
            "error": Pages({None: RuntimeError(f"upstream said {SECRET}")}),
        }
        for label, session in cases.items():
            with self.subTest(label=label):
                found = run(discover(session, "QRadar"))
                self.assertFalse(found.complete)
                self.assertEqual(found.state("missing_tool", set()), "unknown")
                self.assertNotIn(SECRET, json.dumps(found.describe(set())))
        endless = Pages({**{None: page(["a"], "c0")}, **{f"c{i}": page([f"t{i}"], f"c{i + 1}") for i in range(30)}})
        self.assertIn("page cap", run(discover(endless, "QRadar", max_pages=3)).stop_reason)
        slow = Pages({None: page(["a"])}, slow=True)
        self.assertIn("deadline", run(discover(slow, "QRadar", deadline_seconds=0.2)).stop_reason)

    def test_partial_discovery_never_claims_absence(self):
        found = run(discover(Pages({None: page(["get_offense"], "c1"), "c1": page(["x"], "c1")}), "QRadar"))
        names = ToolSet(found.names)
        names.discovery = found
        with self.assertRaisesRegex(RuntimeError, "unknown"):
            RestrictedMCP(object(), {"get_offense", "get_rule"}, names, {"get_rule"}, "QRadar")
        client = RestrictedMCP(object(), {"get_offense", "get_rule"}, names, {"get_offense"}, "QRadar")
        self.assertEqual(absence_state(client, "get_rule"), "availability_unknown")
        with self.assertRaisesRegex(RuntimeError, "availability unknown"):
            run(client.call("get_rule", {}))
        complete = run(discover(Pages({None: page(["get_offense"])}), "QRadar"))
        names = ToolSet(complete.names)
        names.discovery = complete
        client = RestrictedMCP(object(), {"get_offense", "get_rule"}, names, {"get_offense"}, "QRadar")
        self.assertEqual(absence_state(client, "get_rule"), "tool_absent")


class DiagnosticsTests(unittest.TestCase):
    def test_diagnostics_never_expose_tokens_or_upstream_text(self):
        class Reject(BaseHTTPRequestHandler):
            def do_POST(self):
                body = f"denied for token {SECRET}".encode()
                self.send_response(401)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            do_GET = do_POST

            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Reject)
        Thread(target=server.serve_forever, daemon=True).start()
        env = {"QRADAR_MCP_URL": f"http://127.0.0.1:{server.server_address[1]}/mcp", "QRADAR_MCP_TOKEN": SECRET,
               "TREND_VISION_ONE_API_KEY": SECRET}
        try:
            with mock.patch.dict(os.environ, env):
                report = run(diagnose(timeout=5))
        finally:
            server.shutdown()
            server.server_close()
        text = json.dumps(report, default=str)
        self.assertNotIn(SECRET, text)
        self.assertEqual(report["environment"]["QRADAR_MCP_TOKEN"], "set")
        stages = {s["stage"]: s for s in report["qradar"]["stages"]}
        self.assertEqual(stages["tcp"]["state"], "ok")
        self.assertEqual(stages["mcp_initialize"]["state"], "failed")
        self.assertIn("401", stages["mcp_initialize"]["category"])
        self.assertEqual(report["pack"]["state"], "consistent")
        self.assertEqual(report["trend"]["stages"][0]["state"], "skipped")


class StoreTests(unittest.TestCase):
    def test_atomic_revisions_conflict_secret_refusal_and_retention(self):
        with tempfile.TemporaryDirectory() as root:
            store = CaseStore(Path(root), retention_days=1)
            case = store.save(CaseStore.new("offense-12345", offenses=[12345]), 0)
            self.assertEqual(case["revision"], 1)
            with self.assertRaises(CaseConflict):
                store.save(CaseStore.new("offense-12345", offenses=[12345]), 0)
            with mock.patch.dict(os.environ, {"QRADAR_MCP_TOKEN": SECRET}):
                with self.assertRaises(SecretInCase):
                    store.save({**case, "pending": [{"note": f"value {SECRET}"}]}, 1)
            self.assertEqual(store.load("offense-12345")["revision"], 1)  # nothing written
            self.assertNotIn("SEC", scrub({"SEC": "x", "headers": {"a": 1}, "ok": 1}))
            self.assertEqual(store.purge(now=NOW.replace(year=2099)), ["offense-12345"])
            with self.assertRaises(ValueError):
                store.path("../escape")

    def test_consolidation_keeps_every_reference_without_duplicates(self):
        case = CaseStore.new("c1")
        row = {"starttime": MS, "devicetime": MS - 1000, "sourceip": IP, "event_name": "Synthetic", "qid": 5,
               "log_source": "Synthetic WinCollect", "raw_payload": "payload"}
        merge_query(case, "host_context", {"database": "events", "scope": "host_ip_time_context", "search_id": "s1"},
                    [row], "run-1")
        merge_query(case, "events", {"database": "events", "scope": "offense_linked", "search_id": "s2"},
                    [row, dict(row, qid=6)], "run-1")
        self.assertEqual(len(case["evidence"]), 2)
        shared = next(e for e in case["evidence"].values() if e["summary"]["qid"] == 5)
        self.assertEqual({r["query"] for r in shared["seen_in"]}, {"host_context", "events"})
        self.assertEqual(shared["tier"], "offense_associated")  # upgraded, never downgraded
        self.assertTrue(shared["clocks"]["received_utc"].endswith("Z"))
        self.assertNotEqual(shared["clocks"]["received_utc"], shared["clocks"]["device_time_utc"])


def lab_with_events(rows=7, **kw):
    events = [{"starttime": MS + i * 1000, "devicetime": MS + i * 1000, "sourceip": IP, "event_name": f"Synthetic {i}",
               "log_source": "Synthetic WinCollect", "raw_payload": f"synthetic payload {i}", "qid": 100 + i}
              for i in range(rows)]
    return Lab({"INOFFENSE(12345)": ("events", events, None)}, **kw)


class ResumeTests(unittest.TestCase):
    def test_interrupted_collection_resumes_same_job_in_another_process(self):
        lab = lab_with_events()
        with tempfile.TemporaryDirectory() as root:
            first = run(investigate_offense_case(lab, None, 12345, store=CaseStore(Path(root)), include_trend=False,
                                                 budget=Budget(max_seconds=30, page_size=2, max_pages=2), now=NOW))
            self.assertEqual(first["coverage"]["events"]["outcome"], "partial")
            created = [a["query_expression"] for n, a in lab.calls if n == "create_ariel_search"]
            events_jobs = [q for q in created if "INOFFENSE(12345)" in q and "FROM events" in q]
            self.assertEqual(len(events_jobs), 1)
            job = first["coverage"]["events"]["search_id"]
            # A different process: new store object and budget; the upstream job still exists.
            second = run(investigate_offense_case(lab, None, 12345, store=CaseStore(Path(root)), include_trend=False,
                                                  budget=Budget(max_seconds=30, page_size=2, max_pages=10), now=NOW))
            created = [a["query_expression"] for n, a in lab.calls if n == "create_ariel_search"]
            self.assertEqual(len([q for q in created if "INOFFENSE(12345)" in q and "FROM events" in q]), 1)
            self.assertEqual(second["coverage"]["events"]["search_id"], job)
            self.assertEqual(second["coverage"]["events"]["resume"], "continued_same_search")
            self.assertEqual(second["coverage"]["events"]["outcome"], "complete_in_window")
            self.assertEqual(second["coverage"]["events"]["rows"], 7)
            case = CaseStore(Path(root)).load("offense-12345")
            offense_records = [e for e in case["evidence"].values() if e["tier"] == "offense_associated"]
            self.assertEqual(len(offense_records), 7)
            self.assertEqual(len(case["report_revisions"]), 2)  # earlier revision kept
            self.assertEqual([r["stage"] for r in case["runs"]], ["completed", "completed"])
            third = run(investigate_offense_case(lab, None, 12345, store=CaseStore(Path(root)), include_trend=False,
                                                 now=NOW))
            self.assertEqual(third["coverage"]["events"]["resume"], "reused")

    def test_uncertain_creation_is_not_recreated_without_an_explicit_rerun(self):
        class Uncertain(Lab):
            def __init__(self):
                super().__init__({"INOFFENSE(12345)": ("events", [], None)})
                self.fail_creation = True

            async def call(self, name, args):
                if name == "create_ariel_search" and self.fail_creation and "INOFFENSE(12345)" in args["query_expression"] \
                        and "FROM events" in args["query_expression"]:
                    self.calls.append((name, args))
                    raise TimeoutError("synthetic creation timeout")
                return await super().call(name, args)

        lab = Uncertain()
        with tempfile.TemporaryDirectory() as root:
            first = run(investigate_offense_case(lab, None, 12345, store=CaseStore(Path(root)), include_trend=False, now=NOW))
            self.assertEqual(first["coverage"]["events"]["outcome"], "creation_uncertain")
            pivot = next(p for p in first["pivots"] if p["action"] == "verify_uncertain_creation")
            self.assertEqual(pivot["status"], "requires_resolution")
            lab.fail_creation = False
            before = len([1 for n, a in lab.calls if n == "create_ariel_search" and "FROM events WHERE" in a["query_expression"]
                          and "INOFFENSE(12345)" in a["query_expression"]])
            second = run(investigate_offense_case(lab, None, 12345, store=CaseStore(Path(root)), include_trend=False, now=NOW))
            after = len([1 for n, a in lab.calls if n == "create_ariel_search" and "FROM events WHERE" in a["query_expression"]
                         and "INOFFENSE(12345)" in a["query_expression"]])
            self.assertEqual(before, after)
            self.assertEqual(second["coverage"]["events"]["resume"], "requires_resolution")
            third = run(investigate_offense_case(lab, None, 12345, store=CaseStore(Path(root)), include_trend=False,
                                                 rerun_queries=["events"], now=NOW))
            self.assertEqual(third["coverage"]["events"]["outcome"], "empty")
            history = CaseStore(Path(root)).load("offense-12345")["queries"]["events"]
            self.assertEqual(history["outcome"], "empty")


class PivotTests(unittest.TestCase):
    def result(self, **queries):
        return {"queries": queries, "gap_details": [{"id": "rules:cre-definition", "relevance": {"blocks": ["benign_verdict"]}}]}

    def test_pivots_record_hypothesis_cost_and_stop_and_respect_retry_rules(self):
        result = self.result(
            events={"outcome": "partial", "scope": "offense_linked", "search_id": "s1", "aql": "x",
                    "continuation": {"action": "fetch_next_page", "cursor": 40}},
            flows={"outcome": "unavailable", "scope": "offense_linked", "aql": "y",
                   "error": {"category": "permission", "retryable": False, "requires_resolution": True,
                             "next_action": "Fix the QRadar account permission"},
                   "continuation": {"action": "start_planned_query"}},
            host_context={"outcome": "not_started", "scope": "host_ip_time_context", "aql": "z",
                          "error": {"category": "connection", "retryable": True, "requires_resolution": False},
                          "continuation": {"action": "start_planned_query"}})
        pivots = pivot_planner.plan(result)
        by_query = {p["params"].get("query"): p for p in pivots if "query" in p["params"]}
        resume = by_query["events"]
        for field in ("hypothesis", "motivated_by", "source", "cost", "supports_if", "contradicts_if", "stop_criterion"):
            self.assertTrue(resume[field], field)
        self.assertEqual(resume["params"]["cursor"], 40)
        self.assertEqual(by_query["flows"]["status"], "requires_resolution")
        self.assertEqual(by_query["host_context"]["status"], "planned")
        self.assertLess(resume["priority"], by_query["host_context"]["priority"])  # trigger records first
        external = next(p for p in pivots if p["action"] == "request_external_evidence")
        self.assertEqual(external["status"], "requires_analyst")
        self.assertIn("rule editor", external["source"])
        repeated = pivot_planner.plan(result, previous=[{**resume, "status": "executed"}])
        self.assertEqual(next(p for p in repeated if p["id"] == resume["id"])["status"], "skipped_repeat")


class ScopedDecisionTests(unittest.TestCase):
    def result(self, **extra):
        base = {"offense_id": 12345, "assessment": {}, "queries": {
                    "events": {"result_set_complete": True, "search_id": "s1", "outcome": "complete_in_window",
                               "returned_rows": 2, "scope": "offense_linked"},
                    "flows": {"result_set_complete": True, "search_id": "s2", "outcome": "empty",
                              "returned_rows": 0, "scope": "offense_linked"}},
                "linux": {}, "gap_details": [], "metadata": {"status": "OPEN", "offense_source": IP},
                "metadata_interval": {"start": "2026-10-09T16:00:00+00:00", "end": "2026-10-09T16:02:00+00:00"},
                "events": {"observed_interval": {"start": "2026-10-09T16:00:00+00:00", "end": "2026-10-09T16:02:00+00:00"}},
                "processes": {"process_creations": [{
                    "host_norm": HOST, "guid_norm": "g-synth-1",
                    "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "command_line": "powershell.exe -NoProfile -File C:\\ops\\synthetic.ps1",
                    "fields": {"ParentImage": {"value": "C:\\Windows\\explorer.exe", "source": "payload"}},
                    "provenance": {"query": "events", "scope": "offense_linked", "search_id": "s1",
                                   "result_row_index": 0, "starttime_utc": "2026-10-09T16:00:01+00:00"}}]},
                "closing_reasons": {"state": "collected", "reasons": [{"id": 1, "text": "Non-Issue"},
                                                                      {"id": 4, "text": "Local Review"}]}}
        base.update(extra)
        return base

    def auth(self, activity="process_execution", entities=(HOST,), start="2026-10-09T15:00:00+00:00",
             end="2026-10-09T17:00:00+00:00", processes=("powershell.exe",)):
        scope = {"activity": activity, "entities": list(entities), "window_start": start, "window_end": end}
        if activity == "process_execution":
            scope["processes"] = list(processes)
        return {"requirement": "authorization", "source": "Change system", "reference": "CHG-SYNTH-7", "scope": scope}

    def test_sustained_when_scoped_authorization_covers_the_observed_activity(self):
        result = closure_assessment.propose(self.result(), [self.auth()])
        self.assertTrue(result["ready_to_close"])
        self.assertEqual(result["recommended_reason"], {"id": 1, "text": "Non-Issue"})
        self.assertEqual(result["disposition"]["category"], "authorized_activity")
        self.assertEqual(result["confidence_detail"]["level"], "moderate")  # relies on an external record
        self.assertIn("analyst-supplied", " ".join(result["confidence_detail"]["basis"]))

    def test_insufficient_scope_and_window_contradiction_block_the_benign_closure(self):
        wrong_entity = closure_assessment.propose(self.result(), [self.auth(entities=("other-host.example.test",))])
        self.assertFalse(wrong_entity["ready_to_close"])
        self.assertEqual(wrong_entity["requirements"]["authorization"]["status"], "compatible")
        self.assertEqual(wrong_entity["requirements"]["authorization"]["evidence"]["uncovered_activities"],
                         ["process_execution"])
        outside = closure_assessment.propose(self.result(), [self.auth(end="2026-10-09T16:00:00+00:00")])
        self.assertFalse(outside["ready_to_close"])
        self.assertEqual(outside["contradictions"][0]["status"], "unresolved")
        non_issue = next(m for m in outside["decision_matrix"] if m["id"] == 1)
        self.assertNotEqual(non_issue["sufficiency"], "sustained")
        self.assertIn("Contradições não resolvidas", outside["suggested_note"])
        generic = closure_assessment.propose(self.result(), [self.auth(activity="offense_activity")])
        self.assertFalse(generic["ready_to_close"])  # generic authorization does not cover process execution

    def test_contradictory_malicious_evidence_blocks_authorized_disposition(self):
        result = closure_assessment.propose(self.result(), [self.auth()], [],
                                            {"malicious_activity_confirmed": {"alert_id": "WB-SYNTH-1"}, "corroborated": True})
        self.assertFalse(result["ready_to_close"])
        self.assertEqual(result["disposition"]["category"], "malicious_confirmed")
        authorized = next(d for d in result["disposition_matrix"] if d["id"] == "authorized_activity")
        self.assertEqual(authorized["sufficiency"], "contradicted")
        self.assertEqual(result["confidence_detail"]["level"], "high")

    def test_inconclusive_lists_precise_pending_items(self):
        result = closure_assessment.propose(self.result())
        self.assertEqual(result["disposition"]["category"], "inconclusive")
        self.assertIn("authorization", [b["id"] for b in result["blocking_requirements"]])
        self.assertIn("process_execution", result["requirements"]["authorization"]["next_check"])
        self.assertEqual(result["confidence_detail"]["level"], "low")

    def test_custom_reason_needs_a_valid_local_definition(self):
        result = closure_assessment.propose(self.result(), [self.auth()])
        custom = next(o for o in result["conditional_reason_options"] if o["id"] == 4)
        self.assertFalse(custom["eligible_now"])
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "reasons.json"
            path.write_text(json.dumps({"Local Review": {"requires": ["authorization", "relevant_collection_complete"],
                                                         "definition": "Synthetic local definition"},
                                        "Broken": {"requires": ["made_up"], "definition": "x"}}), encoding="utf-8")
            with mock.patch.dict(os.environ, {"SOC_BRIDGE_CLOSING_REASONS": str(path)}):
                result = closure_assessment.propose(self.result(), [self.auth()])
        self.assertEqual(result["custom_reason_definitions"]["loaded"], ["local review"])
        self.assertTrue(result["custom_reason_definitions"]["problems"])
        self.assertTrue(next(o for o in result["conditional_reason_options"] if o["id"] == 4)["eligible_now"])
        self.assertIsNone(result["recommended_reason"])  # two reasons sustained: the analyst chooses

    def test_scope_validation(self):
        bad = [{"requirement": "authorization", "source": "x", "reference": "y", "scope": {"activity": "everything"}},
               {"requirement": "primary_offense", "source": "x", "reference": "7", "scope": self.auth()["scope"]}]
        for item in bad:
            with self.subTest(item=item), self.assertRaises(ValueError):
                closure_assessment.validate_confirmations([item], 12345)


class CaseFlowTests(unittest.TestCase):
    def test_report_is_professional_and_reassessment_adds_a_revision_without_queries(self):
        lab = lab_with_events(rows=3)
        with tempfile.TemporaryDirectory() as root:
            store = CaseStore(Path(root))
            report = run(investigate_offense_case(lab, None, 12345, store=store, include_trend=False, now=NOW))
            for key in ("decision", "observed_behavior", "decisive_evidence", "hypotheses", "contradictions",
                        "coverage", "limitations", "confidence", "next_action", "note_pt"):
                self.assertIn(key, report)
            self.assertEqual(report["trend_state"], "not_requested")
            self.assertTrue(report["decisive_evidence"])
            self.assertTrue(all(e["references"] for e in report["decisive_evidence"]))
            self.assertIn("offense-12345", report["note_pt"])
            self.assertIn("Rule and offense names", report["observed_behavior"]["behavior_vs_label"])
            calls = len(lab.calls)
            observed = store.load("offense-12345")["last_result"]
            scope = {"activity": "offense_activity", "entities": [IP],
                     "window_start": "2026-10-09T15:00:00+00:00", "window_end": "2026-10-09T17:00:00+00:00"}
            reassessed = reassess_case("offense-12345", [{"requirement": "authorization", "source": "Change system",
                                                          "reference": "CHG-SYNTH-9", "scope": scope}], store)
            self.assertEqual(len(lab.calls), calls)
            self.assertEqual(reassessed["reassessment"]["upstream_calls"], 0)
            case = store.load("offense-12345")
            self.assertEqual(len(case["report_revisions"]), 2)
            self.assertEqual(case["confirmations"][0]["origin"], "analyst-supplied; not verified by the bridge")
            self.assertTrue(observed)


    def test_related_true_positive_alert_by_ip_only_does_not_confirm_malice_but_blocks_benign_closure(self):
        lab = lab_with_events(rows=2)
        tp = {"assessment": {"classification": "True Positive", "facts": ["synthetic linked execution"]},
              "auto_pivots": {"records": {"linked": [{"uuid": "ev-1", "tool": "search_endpoint_activities_list",
                                                      "time_utc": "2026-10-09T16:00:01Z"}]}}}
        overview = {"alerts": [{"alert_id": "WB-SYNTH-1"}], "deepened_alerts": {
            "state": "collected", "not_deepened": [], "investigations": [
                {"alert_id": "WB-SYNTH-1", "state": "collected", "report": tp,
                 "association": {"match_fields": ["impactScopeEntityValue"]}}]}}
        with tempfile.TemporaryDirectory() as root, \
                mock.patch("soc_bridge.core.investigate", mock.AsyncMock(return_value=overview)):
            report = run(investigate_offense_case(lab, object(), 12345, store=CaseStore(Path(root)), now=NOW))
            case = CaseStore(Path(root)).load("offense-12345")
        self.assertNotEqual(report["decision"]["disposition"]["category"], "malicious_confirmed")
        self.assertFalse(report["decision"]["ready_to_close"])
        self.assertIn("WB-SYNTH-1", case["references"]["alerts"])
        self.assertIn("alert_linked", {e["tier"] for e in case["evidence"].values()})
        self.assertEqual(report["related_alerts"][0]["classification"], "True Positive")
        self.assertEqual(report["related_alerts"][0]["link"], "candidate")
        self.assertIn("related_alert_unlinked:WB-SYNTH-1", [c["id"] for c in report["contradictions"]])
        self.assertIn("verify_alert_link", [p["action"] for p in report["pivots"]])
