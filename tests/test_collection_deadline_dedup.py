"""Synthetic regressions for the shared deadline, page-failure resumption and record identity."""

import asyncio
import time
import unittest

from soc_bridge.ariel_collection import Budget, collect_query
from soc_bridge.diagnostics import MCPToolFailure
from soc_bridge.offense_evidence import _records, collect_offense_evidence, render_evidence

from synthetic_lab import G_OTHER, G_PS, Lab, NOW, offense, row

QUERY = "SELECT * FROM events LIMIT 100 LAST 1 HOURS"
ROWS = [{"n": i} for i in range(5)]


class Slow(Lab):
    """Lab whose named calls sleep or fail; records when each call started."""

    def __init__(self, *args, delays=None, failures=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.delays, self.failures, self.started = delays or {}, failures or {}, []

    async def call(self, name, args):
        self.started.append((name, time.perf_counter()))
        failure = self.failures.get(name)
        if failure and failure[0](args):
            raise failure[1]
        if name in self.delays:
            await asyncio.sleep(self.delays[name](args) if callable(self.delays[name]) else self.delays[name])
        return await super().call(name, args)

    async def read_aql_resource(self, resource):
        if "resource" in self.delays:
            await asyncio.sleep(self.delays["resource"])
        return await super().read_aql_resource(resource)

    def names(self):
        return [name for name, _ in self.started]


def events_lab(**kwargs):
    return Slow({"FROM events": ("events", ROWS, None)}, **kwargs)


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


class DeadlineTests(unittest.IsolatedAsyncioTestCase):
    async def test_slow_validation_is_cut_at_the_deadline_and_creates_no_job(self):
        qr = events_lab(delays={"validate_aql": 0.08})
        began = time.perf_counter()
        finding = await collect_query(qr, QUERY, "events", "manual", Budget(max_seconds=0.02))
        elapsed = time.perf_counter() - began
        self.assertLess(elapsed, 0.06)
        self.assertNotIn("create_ariel_search", qr.names())
        self.assertEqual(finding["outcome"], "not_started")
        self.assertEqual(finding["continuation"]["action"], "start_planned_query")
        self.assertIsNone(finding["continuation"]["search_id"])

    async def test_budget_is_checked_again_between_validation_and_creation(self):
        clock = Clock()
        qr = events_lab()
        original = qr.call

        async def call(name, args):
            if name == "validate_aql":
                clock.now = 50.0  # validation used up the whole budget
            return await original(name, args)

        qr.call = call
        finding = await collect_query(qr, QUERY, "events", "manual", Budget(max_seconds=10, clock=clock))
        self.assertIn("validate_aql", qr.names())
        self.assertNotIn("create_ariel_search", qr.names())
        self.assertEqual(finding["outcome"], "not_started")
        self.assertIn("after validation", finding["continuation"]["reason"])

    async def test_creation_timeout_is_uncertain_and_never_recreated(self):
        qr = events_lab(delays={"create_ariel_search": 0.2})
        finding = await collect_query(qr, QUERY, "events", "manual", Budget(max_seconds=0.05))
        self.assertEqual(qr.names().count("create_ariel_search"), 1)
        self.assertEqual(finding["outcome"], "creation_uncertain")
        self.assertNotIn("search_id", finding)
        self.assertEqual(finding["error"]["category"], "creation_timeout")
        plan = finding["continuation"]
        self.assertEqual(plan["action"], "verify_creation_before_retry")
        self.assertIsNone(plan["search_id"])
        self.assertIn("did not recreate", plan["note"])
        self.assertFalse(finding["result_set_complete"])

    async def test_polling_timeout_keeps_the_known_search_id(self):
        qr = events_lab(delays={"get_ariel_search_status": 0.2})
        finding = await collect_query(qr, QUERY, "events", "manual", Budget(max_seconds=0.05))
        self.assertEqual(finding["outcome"], "pending")
        self.assertEqual(finding["continuation"]["action"], "poll_same_search")
        self.assertEqual(finding["continuation"]["search_id"], finding["search_id"])
        self.assertEqual(finding["error"]["stage"], "polling")

    async def test_slow_catalog_and_rules_stop_the_whole_collection_at_the_deadline(self):
        qr = Slow({"FROM events": ("events", ROWS, None)}, catalog={}, delays={"resource": 0.3})
        began = time.perf_counter()
        evidence = await collect_offense_evidence(qr, offense(), now=NOW, budget=Budget(max_seconds=0.1))
        self.assertLess(time.perf_counter() - began, 0.25)
        self.assertEqual(evidence["field_catalogs"]["events"]["state"], "not_read_time_budget")
        self.assertFalse({"create_ariel_search", "validate_aql", "get_rule"} & set(qr.names()))
        self.assertEqual(evidence["rules"][0]["state"], "not_read")
        self.assertTrue(all(q["outcome"] == "not_started" for q in evidence["queries"].values()))
        self.assertIn("returned_rows", evidence["queries"]["events"])
        self.assertIn("Continuation plan", "\n".join(render_evidence(evidence)))


class PageFailureTests(unittest.IsolatedAsyncioTestCase):
    async def test_second_page_failure_keeps_rows_cursor_and_search_id(self):
        failure = MCPToolFailure("QRadar", "get_ariel_search_results", "upstream MCP timed out")
        qr = events_lab(failures={"get_ariel_search_results": (lambda a: a["start"] == 2, failure)})
        finding = await collect_query(qr, QUERY, "events", "manual", Budget(page_size=2))
        self.assertEqual(finding["rows"], ROWS[:2])
        self.assertEqual(finding["outcome"], "partial")
        self.assertFalse(finding["result_set_complete"])
        self.assertEqual(finding["error"]["stage"], "results")
        plan = finding["continuation"]
        self.assertEqual((plan["action"], plan["cursor"], plan["search_id"]),
                         ("fetch_next_page", 2, finding["search_id"]))
        self.assertEqual(finding["next_start"], 2)
        self.assertEqual(qr.names().count("create_ariel_search"), 1)

    async def test_page_timeout_keeps_partial_coverage(self):
        qr = events_lab(delays={"get_ariel_search_results": lambda a: 0.3 if a["start"] == 2 else 0})
        finding = await collect_query(qr, QUERY, "events", "manual", Budget(page_size=2, max_seconds=0.1))
        self.assertEqual(len(finding["rows"]), 2)
        self.assertEqual(finding["outcome"], "partial")
        self.assertEqual(finding["continuation"]["cursor"], 2)

    async def test_polling_failure_differs_from_results_failure(self):
        failure = MCPToolFailure("QRadar", "get_ariel_search_status", "cannot connect to local MCP; check Docker/QRadar MCP status")
        qr = events_lab(failures={"get_ariel_search_status": (lambda a: True, failure)})
        finding = await collect_query(qr, QUERY, "events", "manual")
        self.assertEqual(finding["error"]["stage"], "polling")
        self.assertEqual(finding["continuation"]["action"], "poll_same_search")
        self.assertEqual(finding["continuation"]["cursor"], 0)
        self.assertEqual(finding["rows"], [])


def sysmon_without_computer(guid, pid):
    return (f"EventID=1 RecordNumber=100 Process Create: ProcessGuid: {guid} ProcessId: {pid} "
            "Image: C:\\Windows\\System32\\cmd.exe CommandLine: cmd.exe")


def finding(name, rows, sid="synthetic-job-0"):
    return {"scope": name, "search_id": sid, "rows": rows, "truncated_rows": {}}


class RecordIdentityTests(unittest.TestCase):
    def test_same_record_number_without_computer_from_two_sources_stays_separate(self):
        first = {**row(sysmon_without_computer(G_PS, 10)), "log_source": "Synthetic Sysmon A"}
        second = {**row(sysmon_without_computer(G_OTHER, 20)), "log_source": "Synthetic Sysmon B"}
        records = _records("events", finding("offense_linked", [first, second]), {}, {})
        self.assertEqual(len(records), 2)
        twin = {**first, "log_source": "Synthetic Sysmon B"}  # identical text, other origin
        self.assertEqual(len(_records("events", finding("offense_linked", [first, twin]), {}, {})), 2)

    def test_same_event_from_two_queries_is_kept_once_with_both_provenances(self):
        event = row(sysmon_without_computer(G_PS, 10))
        seen = {}
        first = _records("events", finding("offense_linked", [event]), {}, seen)
        second = _records("host_context", finding("host_ip_time_context", [dict(event)], "synthetic-job-3"), {}, seen)
        self.assertEqual(len(first), 1)
        self.assertEqual(second, [])
        also = first[0]["provenance"]["also_returned_by"][0]
        self.assertEqual((also["query"], also["search_id"]), ("host_context", "synthetic-job-3"))
        self.assertIn("log_source", first[0]["provenance"]["identity"])

    def test_payloadless_records_compare_selected_properties(self):
        props = {"prop_eventid": {"logical": "EventID", "property": "EventID"},
                 "prop_commandline": {"logical": "CommandLine", "property": "Process CommandLine"}}
        base = {"starttime": 1, "devicetime": 1, "log_source": "Synthetic Sysmon A", "prop_eventid": "1"}
        a, b = {**base, "prop_commandline": "cmd.exe /c one"}, {**base, "prop_commandline": "cmd.exe /c two"}
        self.assertEqual(len(_records("events", finding("x", [a, b]), props, {})), 2)
        self.assertEqual(len(_records("events", finding("x", [a, dict(a)]), props, {})), 1)

    def test_insufficient_identity_never_merges(self):
        event = {**row(sysmon_without_computer(G_PS, 10)), "log_source": None}
        records = _records("events", finding("x", [event, dict(event)]), {}, {})
        self.assertEqual(len(records), 2)
        self.assertIn("kept separate", records[0]["provenance"]["identity"])


if __name__ == "__main__":
    unittest.main()
