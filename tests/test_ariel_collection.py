"""Synthetic continuation, budget, field metadata, error and isolation regressions."""

import asyncio
import itertools
import unittest

from soc_bridge.capabilities import LOCAL_WRITE_TOOLS

from soc_bridge.aql_errors import AQLPolicyError, AQLValidationError, ResponseFormatError, classify_failure
from soc_bridge.aql_fields import EVENT_COLUMNS, FieldCatalog, plan_select
from soc_bridge.ariel_collection import Budget, collect_query
from soc_bridge.diagnostics import MCPToolFailure
from soc_bridge.kiro_server import mcp
from soc_bridge.offense_evidence import collect_offense_evidence
from soc_bridge.transports import QRADAR_TOOLS, RestrictedMCP

from synthetic_lab import Lab, NOW, offense, row, sysmon, G_PS, G_PARENT

PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
EVENTS = [row("EventID=4624 synthetic logon", 0), row("EventID=4624 synthetic logon", 1000)]


def lab(events=EVENTS, census=None, census_total=None, **kwargs):
    census = [{"total_rows": 0, "distinct_destinations": 0}] if census is None else census
    return Lab({"UNIQUECOUNT": ("flows", census, census_total),
                "FROM flows WHERE INOFFENSE": ("flows", [], None),
                "FROM events WHERE INOFFENSE": ("events", events, None)}, **kwargs)


class ContinuationTests(unittest.IsolatedAsyncioTestCase):
    async def test_pending_job_is_resumed_by_the_same_search_id(self):
        qr = lab(pending_polls=3)
        evidence = await collect_offense_evidence(qr, offense(), now=NOW)
        events = evidence["queries"]["events"]
        self.assertTrue(events["result_set_complete"])
        self.assertEqual(events["polls"], 4)  # three EXECUTE answers, then COMPLETED
        self.assertEqual(events["returned_rows"], 2)
        self.assertEqual(qr.created(), len(evidence["queries"]))  # one job per query, never recreated

    async def test_budget_exhaustion_preserves_search_id_and_cursor(self):
        qr = lab(pending_polls=50)
        evidence = await collect_offense_evidence(qr, offense(), now=NOW, budget=Budget(max_polls=2))
        events = evidence["queries"]["events"]
        self.assertEqual(events["outcome"], "pending")
        plan = events["continuation"]
        self.assertEqual(plan["action"], "poll_same_search")
        self.assertEqual(plan["search_id"], events["search_id"])
        self.assertEqual(plan["cursor"], 0)
        self.assertIn("INOFFENSE(12345)", plan["aql"])
        self.assertEqual(plan["scope"], "offense_linked")
        self.assertIn("status polling budget", plan["reason"])
        self.assertIn("events", [item["query"] for item in evidence["continuation_plan"]])
        self.assertFalse(evidence["assessment"]["final_benign_verdict_permitted"])

    async def test_time_budget_leaves_unstarted_queries_as_a_plan(self):
        ticks = itertools.count(0, 10)
        budget = Budget(max_seconds=25, clock=lambda: next(ticks))
        evidence = await collect_offense_evidence(lab(), offense(), now=NOW, budget=budget)
        outcomes = {name: q["outcome"] for name, q in evidence["queries"].items()}
        self.assertIn("not_started", outcomes.values())
        planned = [p for p in evidence["continuation_plan"] if p["action"] == "start_planned_query"]
        self.assertTrue(planned)
        self.assertIsNone(planned[0]["search_id"])
        self.assertIn(planned[0]["query"], evidence["assessment"]["collection_completeness"]["not_started"])

    async def test_limit_reached_with_has_more_false_needs_a_new_partitioned_query(self):
        qr = Lab({"FROM events": ("events", EVENTS + [row("x", 2000)], None)})
        finding = await collect_query(qr, "SELECT * FROM events LIMIT 3 LAST 1 HOURS", "events", "manual")
        self.assertEqual(finding["returned_rows"], 3)
        self.assertNotIn("next_start", finding)  # every page of this job was read
        self.assertEqual(finding["outcome"], "limited")
        self.assertFalse(finding["result_set_complete"])
        self.assertEqual(finding["continuation"]["action"], "new_partitioned_query")
        self.assertIsNone(finding["continuation"]["search_id"])

    async def test_aggregate_record_count_is_not_the_count_value(self):
        evidence = await collect_offense_evidence(lab(census=[{"total_rows": 7, "distinct_destinations": 2}]),
                                                  offense(), now=NOW)
        self.assertEqual(evidence["queries"]["flow_census"]["record_count"], 1)
        self.assertEqual(evidence["flows"]["total_rows_in_search"], 7)
        self.assertEqual(evidence["flows"]["census_record_count"], 1)
        self.assertIn("not the value of COUNT(*)", evidence["queries"]["flow_census"]["record_count_semantics"])

    async def test_aggregation_without_rows_gets_no_invented_number(self):
        evidence = await collect_offense_evidence(lab(census=[], census_total=0), offense(), now=NOW)
        self.assertEqual(evidence["queries"]["flow_census"]["outcome"], "empty")
        self.assertIsNone(evidence["flows"]["total_rows_in_search"])
        self.assertIsNone(evidence["flows"]["distinct_destinations_in_search"])
        self.assertTrue(any(g["id"] == "census:unavailable" for g in evidence["gap_details"]))

    async def test_flow_census_gap_does_not_block_reporting_a_process_chain(self):
        events = [row(sysmon(G_PS, 4321, PS, "powershell.exe -NoProfile", G_PARENT, 1000))]
        evidence = await collect_offense_evidence(lab(events=events, census=[], census_total=0), offense(), now=NOW)
        blockers = evidence["assessment"]["blocking_gaps_by_conclusion"]
        self.assertNotIn("process_chain", blockers)
        self.assertIn("census:unavailable", blockers["offense_network_claims"])
        self.assertTrue(any(f["fact"] == "process_creation_observed" for f in evidence["assessment"]["confirmed_facts"]))
        self.assertIn("not a ban on reporting facts", evidence["assessment"]["final_benign_verdict_permitted_meaning"])
        self.assertFalse(evidence["assessment"]["final_benign_verdict_permitted"])
        self.assertIn("does not show the host or a process had no communication", evidence["flows"]["zero_rows_note"])


class FieldMetadataTests(unittest.IsolatedAsyncioTestCase):
    CATALOG = {"events": {"fields": [{"name": "starttime"}, {"name": "Process CommandLine"},
                                     {"name": "ProcessGuid"}, {"name": 'Bad" OR 1=1'}]}}

    async def test_live_optional_fields_are_selected_and_missing_ones_recorded(self):
        qr = lab(catalog=self.CATALOG)
        evidence = await collect_offense_evidence(qr, offense(), now=NOW)
        fields = evidence["queries"]["events"]["fields"]
        self.assertIn('"Process CommandLine" AS prop_commandline', evidence["queries"]["events"]["aql"])
        self.assertEqual(fields["optional_selected"], {"CommandLine": "Process CommandLine", "ProcessGuid": "ProcessGuid"})
        self.assertIn("ParentProcessGuid", fields["optional_missing"])
        self.assertIn("sourceip", fields["required_not_listed_in_metadata"])
        self.assertEqual(evidence["field_catalogs"]["events"]["ignored_unsafe_names"], 1)
        self.assertFalse(any("OR 1=1" in q for q in qr.queries))

    async def test_unavailable_resource_keeps_canonical_collection(self):
        evidence = await collect_offense_evidence(lab(), offense(), now=NOW)
        self.assertEqual(evidence["field_catalogs"]["events"]["state"], "unavailable")
        self.assertTrue(evidence["queries"]["events"]["result_set_complete"])
        self.assertNotIn("prop_", evidence["queries"]["events"]["aql"])
        self.assertTrue(any("optional properties not requested" in w for w in evidence["warnings"]))

    async def test_rejected_optional_fields_fall_back_without_dropping_inoffense(self):
        qr = lab(catalog=self.CATALOG, reject=lambda query: '"Process CommandLine"' in query)
        evidence = await collect_offense_evidence(qr, offense(), now=NOW)
        events = evidence["queries"]["events"]
        self.assertTrue(events["result_set_complete"])
        self.assertIn("WHERE INOFFENSE(12345)", events["aql"])
        self.assertNotIn("Process CommandLine", events["aql"])
        self.assertEqual(events["fields"]["optional_rejected_by_validation"], ["CommandLine", "ProcessGuid"])
        self.assertNotIn("Process CommandLine", evidence["queries"]["host_context"]["aql"])

    async def test_inoffense_validation_failure_is_never_replaced_by_an_ip_search(self):
        qr = lab(reject=lambda query: "INOFFENSE" in query)
        evidence = await collect_offense_evidence(qr, offense(), now=NOW)
        events = evidence["queries"]["events"]
        self.assertEqual(events["outcome"], "error")
        self.assertEqual(events["error"]["category"], "upstream_validation")
        self.assertEqual(events["state"], "rejected")
        self.assertEqual(events["scope"], "offense_linked")
        # No job was created and no IP search stood in for the linked records.
        self.assertEqual(qr.queries, [])
        self.assertTrue(any(g["id"] == "host:anchor" for g in evidence["gap_details"]))


class ErrorAndIsolationTests(unittest.IsolatedAsyncioTestCase):
    async def test_local_policy_rejection_is_not_a_transient_qradar_error(self):
        finding = await collect_query(object(), "SELECT * FROM events LIMIT 10", "events", "manual")
        self.assertEqual(finding["error"]["category"], "local_policy")
        self.assertFalse(finding["error"]["retryable"])
        self.assertEqual(finding["state"], "rejected")
        self.assertNotIn("continuation", finding)

    def test_failure_categories_are_distinct_and_redacted(self):
        cases = [(AQLPolicyError("Include LIMIT"), "local_policy", False),
                 (AQLValidationError("not valid"), "upstream_validation", False),
                 (ResponseFormatError("Unexpected"), "response_format", False),
                 (MCPToolFailure("QRadar", "create_ariel_search", "HTTP 403: account or API key lacks permission"), "permission", False),
                 (MCPToolFailure("QRadar", "get_ariel_search_status", "cannot connect to local MCP; check Docker/QRadar MCP status"), "connection", True),
                 (MCPToolFailure("QRadar", "get_ariel_search_status", "upstream MCP timed out"), "timeout", True),
                 (RuntimeError("Optional MCP tool unavailable: get_rule"), "tool_unavailable", False)]
        for exc, category, retryable in cases:
            with self.subTest(category=category):
                result = classify_failure(exc)
                self.assertEqual(result["category"], category)
                self.assertEqual(result["retryable"], retryable)
        leaked = classify_failure(RuntimeError("SEC token=synthetic-secret-value http://10.0.0.1"))
        self.assertNotIn("synthetic-secret-value", leaked["message"])
        self.assertNotIn("10.0.0.1", leaked["message"])

    async def test_offenses_are_isolated(self):
        powershell = row(sysmon(G_PS, 4321, PS, "powershell.exe", G_PARENT, 1000))
        qr = Lab({"INOFFENSE(101)": ("events", [powershell], None), "INOFFENSE(202)": ("events", [], None)},
                 offenses={101: offense(101), 202: offense(202)})
        first = await collect_offense_evidence(qr, offense(101), now=NOW)
        qr.queries.clear()
        second = await collect_offense_evidence(qr, offense(202), now=NOW)
        self.assertTrue(first["processes"]["process_creations"])
        self.assertEqual(second["processes"]["process_creations"], [])
        self.assertEqual(second["focused_queries"], {})
        self.assertFalse(any("101" in q for q in qr.queries))
        self.assertTrue(all("INOFFENSE(202)" in q for q in qr.queries if "INOFFENSE" in q))

    async def test_invalid_arguments_are_rejected_before_any_query(self):
        qr = lab()
        for kwargs in ({"offense": {**offense(), "id": True}}, {"offense": {**offense(), "id": 0}},
                       {"offset_hours": 15}, {"timezone_verified": "yes"}, {"budget": "fast"}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                params = {"offense": offense(), **kwargs}
                await collect_offense_evidence(qr, params.pop("offense"), now=NOW, **params)
        self.assertEqual(qr.calls, [])
        for bad in ({"max_pages": -1}, {"page_size": 0}, {"page_size": 501}, {"max_seconds": 0},
                    {"max_queries": True}, {"poll_wait_seconds": 11}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                Budget(**bad)
        plan = plan_select(EVENT_COLUMNS, FieldCatalog("events"))
        self.assertEqual(plan.optional, {})


class ToolExposureTests(unittest.TestCase):
    def test_existing_tools_schemas_and_read_only_annotations(self):
        tools = {tool.name: tool for tool in asyncio.run(mcp.list_tools())}
        self.assertEqual(len(tools), 28)
        self.assertTrue(all((tool.annotations.readOnlyHint or tool.name in LOCAL_WRITE_TOOLS) and not tool.annotations.destructiveHint for tool in tools.values()))
        verify = tools["qradar_verify_offense"].inputSchema
        self.assertEqual(set(verify["properties"]), {"offense_id", "qradar_utc_offset_hours", "timezone_verified"})
        self.assertEqual(verify["required"], ["offense_id"])
        self.assertEqual(tools["investigate_offense"].inputSchema["required"], ["offense_id"])
        self.assertEqual(tools["qradar_get_search_results"].inputSchema["required"], ["search_id"])
        self.assertFalse({"update_offense", "close_offense", "assign_offense", "add_offense_note",
                          "update_rule", "delete_ariel_search"} & QRADAR_TOOLS)
        client = RestrictedMCP(object(), QRADAR_TOOLS, QRADAR_TOOLS)
        with self.assertRaises(ValueError):
            asyncio.run(client.call("update_offense", {}))


if __name__ == "__main__":
    unittest.main()
