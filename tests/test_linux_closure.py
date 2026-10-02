"""Synthetic Linux evidence and closing recommendations; no real incident data."""
import unittest

from soc_bridge.ariel_collection import Budget
from soc_bridge.closure_assessment import closing_catalog, propose
from soc_bridge.linux_evidence import analyze, parse, stamp
from soc_bridge.offense_evidence import collect_offense_evidence, render_evidence
from soc_bridge.transports import QRADAR_TOOLS, RestrictedMCP
from synthetic_lab import Lab, MS, NOW, offense, row


def sudo(actor="monitor", target="dbuser", command="/opt/checks/status.sh demo status", pid=10):
    return (f"<86>Oct  9 16:00:01 db-demo sudo[{pid}]: {actor} : TTY=unknown ; "
            f"PWD=/ ; USER={target} ; COMMAND={command}")


def ssh(peer="198.51.100.23", target="root", method="publickey"):
    return f"<86>Oct  9 16:00:02 db-demo sshd[123]: Accepted {method} for {target} from {peer} port 12345 ssh2"


def completed(rows, **extra):
    return {"rows": rows, "scope": "synthetic", "search_id": "synthetic-job", "result_set_complete": True,
            "truncated_rows": {}, **extra}


REASONS = [{"id": 21, "text": "Non-Issue", "is_deleted": False, "is_reserved": False},
           {"id": 37, "text": "False-Positive, Tuned", "is_deleted": False, "is_reserved": False}]


class LinuxLab(Lab):
    def __init__(self, events=None, ssh_rows=None, identity_rows=None, **kw):
        self.reason_rows = REASONS
        super().__init__({
            "UNIQUECOUNT": ("flows", [{"total_rows": 0, "distinct_destinations": 0}], None),
            "FROM flows WHERE INOFFENSE": ("flows", [], None),
            "FROM events WHERE INOFFENSE": ("events", events if events is not None else [row(sudo())], None),
            "%sshd:%": ("events", ssh_rows or [], None),
            "%su:%": ("events", identity_rows or [], None),
        }, **kw)

    async def call(self, name, args):
        if name == "list_offense_closing_reasons":
            self.calls.append((name, args))
            return self.reason_rows
        return await super().call(name, args)


class LinuxParserTests(unittest.TestCase):
    def test_sudo_records_actor_target_and_command_without_proving_success(self):
        record = parse(sudo())
        self.assertEqual((record["actor"], record["target"], record["command"]),
                         ("monitor", "dbuser", "/opt/checks/status.sh demo status"))
        self.assertEqual(record["outcome"], "not_established")

    def test_su_root_and_pam_are_not_ssh_authentication(self):
        rows = [row("db-demo su[9]: (to dbuser) root on none"),
                row("db-demo su[9]: pam_unix(su:session): session opened for user root by (uid=0)")]
        data = analyze(completed(rows), "identity")
        self.assertEqual(data["accepted_root_ssh_count"], 0)
        self.assertEqual(data["kind_counts"], {"su_identity_record": 1, "pam_session_record": 1})
        self.assertEqual(data["records"][0]["target"], "dbuser")

    def test_publickey_password_invalid_peer_and_preauth_are_distinct(self):
        rows = [row(ssh()), row(ssh(method="password", target="admin")),
                row("db-demo sshd[12]: Connection closed by 192.0.2.10 port 22 [preauth]"),
                row(ssh(peer="not-an-ip"))]
        data = analyze(completed(rows), "ssh")
        self.assertEqual(data["accepted_root_ssh_count"], 1)
        self.assertEqual(data["accepted_ssh_count"], 2)
        self.assertEqual(data["unparsed_daemon_rows"], 1)
        self.assertIsNone(data["negative_claim"])

    def test_qid_name_alone_and_embedded_windows_command_are_not_linux_proof(self):
        rows = [row("generic CRE classification", name="Root Login"),
                row("EventID=1 CommandLine: echo 'db-demo sshd[12]: Accepted password for root from 192.0.2.1 port 22 ssh2'")]
        data = analyze(completed(rows), "ssh", (MS, MS + 120000))
        self.assertEqual(data["daemon_rows"], 0)
        self.assertFalse(data["recognized_message_census_complete"])
        self.assertIsNone(data["negative_claim"])

    def test_every_row_including_last_command_is_censused(self):
        rows = [row(sudo(pid=i)) for i in range(501)] + [row(sudo(target="storage", command="/opt/checks/space.sh", pid=600))]
        data = analyze(completed(rows), "events")
        self.assertEqual(data["sudo_target_counts"], {"dbuser": 501, "storage": 1})
        self.assertEqual(data["sudo_command_groups"], 2)
        self.assertEqual(data["kind_counts"]["sudo_command_record"], 502)

    def test_cut_and_unknown_content_prevent_negative_claim(self):
        for finding in (completed([row("db-demo sshd[10]: unknown authentication format")]),
                        completed([row("db-demo sshd[10]: Connection closed [preauth]")], truncated_rows={"0": ["raw_payload"]}),
                        completed([], result_set_complete=False)):
            with self.subTest(finding=finding):
                data = analyze(finding, "ssh", (MS, MS + 120000))
                self.assertFalse(data["recognized_message_census_complete"])
                self.assertIsNone(data["negative_claim"])

    def test_earlier_login_is_not_counted_inside_strict_window(self):
        data = analyze(completed([row(ssh(), -60000)]), "ssh", (MS, MS + 120000))
        self.assertEqual(data["outside_window_rows"], 1)
        self.assertEqual(data["accepted_root_ssh_count"], 0)
        self.assertIsNone(data["negative_claim"])

    def test_epoch_is_converted_as_utc_without_payload_offset_assumption(self):
        self.assertEqual(stamp(MS), "2026-10-09T16:00:00.000Z")
        self.assertEqual(parse("<86>1 2026-10-09T16:00:01Z db-demo sudo 100 - - monitor : TTY=unknown ; PWD=/ ; USER=dbuser ; COMMAND=id")["actor"], "monitor")

    def test_similar_long_commands_stay_distinct_before_preview_cut(self):
        prefix = "/opt/checks/tool " + "a" * 2100
        data = analyze(completed([row(sudo(command=prefix + " one")), row(sudo(command=prefix + " two"))]), "events")
        self.assertEqual(data["sudo_command_groups"], 2)
        self.assertTrue(all(c["command_preview_truncated"] for c in data["sudo_commands"]))
        self.assertEqual([c["rows"] for c in data["sudo_commands"]], [1, 1])


class CollectionAndClosingTests(unittest.IsolatedAsyncioTestCase):
    async def test_linux_pivots_are_epoch_bounded_and_read_only(self):
        qr = LinuxLab(ssh_rows=[row(ssh())])
        evidence = await collect_offense_evidence(qr, offense(event_count=1), now=NOW)
        for name in ("linux_ssh_window", "linux_identity_window"):
            query = evidence["queries"][name]["aql"]
            self.assertIn(f"starttime >= {MS}", query)
            self.assertIn(f"starttime <= {MS + 120000}", query)
            self.assertIn("LAST 24 HOURS", query)
            self.assertNotIn("INOFFENSE", query)  # separate context, not incident membership
            self.assertNotIn("prop_", query)  # no Windows property dependency
        self.assertEqual(evidence["linux"]["ssh_window"]["accepted_root_ssh_count"], 1)
        self.assertTrue(any(f["fact"] == "accepted_root_ssh_record" for f in evidence["assessment"]["confirmed_facts"]))
        self.assertFalse(evidence["closure_assessment"]["ready_to_close"])
        self.assertIsNone(evidence["closure_assessment"]["recommended_reason"])
        self.assertFalse({"set_offense_status", "add_offense_note"} & QRADAR_TOOLS)

    async def test_parser_census_survives_pagination_and_witness_cap(self):
        records = [row(sudo(pid=i), i) for i in range(501)] + [row(sudo(target="storage"), 502)]
        evidence = await collect_offense_evidence(LinuxLab(events=records), offense(event_count=502), now=NOW)
        self.assertGreater(evidence["queries"]["events"]["pages"], 1)
        self.assertLessEqual(len(evidence["queries"]["events"]["samples"]), 8)
        self.assertEqual(evidence["linux"]["offense"]["sudo_target_counts"]["storage"], 1)
        self.assertIn("Closing recommendation", "\n".join(render_evidence(evidence)))

    async def test_linux_pending_keeps_existing_search_and_does_not_claim_absence(self):
        evidence = await collect_offense_evidence(LinuxLab(), offense(), now=NOW, budget=Budget(max_queries=3))
        self.assertEqual(evidence["queries"]["linux_ssh_window"]["outcome"], "not_started")
        self.assertIsNone(evidence["linux"]["ssh_window"]["negative_claim"])
        self.assertTrue(any(b["id"] == "coverage:linux_ssh_window" for b in evidence["closure_assessment"]["blocking_requirements"]))

    async def test_live_reason_ids_are_preserved_without_closing_or_tuning(self):
        qr = LinuxLab()
        evidence = await collect_offense_evidence(qr, offense(), now=NOW)
        closing = evidence["closure_assessment"]
        self.assertEqual([r["id"] for r in closing["conditional_reason_options"]], [21, 37])
        tuned = closing["conditional_reason_options"][1]
        self.assertIn("already applied", tuned["condition"])
        self.assertFalse(tuned["eligible_now"])
        self.assertEqual(closing["executed_actions"], [])
        self.assertIn("manter pendente", closing["suggested_note"])
        self.assertIn("linux_ssh_window", closing["suggested_note"])
        self.assertIsNone(closing["numeric_risk_score"])

    async def test_missing_catalog_does_not_break_collection_or_invent_reason(self):
        evidence = await collect_offense_evidence(Lab({"FROM events WHERE INOFFENSE": ("events", [row(sudo())], None)}),
                                                  offense(), now=NOW)
        self.assertEqual(evidence["closing_reasons"]["state"], "unavailable")
        self.assertEqual(evidence["closure_assessment"]["conditional_reason_options"], [])

    async def test_deleted_reserved_and_malformed_reasons_are_not_offered(self):
        qr = LinuxLab()
        qr.reason_rows = REASONS + [{"id": 99, "text": "Deleted", "is_deleted": True, "is_reserved": False},
                                   {"id": 98, "text": "Reserved", "is_deleted": False, "is_reserved": True},
                                   {"id": True, "text": "Invalid", "is_deleted": False, "is_reserved": False}]
        catalog = await closing_catalog(qr, Budget())
        self.assertEqual([r["id"] for r in catalog["reasons"]], [21, 37])

    async def test_no_linux_trigger_means_no_linux_jobs(self):
        evidence = await collect_offense_evidence(LinuxLab(events=[row("EventID=4624 synthetic Windows record")]), offense(), now=NOW)
        self.assertFalse(evidence["linux"]["detected"])
        self.assertNotIn("linux_ssh_window", evidence["queries"])

    async def test_failed_flow_census_is_secondary_for_linux_authentication(self):
        evidence = await collect_offense_evidence(LinuxLab(), offense(), now=NOW)
        evidence["queries"]["flow_census"]["result_set_complete"] = False
        result = propose(evidence)
        self.assertIn("flow_census", result["secondary_collection_pending"])
        self.assertNotIn("coverage:flow_census", [b["id"] for b in result["blocking_requirements"]])

    async def test_read_only_allowlist_rejects_closure_and_notes(self):
        client = RestrictedMCP(object(), QRADAR_TOOLS, QRADAR_TOOLS)
        for name in ("set_offense_status", "add_offense_note", "update_rule"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                await client.call(name, {})

    async def test_closed_status_reports_actual_reason_without_treating_it_as_benign(self):
        evidence = await collect_offense_evidence(LinuxLab(), offense(status="CLOSED", closing_reason_id=21), now=NOW)
        closing = evidence["closure_assessment"]
        self.assertEqual(closing["decision"], "review_existing_closure")
        self.assertEqual(closing["existing_closure"]["reason_text"], "Non-Issue")
        self.assertFalse(closing["ready_to_close"])
        self.assertFalse(evidence["assessment"]["final_benign_verdict_permitted"])

    async def test_identity_query_is_not_used_to_exclude_ssh(self):
        evidence = await collect_offense_evidence(LinuxLab(), offense(), now=NOW)
        self.assertIsNone(evidence["linux"]["identity_window"]["negative_claim"])
        self.assertIsNotNone(evidence["linux"]["ssh_window"]["negative_claim"])

    async def test_rfc5424_daemons_are_included_in_query_filters(self):
        payload = "<86>1 2026-10-09T16:00:01Z db-demo sshd 100 - - Accepted publickey for root from 198.51.100.2 port 1234 ssh2"
        evidence = await collect_offense_evidence(LinuxLab(ssh_rows=[row(payload)]), offense(), now=NOW)
        self.assertIn("% sshd %", evidence["queries"]["linux_ssh_window"]["aql"])
        self.assertIn("% su %", evidence["queries"]["linux_identity_window"]["aql"])
        self.assertIn("% sudo %", evidence["queries"]["host_context"]["aql"])
        self.assertEqual(evidence["linux"]["ssh_window"]["accepted_root_ssh_count"], 1)

    async def test_no_verified_linux_anchor_preserves_gap(self):
        # An unqualified sudo daemon is parseable but provides no host identity.
        payload = "sudo: monitor : TTY=unknown ; PWD=/ ; USER=dbuser ; COMMAND=id"
        evidence = await collect_offense_evidence(LinuxLab(events=[row(payload)]),
                                                  offense(offense_source="monitor"), now=NOW)
        self.assertNotIn("linux_ssh_window", evidence["queries"])
        self.assertEqual(evidence["focused_queries"]["linux_ssh_window"]["state"], "not_built")
        self.assertIn("linux:linux_ssh_window:anchor", [b["id"] for b in evidence["closure_assessment"]["blocking_requirements"]])

    async def test_non_linux_closing_note_carries_relevant_attribution_gaps(self):
        evidence = await collect_offense_evidence(LinuxLab(events=[row("EventID=4624 synthetic Windows record")]),
                                                  offense(), now=NOW)
        closing = evidence["closure_assessment"]
        self.assertIn("attribution:host-process", [b["id"] for b in closing["blocking_requirements"]])
        self.assertIn("attribution:host-process", closing["suggested_note"])


if __name__ == "__main__":
    unittest.main()
