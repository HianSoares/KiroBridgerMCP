"""Proportional assessment: collection completeness, confirmed facts, hypotheses and verdict limits."""

from __future__ import annotations

# Which conclusions each collection area can block. Anything not listed is a
# secondary pending item for that conclusion, not an impediment to reporting it.
BLOCKS = {
    "events": ["benign_verdict", "complete_offense_record_review"],
    "flows": ["benign_verdict", "offense_network_claims", "dhcp_pattern"],
    "flow_census": ["offense_network_claims", "dhcp_pattern"],
    "host_context": ["host_activity_absence_claims"],
    "script_blocks": ["powershell_content_claims"],
    "integrity": ["code_integrity_claims"],
    "host_flows": ["process_network_claims"],
    "parent": ["process_ancestry_root"],
    "linux_ssh_window": ["linux_authentication_claims", "benign_verdict"],
    "linux_identity_window": ["linux_authentication_claims"],
}
CONCLUSIONS = ("benign_verdict", "complete_offense_record_review", "offense_network_claims", "dhcp_pattern",
               "host_activity_absence_claims", "process_chain", "process_ancestry_root",
               "powershell_content_claims", "code_integrity_claims", "process_network_claims",
               "account_nature", "linux_authentication_claims")
VERDICT_MEANING = ("false means this automatic collection alone cannot support a final benign/false-positive "
                   "verdict. It is not a ban on reporting facts supported by evidence, it does not mean the "
                   "activity is malicious, and it does not block a preliminary report with a precise hand-off. "
                   "It is never set to true just to allow closure.")


def gap(gap_id: str, scope: str, state: str, blocks: list[str], evidence: dict | None = None,
        next_action: str = "", text: str = "") -> dict:
    return {"id": gap_id, "scope": scope, "state": state,
            "relevance": {"blocks": blocks, "secondary_for": [c for c in CONCLUSIONS if c not in blocks]},
            "evidence": evidence or {}, "next_action": next_action, "summary": text}


def query_gaps(name: str, finding: dict) -> list[dict]:
    family = "parent" if name.startswith("parent_lookup") else name
    blocks = BLOCKS.get(family, ["benign_verdict"])
    gaps = []
    evidence = {"search_id": finding.get("search_id"), "outcome": finding.get("outcome"),
                "record_count": finding.get("record_count"), "returned_rows": finding.get("returned_rows")}
    if not finding.get("result_set_complete"):
        plan = finding.get("continuation") or {}
        action = (plan.get("note") or (finding.get("error") or {}).get("next_action")
                  or "Re-run only with a hypothesis that can change the conclusion")
        gaps.append(gap(f"query:{name}", finding.get("scope", name), finding.get("outcome", "unknown"),
                        blocks, evidence, action, f"{name}: query coverage incomplete or unavailable"))
    if finding.get("truncated_fields"):
        gaps.append(gap(f"truncation:{name}", finding.get("scope", name), "bridge_truncated", blocks, evidence,
                        "Read the original record (console/collector/source) for the full value",
                        f"{name}: bridge truncated fields; original content unavailable in this response"))
    return gaps


def assess(result: dict) -> dict:
    queries = result["queries"]
    complete = [n for n, q in queries.items() if q.get("result_set_complete")]
    pending = [n for n, q in queries.items() if q.get("outcome") == "pending"]
    not_started = [n for n, q in queries.items() if q.get("outcome") == "not_started"]
    incomplete = [n for n in queries if n not in complete + pending + not_started]
    processes = result.get("processes", {})
    facts = []
    for item in processes.get("process_creations", [])[:20]:
        prov = item["provenance"]
        facts.append({"fact": "process_creation_observed", "image": item.get("image"), "guid": item.get("guid_norm"),
                      "host": item.get("host_norm"), "time_utc": prov.get("starttime_utc"),
                      "source": {"query": prov["query"], "search_id": prov["search_id"],
                                 "result_row_index": prov["result_row_index"]}})
    for link in processes.get("links", [])[:20]:
        facts.append({"fact": "parent_child_link", **link})
    for event in result.get("integrity", {}).get("integrity_events", [])[:10]:
        facts.append({"fact": "integrity_event_recorded", "event_id": event["event_id"],
                      "file_as_reported": event["file_as_reported"], "source": event["provenance"]})
    blocks = processes.get("script_blocks", [])
    if blocks:
        facts.append({"fact": "powershell_session_content_recorded", "records": len(blocks)})
    linux = result.get("linux", {})
    linked_linux = linux.get("offense", {})
    if linked_linux.get("kind_counts", {}).get("sudo_command_record"):
        facts.append({"fact": "sudo_invocation_records", "rows": linked_linux["kind_counts"]["sudo_command_record"],
                      "actors": linked_linux["sudo_actor_counts"], "targets": linked_linux["sudo_target_counts"],
                      "source": {"query": "events", "search_id": linked_linux["search_id"]},
                      "coverage_complete": linked_linux["recognized_message_census_complete"],
                      "meaning": "Invocation records, not proven command success or authorization"})
    for event in linux.get("ssh_window", {}).get("accepted_root_ssh_records", [])[:10]:
        facts.append({"fact": "accepted_root_ssh_record", "peer": event["peer"], "method": event["method"],
                      "host": event["host"], "source": event["provenance"], "authorization": "unverified"})
    by_conclusion: dict[str, list[str]] = {c: [] for c in CONCLUSIONS}
    for item in result["gap_details"]:
        for conclusion in item["relevance"]["blocks"]:
            by_conclusion.setdefault(conclusion, []).append(item["id"])
    chain_confirmed = bool(processes.get("links")) or bool(processes.get("process_creations"))
    reportable = ["Observed records with source, search ID and row index"]
    if chain_confirmed:
        reportable.append("Process creations/links observed, independently of pending flow census or counts")
    return {
        "status": "preliminary",
        "final_benign_verdict_permitted": False,
        "final_benign_verdict_permitted_meaning": VERDICT_MEANING,
        "collection_completeness": {"complete_in_query_window": complete, "incomplete_or_limited": incomplete,
                                    "pending": pending, "not_started": not_started,
                                    "note": "All queries finishing is not evidence of a false positive."},
        "confirmed_facts": facts,
        "fact_note": "Facts are observations in the named records; they are not causes, intent or authorization.",
        "hypotheses": [
            {"id": "malicious_activity", "status": "open"},
            {"id": "legitimate_or_authorized", "status": "open",
             "needs": "Owner, change record, inventory or identity source; vendor paths and repeated hashes do not suffice"},
            {"id": "detection_error", "status": "open", "needs": "Active CRE definition and the triggering records"},
            {"id": "attribution_error", "status": "open",
             "needs": "Same-record identifiers (host/GUID/record number) or historical IP mapping"}],
        "hypothesis_confidence": "Not assigned by the bridge; justify with source, identity, time, completeness and corroboration.",
        "blocking_gaps_by_conclusion": {c: ids for c, ids in by_conclusion.items() if ids},
        "conclusions_without_listed_blockers": [c for c, ids in by_conclusion.items() if not ids],
        "final_verdict_possible": False,
        "final_verdict_reason": "Authorization/inventory/identity sources are outside this bridge; blocking gaps listed by conclusion.",
        "reportable_now": reportable,
        "handoff": "Name the missing record, its source and the exact field; stop repeating searches that cannot change the conclusion.",
    }
