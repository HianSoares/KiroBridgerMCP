"""Curated workflows over the upstream MCP catalogs, and the tools exercised by contract tests.

Every audited upstream tool is reachable through the registry (upstream_registry.json): query tools via
upstream_query on soc-bridge-readonly, changes only via the separate soc-bridge-change server. This
module adds what the registry does not hold: which tools the curated investigation workflows call
automatically (entry point, trigger, limits) and which tools have end-to-end contract tests against
the synthetic upstream (tests/fake_upstream_mcp.py). A tool listed in a catalog may still be absent
from a given installation (feature toggles, toolsets, license, permissions); the bridge checks
availability at run time.
"""

from __future__ import annotations

E_OFF = "investigate_offense/investigate_case (offense)"
E_VER = "qradar_verify_offense, qradar_investigate_offenses, qradar_assess_closure"
E_CTX = "qradar_read_context"
E_AQL = "qradar_* AQL tools, qradar_verify_offense"
E_ALR = "investigate_vision_alert/investigate_case (WB-), deepened alerts of investigate_offense"

# name -> (category, entry point, trigger, limits)
QRADAR = {
    "get_offense": ("offense", f"{E_OFF}; {E_VER}; alert QRadar leads", "offense ID given or offense lead from address index", "single object"),
    "list_offenses": ("offense", "qradar_list_offenses, qradar_find_offenses, qradar_investigate_offenses", "status queue triage or description discovery", "bounded +id pages; local metadata priority or literal description matching"),
    "list_source_addresses": ("offense", f"{E_OFF}; alert leads", "offense ID or alert IP", "100 rows; cap reported"),
    "list_local_destination_addresses": ("offense", f"{E_OFF}; alert leads", "offense ID or alert IP", "100 rows; cap reported"),
    "list_offense_closing_reasons": ("offense", E_VER, "closure proposal", "live catalog; deleted/reserved excluded; no ID invented"),
    "get_rule": ("rules", f"{E_VER}; qradar_get_rule", "rule IDs in offense.rules", "metadata only, not CRE tests"),
    "validate_aql": ("ariel", E_AQL, "every query before creation", "validation only"),
    "create_ariel_search": ("ariel", E_AQL, "planned/requested query", "creates a search job (read of data); budgeted; creation_uncertain kept"),
    "get_ariel_search_status": ("ariel", E_AQL, "same search ID", "poll budget"),
    "get_ariel_search_results": ("ariel", E_AQL, "same search ID and cursor", "page budget; cursor of failed page kept"),
    "get_offense_notes": ("offense", E_VER, "offense under verification", "50 notes; untrusted text"),
    "list_offense_types": ("offense", E_VER, "offense_type in metadata", "one type"),
    "list_assets": ("asset", f"{E_VER}; {E_CTX} asset", "offense IP (max 4)", "10 assets; IP verified locally; snapshot"),
    "list_asset_properties": ("asset", E_VER, "assets were returned", "200 properties"),
    "get_network_hierarchy": ("config", E_VER, "offense IPs", "deployed hierarchy; CIDR match local"),
    "get_log_source": ("log_source", f"{E_VER}; {E_CTX} log_source", "log_sources in offense metadata (max 5)", "configuration snapshot"),
    "list_log_sources": ("log_source", f"{E_CTX} log_sources", "investigator name fragment", "300 items scanned; local match"),
    "list_log_source_types": ("log_source", E_VER, "type_id of offense log sources", "3 types"),
    "list_rules": ("rules", f"{E_CTX} rules", "investigator name fragment", "300 items scanned; metadata only"),
    "list_building_blocks": ("rules", f"{E_CTX} building_blocks", "investigator name fragment", "300 items scanned; metadata only"),
    "get_building_block": ("rules", f"{E_CTX} building_block", "investigator BB ID", "metadata only"),
    "get_qid_record_by_qid": ("data_classification", f"{E_VER}; {E_CTX} qid", "QIDs in collected offense events (max 6)", "type, not payload content"),
    "get_low_level_category": ("data_classification", E_VER, "category of a read QID", "single object"),
    "get_high_level_category": ("data_classification", E_VER, "category of a read low-level category", "single object"),
    "list_dsm_event_mappings": ("data_classification", f"{E_CTX} dsm_mappings", "investigator QID record ID", "100 mappings"),
    "list_reference_sets": ("reference_data", f"{E_CTX} reference_collections", "investigator name fragment", "metadata only; no entry read tool upstream"),
    "list_reference_maps": ("reference_data", f"{E_CTX} reference_collections", "investigator name fragment", "metadata"),
    "list_reference_tables": ("reference_data", f"{E_CTX} reference_collections", "investigator name fragment", "metadata"),
    "get_reference_map": ("reference_data", f"{E_CTX} reference_lookup", "investigator collection + value", "500 elements; exact local match; never closes a case"),
    "get_reference_table": ("reference_data", f"{E_CTX} reference_lookup", "investigator collection + value", "500 elements; exact local match"),
    "list_saved_searches": ("ariel", f"{E_CTX} saved_searches", "investigator name fragment", "definitions only"),
    "list_vulnerabilities": ("qvm", f"{E_CTX} qvm_vulnerabilities", "investigator QVM saved search name", "QVM license; 50 items"),
    "get_case": ("forensics", f"{E_CTX} forensic_case", "investigator case ID", "Incident Forensics license"),
    "geolocate_ip": ("services", f"{E_CTX} geolocation", "investigator public IP", "QRadar geodata; private IPs rejected"),
}

TREND = {
    "workbench_alerts_list": ("workbench", f"trend_find_alerts; {E_OFF}", "status/severity/window or offense IP", "one page; no cursor input upstream"),
    "workbench_alert_detail_get": ("workbench", E_ALR, "WB alert ID", "single alert; reused when deepened"),
    "search_endpoint_activities_list": ("search", E_ALR + " / trend_search_data", "alert hash/path, process instance, then endpoint or explicit source query", "direct: bounded time partitions; automatic: time partitions (no cursor upstream)"),
    "search_detections_list": ("search", E_ALR + " / trend_search_data", "alert hash, then endpoint or explicit source query", "direct: bounded time partitions; automatic: time partitions"),
    "endpoint_security_endpoints_list": ("endpoint", E_ALR, "endpoint name without GUID", "skipToken forwarded"),
    "workbench_alert_notes_list": ("workbench", E_ALR, "always (enrichment)", "first page only: skipToken declared but not forwarded"),
    "workbench_observed_attack_techniques_list": ("workbench", E_ALR, "alert endpoint GUID/name", "nextBatchToken, 5 batches"),
    "workbench_insights_list": ("workbench", E_ALR, "no insight ID in the alert: insights created in the alert window", "50 items; relation = alert ID found in content"),
    "workbench_insight_get": ("workbench", E_ALR, "insight ID in alert or candidate insight", "3 candidates checked"),
    "workbench_insight_impact_scope_entities_list": ("workbench", E_ALR, "insight that references the alert", "values preserved within limits"),
    "workbench_insight_indicators_list": ("workbench", E_ALR, "insight that references the alert", "values preserved within limits"),
    "workbench_insight_matched_highlights_list": ("workbench", E_ALR, "insight that references the alert", "values preserved within limits"),
    "search_network_activities_list": ("search", E_ALR + " / trend_search_data", "hypothesis: transfer of a collected artifact or explicit source query", "direct: bounded time partitions; automatic: one page of 500"),
    "search_identity_activities_list": ("search", E_ALR + " / trend_search_data", "account entity in the alert or explicit source query", "direct: bounded time partitions; automatic: IdP data; partial match; not account nature"),
    "search_email_activities_list": ("search", E_ALR + " / trend_search_data", "mailbox entity in the alert or explicit source query", "direct: bounded time partitions; automatic: one page"),
    "search_container_activities_list": ("search", E_ALR + " / trend_search_data", "container entity in the alert or explicit source query", "direct: bounded time partitions; automatic: one page; partial match"),
    "search_mobile_activities_list": ("search", E_ALR + " / trend_search_data", "mobile entity in the alert or explicit source query", "direct: bounded time partitions; automatic: one page"),
    "search_activity_statistics_get": ("search", E_ALR, "Search empty/no linked record", "tenant-level, period ending now"),
    "search_sensor_statistics_get": ("search", E_ALR, "Search empty/no linked record", "tenant-level, period ending now"),
    "endpoint_security_endpoint_get": ("endpoint", E_ALR, "endpoint GUID in alert", "current snapshot"),
    "eiqs_endpoints_list": ("eiqs", E_ALR, "alert endpoint GUID/name", "current snapshot"),
    "threatintel_suspicious_objects_list": ("threatintel", E_ALR, "alert/insight hash (max 3)", "configured list, not reputation"),
    "threatintel_exceptions_list": ("threatintel", E_ALR, "alert/insight hash", "configuration, not authorization"),
    "sandbox_analysis_results_list": ("sandbox", E_ALR, "alert/insight hash", "existing results; no submission"),
    "sandbox_analysis_result_get": ("sandbox", E_ALR, "existing result for the hash (max 2)", "single result"),
    "sandbox_analysis_result_suspicious_objects_list": ("sandbox", E_ALR, "existing result for the hash", "objects of that analysis"),
    "response_tasks_list": ("response", E_ALR, "alert endpoint", "client-side match by agentGuid/endpointName"),
    "response_task_get": ("response", E_ALR, "matched existing task (max 3)", "single task; read only"),
    "dmm_models_list": ("dmm", E_ALR, "alert model name", "exact local match; no name filter upstream"),
    "dmm_custom_models_list": ("dmm", E_ALR, "model not among built-in models read", "exact local match"),
    "dmm_custom_filters_list": ("dmm", E_ALR, "matched filter IDs/names", "exact local match"),
    "dmm_exceptions_list": ("dmm", E_ALR, "alert has a model", "configuration, not authorization"),
    "crem_attack_surface_devices_list": ("crem", E_ALR, "alert endpoint name", "skipToken forwarded; risk context"),
    "crem_high_risk_devices_list": ("crem", E_ALR, "alert endpoint name", "risk score is context, not a verdict"),
    "crem_vulnerable_devices_list": ("crem", E_ALR, "alert endpoint name", "exposure context"),
    "case_management_cases_list": ("cases", E_ALR, "always; alert ID matched in content", "one page; no cursor input"),
    "case_management_case_get": ("cases", E_ALR, "case containing the alert ID (max 2)", "single case"),
    "case_management_case_contents_list": ("cases", E_ALR, "case containing the alert ID", "50 contents; untrusted text"),
    "audit_logs_list": ("audit", E_ALR, "alert updated after creation", "±10 min; matched by alert ID"),
    "search_cloud_activities_list": ("search", "trend_search_data", "explicit CloudTrail/VPC source query", "bounded time partitions; no upstream cursor"),
}

# Tools with an end-to-end test through upstream_query/upstream_download/soc-bridge-change against the
# synthetic upstream, reproducing the product's response format (tests/test_upstream_access.py).
CONTRACT_TESTED = {
    ("qradar", "list_offenses"): "range pagination forwarded (offset/limit), arguments forwarded unchanged",
    ("qradar", "get_offense"): "HTTP 404 classified, upstream body not copied",
    ("qradar", "list_users"): "HTTP 403 classified as permission, not license",
    ("qradar", "geolocate_ip"): "formatted text over stdio, UTF-8 preserved",
    ("qradar", "get_system_info"): "timeout during the call and cancellation",
    ("qradar", "list_rules"): "absent from tools/list: tool_absent, no call",
    ("qradar", "add_offense_note"): "change path: human approval, policy, single use",
    ("vision_one", "endpoint_security_endpoints_list"): "skipToken continuation and ETag headers block",
    ("vision_one", "workbench_alert_notes_list"): "skipToken not forwarded: continuation refused; untrusted text",
    ("vision_one", "audit_logs_list"): "HTTP 403 with entitlement text: permission_or_license",
    ("vision_one", "search_detections_list"): "empty result; read-only container flags",
    ("vision_one", "sandbox_analysis_result_report_get"): "binary embedded resource, saved by upstream_download",
    ("vision_one", "workbench_alert_notes_create"): "change path in a container started without -readonly",
    ("vision_one", "container_security_generate_service_gateway_password"): "generated credential returned once, not stored",
}


def pagination_qradar(tool: dict) -> str:
    if tool["range_pagination"]:
        return "Range header from offset/limit (forwarded)"
    return "single response"


def pagination_trend(tool: dict) -> str:
    declared = set(tool["declared"])
    missing = set(tool["not_forwarded"])
    for token in ("skipToken", "nextBatchToken"):
        if token in declared:
            return f"{token} declared but NOT forwarded" if token in missing else f"{token} forwarded"
    if "top" in declared:
        return "top only (no continuation input)"
    return "single response"
