"""Bridge coverage of the upstream MCP catalogs: what is integrated, when it runs, and why the rest is not.

The upstream catalogs (docs/coverage/*.json) are snapshots extracted from the official
handlers. A tool listed there may still be absent from a given installation (feature
toggles, toolsets, license, permissions); the bridge checks availability at run time.
"""

from __future__ import annotations

import re

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
    "search_endpoint_activities_list": ("search", E_ALR, "alert hash/path, process instance, then endpoint", "time partitions (no cursor upstream)"),
    "search_detections_list": ("search", E_ALR, "alert hash, then endpoint", "time partitions"),
    "endpoint_security_endpoints_list": ("endpoint", E_ALR, "endpoint name without GUID", "skipToken forwarded"),
    "workbench_alert_notes_list": ("workbench", E_ALR, "always (enrichment)", "first page only: skipToken declared but not forwarded"),
    "workbench_observed_attack_techniques_list": ("workbench", E_ALR, "alert endpoint GUID/name", "nextBatchToken, 5 batches"),
    "workbench_insights_list": ("workbench", E_ALR, "no insight ID in the alert: insights created in the alert window", "50 items; relation = alert ID found in content"),
    "workbench_insight_get": ("workbench", E_ALR, "insight ID in alert or candidate insight", "3 candidates checked"),
    "workbench_insight_impact_scope_entities_list": ("workbench", E_ALR, "insight that references the alert", "values preserved within limits"),
    "workbench_insight_indicators_list": ("workbench", E_ALR, "insight that references the alert", "values preserved within limits"),
    "workbench_insight_matched_highlights_list": ("workbench", E_ALR, "insight that references the alert", "values preserved within limits"),
    "search_network_activities_list": ("search", E_ALR, "hypothesis: transfer of a collected artifact", "one page of 500"),
    "search_identity_activities_list": ("search", E_ALR, "account entity in the alert", "IdP data; partial match; not account nature"),
    "search_email_activities_list": ("search", E_ALR, "mailbox entity in the alert", "one page"),
    "search_container_activities_list": ("search", E_ALR, "container entity in the alert", "one page; partial match"),
    "search_mobile_activities_list": ("search", E_ALR, "mobile entity in the alert", "one page"),
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
}

TREND_RULES = [
    (r"^iam_", "Vision One platform IAM (console accounts, keys, roles); not evidence about Windows/Linux/AD accounts"),
    (r"_generate_|^container_security_generate_service_gateway_password$", "registered as read but generates templates/credentials"),
    (r"^aisecurity_guardrails_apply$", "submits content for AI guardrail evaluation; not a read of case evidence"),
    (r"^(cam_|cloud_risk_management_)", "cloud account management/posture configuration; no verifiable mapping from alert entities"),
    (r"^container_security_", "container security policies/clusters/rulesets; container activity is read through Search when an entity justifies it"),
    (r"^email_security_", "email security deployment inventory"),
    (r"^security_awareness_", "awareness training/phishing simulation data; not case evidence"),
    (r"^security_playbooks_", "playbook definitions/runs; no verifiable link to a case in the handler arguments"),
    (r"^tag_management_", "asset tag administration"),
    (r"^healthcheck_", "connectivity check of the MCP itself"),
    (r"^business_profile_get$", "tenant business profile"),
    (r"^(datalake_|oat_data_pipeline)", "data export pipeline administration"),
    (r"^file_security_", "file security storage configuration"),
    (r"^endpoint_security_", "endpoint fleet policies/tasks/schedules administration"),
    (r"^sandbox_(submission_usage_get|tasks_list|task_get)$", "submission quota/tasks; the bridge never submits samples"),
    (r"^sandbox_analysis_result_(report_get|investigation_package_get)$", "downloads report/package files; binary artifacts are not downloaded"),
    (r"^response_", "response configuration (scripts, osquery, YARA, exceptions, settings); no case trigger"),
    (r"^threatintel_", "intelligence feeds/reports/tasks catalogs; not keyed by the alert's identifiers"),
    (r"^crem_(account_compromise|high_risk_user|attack_surface_high_risk_users)", "account risk needs a CREM user ID; alerts do not provide a verifiable mapping"),
    (r"^crem_", "risk inventory for other asset classes or tenant posture; not keyed to the alert entities"),
    (r"^case_management_", "case attachments/tasks/highlights not read automatically; case and contents are read"),
    (r"^workbench_alert_note_get$", "single note by ID; the notes list already returns the notes"),
    (r"^dmm_exception_get$", "single exception by ID; the exceptions list is read"),
    (r"^search_cloud_activities_list$", "no verifiable mapping from alert entities to CloudTrail/VPC fields"),
]

QRADAR_RULES = [
    (r"^(dns_lookup|whois_lookup)$", "creates a lookup task and sends the IP to external DNS/WHOIS services"),
    (r"^(get_dns_result|get_whois_result)$", "reads a lookup task the bridge never creates"),
    (r"^(list_users|list_user_roles)$", "QRadar console accounts/roles administration; not case evidence"),
    (r"^(get_staged_network_hierarchy|get_deploy_status)$", "staged/deploy administration; the deployed hierarchy is read instead"),
    (r"^(get_system_info|list_servers)$", "platform administration"),
    (r"^(get_custom_action|list_custom_actions)$", "custom action (response script) definitions; no case relation"),
    (r"^(list_high_level_categories|list_low_level_categories|list_qid_records)$", "catalog listings; the specific QID/category is read instead"),
    (r"^(get_qid_record|get_dsm_event_mapping)$", "lookup by internal record ID; QID-based lookups are used"),
    (r"^(get_reference_set)$", "set metadata by ID; listings are read and entries have no read tool upstream"),
    (r"^(get_saved_search)$", "single saved search by ID; the listing is read"),
    (r"^(list_qvm_assets)$", "QVM asset listing by saved search; asset context comes from the asset model"),
    (r"^(list_cases)$", "forensics case listing has no case-to-offense relation; get_case reads a cited case"),
]


def nature_qradar(tool: dict) -> str:
    if tool["name"] in ("create_ariel_search",):
        return "creates an Ariel search job (reads data; allowed and budgeted)"
    if tool["name"] == "validate_aql":
        return "validation (POST without state change)"
    return {"GET": "read", "POST": "mutation (POST)", "PUT": "mutation (PUT)", "DELETE": "mutation (DELETE)"}.get(tool["verb"], tool["verb"])


def exclusion(name: str, rules: list) -> str:
    for pattern, why in rules:
        if re.search(pattern, name):
            return why
    return "not integrated: no investigative trigger identified"


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
