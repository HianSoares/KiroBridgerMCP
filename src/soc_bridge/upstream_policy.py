"""Reviewed policy for every upstream MCP tool: effect, access path and support status.

The classification rests on facts read from the official handlers (scripts/upstream_catalog.py):
the HTTP method the handler sends, the client calls it makes, how the upstream registers it
(QRadar ``approval_required``; Vision One read/write toolset lists) and whether it uploads a local
file. Names, verbs and ``readOnlyHint`` alone never decide: a POST can be a validation or a search
job, a tool registered as read can generate a credential, and a tool annotated destructive can be a
plain GET. Exceptions to the generic rules are listed explicitly below with the reason found in the
handler. A tool that no rule covers is ``pending_review`` and cannot be called.

Access paths:
- ``query``: served by soc-bridge-readonly through ``upstream_query`` (reads, validations and search
  jobs that only read data). Never a state change in the product.
- ``change``: served only by the separate soc-bridge-change server, disabled by default; every call
  needs an out-of-band human approval (see change_control.py). Never used by investigations.
"""

from __future__ import annotations

from typing import Any

POLICY_VERSION = "2026-10-15.2"

EFFECTS = {
    "read": "retrieves data; the handler sends HTTP GET only and changes nothing",
    "validation": "submits input for validation; nothing is stored or changed",
    "query_job": "creates a temporary search job that reads data (consumes search capacity)",
    "external_lookup": "creates a lookup task and sends the value to external DNS/WHOIS services",
    "content_submission": "submits content to the vendor service for evaluation",
    "artifact_generation": "generates onboarding templates/packages that grant access when deployed",
    "credential_generation": "generates a credential (password) in the product",
    "mutation": "creates, changes or deletes state in the product or on managed assets",
}
QUERY_EFFECTS = {"read", "validation", "query_job"}

# QRadar exceptions to "GET = read, anything else = mutation", each checked in the IBM handler.
QRADAR_EXCEPTIONS = {
    "validate_aql": ("validation", "POST to ariel/validators/aql: validates the AQL text; nothing is created"),
    "create_ariel_search": ("query_job", "POST ariel/searches creates an Ariel search job that reads events/flows; "
                                         "results expire upstream"),
    "dns_lookup": ("external_lookup", "POST services/dns_lookups creates a lookup task and resolves the value outside QRadar"),
    "whois_lookup": ("external_lookup", "POST services/whois_lookups creates a lookup task and queries external WHOIS"),
}

# Vision One tools registered in the read lists whose handler sends POST: never treated as reads.
TREND_READ_REGISTERED_EXCEPTIONS = {
    "aisecurity_guardrails_apply": ("content_submission", "POST v3.0/aiSecurity/applyGuardrails evaluates the submitted "
                                                          "prompt/response text"),
    "container_security_generate_service_gateway_password": (
        "credential_generation", "POST v3.0/containerSecurity/generateServiceGatewayPassword generates a password"),
    **{name: ("artifact_generation", f"POST {path} generates an onboarding template/package")
       for name, path in {
           "cam_alibaba_accounts_generate_terraform_package": "v3.0/cam/alibabaAccounts/generateTerraformPackage",
           "cam_aws_accounts_generate_cfn_template_links": "v3.0/cam/awsAccounts/generateCfnTemplateLinks",
           "cam_aws_accounts_generate_terraform_package": "v3.0/cam/awsAccounts/generateTerraformPackage",
           "cam_azure_subscriptions_generate_mgmt_group_terraform_package":
               "v3.0/cam/azureSubscriptions/generateManagementGroupTerraformPackage",
           "cam_azure_subscriptions_generate_terraform_package": "v3.0/cam/azureSubscriptions/generateTerraformPackage",
           "cam_gcp_projects_generate_terraform_package": "v3.0/cam/gcpProjects/generateTerraformPackage",
           "cam_oci_compartments_generate_terraform_package": "v3.0/cam/ociCompartments/generateTerraformPackage",
       }.items()},
}

# Product areas and the entitlements/permissions they depend on (documentation; verified per tenant
# only at run time by the actual response).
QRADAR_DEPENDENCIES = {
    "offense": "QRadar user with Offenses capability",
    "ariel": "QRadar user with Log Activity/Network Activity capability; searches consume Ariel capacity",
    "reference_data": "QRadar user with reference data capability",
    "asset": "QRadar user with Assets capability",
    "log_source": "QRadar user with log source read capability",
    "analytics": "QRadar user with rule/custom action read capability",
    "system": "QRadar administrator capability",
    "config": "QRadar administrator capability (users/roles, network hierarchy, deploy)",
    "services": "QRadar geodata/DNS/WHOIS services; DNS/WHOIS send the value outside QRadar",
    "forensics": "QRadar Incident Forensics license",
    "qvm": "QRadar Vulnerability Manager license",
    "data_classification": "QRadar user with DSM editor/QID read capability",
}
TREND_DEPENDENCIES = {
    "iam": "Vision One API key role with Identity and Account Management permissions",
    "crem": "Cyber Risk Exposure Management entitlement and permissions",
    "cloudrisk": "Cloud Risk Management (Conformity) entitlement",
    "workbench": "Workbench permissions",
    "cam": "Cloud Accounts Management permissions",
    "email": "Email security products integrated with Vision One",
    "container": "Container Security entitlement",
    "endpoint": "Endpoint Security / Standard Endpoint Protection integration",
    "ai": "AI Security (AI Guard) entitlement",
    "threatintel": "Threat Intelligence permissions (feeds, suspicious objects, reports)",
    "audit": "Audit log permissions",
    "business": "Business profile permissions",
    "cases": "Case Management permissions",
    "datalake": "Data pipeline permissions",
    "dmm": "Detection Model Management permissions",
    "eiqs": "Endpoint Inventory (Endpoint Security) permissions",
    "filesecurity": "File Security entitlement",
    "healthcheck": "API key validity",
    "response": "Response Management permissions; actions run on managed endpoints/accounts/emails",
    "sandbox": "Sandbox Analysis entitlement and daily quota",
    "search": "Search app permissions; data depends on sensor/product data sources and retention",
    "awareness": "Security Awareness entitlement",
    "playbooks": "Security Playbooks permissions",
    "tags": "Asset tag management permissions",
}


def classify_qradar(tool: dict[str, Any]) -> dict[str, Any]:
    """tool: handler facts from docs/coverage/qradar-mcp-tools.json."""
    name, verb, calls = tool["name"], tool.get("verb"), set(tool.get("client_calls") or [])
    if name in QRADAR_EXCEPTIONS:
        effect, basis = QRADAR_EXCEPTIONS[name]
        status = "verified"
    elif verb == "GET" and calls == {"get"} and tool.get("approval_required") is False:
        effect, basis, status = "read", f"GET {tool.get('endpoint')}; handler calls client.get only", "verified"
    elif verb in ("POST", "PUT", "DELETE", "PATCH") and calls & {"post", "put", "delete", "patch"}:
        effect, basis, status = "mutation", f"{verb} {tool.get('endpoint')}; handler sends {', '.join(sorted(calls))}", \
            "verified"
    else:
        effect, basis, status = "mutation", "handler facts do not match a reviewed rule", "pending_review"
    return _decision(effect, basis, status, None)


def classify_trend(tool: dict[str, Any]) -> dict[str, Any]:
    """tool: handler facts from docs/coverage/vision-one-mcp-tools.json."""
    name, methods, registered = tool["name"], set(tool.get("http_methods") or []), tool.get("registered_as")
    unsupported = None
    if tool.get("file_upload") and registered != "write":
        unsupported = "file upload in a tool not registered as write: not reviewed"
    if registered == "read" and name in TREND_READ_REGISTERED_EXCEPTIONS:
        effect, basis = TREND_READ_REGISTERED_EXCEPTIONS[name]
        status = "verified" if methods == {"POST"} else "pending_review"
    elif registered == "read" and methods == {"GET"}:
        effect, basis, status = "read", f"GET {', '.join(tool.get('paths') or [])}; registered as read", "verified"
    elif registered == "write" and methods and methods <= {"POST", "PUT", "PATCH", "DELETE"}:
        effect = "mutation"
        basis = f"{'/'.join(sorted(methods))} {', '.join(tool.get('paths') or [])}; registered as write"
        status = "verified"
    else:
        effect, basis, status = "mutation", "handler facts do not match a reviewed rule", "pending_review"
    return _decision(effect, basis, status, unsupported)


def _decision(effect: str, basis: str, status: str, unsupported: str | None) -> dict[str, Any]:
    access = "query" if effect in QUERY_EFFECTS and status == "verified" else "change"
    return {"effect": effect, "effect_meaning": EFFECTS[effect], "basis": basis, "review": status,
            "access": access, "support": "unsupported" if unsupported else "supported",
            "unsupported_reason": unsupported}


def callable_for_query(entry: dict[str, Any]) -> bool:
    return (entry.get("review") == "verified" and entry.get("access") == "query"
            and entry.get("effect") in QUERY_EFFECTS and entry.get("support") == "supported")


def callable_for_change(entry: dict[str, Any]) -> bool:
    return (entry.get("review") == "verified" and entry.get("access") == "change"
            and entry.get("support") == "supported")
