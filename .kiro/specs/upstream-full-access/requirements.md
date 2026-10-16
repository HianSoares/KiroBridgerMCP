# Requirements: Full upstream access with capability separation

### Requirement 1 — Audited registry

#### Acceptance Criteria

1.1 THE SYSTEM SHALL record every tool of the audited QRadar MCP and Vision One MCP versions with effect, basis, access path, schema, pagination, output and dependencies derived from the handlers and the complete paginated tools/list.
1.2 THE SYSTEM SHALL classify effects from handler facts (HTTP method, client calls, registration) and never from the name, verb or readOnlyHint alone; unmatched tools SHALL be pending review and not callable.
1.3 THE SYSTEM SHALL fail CI when the registry, catalogs, policy, coverage matrix or curated workflows diverge, or when a tool has neither a route nor a stated unsupported reason.

### Requirement 2 — Read access on soc-bridge-readonly

#### Acceptance Criteria

2.1 THE SYSTEM SHALL let Kiro search, describe and call every query tool by exact name with arguments validated against the audited schema, without offense or Workbench IDs.
2.2 THE SYSTEM SHALL refuse change, unsupported, pending and unknown tools before any upstream contact, and start Vision One only with -readonly=true and the tool's toolset.
2.3 THE SYSTEM SHALL block the call unless tools/list discovery completed and the announced schema matches the audited one recursively (types, required, enums, bounds, patterns, nested objects and arrays, anyOf/oneOf/allOf, references), reporting discovery_incomplete, tool_absent or contract_changed without calling.
2.4 THE SYSTEM SHALL normalize JSON, text, response headers and binary bodies, keep the JSON of data within max_output_chars, report pagination only as the handler forwards it, offer recovery of locally cut items before the next page, treat empty pages with continuation as partial, and classify errors without copying upstream bodies.
2.5 THE SYSTEM SHALL start the Vision One image pinned by the digest whose labels and provenance name the audited commit, and SHALL NOT claim verification of the running QRadar MCP version.

### Requirement 3 — Separate change control

#### Acceptance Criteria

3.1 THE SYSTEM SHALL expose change tools only in soc-bridge-change, disabled by default, never in soc-bridge-readonly or its autoApprove lists.
3.2 THE SYSTEM SHALL execute a change only with the server enabled, the tool in a human-maintained policy file, and a signed, unexpired, single-use approval typed by a person in an interactive terminal for that exact request.
3.3 THE SYSTEM SHALL keep generated credentials out of storage and record any failure after sending (timeout, cancellation, broken connection, invalid response, server error) as outcome_uncertain without retrying, keeping single use.
3.4 THE SYSTEM SHALL support file uploads only from a staged copy whose SHA-256 is part of the approved digest, verified before and after the call, mounted read-only as one file, and removed after execution, rejection or expiry; links, directories and oversized files SHALL be refused.

### Requirement 4 — Evidence and documentation

#### Acceptance Criteria

4.1 THE SYSTEM SHALL document totals per platform and category, unsupported tools with reasons, dependencies, enablement and audit refresh, keeping catalogued, announced, supported, enabled, contract-tested and real-executed separate.
4.2 THE SYSTEM SHALL test the routes end to end against synthetic servers built from the audited contracts, including paginated discovery, forwarding, pagination, failures, timeout, cancellation, change-control gates and UTF-8 without UTF-8 mode.
4.3 THE SYSTEM SHALL keep catalogued, routed, policy-blocked, contract-checked, end-to-end (synthetic) and real-product evidence separate and never present routed tools as proven to work.
