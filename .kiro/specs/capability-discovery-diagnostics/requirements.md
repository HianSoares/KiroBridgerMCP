# Requirements Document

## Introduction

The bridge connects to the IBM QRadar MCP and the Trend Vision One MCP and exposes its own read-only tools to Kiro. Tool availability must be discovered from every `tools/list` page, classified without overstating access, and diagnosed identically on Windows and WSL without exposing secrets.

## Requirements

### Requirement 1 — Paginated discovery

**User Story:** As an analyst, I want the bridge to read every page of the upstream tool list, so that a tool is never reported missing because of an unread page.

#### Acceptance Criteria

1. WHEN an upstream `tools/list` response carries `nextCursor` THE SYSTEM SHALL request the next page with that cursor until no cursor is returned.
2. WHEN a cursor repeats, a page has an invalid shape, a page call fails, the page cap is reached or the discovery deadline expires THE SYSTEM SHALL stop and mark the discovery incomplete with the stop reason.
3. WHEN discovery is incomplete THE SYSTEM SHALL report a non-advertised tool as availability unknown and SHALL NOT report it as absent.
4. WHEN a required read tool is not advertised and discovery is incomplete THE SYSTEM SHALL fail with "availability unknown" instead of "missing".

### Requirement 2 — Availability and call states

**User Story:** As an analyst, I want advertised, allowed and verified access kept apart, so that I do not mistake a tool list for permission or license.

#### Acceptance Criteria

1. THE SYSTEM SHALL classify each tool as available_allowed, advertised_blocked, absent (complete discovery only) or unknown.
2. WHEN a tool call returns THE SYSTEM SHALL record tested_ok, rejected, permission, license_or_integration, unavailable, format_incompatible or not_found, using categories only.
3. THE SYSTEM SHALL state that a successful call shows access for that call only.

### Requirement 3 — Common diagnostics

**User Story:** As an operator on Windows or WSL, I want one diagnostic that names the failing stage and the fix, so that I can repair the installation without reading logs that may contain secrets.

#### Acceptance Criteria

1. THE SYSTEM SHALL provide the diagnostic through `soc-bridge doctor` and the read-only tool `bridge_diagnostics`.
2. THE SYSTEM SHALL show bridge version, Python, platform, WSL distribution, environment variable states, QRadar stages (URL, TCP, MCP initialize with server identity, paginated discovery), optional Vision One stages and call outcomes.
3. WHEN a stage fails THE SYSTEM SHALL show a fixed category and a remediation and SHALL NOT show tokens, authentication headers, credential URLs or upstream messages.
4. WHEN Vision One is not requested THE SYSTEM SHALL NOT start the container.

### Requirement 4 — Central capability source

**User Story:** As a maintainer, I want one source of the bridge tools, so that agents and documentation cannot reference tools that do not exist.

#### Acceptance Criteria

1. THE SYSTEM SHALL derive the public tool list from the MCP server registry.
2. WHEN an agent profile references a tool that the bridge does not expose THE SYSTEM SHALL report the pack as inconsistent in diagnostics and tests SHALL fail.
