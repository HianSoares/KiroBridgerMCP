# Requirements Document

## Introduction

Investigations must survive restarts and chat changes. A local, versioned case keeps what is needed to resume collection on the same Ariel jobs, consolidate new evidence and revise the report without losing earlier versions.

## Requirements

### Requirement 1 — Versioned local case

**User Story:** As an analyst, I want each investigation stored as a local case, so that I can continue it later from another process.

#### Acceptance Criteria

1. THE SYSTEM SHALL store a case with a schema version, the case ID, offense/alert references, scope and sources, metadata snapshots with collection time, queries with search IDs, states and cursors, rows, evidence, pivots, hypotheses, contradictions, pending items, analyst confirmations with explicit origin, decisions and report revisions.
2. THE SYSTEM SHALL write the case atomically (temporary file and replace) and SHALL refuse a write when the on-disk revision differs from the loaded one.
3. THE SYSTEM SHALL NOT persist tokens, MCP sessions, network clients or credential-like keys, and SHALL refuse to write when a configured credential value appears in the data.
4. THE SYSTEM SHALL keep the store outside Git (`reports/cases` by default, or `SOC_BRIDGE_CASE_DIR`) and SHALL support listing, showing, deleting and purging by retention days.

### Requirement 2 — Resume on the same job

**User Story:** As an analyst, I want an interrupted collection to continue where it stopped, so that no Ariel search is recreated just because the chat or process changed.

#### Acceptance Criteria

1. WHEN a stored query has a search ID and a pending or partial outcome THE SYSTEM SHALL poll and page that same search ID from the stored cursor and append the new rows.
2. WHEN a stored query is complete THE SYSTEM SHALL reuse it without an upstream call.
3. WHEN a stored query has `creation_uncertain` and no search ID THE SYSTEM SHALL NOT recreate it unless the analyst names it in `rerun_queries`, and SHALL report it as requiring resolution.
4. THE SYSTEM SHALL derive planned query windows from the case's first collection time so a resumed run plans the same AQL.
5. THE SYSTEM SHALL NOT promise exactly-once execution: a local cancellation does not prove the upstream did not create a job.

### Requirement 3 — Consolidation without duplication

**User Story:** As an analyst, I want records returned by several queries merged with all their references, so that coverage is updated without double counting.

#### Acceptance Criteria

1. THE SYSTEM SHALL identify a record by database, times, QID/name, addresses, log source, user, ports and payload hash.
2. WHEN a record is returned again THE SYSTEM SHALL add the new query reference and SHALL NOT create a second record.
3. THE SYSTEM SHALL keep the relation tier: offense-associated, alert-linked, identifier-demonstrated, candidate or context. A stronger tier from another query upgrades it and is never downgraded.
4. THE SYSTEM SHALL keep receipt time (`starttime`), device time and collection run as separate clocks, converting epochs to UTC without assuming a console timezone.

### Requirement 4 — Report revisions

**User Story:** As a reviewer, I want each run or reassessment to add a report revision, so that earlier conclusions stay auditable.

#### Acceptance Criteria

1. WHEN a run or reassessment completes THE SYSTEM SHALL append a report revision and a decision entry and SHALL keep earlier revisions (up to 50).
2. WHEN a case is reassessed with new analyst records THE SYSTEM SHALL make no upstream call.
