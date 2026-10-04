# Requirements Document

## Introduction

Investigations must survive restarts, cancellations and chat changes. A local, versioned case keeps what is needed to resume collection on the same Ariel jobs of the same offense, consolidate new evidence conservatively and revise the report without losing earlier versions or earlier evidence.

## Requirements

### Requirement 1 — Versioned local case

**User Story:** As an analyst, I want each investigation stored as a local case, so that I can continue it later from another process.

#### Acceptance Criteria

1. THE SYSTEM SHALL store a case with a schema version, the case ID, the offense it is bound to, offense/alert references, scope and sources, metadata snapshots with collection time, queries with offense ID, database, scope, AQL, search IDs, states and cursors, rows, evidence, stored Trend results, pivots, hypotheses, contradictions, pending items, analyst confirmations with explicit origin, decisions and report revisions.
2. THE SYSTEM SHALL write the case atomically (temporary file and replace) and SHALL read the on-disk revision, compare it with the loaded one and replace the file while holding an exclusive inter-process lock, refusing the write when the revision differs.
3. WHEN two processes write the same revision concurrently THE SYSTEM SHALL let at most one succeed; the other SHALL receive a conflict and no update SHALL be lost silently.
4. THE SYSTEM SHALL NOT persist tokens, MCP sessions, network clients or credential-like keys, and SHALL refuse to write when a configured credential value appears in the data.
5. THE SYSTEM SHALL keep the store outside Git (`reports/cases` by default, or `SOC_BRIDGE_CASE_DIR`) and SHALL support listing, showing, deleting and purging by retention days.

### Requirement 2 — Isolation by offense

**User Story:** As an analyst, I want a case to belong to one offense, so that a reused case ID never continues another offense's searches.

#### Acceptance Criteria

1. WHEN `investigate_offense_case` is called with a `case_id` bound to another offense THE SYSTEM SHALL refuse it before any upstream call.
2. WHEN a saved query differs from the query planned now in offense ID, database, scope or AQL THE SYSTEM SHALL NOT continue its job, SHALL run the planned query as a new job, SHALL record the mismatched fields and SHALL keep the earlier job in the query history.

### Requirement 3 — Checkpoints and resume on the same job

**User Story:** As an analyst, I want an interrupted or cancelled collection to continue where it stopped, so that no Ariel search is recreated just because the chat or process changed.

#### Acceptance Criteria

1. THE SYSTEM SHALL save the case before the first upstream call of a run.
2. THE SYSTEM SHALL save the query as `creation_uncertain` before each job creation call, SHALL save the search ID as soon as it is received and SHALL save the rows and the next cursor after every page.
3. WHEN a run is cancelled THE SYSTEM SHALL keep the saved search IDs, cursors and rows, SHALL record the cancellation in the run and SHALL NOT recreate any job automatically.
4. WHEN a stored query has a search ID and a pending or partial outcome THE SYSTEM SHALL poll and page that same search ID from the stored cursor and append the new rows.
5. WHEN a stored query is complete THE SYSTEM SHALL reuse it without an upstream call.
6. WHEN a stored query has `creation_uncertain` and no search ID THE SYSTEM SHALL NOT recreate it unless the analyst names it in `rerun_queries`, and SHALL report it as requiring resolution.
7. THE SYSTEM SHALL derive planned query windows from the case's first collection time so a resumed run plans the same AQL.
8. THE SYSTEM SHALL NOT promise exactly-once execution: a local cancellation does not prove the upstream did not create a job.

### Requirement 4 — Conservative consolidation

**User Story:** As an analyst, I want records returned by several queries merged only when they are demonstrably the same, with all their references, so that coverage is updated without double counting or hiding distinct records.

#### Acceptance Criteria

1. THE SYSTEM SHALL merge records across queries only when they share database, log source, stored time, device time, QID and identical payload.
2. WHEN a record has no payload, log source or stored time THE SYSTEM SHALL NOT merge it with any other record; it SHALL stay tied to the query, job and row that returned it.
3. WHEN records share the payload key but differ in a property present in both (for example `ProcessGuid`) THE SYSTEM SHALL keep them separate.
4. WHEN a record is returned again THE SYSTEM SHALL add the new query reference; references of replaced jobs SHALL stay in the evidence and in the query history.
5. THE SYSTEM SHALL keep the relation tier: offense-associated, alert-linked, identifier-demonstrated, candidate or context. A stronger tier from another query upgrades it and is never downgraded.
6. THE SYSTEM SHALL keep receipt time (`starttime`), device time and collection run as separate clocks, converting epochs to UTC without assuming a console timezone.

### Requirement 5 — Report revisions and complete reassessment

**User Story:** As a reviewer, I want each run or reassessment to add a report revision built from all stored evidence, so that earlier conclusions stay auditable and no evidence is dropped.

#### Acceptance Criteria

1. WHEN a run or reassessment completes THE SYSTEM SHALL append a report revision and a decision entry and SHALL keep earlier revisions (up to 50).
2. THE SYSTEM SHALL persist per alert and per run the Trend attempts (state, classification, error), the assessments and the structured verdict basis, and the facts they establish with their provenance.
3. WHEN a case is reassessed THE SYSTEM SHALL make no upstream call and SHALL evaluate the stored QRadar collection together with the stored Trend facts and links, not only the latest report.
4. WHEN a later attempt is inconclusive, times out, fails or is not requested THE SYSTEM SHALL record the attempt and SHALL keep the earlier facts sustained: not observing a fact again does not refute it.
5. WHEN pertinent new evidence contradicts a fact (a later evaluation sustained as False Positive or Benign True Positive, or an analyst `trend_finding_refuted` record) THE SYSTEM SHALL mark the facts refuted and SHALL record the basis, the source and the replaced facts; a refuted instance observed again with a malicious verdict SHALL be re-established with its own revision.
6. THE SYSTEM SHALL derive the current assessment from the sustained and refuted facts and SHALL keep the history.
