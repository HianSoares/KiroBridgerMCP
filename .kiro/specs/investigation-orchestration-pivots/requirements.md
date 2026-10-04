# Requirements Document

## Introduction

"Investigue a offense X" must start a professional, evidence-driven investigation: scope, offense-linked records, behavior separated from labels, competing hypotheses, discriminating pivots within budget, correlation by demonstrated link, and a reasoned decision.

## Requirements

### Requirement 1 — End-to-end flow

**User Story:** As an analyst, I want one request to run the whole investigation, so that I get a traceable decision without micromanaging tools.

#### Acceptance Criteria

1. WHEN `investigate_offense_case(offense_id)` is called THE SYSTEM SHALL identify the case, scope and sources, snapshot the offense metadata, collect offense-linked records, add related Trend alerts with alert-first depth when Vision One is available, interpret scenarios, build hypotheses, plan pivots and evaluate the decision.
2. THE SYSTEM SHALL treat the request as authorization for the read pivots needed within project limits and SHALL ask the analyst only for indispensable data or decisions outside the telemetry.
3. WHEN Vision One is not configured THE SYSTEM SHALL record it as not configured and complete the QRadar case.

### Requirement 2 — Behavior versus label

**User Story:** As a reviewer, I want observed behavior separated from rule names, so that conclusions rest on records.

#### Acceptance Criteria

1. THE SYSTEM SHALL list rule and offense names separately from observed behavior, which comes only from records.
2. THE SYSTEM SHALL interpret Windows/PowerShell, Linux, lockout, credential dumping, network/DHCP and integrity scenarios only from the existing parsers, with "not established" statements and discriminating evidence.

### Requirement 3 — Next pivots

**User Story:** As an analyst, I want each next query justified, so that the investigation does not query everything indiscriminately.

#### Acceptance Criteria

1. THE SYSTEM SHALL record for each pivot the hypothesis or requirement, motivating evidence, source, entity/filters/window, expected cost, results that support or contradict, and stop criterion.
2. THE SYSTEM SHALL prioritize trigger records, then strong identifiers, then process/session, then context, and keep the correlation budget reserved.
3. WHEN a pivot was executed with the same motivation THE SYSTEM SHALL mark it `skipped_repeat`.
4. WHEN a failure is deterministic (`requires_resolution`) THE SYSTEM SHALL NOT retry it; WHEN it is transient (`retryable`) THE SYSTEM SHALL plan one retry.
5. WHEN evidence depends on an inaccessible source THE SYSTEM SHALL state the data, source and validation needed and SHALL NOT substitute another query.

### Requirement 4 — Correlation levels and clocks

**User Story:** As a reviewer, I want each related record labelled by its link, so that candidates are not presented as facts.

#### Acceptance Criteria

1. THE SYSTEM SHALL separate offense-associated, alert-linked, identifier-demonstrated, candidate and context records.
2. THE SYSTEM SHALL NOT reconcile counts from different snapshots, units or windows by assumption.
3. THE SYSTEM SHALL keep event/receipt/detection/alert-creation/collection times separate.
4. THE SYSTEM SHALL treat an alert found by offense IP and time as a candidate until an offense-linked record demonstrates the same execution or its chain (see the evidence-decisions-closure spec), and SHALL propose a pivot to verify that link.

### Requirement 5 — Global deadline

**User Story:** As an operator, I want the collection deadline to be absolute, so that no upstream call starts after the budget cut a call.

#### Acceptance Criteria

1. WHEN a call is cut at the deadline THE SYSTEM SHALL treat the time of that phase as used, even if the budget clock still shows time left (asyncio timers may fire up to one clock resolution early).
2. AFTER the global budget is exhausted THE SYSTEM SHALL start no new upstream call (validation, creation, polling, paging, rule or context read).
3. THE SYSTEM SHALL keep the time reserved for later phases available to them.

### Requirement 6 — Report delivery and alert resumption

**User Story:** As an analyst, I want completed and partial evidence delivered even when connection cleanup fails, so that I can continue the pending work without duplicating searches.

#### Acceptance Criteria

1. WHEN collection returns and a resource shutdown fails THE SYSTEM SHALL preserve the report, identify the resource, and report cleanup separately from collection coverage.
2. WHEN a secondary alert phase fails THE SYSTEM SHALL preserve earlier evidence and known Ariel search IDs/cursors; it SHALL NOT interpret the failure as empty results.
3. WHEN the same alert/credential/parameter scope is resumed within the running bridge cache THE SYSTEM SHALL reuse successful reads and resume matching Ariel jobs; polling and creation SHALL NOT be memoized.
4. THE SYSTEM SHALL isolate alert cache state, serialize same-alert runs, bound the cache, and state that restart/expiry/eviction removes this temporary memory.
5. THE SYSTEM SHALL preserve cancellation and the primary collection error, keep continuation values uncut in reports, and report reused reads separately from new calls/records/partitions.
6. THE SYSTEM SHALL use the same conservative execution identity checker for alert-first correlation; conflicting complete hashes or known identifiers SHALL prevent confirmation even when path/PID/time coincide.

### Requirement 7 — Execute clear chat requests

**User Story:** As an analyst, I want the agent to execute authorized investigation work and produce a decision/note without repeatedly presenting menus.

#### Acceptance Criteria

1. THE SYSTEM SHALL instruct Kiro to discover by status or description with the available bridge tools and to use documented defaults rather than ask for obtainable IDs.
2. WHEN multiple alert IDs are known THE SYSTEM SHALL instruct Kiro to investigate sequentially, continue independent alerts after a failure, and deliver a consolidated evidence-based report.
3. THE SYSTEM SHALL distinguish per-attempt ledgers from cumulative diagnostics and SHALL NOT claim initialization repairs another session or proves data API permissions.
4. THE SYSTEM SHALL request only indispensable missing data, continue authorized pertinent pivots, and preserve the read-only upstream boundary.
