# Requirements: Trend direct Search

### Requirement 1 — Independent read-only query

#### Acceptance Criteria

1.1 THE SYSTEM SHALL expose live source metadata and Search independently of WB/offense/QRadar.
1.2 THE SYSTEM SHALL allow only the eight verified Search reads, validate query, select, top and explicit timezones before startup, and preserve existing public schemas.

### Requirement 2 — Evidence and coverage

#### Acceptance Criteria

2.1 THE SYSTEM SHALL preserve bounded native fields with explicit cuts and per-record provenance without merging PID-reused executions.
2.2 THE SYSTEM SHALL split full pages by time, return executable pending-window plans, require refinement for dense leaves and distinguish failures, countOnly and incomplete progress from complete empty logs.
2.3 THE SYSTEM SHALL limit calls, duration, records and output, propagate cancellation and preserve evidence on cleanup failure.

### Requirement 3 — Professional interpretation

#### Acceptance Criteria

3.1 THE SYSTEM SHALL route scoped log requests without asking for WB and distinguish actor/object/instance, dump intent/execution/artifact and authorization.
3.2 THE SYSTEM SHALL document partial console/API parity, logging limits, no cursor, no automatic case insertion and no automatic verdict/mutation.
