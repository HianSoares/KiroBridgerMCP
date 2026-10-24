# Requirements: Workbench alert + XDR Data Explorer follow-up

### Requirement 1 — Explicit XDR phase

#### Acceptance Criteria

1.1 THE SYSTEM SHALL run the Workbench investigation once and report seeds (endpoints, users, hashes, process instances, commands, times) with the source of each value.
1.2 THE SYSTEM SHALL plan deduplicated trend_search_data calls for the pertinent sources from validated seeds and audited field names, without asking the analyst for a host or IP that the seeds or Search records provide.
1.3 THE SYSTEM SHALL summarize each direct Search result (actors, parents, users, commands, instances, file objects, connections with attribution) with record provenance and identifiers comparable with the seeds, so the agent can state what the XDR phase added.

### Requirement 2 — Transfer hypotheses and volume

#### Acceptance Criteria

2.1 THE SYSTEM SHALL plan transfer phases for backup, sync and transfer tools and distinguish binary present, configuration accessed, command started, connection attributed and transfer completed.
2.2 THE SYSTEM SHALL report byte and packet counters only as returned, with field, direction as named, unit and session identity, never summing readings, and SHALL treat file size, event counts and ports as not transferred volume.
2.3 THE SYSTEM SHALL state, when no counter is returned, which records were checked and that volume is not established, without an estimate.

### Requirement 3 — Continuation and conclusion

#### Acceptance Criteria

3.1 THE SYSTEM SHALL keep partition continuation plans for large results, never re-plan an identical window, and mark digest coverage as partial while windows are pending.
3.2 THE SYSTEM SHALL scope the alert assessment to the initial collection and keep complementary evidence for a separate agent opinion.
3.3 THE SYSTEM SHALL keep technical facts when authorization is pending and SHALL NOT recommend Benign True Positive without an authorization source.
3.4 THE SYSTEM SHALL keep agents, steering and skills consistent with the tools each profile exposes.
