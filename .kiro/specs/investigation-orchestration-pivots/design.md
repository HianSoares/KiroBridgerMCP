# Design — Investigation orchestration and next pivots

## Flow (`case_investigation.investigate_offense_case`)

1. Load or create the case (`offense-<id>`). A case bound to another offense is refused. Record the scope ("read-only pivots needed for this offense") and the sources, and save the case before any upstream call.
2. Snapshot `get_offense` (selected fields and collection time).
3. Call `collect_offense_evidence`, reusing the existing collector. The pivots it already contains are:
   - INOFFENSE events and flows;
   - the flow census;
   - rule metadata;
   - Linux strict windows;
   - lockout context;
   - the host window;
   - parent GUID lookups;
   - PowerShell 4104;
   - integrity;
   - host flows;
   - QRadar context.

   Known jobs of the same offense and query are resumed. The shared `Budget` limits time, queries, pages and polls. The case is saved before each job creation, when the search ID arrives and after every page.
4. Save after the QRadar collection.
5. Trend: `core.investigate(..., deepen_alerts=2)`. Alerts are discovered by offense IPs and up to two are deepened with the alert-first flow, using a shared budget, a call cache and no QRadar recursion. Linked records are merged into the case and the alert results are stored (`compact_trend`), keeping earlier results when this run does not collect them.
6. `scenarios.interpret` and `scenarios.hypotheses`.
7. `pivot_planner.plan(result, trend, previous_pivots)`.
8. `bridge_findings` + `closure_assessment.propose(..., contradictions, bridge_findings)`. A deepened True Positive confirms malicious activity and corroborates the QRadar evidence only with a demonstrated link (shared hash or exact command line in an offense-linked process record on the same host). An IP/time relation stays a candidate: an unresolved contradiction against benign dispositions plus a `verify_alert_link` pivot.
9. `build_report` → save a revision → return the report.

## Deadline (`ariel_collection.Budget`)

`Budget.run()` bounds each call with `asyncio.wait_for`. Two effects let a new call start right after a cut:

- the event loop may fire the timer up to one clock resolution early (15.6 ms with `GetTickCount64` on Windows before Python 3.13), while the budget clock (`time.monotonic`) still shows time left;
- recomputing `start + allowed - elapsed` in floating point can leave a positive residue of about 1e-14 s.

A cut is therefore recorded as state, not derived from arithmetic: the phase goes to `cut_phases` (`available_seconds()` is 0 for it) and, when no later phase holds a reservation, `expired` makes `remaining_seconds()` 0. Later phases keep their reservations. `deadline_floor` keeps the reported elapsed time consistent. Tests use frozen and residue-producing budget clocks to make this deterministic (`test_case_review_round2.DeadlineTests`).

## Planner (`pivot_planner.py`)

Pivot actions:
- `resume_same_search`
- `start_planned_query`
- `verify_uncertain_creation`
- `partition_query`
- `resolve_query_failure`
- `request_external_evidence`
- `investigate_related_alert`
- `verify_alert_link`

Each pivot carries a deterministic ID (hash of action and parameters) used to detect repeats. Priority classes are `trigger_records` < `strong_identifier` < `process_session` < `context` < `external`. Retry decisions use the `retryable` and `requires_resolution` flags from `aql_errors`.

## Scenarios (`scenarios.py`)

The interpretation reads existing outputs only:
- `processes` and `host.explicit_credential_attempts`;
- `linux.offense.kind_counts`;
- `lockout.groups`;
- the Trend `dump_analysis` of deepened alerts;
- `flows.port_groups`;
- `integrity.integrity_events`.

It creates no new taxonomy.

## Compatibility and limitations

- `investigate_offense`, `qradar_verify_offense` (QRadar only) and `trend_find_alerts` (Trend only) are unchanged.
- Partition, related-alert and alert-link pivots are proposed, not executed automatically. A new AQL or a full alert flow needs its own call.
- The investigation is synthetic-tested only; live behavior depends on the upstream deployments.

## Testing

`tests/test_professional_investigation.py`:
- `PivotTests`
- `CaseFlowTests`
- `ResumeTests`
- `test_related_true_positive_alert_by_ip_only_does_not_confirm_malice_but_blocks_benign_closure`

`tests/test_case_review_regressions.py`: `CorrelationTests`, `CheckpointCancellationTests`, `OffenseIsolationTests`.
