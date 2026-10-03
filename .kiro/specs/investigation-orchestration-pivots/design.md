# Design — Investigation orchestration and next pivots

## Flow (`case_investigation.investigate_offense_case`)

1. Load or create the case (`offense-<id>`). Record the scope ("read-only pivots needed for this offense") and the sources.
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

   Known jobs are resumed. The shared `Budget` limits time, queries, pages and polls.
4. Checkpoint save.
5. Trend: `core.investigate(..., deepen_alerts=2)`. Alerts are discovered by offense IPs and up to two are deepened with the alert-first flow, using a shared budget, a call cache and no QRadar recursion. Linked records are merged into the case.
6. `scenarios.interpret` and `scenarios.hypotheses`.
7. `pivot_planner.plan(result, trend, previous_pivots)`.
8. `closure_assessment.propose(..., contradictions, bridge_findings)`. A deepened True Positive becomes bridge evidence of malicious activity and, with offense-linked records, corroboration.
9. `build_report` → save a revision → return the report.

## Planner (`pivot_planner.py`)

Pivot actions:
- `resume_same_search`
- `start_planned_query`
- `verify_uncertain_creation`
- `partition_query`
- `resolve_query_failure`
- `request_external_evidence`
- `investigate_related_alert`

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
- Partition and related-alert pivots are proposed, not executed automatically. A new AQL or a full alert flow needs its own call.
- The investigation is synthetic-tested only; live behavior depends on the upstream deployments.

## Testing

`tests/test_professional_investigation.py`:
- `PivotTests`
- `CaseFlowTests`
- `ResumeTests`
- `test_related_true_positive_alert_is_bridge_evidence_against_benign_closure`
