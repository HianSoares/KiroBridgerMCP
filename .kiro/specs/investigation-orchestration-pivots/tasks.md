# Implementation Plan

- [x] 1. Orchestrator `investigate_offense_case` reusing the offense collector, deepening and closure engine
  - snapshot, resume, checkpoint, Trend stage with "not configured" fallback, report revision
  - _Requirements: 1.1, 1.3_
- [x] 2. Public tool and steering: one request authorizes the needed read pivots; ask only for indispensable data
  - `kiro_server.investigate_offense_case`, `.kiro/steering/case-workflow.md`
  - _Requirements: 1.2_
- [x] 3. Scenario interpretation and behavior/label separation from existing parsers
  - `scenarios.interpret`, `scenarios.hypotheses`
  - _Requirements: 2.1, 2.2_
- [x] 4. Next-pivot planner with hypothesis, motivation, source, params, cost, outcomes, stop, priority, retry rules and repeat detection
  - `pivot_planner.plan`, `next_action`
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_
- [x] 5. Correlation tiers and separate clocks in consolidated evidence
  - `case_store.TIERS`, `merge_query`, `merge_trend`; count comparison kept unresolved by the collector
  - _Requirements: 4.1, 4.2, 4.3_
- [x] 6. Synthetic tests
  - `PivotTests`, `CaseFlowTests`, `ResumeTests`
  - _Requirements: 1.1-4.3_
