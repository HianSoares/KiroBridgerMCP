# Design — Evidence, contradictions and closure decisions

## Engine

- `decision.evaluate(conclusions, requirements, contradictions)`:
  - **sustained:** every requirement is confirmed;
  - **contradicted:** a requirement listed in `contradicted_by` is met, or an unresolved contradiction affects one of the conclusion's requirements or the conclusion itself;
  - **partially_supported:** some requirements are met or compatible;
  - **not_supported:** otherwise.
- `closure_scope.py`:
  - `ACTIVITIES` lists the activities the parsers can demonstrate.
  - `validate_scope()` requires `processes` for `process_execution` (optional `command_lines`, `parent_processes`) and `script_block_ids` for `script_execution`, and rejects those fields for other activities. `strict_instant()` accepts only ISO-8601 times with `Z` or an offset.
  - `observed_profile(result)` derives activities and instances:
    - one per process creation (host, image, command line, parent image, time, query/search ID/row);
    - one per script block;
    - one per entity (IP, account, host) of the other activities, from the rows of the queries that carry them (`ACTIVITY_QUERIES`), with the earliest and latest record time; up to 200 instances, the rest counted as not evaluated.
  - `coverage(confirmations, profile, requirement)` checks each instance against each scoped record: activity, every instance entity named (short host names match their FQDN), process/command line/parent, then window. It returns covered instances, uncovered instances with reasons (up to 50 listed plus a count), uncovered activities and window contradictions.
  - `CATEGORIES` and `CATEGORY_REASONS` define the dispositions and their relation to the catalog.
  - `load_reason_definitions()` reads custom reason definitions.
  - `confidence()` assigns levels:
    - **high:** bridge-demonstrated and corroborated by a demonstrated link;
    - **moderate:** sustained but relying on external records or a single source;
    - **low:** not sustained.
- `trend_link.py`:
  - `identifiers(report)` extracts full hashes, command lines and hosts of the alert.
  - `link(result, alert_id, identifiers, association)` returns `demonstrated` (with the matching offense-linked process records) or `candidate` (with what is missing).
- `case_investigation.bridge_findings(result, trend)`: a True Positive with a demonstrated link sets `malicious_activity_confirmed` and `corroborated`; a candidate one adds the contradiction `related_alert_unlinked:<alert>` affecting authorization and detection_error. `pivot_planner` proposes `verify_alert_link`.
- `closure_assessment.propose(result, confirmations, contradictions, bridge_findings, reason_definitions)`:
  - builds the requirements (instance coverage for authorization, malicious activity and detection error; bridge findings take precedence);
  - evaluates catalog reasons and dispositions with contradictions;
  - returns the existing fields plus `disposition`, `disposition_matrix`, `observed_activity`, `contradictions`, `confidence_detail` and `custom_reason_definitions`.

## Report (`case_investigation.build_report`)

The report carries:
- decision;
- `observed_behavior` (scenarios plus a behavior-versus-label statement);
- `decisive_evidence` (alert-linked, then offense-associated, then identifier-demonstrated records, each with references);
- hypotheses with tests (including each alert's link level);
- contradictions;
- coverage per query (search ID, outcome, resume action);
- limitations;
- confidence;
- closure matrices;
- related alerts with classification, link level and the run that collected them;
- next action and pivots;
- capabilities;
- a clocks note;
- `note_pt`, built from the closure note, the decisive evidence references and the next action.

## Compatibility

- `qradar_assess_closure` and `reassess_case` keep their input schemas; `scope` and its fields live inside each confirmation object.
- A confirmation without scope is still accepted, but it does not confirm authorization, malicious activity or detection error.
- A `process_execution` scope without `processes`, or a window without timezone, is now rejected with an explicit message.

## Limitations

- The bridge cannot read authorization, change, CRE test or remediation systems. Those requirements are met only by cited, scoped analyst records.
- Activity detection depends on the parsers that exist. An activity without a parser falls back to `offense_activity`.
- The QRadar↔Trend link uses process creation records parsed from offense-linked events. Without parsed process records (no Sysmon 1/4688 or no hash/command line) a related alert stays a candidate.

## Testing

- `ScopedDecisionTests` (`test_professional_investigation`): sustained case, wrong entity, window contradiction, generic authorization, malicious contradiction, inconclusive pending items, custom definitions, scope validation.
- `test_case_review_regressions`: `CorrelationTests`, `ScopeTests`, `TimezoneTests`.
- Further coverage: `CaseFlowTests`, `test_investigative_coverage.DecisionTests`, `test_coverage_review_regressions`, `test_linux_closure`.
