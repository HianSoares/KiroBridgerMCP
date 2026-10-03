# Design — Evidence, contradictions and closure decisions

## Engine

- `decision.evaluate(conclusions, requirements, contradictions)`:
  - **sustained:** every requirement is confirmed;
  - **contradicted:** a requirement listed in `contradicted_by` is met, or an unresolved contradiction affects one of the conclusion's requirements or the conclusion itself;
  - **partially_supported:** some requirements are met or compatible;
  - **not_supported:** otherwise.
- `closure_scope.py`:
  - `ACTIVITIES` lists the activities the parsers can demonstrate.
  - `observed_profile(result)` derives activities, entities and the observed window from the collection.
  - `coverage(confirmations, profile, requirement)` returns covered and uncovered activities and window contradictions.
  - `CATEGORIES` and `CATEGORY_REASONS` define the dispositions and their relation to the catalog.
  - `load_reason_definitions()` reads custom reason definitions.
  - `confidence()` assigns levels:
    - **high:** bridge-demonstrated and corroborated;
    - **moderate:** sustained but relying on external records or a single source;
    - **low:** not sustained.
- `closure_assessment.propose(result, confirmations, contradictions, bridge_findings, reason_definitions)`:
  - builds the requirements (scoped coverage for authorization, malicious activity and detection error; bridge findings take precedence);
  - evaluates catalog reasons and dispositions with contradictions;
  - returns the existing fields plus `disposition`, `disposition_matrix`, `observed_activity`, `contradictions`, `confidence_detail` and `custom_reason_definitions`.

## Report (`case_investigation.build_report`)

The report carries:
- decision;
- `observed_behavior` (scenarios plus a behavior-versus-label statement);
- `decisive_evidence` (alert-linked, then offense-associated, then identifier-demonstrated records, each with references);
- hypotheses with tests;
- contradictions;
- coverage per query (search ID, outcome, resume action);
- limitations;
- confidence;
- closure matrices;
- related alerts;
- next action and pivots;
- capabilities;
- a clocks note;
- `note_pt`, built from the closure note, the decisive evidence references and the next action.

## Compatibility

- `qradar_assess_closure` keeps its schema and accepts the optional `scope` inside confirmations.
- A confirmation without scope is still accepted, but it no longer confirms authorization, malicious activity or detection error. This is a deliberate tightening.

## Limitations

- The bridge cannot read authorization, change, CRE test or remediation systems. Those requirements are met only by cited, scoped analyst records.
- Activity detection depends on the parsers that exist. An activity without a parser falls back to `offense_activity`.

## Testing

`ScopedDecisionTests` cover:
- the sustained case;
- wrong entity;
- the window contradiction;
- a generic authorization;
- malicious contradiction;
- inconclusive pending items;
- custom definitions;
- scope validation.

Further coverage comes from `CaseFlowTests`, `test_investigative_coverage.DecisionTests`, `test_coverage_review_regressions` and `test_linux_closure`.
