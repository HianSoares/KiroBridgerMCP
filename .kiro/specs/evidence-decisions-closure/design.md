# Design — Evidence, contradictions and closure decisions

## Engine

- `decision.evaluate(conclusions, requirements, contradictions)`:
  - **sustained:** every requirement is confirmed;
  - **contradicted:** a requirement listed in `contradicted_by` is met, or an unresolved contradiction affects one of the conclusion's requirements or the conclusion itself;
  - **partially_supported:** some requirements are met or compatible;
  - **not_supported:** otherwise.
- `closure_scope.py`:
  - `ACTIVITIES` lists the activities the parsers can demonstrate.
  - `validate_scope()`:
    - `process_execution`: `processes` plus a behavior discriminator (`command_lines` kept as original strings, `script_paths`, `artifact_hashes`, `process_instances`, or `breadth="any_behavior_of_named_processes"` with `breadth_basis`); an artifact hash alone is rejected for `INTERPRETERS`; optional `parent_processes`;
    - `privilege_use`: `commands`, `identity_switch=true` or `breadth="any_privileged_command_of_named_accounts"` with `breadth_basis`; optional `run_as`;
    - `script_execution`: `script_block_ids`;
    - fields of another activity are rejected; `strict_instant()` accepts only ISO-8601 times with `Z` or an offset.
  - `script_invocation(command_line, image)` reads, without executing, what an interpreter was asked to run: a `-File`/first-argument script, inline code (`-Command`, `-EncodedCommand`, `/c`, `-c`, ...) or nothing. A script path covers an instance only when that script ran with no inline code and no additional arguments.
  - `observed_profile(result)` derives activities, instances and `instances_not_evaluated` (per activity: count, reason, next action):
    - process creations from `processes.process_instances` (analysis list, cap 5000) — or, for results stored before it existed, from the presentation list with its omitted count declared not evaluated;
    - script blocks from `processes.script_block_instances`;
    - sudo commands and su switches from `linux.*.privilege_instances` (per host/account/run-as/command, with first/last times);
    - one per entity (IP, account, host) of the other activities, from all collected rows of `ACTIVITY_QUERIES`; rows returned but not available (witness samples only, rows beyond the stored limit) are declared not evaluated.
  - `coverage(confirmations, profile, requirement)` checks each instance against each scoped record: activity, every instance entity named (short host names match their FQDN), behavior/chain, then window. It returns covered instances, uncovered instances with reasons (up to 50 listed plus a count), not-evaluated counts, broad authorizations used, uncovered activities and window contradictions. `confirmed` needs no uncovered and no not-evaluated instance.
  - `CATEGORIES` and `CATEGORY_REASONS` define the dispositions and their relation to the catalog.
  - `load_reason_definitions()` reads custom reason definitions.
  - `confidence()` assigns levels:
    - **high:** bridge-demonstrated and corroborated by a demonstrated link;
    - **moderate:** sustained but relying on external records or a single source;
    - **low:** not sustained.
- `trend_link.py`:
  - `evidence(report)` persists the verdict basis: linked Search records whose executed role (`alert_assessment._executed_roles`) has a hash with a high-risk sandbox verdict, with record UUID, endpoint, event time, role, image, original command line, PID, instance ID, launch time, hashes and the parent instance; plus all observables with role, sources and cut flag, and the alert creation time labelled as a non-execution clock.
  - `compare_hashes()` compares hash states (`process_chain.hash_states` for Sysmon, `trend_hash_states` for Trend, inferred by length for stored legacy lists) per algorithm: `equal`, `conflict`, `incomplete`, `not_comparable`, `absent`, with the source of each value.
  - `same_execution(q, t)` applies the identity rules (`LINK_CRITERIA = "activity-v3"`): conflicts in hashes or known identifiers block identity; equal hash needs an equal PID or identical command line; without a comparable hash, an identical path and an equal PID are needed; execution times within `TOLERANCE_SECONDS`.
  - `link(result, alert_id, basis, association)` compares offense-linked QRadar process instances (Sysmon `UtcTime`, else device time) with each malicious instance: `same_process_instance`; `parent_of_malicious_instance` (QRadar process = Trend parent instance; for an object, the record's actor); `child_of_malicious_instance` (ParentProcessGuid -> QRadar parent record on the same endpoint, INOFFENSE or host context, that is the malicious instance). Otherwise `candidate` with `why_not_demonstrated`. Conflicts where weaker signals coincide are returned in `conflicts`. Each match carries `qradar_instance_key` (ProcessGuid on the host, else PID+start+image).
- `trend_state.py` keeps per alert the attempts, assessments, facts (`sustained`/`refuted`), revisions and the derived current assessment (see the case-persistence spec).
- `case_investigation.bridge_findings(result, trend, run_id)`: recomputes the links from the sustained instances, records them as `qradar_link` facts (ID = Trend fact + relation + QRadar instance key, so a new Ariel job for the same records is the same fact) and uses only links that are sustained under the current criteria; a stored link not demonstrated now is reused only while `stored_link_conflicts` finds no positive contradiction, otherwise it becomes `contradicted`. A True Positive with such a link sets `malicious_activity_confirmed` and `corroborated`; otherwise `related_alert_unlinked:<alert>` affects authorization and detection_error. It also reports `link_conflict:<alert>`, `link_contradicted:<alert>:<fact>`, `refuted_link_still_matched:<alert>:<fact>` and `link_needs_revalidation:<alert>` (informational, unresolved) and refutations as resolved contradictions. `pivot_planner` proposes `verify_alert_link` with the malicious instances to look for.
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
- The QRadar↔Trend link uses process creation records parsed from offense-linked events and the Trend linked records with executed-role data. Without them (no Sysmon 1/4688, no PID/command line, no launch time, verdict on another artifact) a related alert stays a candidate.
- `script_invocation` recognizes common interpreter flags; unusual syntaxes are treated as "no script executed", so `script_paths` does not cover them (cite the exact command line).

## Testing

- `ScopedDecisionTests` (`test_professional_investigation`): sustained case, wrong entity, window contradiction, generic authorization, malicious contradiction, inconclusive pending items, custom definitions, scope validation.
- `test_case_review_regressions`: `CorrelationTests`, `ScopeTests`, `TimezoneTests`.
- `test_case_review_round2`: `ActivityLinkTests`, `OmittedRecordsTests`, `BehaviorAuthorizationTests`.
- Further coverage: `CaseFlowTests`, `test_investigative_coverage.DecisionTests`, `test_coverage_review_regressions`, `test_linux_closure`.
