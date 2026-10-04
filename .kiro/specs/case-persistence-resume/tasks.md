# Implementation Plan

- [x] 1. Versioned case model, atomic save with optimistic revision, secret refusal, list/show/delete/purge
  - `case_store.CaseStore`, `scrub`, `CaseConflict`, `SecretInCase`; CLI `soc-bridge cases`
  - _Requirements: 1.1, 1.2, 1.3, 1.4_
- [x] 2. Resume known Ariel jobs from saved cursors; reuse complete results; never recreate uncertain creations
  - `ariel_collection._resume/_drive`, `collect_query(resume=...)`, `collect_offense_evidence(resume, rerun, keep_rows)`
  - _Requirements: 2.1, 2.2, 2.3, 2.5_
- [x] 3. Stable planning windows across runs (`collection_now`) and a checkpoint after QRadar collection
  - `case_investigation.investigate_offense_case`
  - _Requirements: 2.4_
- [x] 4. Consolidation with identity, references, tiers and separate clocks
  - `merge_query`, `merge_trend`, `evidence_key`, `epoch_utc`
  - _Requirements: 3.1, 3.2, 3.3, 3.4_
- [x] 5. Report revisions and decisions appended; reassessment without upstream calls
  - `report_revisions`, `decisions`, `reassess_case`
  - _Requirements: 4.1, 4.2_
- [x] 6. Documentation of storage, retention and deletion (`docs/case-store.md`) and synthetic tests
  - `StoreTests`, `ResumeTests`, `CaseFlowTests`
  - _Requirements: 1.4, 2.1-4.2_
