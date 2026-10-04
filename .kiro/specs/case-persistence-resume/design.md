# Design — Case persistence and resume

## Store (`src/soc_bridge/case_store.py`)

- `CaseStore(root, retention_days)` provides `lock`, `load`, `save(case, expected_revision)`, `list`, `delete` and `purge`.
  - **Lock:** `lock(case_id)` holds an exclusive lock on `.<case_id>.lock` in the store directory (`msvcrt.locking` on Windows, `fcntl.flock` on Linux/WSL), with a timeout (`CaseLocked`). It works across processes and across threads of one process.
  - **Writes:** `save` reads the on-disk revision, compares it and replaces the file while holding the lock. Each write is a temporary file plus `os.replace`, with mode 0600 on POSIX; on Windows the replace is retried briefly if an unlocked reader has the file open.
  - **Conflicts:** `CaseConflict` is raised on a revision mismatch. `_before_write` is an empty hook between the check and the replace, used by the concurrency tests.
  - **Secrets:** `scrub()` drops credential-like keys and raises `SecretInCase` if a configured token or API key value appears anywhere in the data.
- The case ID pattern rejects path separators.
- `SCHEMA_VERSION = 1`. A different version is rejected instead of being guessed.
- `merge_query(case, name, finding, rows, run_id, offense_id)` stores the query state with its offense ID (rows separately, up to 5000 per query). A replaced job goes to `history` with its search ID, AQL, offense, cursor and outcome.
- `evidence_identity()` merges only records with log source, stored time, device time, QID and identical payload (`rec:` keys). Other records get a `row:` key bound to query, search ID and row index, so they are never merged. A payload key whose stored properties differ from the new row's (for example `ProcessGuid`) gets a separate key. Each evidence item keeps `identity`, `properties` and every `seen_in` reference.
- `merge_trend()` merges Vision One Search records by uuid.

## Isolation (`case_investigation.py`, `offense_evidence.py`)

- A case stores `offense_id`. `investigate_offense_case` refuses a `case_id` bound to another offense before loading anything else or calling upstream.
- `offense_evidence.resume_mismatch()` compares offense ID, database, scope and AQL (or its fallback) of the saved query with the planned one. Any mismatch → the planned query runs as a new job, `resume.action = not_resumed_state_mismatch` lists the fields, and the earlier job stays in history.

## Checkpoints and resume (`ariel_collection.py`)

- `collect_query(..., progress=)` and `_drive(..., progress=)` call `progress(snapshot, stage)`:
  - `creating`: before the creation call, saved as `creation_uncertain` with `verify_creation_before_retry`;
  - `created`: with the search ID, cursor 0;
  - `page`: after each page that has more, with rows and `next_start` of the next page.
- `offense_evidence.run()` adds `finished` with the final finding. `case_investigation` merges each snapshot into the case and saves it under the lock. A failed checkpoint stops the collection (`CheckpointFailed`) instead of continuing unsaved.
- The case is saved before `get_offense`. On `asyncio.CancelledError` the run is marked cancelled (best effort) and the cancellation propagates.
- `_resume()` handles each saved state:
  - complete → reused;
  - no search ID with `creation_uncertain` → `requires_resolution`;
  - known search ID → `_drive()` polls and pages from `next_start` (or the stored row count).
- `_drive()` never creates a search.

## Trend results and reassessment (`case_investigation.py`)

- `trend_state.apply_run(state, raw, run_id)` records the run and, per alert, an attempt; a collected report adds an assessment with its `trend_link.evidence` basis. True Positive sustains the facts `assessment:true_positive` and `malicious_instance:<uuid>:<role>`; False Positive/Benign True Positive refutes the sustained facts with a revision; anything else (Inconclusive, failure, timeout, not requested) changes no fact.
- `trend_state.current(entry)` derives the classification: True Positive while those facts are sustained (with "not observed again" in the basis when the latest attempt differs), the refuting classification, `Refuted` after an analyst refutation, else the latest collected assessment.
- `trend_state.migrate()` converts states written by the previous format.
- `bridge_findings()` (used by runs and reassessments) evaluates the link against the sustained instances and keeps demonstrated links as `qradar_link` facts; see the evidence-decisions-closure spec.
- `probative(kind, data)` extracts what a fact asserts: for instances the UUID, endpoint, complete hashes, PID, launch time, image and complete command line of the instance and its parent, and the verdict hashes; for links the relation, QRadar instance key, complete QRadar hashes, QRadar execution time, the probative Trend instance and chain GUIDs. Incomplete values, sources, lengths, cut flags, search IDs and row numbers are provenance. Facts store `probative` and its `fingerprint`; a sustained fact whose probative content changes keeps the previous content in `history`.
- `refute()` stores the probative content it addressed. `_sustain()` never re-establishes a refuted fact: it records `observations_after_refutation` (run, `probative_change`, `changes`), reported as `refuted_link_still_matched` for review. `reinstate()` applies an explicit `trend_finding_reinstated` record.
- `trend_link.stored_link_conflicts()` checks a stored link against current evidence (conflict found now for the same Trend fact and QRadar instance; changed complete hashes, PID or launch time of the linked Trend instance; linked QRadar hashes against the current Trend instance or parent). `contradict()` marks such a link `contradicted` (reported as `link_contradicted`); a later conflict-free demonstration revalidates it.
- Links carry `criteria`; `mark_unvalidated_links()` sets `needs_revalidation` on sustained links from earlier criteria that the current computation did not re-demonstrate.
- `reassess_case()` applies `trend_finding_refuted` and `trend_finding_reinstated` records (alert and fact IDs validated against the case) before the evaluation.
- `reassess_case()` rebuilds the decision from `last_result`, the stored rows and the stored Trend results. It makes no upstream call.
- `collection_now` is stored on the first run and reused, so the same windows are planned.

## Retention and deletion

- `SOC_BRIDGE_CASE_RETENTION_DAYS` sets the retention period (default 30).
- `soc-bridge cases purge|delete <id>` purges or deletes cases. Lock files (`.<id>.lock`) stay in the directory and hold no data.
- These operations act on local files only.
- See `docs/case-store.md`.

## Limitations

- If the process stops after QRadar created a job but before the creation response arrived, the case holds `creation_uncertain` without the search ID; the analyst verifies in QRadar before `rerun_queries`.
- Ariel results can expire upstream. A known search ID that is no longer readable becomes a failure that requires an explicit `rerun_queries`.
- A case written by an earlier version has no `offense_id` per query; the case binding and the AQL comparison still apply.

## Testing

- `tests/test_professional_investigation.py`: `StoreTests`, `ResumeTests`, `CaseFlowTests`.
- `tests/test_case_review_regressions.py`:
  - `ReassessmentKeepsTrendEvidenceTests`: reassessment, run without Trend and run with Trend failing keep the linked True Positive.
- `tests/test_case_review_round2.py`: `EvidencePreservationTests` — inconclusive re-collection, timeout, Trend failure, refutation by a sustained False Positive and by an analyst record.
- `tests/test_case_review_round4.py`: `StoredLinkContradictionTests` (conflicting Trend hash across reassessment, recollection, new job and resume; absent observations; independent links) and `RefutationPertinenceTests` (incomplete hash/metadata, probative change kept for review, resume, explicit reinstatement).
- `tests/test_case_review_round3.py`: `RefutationTests` — link-only refutation across reassessments and a new Ariel job, independent links, reasoned reinstatement, new chain evidence, whole-alert refutation, legacy links marked for revalidation.
  - `OffenseIsolationTests`: case bound to another offense refused before any call; saved job of another offense/query never continued.
  - `CheckpointCancellationTests`: real `task.cancel()` during pagination, during creation and before the first call.
  - `ConcurrencyTests`: two processes (spawn) and two threads writing the same revision.
  - `DeduplicationTests`: payload-less rows, distinct properties and history provenance.
