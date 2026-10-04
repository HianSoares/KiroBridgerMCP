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

- `compact_trend()` keeps, per deepened alert, the alert summary, assessment, dump analysis, entities, strong identifiers and association. `merge_trend_state()` keeps earlier collected alerts when the new run did not collect them (`earlier_results_kept`).
- `bridge_findings()` (used by runs and reassessments) recomputes the QRadar↔Trend link from the stored results; see the evidence-decisions-closure spec.
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
  - `OffenseIsolationTests`: case bound to another offense refused before any call; saved job of another offense/query never continued.
  - `CheckpointCancellationTests`: real `task.cancel()` during pagination, during creation and before the first call.
  - `ConcurrencyTests`: two processes (spawn) and two threads writing the same revision.
  - `DeduplicationTests`: payload-less rows, distinct properties and history provenance.
