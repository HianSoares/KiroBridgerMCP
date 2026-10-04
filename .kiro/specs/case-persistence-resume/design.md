# Design — Case persistence and resume

## Store (`src/soc_bridge/case_store.py`)

- `CaseStore(root, retention_days)` provides `load`, `save(case, expected_revision)`, `list`, `delete` and `purge`.
  - **Writes:** each save is a temporary file plus `os.replace`, with mode 0600 on POSIX.
  - **Conflicts:** `CaseConflict` is raised on a revision mismatch.
  - **Secrets:** `scrub()` drops credential-like keys and raises `SecretInCase` if a configured token or API key value appears anywhere in the data.
- The case ID pattern rejects path separators.
- `SCHEMA_VERSION = 1`. A different version is rejected instead of being guessed.
- `merge_query()` stores the query state (rows separately, up to 5000 per query) and consolidates evidence by `evidence_key()`, using `seen_in` references and tier upgrade.
- `merge_trend()` merges Vision One Search records by uuid.

## Resume (`ariel_collection.collect_query(..., resume=saved)`)

- `_resume()` handles each saved state:
  - complete → reused;
  - no search ID with `creation_uncertain` → `requires_resolution`;
  - known search ID → `_drive()` polls and pages from `next_start` (or the stored row count).
- `_drive()` is the polling and paging loop extracted from `collect_query`. It never creates a search.
- `offense_evidence.collect_offense_evidence(resume=..., rerun=..., keep_rows=True)` resumes by query name. If the stored AQL differs from the one a fresh run would plan, the saved job is still continued and a warning is recorded.

## Orchestration hooks (`case_investigation.py`)

- `collection_now` is stored on the first run and reused, so the same windows are planned.
- A checkpoint is saved after the QRadar collection, before the Trend stage. A later failure therefore keeps the QRadar progress.
- `reassess_case()` rebuilds the decision from `last_result` and the stored rows. It makes no upstream call.

## Retention and deletion

- `SOC_BRIDGE_CASE_RETENTION_DAYS` sets the retention period (default 30).
- `soc-bridge cases purge|delete <id>` purges or deletes cases.
- These operations act on local files only.
- See `docs/case-store.md`.

## Limitations

- If a process stops between job creation and the next save, the job exists upstream but not in the case. The next run re-plans that query. This is documented as at-least-once at most for that window.
- Ariel results can expire upstream. A known search ID that is no longer readable becomes a failure that requires an explicit `rerun_queries`.

## Testing

`tests/test_professional_investigation.py`:
- `StoreTests`: atomicity, conflict, secret refusal, retention, path safety and consolidation.
- `ResumeTests`: interrupted collection continued in another store instance with the same job, no duplicates and revisions kept; uncertain creation not recreated until rerun.
- `CaseFlowTests`: reassessment makes no upstream call.
