# Design — Capability discovery and diagnostics

## Components

- `src/soc_bridge/capabilities.py`
  - `discover(session, source, max_pages=20, deadline_seconds=30)` walks `tools/list` with the MCP SDK cursor, keeping a set of seen cursors and a monotonic deadline. It returns a `Discovery` with `names`, `pages`, `complete`, `stop_reason` and `server`.
  - `tool_names()` returns a `ToolSet` (a set of names with the attached `discovery`) so existing call sites keep their set semantics.
  - `absence_state(client, tool)` returns `tool_absent`, `availability_unknown` or `None`.
  - `Ledger`/`GLOBAL_LEDGER` record per-tool call outcomes for this process.
  - `LOCAL_WRITE_TOOLS` names the case tools that write local files.
- `transports.RestrictedMCP` raises "availability unknown" for a partial discovery. Every call is recorded in the ledger by category (`outcome_for(classify_failure(...))`).
- `aql_errors` adds the `availability_unknown` category and `requires_resolution` to every classification.
- `src/soc_bridge/diagnose.py` builds the report:
  - QRadar: URL → TCP → initialize → discovery.
  - Vision One (opt-in): key → Docker → container → initialize → discovery.
  - Pack consistency: agent tool references against the registry.
  - `render()` produces the CLI text.

## Security

- Failures go through `diagnostics.failure_reason`, which uses exception types and HTTP status only.
- Environment variables are shown as states (`set`, `absent`, `empty`, `unexpanded reference`).

## Compatibility

- Existing tools and schemas are unchanged.
- Allowlists are unchanged; discovery only refines how missing tools are described.

## Limitations

- The IBM and Trend servers currently return a single page, so the pagination path is exercised with synthetic sessions.
- Diagnostics do not prove permissions; only successful calls in the ledger show access.

## Testing

`tests/test_professional_investigation.py`:
- `DiscoveryTests`: pages, repeated cursor, invalid page, failing page, page cap, deadline, unknown versus absent.
- `DiagnosticsTests`: a 401 response carrying a synthetic secret, with environment secrets set.
- `SurfaceTests`: schemas and annotations.
