# Implementation Plan

- [x] 1. Paginated `tools/list` discovery with cursor-repeat, invalid page, failure, page cap and deadline guards
  - `capabilities.discover`, `Discovery`, `ToolSet`, `tool_names`
  - _Requirements: 1.1, 1.2, 1.3_
- [x] 2. Use discovery at every MCP session in `transports.py`; partial discovery yields "availability unknown"
  - `RestrictedMCP` required/optional checks; `absence_state` in Trend and QRadar optional reads
  - _Requirements: 1.3, 1.4_
- [x] 3. Availability states and call-outcome ledger by category
  - `Discovery.state/describe`, `Ledger`, `GLOBAL_LEDGER`, `outcome_for`; `requires_resolution` in `aql_errors`
  - _Requirements: 2.1, 2.2, 2.3_
- [x] 4. Common diagnostics for Windows/WSL through CLI and read-only tool
  - `diagnose.py`, `soc-bridge doctor [--trend] [--json]`, `bridge_diagnostics(check_trend)`
  - _Requirements: 3.1, 3.2, 3.3, 3.4_
- [x] 5. Central capability source and pack consistency check
  - `capabilities.public_tools`, `diagnose.pack_consistency`, `tests/test_pack_consistency.py`
  - _Requirements: 4.1, 4.2_
- [x] 6. Synthetic tests
  - `DiscoveryTests`, `DiagnosticsTests`, `SurfaceTests`, pack consistency tests
  - _Requirements: 1.1-4.2_
