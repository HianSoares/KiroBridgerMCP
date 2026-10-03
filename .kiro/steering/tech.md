# Implementation constraints

- Python 3.11+, package source under `src/soc_bridge/`, tests under `tests/`.
- Use the `mcp` Python SDK for local stdio and Streamable HTTP. The QRadar MCP endpoint is bound to loopback; Trend Vision One MCP runs as a local stdio container with `-readonly=true`.
- Kiro connects only to `soc-bridge-readonly`, whose main entry point is `investigate_case(reference)` for either an offense number or a WB alert ID. The optional `investigate_epm_uac` and `investigate_web_reputation` tools perform bounded read-only Ariel and Trend Search lookups. Do not configure Kiro to connect directly to the upstream QRadar server, which offers mutation tools.
- `qradar_read_context` (allowlisted GET context reads) and `qradar_assess_closure` (per-reason closure matrix with cited analyst records) are QRadar-only. Regenerate `docs/coverage-matrix.md` with `scripts/build_coverage_matrix.py` after changing an allowlist; tests fail when it is stale.
- Six qradar_* tools expose bounded custom AQL, live field/function resources, status and paginated results (including selected payload). These use QRadar alone and do not start Trend. Follow qradar-aql-conventions.
- Offense-first live investigations also use bounded read-only Ariel and Trend Search; preserve per-query state, pagination warnings and source attribution. Never imply that a matching IP identifies an endpoint process.
- Never add a write/response/containment MCP tool without an explicit design review. Do not switch Trend Vision One to `readonly=false`.
- Keep stdout of the MCP server and of `soc_bridge.wsl_launch` (Kiro for Windows -> wsl.exe -> WSL) for JSON-RPC only; diagnostics go to stderr and name variable states, never values.
- Keep credentials in environment variables, outside Git. Run `PYTHONPATH=src python -m unittest discover -s tests -v` after changes to correlation logic.
- Avoid implying a complete search when a source is paginated, unavailable, or capped.
