# Design

`scripts/upstream_catalog.py` extracts handler facts from the upstream sources without importing them. `scripts/build_upstream_registry.py` joins those facts with the complete tools/list snapshots and the policy in `upstream_policy.py` to produce `upstream_registry.json`. A generated registry with on-demand dispatch has two benefits:

- it avoids registering all 432 upstream schemas (about 410 KB) in every Kiro session;
- it keeps one gate for names, schemas and effects.

`upstream_access.py` covers registry search and description, the query gate, jsonschema argument validation, contract drift detection, error classification and output normalization.

`upstream_live.py` opens one session per call:

- QRadar over loopback Streamable HTTP;
- Vision One over Docker stdio, with -readonly=true and the tool's own toolset only.

For each call it walks the paginated tools/list, checks the contract, then makes one call inside InvestigationConnections under a global timeout.

`change_control.py` controls changes:

- it stores proposals;
- it requires approval typed at a TTY and signed with a local HMAC key;
- it enforces the environment flag and the policy file;
- it executes each approved request once.

`change_server.py` exposes four FastMCP tools. soc-bridge-readonly never imports it.

Tests use `tests/fake_upstream_mcp.py`. It announces the audited contracts and reproduces each product's response format, over memory streams and stdio.

Review fixes:

- **Calls are blocked** on incomplete discovery or on any recursive contract difference.
- **`data` stays within `max_output_chars`.** Continuation, total and ID fields are kept. Locally cut pages offer `skip_items` recovery before the next page, and empty pages with continuation are partial.
- **Vision One runs a pinned image**, by index digest. Its labels and provenance name the audited commit.
- **Change outcomes after sending are uncertain** unless the upstream answered explicitly.
- **Uploads** use a staged copy that is hash-bound to the approval and mounted read-only as a single file.
