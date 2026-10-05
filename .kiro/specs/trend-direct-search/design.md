# Design

`trend_search.py` validates arguments, preserves native JSON and conservatively partitions retrieval windows. Full pages, links or a count beyond the page trigger division; dense windows require refinement. UUID plus identical full native content deduplicates boundary reads; missing identity keeps records separate. Fields and row coverage have distinct completeness flags.

`live_trend_search` starts only readonly Search Docker/MCP, uses shared collection Budget and per-call ledger, captures live inputSchema and closes resources in the owning task with InvestigationConnections. Native records survive shutdown errors. No QRadar credentials/Workbench ID, export URL or response task is used.

Two additive FastMCP tools expose schema/guide and query. Agents, always-included steering and skills route requests and interpret evidence. Synthetic async/real-stdio tests exercise complete, empty, partial, count, shape, limits, errors, cancellation and shutdown. Existing schemas and coverage matrix remain checked.
