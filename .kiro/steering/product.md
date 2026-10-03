# SOC Bridge purpose

SOC Bridge helps analysts investigate a QRadar offense with related Trend Vision One Workbench alerts. Kiro is the primary AI interface: it requests a bounded read-only evidence report from the local `soc-bridge-readonly` MCP server, interprets the evidence, runs bounded custom Ariel/AQL follow-up queries through qradar_* tools, names gaps, and suggests checks an analyst can perform.

The Python project is the deterministic collection and evaluation layer. It recommends a disposition or closing reason only when every requirement of that conclusion is met (with contradictions and analyst-supplied records shown as such); otherwise it reports the case as inconclusive with the precise pending items. It never closes, posts or contains anything. Exact IP and time overlap are leads, not proof that alerts belong to the same incident. Investigations are kept as local resumable cases (`investigate_offense_case`).

The demo is fully fabricated. Do not include customer names, internal hostnames, screenshots, tokens, or real incident details in code, examples, issues, or public documentation.
