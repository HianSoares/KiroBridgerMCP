# SOC Bridge purpose

SOC Bridge helps analysts investigate a QRadar offense with related Trend Vision One Workbench alerts. Kiro is the primary AI interface: it requests a bounded read-only evidence report from the local `soc-bridge-readonly` MCP server, interprets the evidence, names gaps, and suggests checks an analyst can perform.

The Python project is the deterministic data collection layer. It never assigns a final malicious/benign verdict. Exact IP and time overlap are leads, not proof that alerts belong to the same incident.

The demo is fully fabricated. Do not include customer names, internal hostnames, screenshots, tokens, or real incident details in code, examples, issues, or public documentation.
