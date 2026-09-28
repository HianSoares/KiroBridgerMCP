# Investigation of QRadar offense 1842

Generated (UTC): 2026-09-23T20:56:18+00:00
QRadar summary: Repeated remote access failures followed by a successful login

## Scope and method

Searched IPs: 192.0.2.15, 198.51.100.24
Window: 2026-06-24T12:00:00+00:00 to 2026-06-24T14:30:00+00:00
Exact IP server-side filters; one hour padding; bounded first-page results; read-only MCP calls

## Vision One leads

### WB-2048 — Suspicious remote sign-in and endpoint activity

- Severity: high
- Seen: 2026-06-24T12:55:00+00:00; temporal check: within window
- IP evidence: 198.51.100.24; fields: impactScopeEntityValue, indicatorValue
- Investigation rank: 70/70 (heuristic, not a verdict)

## Coverage limits

- No additional collection warnings in this run. Searches remain bounded to first-page results.

Analyst review required. Matching an IP and time window alone does not establish a shared incident.
