# KiroBridgerMCP

![KiroBridgerMCP](KiroBridgerMCP.png)

**Investigate a QRadar offense or a Trend Vision One Workbench alert from Kiro using just its ID.**

Kiro connects to one local MCP server, `soc-bridge-readonly`. The bridge gathers bounded evidence from the [IBM QRadar MCP](https://github.com/IBM/qradar-mcp) and [Trend Vision One MCP](https://github.com/trendmicro/vision-one-mcp-server), then returns a report with findings, possible links, and collection gaps. Matching an IP or time is a lead, not proof of a shared incident.

```text
Kiro → SOC Bridge → QRadar MCP + Trend Vision One MCP → evidence report
```

## Try the demo on Windows

You need Git, Python 3.11+, and Kiro IDE. The synthetic demo needs no Docker or product credentials. Run these commands in **PowerShell**:

```powershell
git clone https://github.com/HianSoares/KiroBridgerMCP.git
Set-Location .\KiroBridgerMCP
Test-Path .\pyproject.toml  # Expected: True
py -3 -m venv .venv
& .\.venv\Scripts\python.exe -m pip install -e .
& .\.venv\Scripts\python.exe -m soc_bridge.cli demo --output reports\demo
& .\.venv\Scripts\python.exe .\scripts\configure_kiro.py
```

Open this **same folder** in Kiro. Under **MCP Servers**, confirm that `soc-bridge-readonly` is connected. Then ask:

> Call `investigate_demo` and explain the evidence and collection limits.

The configurator creates `.kiro/settings/mcp.json` locally; it is not included in the clone. The demo writes `reports/demo.md` and `reports/demo.json` with fabricated data.

For macOS/Linux commands, Docker setup, QRadar and Trend credentials, and a live connection check, follow the [full installation guide (Portuguese)](docs/guia-instalacao.md).

**Kiro on Windows with the bridge in WSL 2?** Follow the [WSL guide (Portuguese)](docs/guia-wsl.md). Kiro for Windows starts MCP servers as Windows processes, so it cannot run the `.venv/bin/python` path that `configure_kiro.py` writes inside WSL. `scripts/configure_kiro_wsl.py` configures `soc-bridge-readonly` to start through `wsl.exe` instead, and `scripts/wsl_preflight.py` checks the setup end to end without credentials.

## Investigate a real case

Clear investigation requests authorize the required read-only pivots. Completed reports survive connection shutdown errors; partial evidence and known Ariel search IDs are preserved. See [execution and resumption (Portuguese)](docs/investigation-recovery.md) for the temporary alert cache and recovery limits.

After completing the live setup in the guide, give Kiro a QRadar offense number or a Vision One Workbench alert ID:

> Investigate offense `<OFFENSE_ID>` end to end. Show the evidence, decision, confidence, pending checks and a draft note.

> Use `investigate_case` with reference `WB-EXAMPLE-20260924-00001`. Explain which endpoint details were retrieved and which remain unverified.

The bridge exposes seven investigation tools to Kiro: `investigate_case`, `investigate_offense`, `investigate_vision_alert`, `investigate_vision_event`, `investigate_epm_uac`, `investigate_web_reputation`, and `investigate_demo`. Project steering, skills, and agents under `.kiro/` provide focused investigation workflows. Kiro only needs the `soc-bridge-readonly` MCP entry; the bridge connects to the upstream servers.

## Run custom AQL from Kiro

Six additional `qradar_*` tools let Kiro read live field/function metadata, validate and execute custom AQL, inspect events/flows and selected `UTF8(payload)`, and resume/paginate an existing search ID. These tools use QRadar alone and do not require Trend credentials. Read-only mode permits Ariel search jobs.

> Read AQL metadata, then use `qradar_run_aql` to collect the missing evidence for this case. Keep the search ID, use the verified time window, and report pagination and truncation.

See [custom AQL setup, examples and limits](docs/dynamic-aql.md). Offense investigations now also collect INOFFENSE events/flows, a COUNT/UNIQUECOUNT census, contributing rule metadata and a separate host context. The legacy IP samples remain labelled as context.

## Verify an offense before concluding

`qradar_verify_offense` performs the QRadar collection without Trend credentials; `qradar_get_rule` reads contributing rule metadata. Together with the existing tools, the bridge exposes **26 tools** (24 read-only; the two case tools write only the local case store). The report distinguishes original metadata times, observed event times and padded collection windows, follows result pages within a budget and preserves unresolved count/payload/attribution gaps.

> Use `qradar_verify_offense` with the offense ID. Resume pending search IDs and collect missing evidence before assessing the case. For a historical case, confirm the actual QRadar timezone before setting `timezone_verified=true`.

The verification reads live field metadata and uses optional Windows/Sysmon properties only when they are listed. It polls pending jobs by the same search ID within an explicit time/job/page budget and returns a `continuation_plan` (search ID, cursor, AQL, scope, reason) instead of recreating searches. When linked records show processes, it reports process creations with GUID+host parent links, PowerShell 4104/4103 content and 5038 code-integrity records as separate evidence classes, with structured gaps per conclusion. Collected telemetry is parsed as data and never executed.

A DHCP-compatible port pattern supports a preliminary hypothesis. It does not establish authorization, successful authentication, endpoint health or a false positive. See [verification workflow and decision limits](docs/offense-verification.md).

Linux records now receive a census of sudo actors, targets and commands across all collected pages, plus separate SSH and su/PAM searches bounded to the original offense interval. The report reads the optional live closing-reason catalog and supplies a reviewable decision, rationale and Portuguese note draft. Kiro can recommend a specific reason after cited evidence resolves the relevant gaps; it never closes the offense or posts the note.

## Investigate a Vision One alert

`investigate_vision_alert` parses Workbench `impactScope` entities, typed indicators and matched rules with provenance, then searches endpoint/detection data and OAT by the alert's own identifiers (not the model name) under a shared time/call/record/partition budget. Search has no continuation token in the official MCP, so full pages are split into time partitions; OAT pages by `nextBatchToken`. Optional read-only enrichments (notes, inventory, DMM, intel lists, cases, existing sandbox results and response tasks) report missing tools, permissions and licenses separately. QRadar correlation reuses the budgeted Ariel collector with epoch predicates, and each Trend↔QRadar relation is labelled confirmed, candidate or unverified. The report ends with a recommended classification and a Portuguese note for human review; nothing is closed, posted or executed. Set `QRADAR_AQL_TIMEZONE_VERIFIED=true` only after confirming the console offset for historical windows. See [Trend alert investigation](docs/trend-alert-investigation.md).

## Investigate an offense end to end (persistent case)

Ask Kiro: "Investigue a offense 12345". `investigate_offense_case` collects offense-linked records, resumes known Ariel jobs from their saved cursors instead of recreating them, deepens related Trend alerts when Vision One is available, separates observed behavior from rule names, builds competing hypotheses, plans the next pivots (hypothesis, motivation, cost, stop criterion) and evaluates each disposition and live closing reason with explicit contradictions. Analyst records count only within their scope: each observed instance is checked by entity, process/chain and a window with an explicit timezone. Authorizations name a behavior (exact command, script, artifact, instance, sudo command or an explicitly declared breadth), never just an executable or account. A related Trend True Positive confirms malicious activity only when the offense-linked process is the malicious Trend execution or its demonstrated parent/child; a shared hash, IP or time stays a candidate. Trend facts are kept per alert: an inconclusive or failed re-collection never erases them, and only cited evidence refutes them. The result is a decision with justified confidence (no numeric score), decisive evidence with query/row references and a Portuguese note for human review. The case is stored locally in `reports/cases` (ignored by Git) under an inter-process lock, with checkpoints during collection; it belongs to one offense, can be continued with the same `case_id` after an interruption and re-evaluated with `reassess_case` from the stored QRadar and Trend results without new queries; earlier report revisions are kept. `soc-bridge doctor` / `bridge_diagnostics` show versions, connection stages and paginated tool discovery without secrets. See [professional investigation](docs/professional-investigation.md) and [case store](docs/case-store.md).

## Investigative coverage and closure decisions

The bridge now integrates 34 of 83 QRadar MCP tools (GET reads plus Ariel validation/search creation) and 39 of 349 Trend Vision One MCP tools, each with a trigger, limits and handler-verified pagination; every upstream tool is classified in the [coverage matrix](docs/coverage-matrix.md). Alert investigations run in budgeted phases (primary evidence, hypothesis checks, reserved Trend↔QRadar correlation, optional enrichments), keep Insight values with explicit truncation, and offense investigations deepen up to two related Workbench alerts without recursion. `qradar_read_context` reads rules, building blocks, QIDs, log sources, assets and reference data by validated arguments; `qradar_assess_closure` evaluates each live closing reason against its own requirements and accepts cited analyst records. Conclusions use explicit evidence statuses instead of scores; nothing is closed or posted. See [investigative coverage (Portuguese)](docs/investigative-coverage.md).

## Scope and safety

- Investigations use limited searches. No Workbench alert or no result on an inspected page does **not** mean there was no endpoint activity.
- An alert may omit its View event fields. Automatically discovered hosts, hashes, and IPs are labelled as candidates; analyst-supplied fields are not independently verified by the bridge.
- The tools do not block domains, isolate endpoints, close offenses, or change product settings. Verify the upstream read-only allowlist and account permissions for your deployment.
- Live reports may contain sensitive telemetry and enter the context of the AI model configured in Kiro. Keep credentials and `reports/` out of public repositories and follow your organization's data policy.

See [known limitations](docs/bridge-known-limitations.md), the [Kiro pack notes](README-kiro-pack.md), and the [engineering backlog](BRIDGE-BACKLOG.md) for details. Licensed under [MIT](LICENSE).

Offenses sharing a description can be discovered with `qradar_find_offenses` and investigated in bounded batches with `qradar_investigate_offenses`. Each case keeps its own evidence, continuation and closing-note draft. See [batch investigations](docs/offense-batch-investigation.md).

To list all OPEN offenses without a description, use `qradar_list_offenses`. It orders returned metadata by magnitude, severity, credibility, relevance and recency, with explicit criteria and no calculated risk score. Follow its continuation cursors and re-sort the combined population before claiming a global investigation order. Listing does not start case investigations. See [queue triage](docs/offense-batch-investigation.md#list-the-open-queue-and-prioritize-investigation).

### Discover Trend alerts without an ID

Ask Kiro: "Veja se há alertas abertos na Trend nas últimas 24 horas." It calls `trend_find_alerts(status="OPEN")`, including Open and In Progress, with no QRadar connection. Filter by severity or provide both ISO time bounds (maximum 30 days). Results include WB IDs for `investigate_vision_alert`. The official Workbench list MCP handler does not forward a pagination cursor: nextLink, local output caps and collection failures are explicitly distinguished from a complete empty page. This does not enumerate all historical open alerts. See [discovery limits](docs/trend-alert-discovery.md).
