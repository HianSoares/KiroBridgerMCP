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

## Investigate a real case

After completing the live setup in the guide, give Kiro a QRadar offense number or a Vision One Workbench alert ID:

> Use `investigate_case` with reference `<OFFENSE_ID>`. Show the queries run, confirmed findings, candidate links, and gaps.

> Use `investigate_case` with reference `WB-EXAMPLE-20260924-00001`. Explain which endpoint details were retrieved and which remain unverified.

The bridge exposes seven investigation tools to Kiro: `investigate_case`, `investigate_offense`, `investigate_vision_alert`, `investigate_vision_event`, `investigate_epm_uac`, `investigate_web_reputation`, and `investigate_demo`. Project steering, skills, and agents under `.kiro/` provide focused investigation workflows. Kiro only needs the `soc-bridge-readonly` MCP entry; the bridge connects to the upstream servers.

## Run custom AQL from Kiro

Six additional `qradar_*` tools let Kiro read live field/function metadata, validate and execute custom AQL, inspect events/flows and selected `UTF8(payload)`, and resume/paginate an existing search ID. These tools use QRadar alone and do not require Trend credentials. Read-only mode permits Ariel search jobs.

> Read AQL metadata, then use `qradar_run_aql` to collect the missing evidence for this case. Keep the search ID, use the verified time window, and report pagination and truncation.

See [custom AQL setup, examples and limits](docs/dynamic-aql.md). Existing investigation tools keep their fixed initial samples; the new tools provide follow-up queries.

## Scope and safety

- Investigations use limited searches. No Workbench alert or no result on an inspected page does **not** mean there was no endpoint activity.
- An alert may omit its View event fields. Automatically discovered hosts, hashes, and IPs are labelled as candidates; analyst-supplied fields are not independently verified by the bridge.
- The tools do not block domains, isolate endpoints, close offenses, or change product settings. Verify the upstream read-only allowlist and account permissions for your deployment.
- Live reports may contain sensitive telemetry and enter the context of the AI model configured in Kiro. Keep credentials and `reports/` out of public repositories and follow your organization's data policy.

See [known limitations](docs/bridge-known-limitations.md), the [Kiro pack notes](README-kiro-pack.md), and the [engineering backlog](BRIDGE-BACKLOG.md) for details. Licensed under [MIT](LICENSE).
