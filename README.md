# KiroBridgerMCP

![KiroBridgerMCP](KiroBridgerMCP.png)

**Investigue uma offense do QRadar ou um alerta Workbench da Trend Vision One informando apenas a referência ao Kiro.**

O projeto instala um único MCP local, `soc-bridge-readonly`, que coleta evidências limitadas via IBM QRadar MCP e Trend Vision One MCP. **Kiro é a interface principal**: interpreta o relatório, separa fatos de hipóteses e indica as próximas verificações. A CLI Python também exporta Markdown e JSON localmente. A pontuação de investigação ordena pistas; não é probabilidade nem veredito.

```
Kiro chat → local SOC Bridge MCP → QRadar MCP + Vision One MCP
          → bounded evidence report → Kiro's analyst-facing explanation
```

O primeiro teste é um **demo fabricado**, sem credenciais ou conexão com os produtos. Para uma investigação real, você precisa de acesso autorizado a ambos os ambientes.

## Comece aqui — Windows PowerShell

Na pasta em que você quer guardar o projeto:

```powershell
git clone https://github.com/HianSoares/KiroBridgerMCP.git
Set-Location .\KiroBridgerMCP
Test-Path .\pyproject.toml                # precisa retornar True
py -3 -m venv .venv                      # Python 3.11 ou superior
& .\.venv\Scripts\python.exe -m pip install -e .
& .\.venv\Scripts\python.exe -m soc_bridge.cli demo --output reports\demo
& .\.venv\Scripts\python.exe .\scripts\configure_kiro.py
```

Abra **esta mesma pasta** no Kiro IDE. Confirme `soc-bridge-readonly` em **MCP Servers** e peça: **“Use `investigate_demo` e explique as evidências e os limites.”** Nenhuma API key ou Docker é necessária para esse teste. O arquivo `.kiro/settings/mcp.json` é gerado localmente pelo último comando e é ignorado pelo Git; ele **não acompanha o clone**.

> [Guia completo de instalação e solução de problemas](docs/guia-instalacao.md) — contém Linux/macOS, conexão real com QRadar e Trend, credenciais e verificação de cada etapa.

## Use o Kiro como analista principal

O configurador cria uma entrada para **um MCP local**, `soc-bridge-readonly`, com sete tools declaradas somente leitura: `investigate_case`, `investigate_offense`, `investigate_vision_alert`, `investigate_vision_event`, `investigate_epm_uac`, `investigate_web_reputation` e `investigate_demo`. `investigate_case(reference)` aceita um número de offense ou ID `WB-` e encaminha à investigação adequada. O Kiro não recebe diretamente as tools de mutação dos MCPs upstream.

### Steering, skills and agents

`.kiro/` carries three layers on top of the MCP tools, so Kiro's behavior is governed by the project, not just prompted per-session:

- **Steering** (`.kiro/steering/*.md`): regras do projeto com inclusão `always` ou `manual` conforme cada arquivo. O steering manual `investigation.md` fornece um formato de resposta quando invocado.
- **Skills** (`.kiro/skills/*/SKILL.md`, loaded on demand): one focused playbook per investigation type — offense investigation, Trend alert investigation, EPM/UAC-from-QRadar, web reputation vs. FortiGate, exfiltration assessment, hypothesis hunting, AD user scope, and incident report writing. Each skill states exactly which tool calls it's allowed to make and when to stop rather than guess.
- **Agents** (`.kiro/agents/*.md`): `case-investigator` pode usar as sete tools de investigação; `threat-hunter` recebe um subconjunto de seis; `report-writer` usa apenas `investigate_case`/`investigate_demo`; `response-advisor` tem **`tools: []`** e só recomenda um plano para revisão e execução humana fora do Kiro.

Para passar do demo a um caso real, inicie o QRadar MCP local, confira o Docker e a região/permissões da API key do Vision One. O [guia de instalação](docs/guia-instalacao.md#4-prepare-as-conexões-reais) separa token do MCP local e credencial QRadar e mostra como iniciar o Kiro sem gravar segredos no repositório. Confirme o fuso do console QRadar antes de interpretar a linha do tempo. No Windows, o script `start-kiro-soc-bridge.ps1` inicia o demo sem segredos; use `-Live` para inserir credenciais temporárias no processo que lança o Kiro.

Depois, peça: **“Investigue a offense `<ID>` usando `investigate_case` e apresente evidências, consultas executadas, limites e lacunas.”** Para um alerta, use um ID `WB-...`. O `/investigation` é opcional e fornece um formato de resposta; você também pode falar diretamente com o agente `case-investigator`.

For a numeric offense, the live bridge now also samples QRadar Ariel events near the offense time and searches Vision One endpoint activities and detections by the offense IP, even when Workbench has no matching alert. If the 100-event Ariel page is full, it retries with ±60s and then ±20s around the offense midpoint. Trend searches inspect the first 50 rows per source. The report lists actual search states, AQL, UTC/local windows, sample counts, event names, host candidates and any exact IP + destination + port + ≤60s network leads. These are leads, not proof that an endpoint process caused the QRadar event. The QRadar console UTC offset defaults to −3 through `QRADAR_AQL_UTC_OFFSET_HOURS`; confirm it for the incident date. The tool does not paginate exhaustively or infer absent activity from an empty bounded search.

If a live call fails, the error names the stage (QRadar connection/initialization, Vision One Docker startup/initialization, tool listing, or evidence collection) and, where available, the HTTP status or read-only tool. `HTTP 401` at QRadar initialization calls for checking the local QRadar MCP token in Kiro's environment; `HTTP 403` indicates insufficient access; Docker startup failures call for checking Docker in the same environment that launched Kiro. A failed call is not an empty investigation. Fix the named connection and rerun the same `investigate_case` reference; the error deliberately omits raw upstream messages and incident data.

To start from a Workbench alert instead, use **`/investigation Investigate Vision One alert WB-EXAMPLE-20260924-00001 using investigate_case. Use only this ID; report automatic pivots and evidence gaps.`** (replace the fabricated ID). For the exact RClone Detection label in the structured `name` or `model` field, if Workbench omits the View event fields, the bridge looks for a unique host/hash in nearby detections. This is explicitly a **candidate**, not a verified alert-event link. If attribution is ambiguous, it will not guess an endpoint IP.

If you can see an IP and timestamp under the alert's **Highlights → View event**, send those fields to Kiro with the alert ID and ask it to use `investigate_vision_event`. For example: **`/investigation Investigate WB-EXAMPLE-20260924-00001 with investigate_vision_event: endpoint_ip=198.51.100.24, event_time=2026-09-24T13:15:01Z, endpoint_host=DEMO-PC, file_hash=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`**. The example uses fabricated data; replace it with your authorized incident details. The tool also accepts optional `file_path` and `process_path`. The Workbench MCP alert detail may not include the fields shown in View event; manually copied fields appear separately in the report and are **not verified against the event API**. The tool executes bounded Ariel event searches when the IBM MCP exposes those tools; it searches the IP and separately the hostname if provided. When a host/hash is supplied, it also searches Vision One endpoint activities, file detections and process hash activity through the read-only `search` toolset, if the API key has access. Do not treat the endpoint IP alone as the source of an attack, especially if it is a public or NAT address.

The AQL `START` and `STOP` times must use the QRadar console's local time. This example is configured for **UTC-3**, the timezone observed in the QRadar screenshot: the `investigate_vision_event` argument `qradar_utc_offset_hours` defaults to `-3`. Change it for a different deployment. The `investigate_vision_alert` tool uses environment variable `QRADAR_AQL_UTC_OFFSET_HOURS`, default `-3`. The report shows both UTC and QRadar local windows and warns if retrieved event timestamps disagree. A fixed offset does not account for daylight-saving changes; set the value for the incident date.

The Kiro MCP bridge does not write files or change either product. Kiro will receive the investigation report in its model context. Use synthetic data for a public portfolio and follow your organization's AI data handling rules before analyzing real incidents. `.kiroignore` keeps local secrets and reports out of supported Kiro file reads; it does not suppress the MCP tool result that you deliberately request.

### CyberArk EPM UAC from QRadar

Ask Kiro to call `investigate_epm_uac(last_event_id="<lastEventId>", last_event_date="<lastEventDate UTC>")`. Provide `endpoint_host` only when you have independently verified the host elsewhere. The tool finds an exact `lastEventId` in QRadar `EPM_API` events using a bounded Ariel search around the last-event date and decodes its JSON payload. If the event omits `lastEventComputerName` but contains a valid `lastEventAgentId`, a second QRadar search looks ±30 minutes for other EPM_API events with the **same last-event agent ID** and an explicit `lastEventComputerName`. A unique hostname from those records is only an agent-linked candidate; ambiguous or capped results cannot be attributed. If there is a host candidate, the tool asks Vision One Search for bounded detections of the same host/file name near the UAC time. Without a hostname but with a specific user Temp subfolder and filename, it makes at most eight read-only Vision One path searches: detection `filePathName`/`objectFilePath` and endpoint `objectFilePath`/`processFilePath` around `firstEventDate` and `lastEventDate` (±10 minutes each). The report gives each query's inspected-page count, exact-path/time count and aggregate reasons for discarding rows; counts from separate queries can duplicate the same event. Returned rows must contain the **entire exact file path** and fall in the window before they are listed as candidates. The path only supplies a lead; a match does not prove EPM/Trend event linkage, elevation or execution. It does not infer a SHA1 from `fileQualifier`, conclude elevation was granted from `Collect UAC actions`, or identify `updater.exe` without a corroborating hash/path. Because this EPM event is aggregated, check `firstEventDate` separately and distinguish EPM arrival from occurrence. Verify the QRadar console UTC offset before interpreting AQL windows. Some QRadar deployments index ingestion time differently: an empty result needs a manual check of the ingestion window.

### Trend Web Reputation versus FortiGate

The Trend event-viewer link is a filtered **list**, not a unique event reference. Open a specific event and ask Kiro to call `investigate_web_reputation(url_or_domain="https://bad.example/", event_time="2026-09-24T13:33:46Z", event_id="01234567-89ab-cdef-0123-456789abcdef", endpoint_host="DEMO-PC", endpoint_guid="11111111-2222-3333-4444-555555555555")` (fabricated example). Supply the event time with its actual UTC offset: a portal display of `10:33:46` alone does not establish its timezone. `endpoint_ip` is optional when an event UUID and host are supplied. The tool first searches Vision One detections and endpoint activities for the exact event UUID, host, GUID, domain and time. If the specific event does not surface, an unambiguous private IP from host/GUID activity near the event may be used only as a labelled candidate. A full 50-row host page triggers narrower ±60s and ±10s searches before deciding whether the IP evidence is usable. Current inventory IPs may be shown as context but are never used automatically as historical IPs. If discovery still cannot attribute an IP, the tool makes a separate domain-only FortiGate search; logs found there cannot be assigned to this endpoint. Provide an independently checked historical `endpoint_ip` to retry endpoint-specific matching. QRadar Ariel is searched by domain in a ±5 minute window, checking exact source IP, hostname/url and event timestamp in returned FortiGate payloads when the endpoint IP is available. `traffic action=accept` means an accepted connection; only a FortiGate webfilter `passthrough` or comparable allow record matching the domain supports a domain-level allow. Neither establishes delivery of a page or proves Trend did not block the endpoint request. The report includes policy ID, destination IP where logged, and first-page caps; a draft for the network team is generated only when a domain-specific webfilter permission record is found. A blocked-only result generates no request to add a block. No message, rule update, or domain block is sent. NAT/proxy egress, source-IP mismatch, incomplete pages and QRadar local timezone can prevent attribution; confirm these manually.

## Demo e conexões reais

O [passo a passo](docs/guia-instalacao.md) começa com `investigate_demo`, sem API key. Depois descreve QRadar MCP em loopback, Docker para Vision One, as variáveis de ambiente e o primeiro caso autorizado. O arquivo `.env.example` é apenas uma referência: o programa **não carrega `.env` automaticamente**. O cliente aceita somente `http://127.0.0.1:<porta>/mcp` (ou outro endereço de loopback suportado) e permite apenas as tools upstream da allowlist no código.

## What a report means

### Alert-first investigation

`investigate_case` routes a QRadar number to the offense-first investigation, or a `WB-` ID to alert-first. Alert-first reads structured IP, host and hash fields when present. For the exact RClone Detection model with missing fields, up to six bounded detection queries search from 30 minutes before to 5 minutes after alert creation for `fileName`, `filePath`, `fullPath`, and `filePathName` containing `rclone.exe`, then for known RClone detection labels in `malName`, stopping at the first nonempty result. Unsupported query fields are reported without stopping the remaining searches. A unique host/hash **and exact rclone.exe file path** in the returned record are required before using an IP as a candidate; multiple identities or a capped page prevent attribution. It then searches endpoint activity for the exact host, uses a unique private RFC1918 host IP as a candidate QRadar pivot, and queries the QRadar offense address indexes. All searches remain capped and label their source. Model/name detection candidates are not verified Workbench View events.

If the same process hash has activity, alert-first runs one extra QRadar Ariel query ±12 seconds around the earliest displayed process event. The fixed AQL uses a numeric `starttime` predicate for seconds-level precision, since QRadar rounds START/STOP to minutes. It retrieves at most 100 events and displays at most 20. A firewall event sharing IP and time does not prove which process generated it or that data was transferred.

`investigate_vision_event` uses the same bounded offense searches with the manually provided View event IP and UTC event time, even when the Workbench alert API detail contains no IP. It also checks AQL validity and automatically creates, polls and retrieves QRadar Ariel event searches for the IP and optionally the hostname. Each search inspects at most 100 events and displays up to 20 with event name, log source, time, source and destination IP and user when available. It omits raw payload. A search can return a truncated sample or time out; the report says so. The hash is a Vision One Search pivot only; file/process paths are context only. Neither the hash nor paths are QRadar pivots in this version. `fullPath` identifies the detected file while `processFilePath` identifies a separate process path, so a file detection is not evidence that RClone ran or sent data.

When a host or SHA-1/SHA-256 is discovered or supplied, alert-first runs at most three additional Vision One Search calls: endpoint activities for the host, detections for the file hash, and endpoint activity for the process image hash. Each is limited to a 60-minute UTC window and the first 50 results; up to 20 safe fields per query are sent to Kiro. These searches require the Vision One Search API entitlement and key permission. The report merges returned records into a 40-entry UTC evidence timeline, with source and search references. If the alert has no usable structured entity and is not the known RClone model, the API cannot retrieve an arbitrary View event and the report marks the gap.

If exact-host activity supplies two or three private interface IPs and a matching process-hash event, alert-first runs a separate fixed Ariel IP query for each candidate within twelve seconds of the process activity. The results are capped at 100 per IP, with up to 20 rows displayed and at most three rows per IP in the combined timeline. None of these searches assigns an IP to the process; virtual interfaces and public NAT addresses require independent identity validation. If more than three private IPs appear, the focused checks are skipped with an explicit coverage warning.

From PowerShell with the same temporary credentials as the offense-first CLI, you may also run:

```powershell
.\.venv\Scripts\python.exe -m soc_bridge.cli alert --alert-id WB-EXAMPLE-20260924-00001 --output reports\alert-00008
```

Local reports may contain sensitive incident data; keep them out of a public portfolio. The Kiro tool's Markdown report is sent to the configured AI model when invoked. Although creating and validating an Ariel search use POST requests in the IBM QRadar MCP, they only operate on query jobs; this bridge never calls QRadar's offense or configuration mutation tools. Blocking all QRadar POST requests at deployment would also disable Ariel search. Use a per-tool allowlist instead; keep write operations disabled in SOC Bridge and restrict the upstream account appropriately.

- QRadar: `get_offense`, `list_source_addresses`, `list_local_destination_addresses`.
- Vision One: `workbench_alerts_list` with exact `indicatorValue` or `impactScopeEntityValue` filters, followed by `workbench_alert_detail_get`.
- The QRadar start and last update times create a search window padded by one hour. Results are deduplicated by Vision One alert ID.
- Ranking awards points for a returned IP match, matching both Workbench fields, a creation time inside the window and high/critical severity. This is **investigation order**, not evidence of causality.
- The tool checks up to eight IPs, 100 QRadar addresses per list, and 20 unique alerts by default. Workbench pagination is not followed in this MVP. Missing results **do not prove the absence** of malicious activity.
- The local JSON retains raw offense and alert details for an analyst to inspect. Treat it as sensitive incident data.

## Security and portfolio use

Publique somente código e exemplos fabricados. Nunca publique `reports/`, um `.env` populado nem `.kiro/settings/mcp.json` com valores reais. A ponte inicia o MCP da Trend em modo somente leitura e não faz chamada direta a um LLM, **mas o conteúdo do relatório retornado a uma tool é entregue ao modelo configurado no Kiro**. Verifique as regras de tratamento de dados da sua organização antes de usar incidentes reais.

IBM's and Trend Micro's MCP servers are separate upstream projects. SOC Bridge is an independent client; it does not copy or modify their source code. Check their licenses and API requirements for your deployment.

## Tests

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

The tests verify matching, temporal context and the no-match caveat using the synthetic fixtures. A live integration run requires access to both products and has not been simulated by the demo.

## Known limitations

- **PAM/privilege-escalation identity is not recoverable through the bridge.** `investigate_offense`'s internal Ariel query uses a fixed `SELECT` (`starttime`, `sourceip`, `sourceport`, `destinationip`, `destinationport`, `username`, event name, log source) with no event-type/QID filter or raw payload. When an escalation event's normalized `username` is empty, the bridge cannot recover the source/target user, which QRadar exposes only through DSM-specific custom properties (names vary by deployment, e.g. "Source Username"/"Target Username") or the raw payload — that identity must be checked manually in QRadar Log Activity. The report labels it `não verificado` rather than guessing.
- **Ariel search IDs aren't consistently returned.** Some flows surface the QRadar search ID for a completed Ariel search; others only reconstruct the AQL, window and result count in text. This limits reopening the exact same search for audit or deeper pagination.
- **No aggregate/inventory queries.** All seven tools do bounded, first-page lookups by IP/host/hash/event — there is no free AQL and no aggregate count. The bridge cannot answer inventory questions (e.g., "how many AD users exist"); it can only report users that happen to appear in the sampled events, which is never the same as a directory count.

Full detail, proposed fixes and manual workarounds for each item are in [docs/bridge-known-limitations.md](docs/bridge-known-limitations.md).

## More documentation

- [README-kiro-pack.md](README-kiro-pack.md) — status and install notes for the `.kiro/` steering/skills/agents pack, and what was validated against a real QRadar offense (identifiers replaced with a fabricated example ID for this public repository).
- [docs/guia-instalacao.md](docs/guia-instalacao.md) — instalação desde o clone, demo sem credenciais, Kiro e conexão real no Windows/Linux/macOS.
- [BRIDGE-BACKLOG.md](BRIDGE-BACKLOG.md) — proposed engineering improvements for the bridge itself and for deterministic Kiro agent routing.
- [docs/bridge-known-limitations.md](docs/bridge-known-limitations.md) — full write-up behind the "Known limitations" summary above.

## Next contributions

- Paginate Workbench results with an explicit maximum and visible coverage count.
- Extend normalized timelines to offense-first investigations and include asset identity where supported.
- Add a guided host/identity investigator and targeted playbooks for lockouts and lateral movement.
- Record query duration, caps and analyst accept/reject feedback for auditable quality metrics.
- Map Workbench endpoint and identity telemetry to a common entity graph.
- Add structured findings that an analyst can accept or reject before exporting a case.

## License

MIT. See [LICENSE](LICENSE).
