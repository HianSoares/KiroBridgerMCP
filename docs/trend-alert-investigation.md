# Investigação de alertas Trend Vision One

Este guia descreve o fluxo de `investigate_vision_alert` e `investigate_vision_event`
depois da revisão contra o código oficial do
[Vision One MCP Server](https://github.com/trendmicro/vision-one-mcp-server)
(commit `2d13740`, 23/09/2026) e os exemplos do
[tm-v1-api-cookbook](https://github.com/trendmicro/tm-v1-api-cookbook). As duas tools
mantêm o mesmo schema de entrada; o enriquecimento acontece por trás delas.

## O que mudou

1. **Extração estruturada do Workbench.** `impactScope.entities` com `entityType`,
   `entityId` e `entityValue` como objeto (`name`, `guid`, `ips`) ou valor escalar;
   IPs em listas (IPv4 e IPv6); indicadores `type`/`field`/`value` com `id`,
   `relatedEntities` e `filterIds`; `matchedRules → matchedFilters → matchedEvents`.
   Aliases de campo preservam papéis (endpoint, processo, objeto, pai). Cada valor
   guarda a origem. Texto livre (descrição, nome do modelo) nunca é raspado.
2. **Estados de campo.** `extraction.field_states` diferencia ausente, vazio, formato
   não reconhecido e corte da ponte; `shape` mostra só chaves e tipos para diagnóstico.
   Fonte indisponível ou sem permissão aparece como falha da etapa, não como vazio.
3. **Descoberta independente do modelo.** Pivôs por GUID/host/IP de cada endpoint,
   hashes por papel (`process*`, `object*`, `parent*`), nome-base de caminho com
   conferência exata depois, OAT por endpoint e seguimento da instância de processo
   (`processHashId`). Registros são `linked` (uuid em `matchedEvents`),
   `identifier_match` (candidato forte) ou `context`.
4. **Relógios separados.** Evento, correspondência, detecção/ingestão OAT,
   criação/atualização do alerta e coleta. `createdDateTime` só é âncora provisória.
   UTC com milissegundos; strings com `Z` são interpretadas uma vez.
5. **Search com cobertura honesta.** O handler oficial de Search aceita apenas
   `startDateTime`, `endDateTime`, `top`, `mode`, `select` e o header `TMV1-Query`:
   não há token de continuação. Página cheia é dividida em partições temporais; a fatia
   mínima ainda cheia vira `limited` com plano de refinamento. OAT pagina por
   `nextBatchToken`. `countOnly` é uma medida independente.
6. **Enriquecimentos opcionais em leitura** (com gatilho, limite e estado):
   notas do alerta, insight (só com ID de insight no alerta), inventário do endpoint,
   dispositivo CREM, modelo e exceções DMM, Suspicious Object/Exception List,
   resultados de sandbox existentes, casos, auditoria, tarefas de resposta existentes,
   busca de rede (hipótese de transferência) e de e-mail (entidade de e-mail).
7. **Trend → QRadar com o coletor Ariel orçado.** Janela curta (±2 min) e ampliação
   única (±30 min) com hipótese registrada; predicados epoch; `LAST 24 HOURS` para
   casos recentes; histórico só com fuso verificado (`QRADAR_AQL_TIMEZONE_VERIFIED=true`),
   caso contrário a consulta vira plano. Eventos, flows, pista textual de hostname e
   leads de offense ficam separados; relações são `confirmed`, `candidate` ou `unverified`.
8. **Ferramentas de dump (ProcDump).** Intenção (linha de comando), execução observada,
   arquivo `.dmp` confirmado e alvo (PID + endpoint + início anterior; instância quando
   disponível) são separados; atividade posterior do `.dmp` e conexões atribuíveis são
   buscadas. Nenhuma conclusão automática de extração de credenciais.
9. **Conclusão.** Cronologia com proveniência, hipóteses concorrentes, cobertura,
   classificação recomendada (True Positive, Benign True Positive, False Positive ou
   inconclusiva), confiança e nota sugerida em português, nunca publicada.

## Toolsets e allowlist

O container da Trend é iniciado com `-readonly=true` e
`-toolsets=workbench,search,endpoint,threatintel,dmm,crem,cases,audit,sandbox,response`.
Com `-readonly=true` o upstream registra apenas as tools de leitura desses toolsets, e a
ponte ainda restringe a uma allowlist explícita (`ALERT_VISION_TOOLS`). Tools de
escrita (atualizar alerta, criar notas, isolar, executar scripts, coletar arquivos,
submeter ao sandbox) não são permitidas.

## Orçamento

Um único orçamento por investigação: 75 s, 8 jobs Ariel, 40 chamadas Trend, 5000
registros e 16 partições. Nenhuma chamada começa depois do prazo; o progresso parcial é
mantido e as pendências aparecem em `auto_pivots.continuation` e
`qradar_correlation.plan`.

## Lacunas que dependem do upstream

- Search não aceita cursor de continuação no MCP oficial; a ponte usa partições
  temporais. Encaminhar um token exigiria mudança no handler upstream.
- `workbench_alert_notes_list` declara `skipToken`, mas o handler não o encaminha: só a
  primeira página de notas é recuperável.
- Endpoint/Detection Search não aceitam `uuid` como campo de consulta: o vínculo com
  `matchedEvents` é verificado após a recuperação por endpoint e janela.
- `dmm_models_list` não filtra por nome do modelo; a ponte compara o nome na página lida.
- Insights só podem ser lidos com ID de insight; a busca de insights não aceita ID de
  alerta Workbench.
- Os campos de IPv6 do QRadar não foram verificados nesta ponte: IPv6 é listado e não
  consultado no Ariel.

Nenhuma alteração foi publicada no repositório da Trend.

## Recarregar no Kiro

```powershell
git pull --ff-only
& .\.venv\Scripts\python.exe -m pip install -e .
```

Reconecte o servidor `soc-bridge-readonly` no painel MCP do Kiro e abra um chat novo para
recarregar descrições, steering e skills. O total de tools continua 15.
