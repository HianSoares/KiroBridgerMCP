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
   (`processHashId` e `objectProcessHashId`, com endpoint e papel preservados). Registros são `linked` (uuid em `matchedEvents`),
   `identifier_match` (candidato forte) ou `context`.
4. **Relógios separados.** Evento, correspondência, detecção/ingestão OAT,
   criação/atualização do alerta e coleta. `createdDateTime` só é âncora provisória.
   UTC com milissegundos; strings com `Z` são interpretadas uma vez.
5. **Search com cobertura honesta.** O handler oficial de Search aceita apenas
   `startDateTime`, `endDateTime`, `top`, `mode`, `select` e o header `TMV1-Query`:
   não há token de continuação. Página cheia é dividida em partições temporais; a fatia
   mínima ainda cheia vira `limited` com plano de refinamento. OAT pagina por
   `nextBatchToken`. Falha em qualquer lote posterior mantém o resultado `partial`,
   os itens lidos e uma continuação com token, filtro, janela e `top`. Lote não iniciado
   também recebe plano; token repetido interrompe a paginação. Uma retomada interna
   com `next_batch_token` cobre apenas os lotes restantes, sem afirmar que releu os anteriores.
   `countOnly` é uma medida independente.
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
   `confirmed` exige mesmo host, PID igual, `launchTime` do papel Trend compatível
   com `UtcTime` de criação Sysmon EventID 1 (≤2 s), início não posterior ao evento
   Trend e caminho/comando/hash completo no mesmo papel, sem cortes conhecidos.
   Mesmo binário e comando em execuções distintas permanecem candidatos.
8. **Ferramentas de dump (ProcDump).** Intenção (linha de comando), execução observada,
   referência ao arquivo `.dmp` e alvo (PID + endpoint + início anterior; instância quando
   disponível) são separados. Atribuição de arquivo exige endpoint, instância do ator
   e janela compatíveis; sem instância, PID/início podem produzir apenas candidato.
   Código `eventSubId` ou extensão `.dmp` não comprovam criação/escrita: a operação fica
   não verificada enquanto a taxonomia não for decodificada. Pivôs posteriores usam
   o endpoint investigado e distinguem caminho exato de nome-base candidato. Conexão
   atribuível após a referência não comprova o conteúdo transferido. Reutilização do
   PID pelo mesmo executável também pode tornar o alvo ambíguo.
9. **Conclusão.** Cronologia com proveniência, hipóteses concorrentes, cobertura,
   critérios de classificação (True Positive, Benign True Positive, False Positive ou
   inconclusiva), confiança e nota sugerida, nunca publicada. As fontes atuais de
   telemetria e rótulos de risco não verificam uso malicioso nem autorização: a
   classificação automática permanece `Inconclusive`. Conexões, alvo LSASS e rótulo
   de risco alto são observações/pistas, não vereditos. O Kiro pode reavaliar com
   evidência decisiva citada, mantendo separada a recomendação humana da coleta.
   Falhas/limites em OAT, Search e seguimento do dump aparecem nas pendências.

## Workbench + XDR Data Explorer

O relatório de `investigate_vision_alert` traz a seção **XDR Data Explorer follow-up** (`xdr_followup`). A investigação inicial roda uma vez; essa seção prepara o que vem depois:

- **Sementes com proveniência:** host/GUID, IPs, usuários, hashes, instâncias de processo, comandos e horários. O agente não pede ao analista o host ou IP que já estão ali ou nos registros Search.
- **Fases `trend_search_data` sem duplicatas:**
  - série de comandos e atividade posterior do endpoint;
  - detecções e Network Activity Data;
  - atividade e filhos de cada instância;
  - para backup/RClone/transferência, comando, launcher e acesso à configuração da ferramenta.
- **Estágios de transferência:** binário, configuração, comando, conexão atribuída, tráfego observado e operação concluída, cada um com o que o estabelece e o que não estabelece. Contadores sustentam no máximo tráfego observado; a conclusão exige resultado do aplicativo vinculado à execução ou confirmação no destino.
- **Fontes de volume:** flows do QRadar por tupla e janela e, na Trend, só campos com semântica de contador verificada (nenhum nos contratos auditados), com o que cada fonte prova.

Cada resultado de `trend_search_data` traz `evidence_digest`:

- atores: uma execução só quando `processHashId` a identifica no mesmo endpoint; sem ele, cada registro fica como observação separada, com PID, usuário e referência; `image_aggregates` agrupa por imagem e é rotulado como agregado, não execução;
- comandos com todas as ocorrências (endpoint, papel process/parent/object, instância e referência), objetos de arquivo e conexões com a sua atribuição;
- contadores só para campos com semântica de rede verificada, com campo, direção, unidade e sessão; os demais campos numéricos (por exemplo `memoryBytes`, `fileBytesWritten`, `packetLossRate`) ficam em `unclassified_metrics` com o valor nativo;
- `volume.total` sempre nulo. Não há soma; leituras repetidas da mesma sessão são sinalizadas, e tamanho de arquivo e porta ficam em `not_transfer_volume`.
- `identifiers`, comparável com `seeds.identifiers`, para registrar o que o XDR acrescentou.

`assessment.scope` delimita a avaliação à coleta inicial. As evidências complementares entram no parecer do agente, separado, sem reescrever a classificação. Registro de autorização pendente não oculta fatos técnicos e não sustenta Benign True Positive.
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
