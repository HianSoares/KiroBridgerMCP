---
name: trend-alert-investigation
description: Investigar alerta Workbench do Trend Vision One por ID, recuperar evidências (entidades, Search, OAT, enriquecimentos) e correlacionar com QRadar sem confundir proximidade com vínculo.
---

# Alerta Workbench Trend

## Quando ativar

O analista informa um ID exato de alerta Workbench ou copia campos de um único View event.

## Passo a passo

1. Com somente o ID, chame `investigate_vision_alert` com `{"alert_id": "WB-EXEMPLO-0001"}` (exemplo ilustrativo). Se a origem do texto for incerta, `investigate_case({"reference": "WB-EXEMPLO-0001"})`.
2. Leia `extraction`: endpoints (nome, GUID, IPs, inclusive listas e IPv6), indicadores com `id`/`type`/`field` e relações, `matched_rules` e `field_states`. Diferencie campo ausente, vazio, formato não reconhecido e corte da ponte; com entidade vazia, use `shape` antes de qualquer conclusão sobre a API.
3. Leia `anchor` e `clocks`: cite a base da âncora e se é provisória. Evento, correspondência, ingestão, criação/atualização e coleta são relógios distintos.
4. Leia `auto_pivots`: pivôs por GUID/host/IP de cada endpoint, hashes por papel e nomes de arquivo; OAT; seguimento de instâncias (`processHashId`); relações `linked`, `identifier_match`, `context` com motivos. Relate estados das consultas (`complete_in_window`, `partial`, `limited`, `empty`, `unavailable`, `not_started`) e `continuation`.
5. Se houver `dump_analysis`, separe intenção, execução, arquivo `.dmp` e alvo; leia atividade posterior do dump e conexões atribuíveis; mantenha as hipóteses operacional e maliciosa e peça a fonte de autorização/diagnóstico.
6. Leia `enrichment` com gatilho e estado; enriquecimento indisponível é lacuna secundária, não falha da coleta.
7. Em QRadar, separe leads de offense (índice de endereço), eventos, flows e pista textual de hostname; cite search ID, AQL, cláusula temporal e `relations` com seus critérios. Histórico sem fuso verificado aparece como plano (`run_with_verified_timezone`).
8. Continue as pesquisas read-only autorizadas que possam mudar a conclusão (partições pendentes, refinamentos, mesmo search ID, View event) sem perguntar qual pivô o analista prefere. Pare quando a próxima evidência depender de fonte inacessível e diga qual.
9. Se o analista fornecer campos do **mesmo** View event, confirme timezone explícito e IP exato; chame `investigate_vision_event` com `{"alert_id":"WB-EXEMPLO-0001","endpoint_ip":"192.0.2.10","event_time":"2026-01-15T12:00:00Z","endpoint_host":"HOST-DEMO","qradar_utc_offset_hours":-3}` somente após verificar o offset do console. Os campos continuam `não verificados` pela ponte. Omita campos opcionais sem valor.

## Entrega

Resumo do comportamento observado; cronologia com proveniência; relações Trend ↔ QRadar e critérios; hipóteses concorrentes e evidências discriminantes; cobertura, pendências e próximas fontes; classificação recomendada (True Positive, Benign True Positive, False Positive ou inconclusiva), confiança qualitativa e justificativa; nota sugerida em português para revisão humana (`assessment.note_pt`), sem publicá-la.

## Tools permitidas

`investigate_vision_alert(alert_id: string)`, `investigate_case(reference: string)` e, quando o analista trouxer campos obrigatórios exatos, `investigate_vision_event(alert_id: string, endpoint_ip: string, event_time: string, endpoint_host?: string, file_hash?: string, file_path?: string, process_path?: string, qradar_utc_offset_hours?: integer)`. AQL complementar pelas tools `qradar_*` conforme qradar-aql-conventions, no perfil que as expõe.

## Critério de conclusão

Cada pivô mantém proveniência, timezone e limite. Detecção próxima não vira parte do alerta sem vínculo por uuid ou identificadores. A classificação só avança quando a evidência citada resolve os impedimentos; sem dados decisivos, explique por que continua preliminar. Nada é fechado, publicado, isolado, executado ou submetido.

## Leitura do relatório ampliado

1. Comece por `insights` (critério de relação) e `auto_pivots.priority_order`; depois `hypothesis_checks` e só então `enrichment`.
2. Para cada conclusão, leia `assessment.decision_matrix`: cite os requisitos atendidos e o que bloqueia aquela conclusão específica, com o status de evidência (confirmado, compatível, candidato, não verificado, não retornou, não executado).
3. Se `budget.phase_log` ou `lead_queries` mostrar etapa não executada, diga "não executado", nunca "nenhum resultado".
4. Hipóteses concorrentes: registre o teste feito para cada uma (`hypotheses[].status`) e a próxima verificação que mudaria a decisão.

## Execução e recuperação

- Pedido claro autoriza as leituras necessárias: investigue, correlacione e entregue decisão/razão/nota sem perguntar se deve montar o relatório. Com vários IDs já conhecidos, investigue um por vez; falha num alerta não bloqueia os demais.
- Leia `collection.errors` e `connection_lifecycle`: falha de encerramento com relatório preservado não é falha de coleta. Não diga que nada foi pesquisado nem repita buscas concluídas.
- Continue pelo search ID/cursor do plano QRadar; os valores de continuação são exibidos sem corte. `creation_uncertain` nunca autoriza recriar automaticamente o job.
- Repetir o mesmo alerta nesta ponte reutiliza leituras e jobs enquanto o estado temporário existir: até 15 minutos, quatro alertas, sem persistência após reinício. Leia `resumption` e mantenha os planos para retomada por ID; não prometa recuperação automática depois da perda desse estado.
- O ledger de `bridge_diagnostics` é cumulativo, o `call_outcomes` do alerta é daquela tentativa. Inicialização/descoberta não repara sessões anteriores nem prova acesso ao sandbox, Insights ou Search. Informe permissão/parâmetros/fonte conforme a falha específica, sem inventar a causa.
