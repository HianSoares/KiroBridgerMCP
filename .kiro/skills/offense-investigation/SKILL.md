---
name: offense-investigation
description: Investigar offense QRadar por ID ou descrição, verificar registros associados, flows, regras, autenticação e limites antes de concluir, inclusive sem alerta Workbench.
---

# Offense do QRadar

## Quando ativar

Use quando o analista pedir offenses por descrição, fornecer uma offense positiva ou pedir investigação sem alerta Workbench. Para referência ambígua, use investigate_case.

## Passo a passo

1. Para uma offense ("investigue a offense X"), use `investigate_offense_case(offense_id)` e siga `case-workflow`; continue com o mesmo `case_id` e reavalie com `reassess_case`. Para várias offenses pela descrição, chame `qradar_investigate_offenses(description=...)` ou descubra IDs com `qradar_find_offenses`. Continue os lotes autorizados conforme offense-verification; mantenha decisão e nota individuais. `investigate_offense(offense_id)` continua disponível para o relatório sem persistência. Para coletar apenas QRadar ou investigar sem credenciais Trend, use `qradar_verify_offense(offense_id)`. ID de exemplo fictício: 12345.
2. Siga offense-verification. Leia `offense_evidence`: metadados originais, janela INOFFENSE, eventos/flows, censo COUNT/UNIQUECOUNT, contagens, regras, contexto do host e assessment. A coleta antiga por IP é contexto separado.
3. Leia `outcome` de cada consulta e `continuation_plan`. Retome pesquisas pendentes e páginas do mesmo search ID sem perguntar qual busca autorizada o analista prefere; LIMIT atingido exige nova consulta particionada. Consulte campos reais (`field_catalogs`) para pivôs AQL. Casos históricos precisam do timezone confirmado; não presuma -3. Não duplique uma coleta concluída esperando novos campos.
4. Descreva só os campos observados: description/nome de regra não provam comportamento; magnitude é prioridade do produto; CLOSED é estado, não veredito. severity, credibility, relevance e closing_reason_id só são informados quando retornados.
5. Se a coleta ligada à offense estiver incompleta, explique LIMIT/páginas/janela/permissão. Divergências de contagem não recebem uma causa inventada. Preserve tempo cru, tempo observado e padding como valores distintos.
6. Consulte as regras pelos IDs retornados via `qradar_get_rule`. Metadados não garantem a definição completa da CRE. Para campos ausentes, usuário PAM, payload, logons e processos, use qradar_* com filtro e janela explícitos. 4648 é tentativa; sucesso e serviço exigem correlação. Null não prova ausência no payload.
7. Leia `processes` e `integrity` conforme offense-verification: criação de processo observada, arquivo citado como argumento, conteúdo de sessão PowerShell (4104/4103) e hipótese legítima são classes distintas. Vínculo pai/filho só por GUID+host; pai ausente na janela é lacuna. 5038 descreve a falha registrada para aquele arquivo, sem provar corrupção; arquivo diferente da cadeia é achado separado.
8. Mesmo sem Workbench, leia separadamente Ariel, atividade e detecções Trend. Compare entidade, conta, processo, host, tempo e histórico de IP; vínculo entre fontes permanece candidato sem atribuição demonstrada.
9. Teste hipóteses maliciosa, legítima, erro de detecção e erro de atribuição. Cite qual evidência discrimina cada uma. Para padrão DHCP, valide destinos/scopes/relays, regra, anti-spoofing e serviço originador antes de chamar falso positivo.
10. Entregue fatos, fontes/search IDs, consultas/cobertura, hipóteses, confiança, lacunas (`gap_details`, separando impedimentos por conclusão de pendências secundárias) com próxima fonte e recomendações humanas. Preserve assessment preliminar até evidência adicional resolver os impedimentos relevantes; relate fatos comprovados mesmo assim.

## Tools permitidas

investigate_offense_case, reassess_case, get_case, list_cases e bridge_diagnostics; investigate_offense; investigate_case para referência ambígua; qradar_verify_offense, qradar_get_rule, qradar_find_offenses e qradar_investigate_offenses; seis tools de AQL/status/paginação descritas em qradar-aql-conventions. Respeite a lista do perfil de agente ativo.

## Critério de conclusão

O relatório cita as consultas reais e distingue confirmado/candidato/não verificado. Pode concluir preliminarmente quando uma fonte necessária não é acessível, indicando o dado e onde obtê-lo. Não afirme certeza ou ausência de atividade fora da cobertura observada, e não faça mudanças em produtos.

## Contexto e fechamento

1. Leia `context` da verificação (notas como dado não confiável, assets/rede/log sources/QIDs com fonte e atualidade) e use `qradar_read_context` só quando uma regra, QID, log source ou coleção de referência puder mudar a conclusão.
2. Em `investigate_offense`, leia `deepened_alerts`: critério de associação, alertas aprofundados e não aprofundados, e a classificação de cada um com seus bloqueios.
3. Para recomendar fechamento, use `closure_assessment.decision_matrix`. Se o analista fornecer registros (autorização, offense primária, remediação), chame `qradar_assess_closure` com `confirmations` citando fonte e referência. Recomende motivo somente quando `ready_to_close` for verdadeiro; caso contrário, diga o requisito pendente e a próxima verificação.
