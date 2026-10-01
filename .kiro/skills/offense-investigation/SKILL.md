---
name: offense-investigation
description: Investigar offense QRadar por ID, verificar registros associados, flows, regras, autenticação e limites antes de concluir, inclusive sem alerta Workbench.
---

# Offense do QRadar

## Quando ativar

Use quando o analista fornecer uma offense positiva ou pedir investigação sem alerta Workbench. Para referência ambígua, use investigate_case.

## Passo a passo

1. Chame `investigate_offense(offense_id)` para QRadar e Trend. Para coletar apenas QRadar ou investigar sem credenciais Trend, use `qradar_verify_offense(offense_id)`. ID de exemplo fictício: 12345.
2. Siga offense-verification. Leia `offense_evidence`: metadados originais, janela INOFFENSE, eventos/flows, censo COUNT/UNIQUECOUNT, contagens, regras, contexto do host e assessment. A coleta antiga por IP é contexto separado.
3. Retome pesquisas pendentes e páginas do mesmo search ID. Consulte campos reais para pivôs AQL. Casos históricos precisam do timezone confirmado; não presuma -3. Não duplique uma coleta concluída esperando novos campos.
4. Descreva só os campos observados: description/nome de regra não provam comportamento; magnitude é prioridade do produto; CLOSED é estado, não veredito. severity, credibility, relevance e closing_reason_id só são informados quando retornados.
5. Se a coleta ligada à offense estiver incompleta, explique LIMIT/páginas/janela/permissão. Divergências de contagem não recebem uma causa inventada. Preserve tempo cru, tempo observado e padding como valores distintos.
6. Consulte as regras pelos IDs retornados via `qradar_get_rule`. Metadados não garantem a definição completa da CRE. Para campos ausentes, usuário PAM, payload, logons e processos, use qradar_* com filtro e janela explícitos. 4648 é tentativa; sucesso e serviço exigem correlação. Null não prova ausência no payload.
7. Mesmo sem Workbench, leia separadamente Ariel, atividade e detecções Trend. Compare entidade, conta, processo, host, tempo e histórico de IP; vínculo entre fontes permanece candidato sem atribuição demonstrada.
8. Teste hipóteses maliciosa, legítima, erro de detecção e erro de atribuição. Cite qual evidência discrimina cada uma. Para padrão DHCP, valide destinos/scopes/relays, regra, anti-spoofing e serviço originador antes de chamar falso positivo.
9. Entregue fatos, fontes/search IDs, consultas/cobertura, hipóteses, confiança, lacunas com próxima fonte e recomendações humanas. Preserve assessment preliminar até evidência adicional resolver os impedimentos relevantes.

## Tools permitidas

investigate_offense; investigate_case para referência ambígua; qradar_verify_offense e qradar_get_rule; seis tools de AQL/status/paginação descritas em qradar-aql-conventions. Respeite a lista do perfil de agente ativo.

## Critério de conclusão

O relatório cita as consultas reais e distingue confirmado/candidato/não verificado. Pode concluir preliminarmente quando uma fonte necessária não é acessível, indicando o dado e onde obtê-lo. Não afirme certeza ou ausência de atividade fora da cobertura observada, e não faça mudanças em produtos.
