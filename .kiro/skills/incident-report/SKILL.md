---
name: incident-report
description: Redigir relatório de investigação SOC a partir de resultados das tools da ponte, com proveniência, confiança e lacunas sem fabricar telemetria.
---

# Relatório de incidente

## Quando ativar

O analista pede um relatório após uma chamada real do MCP ou apresenta um relatório bruto da ponte. Demonstração fabricada deve ser marcada como tal.

## Passo a passo

1. Estabeleça a fonte do relatório, tool, parâmetros fornecidos, horário de geração, referência e se a coleta terminou. Falha parcial não vira relatório de ausência.
2. Organize a saída em: resumo executivo; gatilho; escopo e fuso; tabela de consultas (`QRadar Ariel`, `Trend Workbench/Search`, outras), com estado, janela, filtro, páginas/cap e resultados; cronologia UTC com fonte por linha.
3. Para cada afirmação, identifique observação `confirmado`, correlação `candidato` ou dado `não verificado`. Preserve IDs e timestamps; masque valores reais se o texto for destinado ao portfólio. Não inclua evidência real sanitizada parcialmente se ainda puder identificar pessoa/órgão.
4. Monte hipóteses concorrentes e perguntas dos cinco porquês até o limite da evidência. Anote vetor e falha de controle somente quando demonstrados; caso contrário, “causa raiz indeterminada”.
5. Classifique impacto observado versus potencial, severidade avaliada, ATT&CK sustentado e confiança qualitativa com justificativa. Não adote disposition de produto como veredito próprio.
6. Liste lacunas com campo preciso e fonte de obtenção; depois plano para revisão humana de contenção → erradicação → recuperação e ajuste de detecção. Não execute nem envie nenhuma ação.
7. Termine com decisão recomendada, razão fundamentada e nota de revisão em pt-BR. Leia `closure_assessment` e o catálogo real `closing_reasons`; não invente IDs. Se faltarem validações relevantes, indique manter pendente e explique o impedimento na nota. Se novas fontes citadas sustentarem fechamento, explique como resolveram esses impedimentos e por que o motivo escolhido se aplica. `False-Positive, Tuned` exige tuning aplicado e verificado; motivo customizado exige definição local. Status CLOSED e comportamento compatível não substituem justificativa.

## Tools permitidas

Nenhuma nova chamada é necessária se um relatório real completo já foi fornecido. Se faltar o relatório e houver referência, escolha `investigate_case(reference)`, `investigate_offense(offense_id)` ou `investigate_vision_alert(alert_id)` conforme a referência; para demonstrar o formato, `investigate_demo()`.

## Critério de conclusão

Todas as seções têm fonte ou a indicação “não informado”; consultas não executadas não aparecem como vazias. O documento é revisável por outro analista sem depender de suposições ocultas. Em offense, siga offense-verification: preserve assessment preliminar, horários originais versus padding, registros INOFFENSE versus contexto, e lacunas de contagem/payload/atribuição. Classifique como final somente quando evidências adicionais citadas resolverem os impedimentos relevantes. “Compatível com DHCP” não equivale a “falso positivo confirmado”.
