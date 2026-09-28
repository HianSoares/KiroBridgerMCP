---
inclusion: always
---

# Interpretar consultas QRadar/Ariel da ponte

O `soc-bridge-readonly` não oferece AQL livre ao Kiro. Esta orientação serve para ler AQL e metadados já retornados pelas sete tools, nunca para gerar ou executar consultas próprias.

1. Identifique a tool de entrada, a referência e a busca Ariel efetivamente executada: search ID, estado (`COMPLETED`, erro, pendente), origem da consulta, fonte/log source e campos selecionados, se constarem do relatório.
2. Registre o relógio da offense ou evento, a janela UTC pedida, o `START`/`STOP` apresentado e o offset local aplicado. O `qradar_utc_offset_hours` tem default `-3`; confirme o fuso do console para esta execução antes de afirmar alinhamento. A ferramenta pode acrescentar um predicado em milissegundos para limitar segundos; descreva o que aparece no AQL, sem recalcular por suposição.
3. Leia filtros como pistas de cobertura: `sourceip`/`destinationip`, hostname via texto, domínio, ação e log source podem observar conjuntos diferentes. IP compartilhado, hostname textual e proximidade temporal não atribuem um processo ou usuário.
4. Informe linhas inspecionadas, total reportado, `LIMIT`, página e cap *quando aparecerem no relatório*. `COMPLETED` significa que aquela consulta terminou; não significa busca exaustiva do incidente. Uma primeira página cheia pede cautela; 8 registros retornados com limite 100 não são, por si, amostra truncada.
5. Se a offense não tiver Workbench correspondente, verifique se o relatório trouxe busca Ariel e buscas Trend de endpoint/detecções. Se não, classifique como lacuna de coleta, sem afirmar silêncio do endpoint.
6. Se uma linha cair fora da janela UTC pedida, sinalize o desalinhamento de fuso ou conversão e suspenda conclusões temporais até conferência.

Para uma pesquisa ausente, diga “não executada” e explique a dependência (pivô não atribuído, upstream indisponível ou tool não exposta). Consultas agregadas de usuários do AD e caça AQL arbitrária estão fora das tools disponíveis; mencione como possíveis melhorias da ponte, sem apresentar sintaxe AQL como se o agente pudesse executá-la.
