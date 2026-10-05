---
inclusion: always
---

# Executar pedidos claros

Um pedido de investigação autoriza as leituras necessárias dentro dos limites da ponte. Execute a entrada adequada, leia os resultados, continue os pivôs que podem mudar a decisão e entregue o resultado. Não responda apenas com um plano ou um menu de opções. Não peça autorização novamente para consultar, correlacionar, paginar ou continuar o mesmo caso.

## Escolher a entrada real

| Pedido | Primeira ação |
| --- | --- |
| Listar offenses OPEN e priorizar | `qradar_list_offenses(status="OPEN")`; seguir `continuation_plan`, reunir os IDs e ordenar o conjunto pelos critérios retornados. Não exigir descrição. |
| Investigar offense por número | `investigate_offense_case(offense_id=...)`; continuar o mesmo `case_id`, executar os pivôs `planned` acessíveis e avaliar decisão/razão/nota. |
| Investigar várias offenses com a mesma descrição | `qradar_investigate_offenses(description=..., status="OPEN", match="exact")`; seguir cursores e IDs pendentes sem pedir que o analista os descubra manualmente. |
| Buscar logs/comandos no XDR Data Explorer por host/filtro | `trend_read_search_resource(source=...)`, depois `trend_search_data` com query e janela; não exigir WB/offense nem conexão QRadar. |
| Ver alertas abertos na Trend | `trend_find_alerts(status="OPEN")`; declarar a janela padrão de 24h e que OPEN inclui Open/In Progress. Não confundir seleção completa na janela com todos os alertas históricos. |
| Investigar alerta WB e correlacionar no QRadar | `investigate_vision_alert(alert_id=...)`; ler evidência, correlação e continuação. |
| Investigar os alertas que acabaram de ser listados | Usar os IDs já obtidos e investigar um por vez, em sequência. Uma falha num alerta não impede investigar o próximo. |

Leia o schema disponível nesta sessão antes de declarar uma capacidade ausente. Não invente `match="any"`, nomes de tools upstream ou argumentos que a ponte não expõe. Se as tools previstas não aparecem, execute `bridge_diagnostics`; reporte a divergência e o passo de reconexão, sem tratar isso como zero resultados.

Use os padrões documentados quando o usuário não indicar período, declare-os e prossiga. Não exija fuso do console para `LAST` com predicados epoch ou para listar por status. Peça esclarecimento somente quando um identificador, horário manual com fuso ou registro externo indispensável não puder ser obtido pelas tools.

## Falha, encerramento e continuação

- `connection_lifecycle.report_preserved=true` significa que a coleta retornou um relatório e houve falha no encerramento. Leia o relatório normalmente, declare o aviso e os limites de cada consulta. Não diga que nada foi coletado e não repita buscas concluídas por causa desse aviso.
- Na entrada de alerta WB, indisponibilidade do QRadar não impede a coleta Trend; o relatório registra a correlação como não executada. Não diga que nenhuma fonte foi consultada quando houver evidência Trend preservada.
- `collection.state=partial` e `collection.errors` identificam etapas interrompidas. Preserve fatos das etapas concluídas, sem inventar resultado para as outras. Permissão, licença, parâmetros rejeitados e indisponibilidade são lacunas diferentes.
- Jobs Ariel conhecidos: `poll_same_search` e `fetch_next_page` continuam o mesmo search ID e cursor, pelas tools indicadas no plano. `creation_uncertain` exige verificar a criação antes de qualquer repetição; não recrie às cegas.
- Na mesma ponte em execução, repetir o mesmo alerta com os mesmos parâmetros reutiliza leituras bem-sucedidas e checkpoints Ariel enquanto o estado temporário estiver disponível (até 15 minutos, quatro alertas). Leia `resumption`: reinício, expiração ou remoção por limite elimina esse estado; os planos devolvidos continuam sendo a referência para retomada pelos IDs. Essa memória não é um caso persistido.
- Para falha transitória, faça no máximo uma continuação/repetição pertinente, resumindo o progresso. Para erro não repetível, registre a correção necessária e continue as fontes/alertas independentes; não rode quatro vezes a investigação inteira nem alterne tools que chamam o mesmo coletor.
- `bridge_diagnostics` verifica inicialização/descoberta, não conserta outra sessão nem prova acesso a todas as APIs. Seu ledger é cumulativo do processo; `call_outcomes` do relatório de alerta pertence àquela tentativa. `reused_read` não é nova chamada upstream.
- Cite a conexão/componente quando o diagnóstico os identificar. Sem essa informação, a origem está indeterminada; não atribua a falha ao contêiner Trend, à carga ou ao QRadar por suposição.

## Entrega

Entregue comportamento observado, evidências decisivas com referência e horário, hipóteses testadas, cobertura/pendências, decisão recomendada, confiança justificada e nota em pt-BR. Quando a evidência não permitir fechar, a decisão é manter pendente com motivo específico, sem perguntar se deve montar o relatório. Classificação e fechamento dependem de evidência, nunca só do nome do alerta ou do sucesso da conexão. A autorização de investigar não autoriza mutações no QRadar/Trend, publicação de notas ou contenção.
