---
name: trend-alert-investigation
description: "Investigar alerta Workbench do Trend Vision One (WB-...) e usar o XDR Data Explorer: extração de entidades, âncora de tempo, pivôs Search/OAT, fases xdr_followup com evidence_digest, correlação QRadar e classificação recomendada sem confundir proximidade com vínculo. Também para alertas abertos sem ID e logs por host."
---

# Alerta Workbench e XDR Data Explorer

Regras comuns: `soc-core.md`. Detalhes de domínio: `trend-search-conventions.md`.

## Quando usar

- Um ID `WB-`, campos de um único View event, "há alertas abertos na Trend?" ou logs e comandos por host ou filtro.

## Quando não usar

- Offense QRadar como entrada principal: use offense-investigation. Alertas relacionados chegam por `deepened_alerts`.
- Transferência, backup ou RClone: comece aqui e aprofunde com exfiltration-assessment.

## Entradas mínimas e descoberta automática

- **Entrada mínima:** o ID exato do alerta. Sem ID, chame `trend_find_alerts(status="OPEN")`; o padrão são as últimas 24 h, com Open e In Progress.
- **Descoberta automática:** a ponte extrai endpoints (nome, GUID, IPs), usuários, hashes, instâncias, comandos e horários, com proveniência (`extraction`, `xdr_followup.seeds`). Não peça host ou IP que as sementes ou os registros trazem.
- **View event:** só com os campos do mesmo View event, horário com fuso explícito e IP exato, chame `investigate_vision_event`. Os campos continuam `não verificados`.

## Procedimento

1. **Coleta inicial, uma vez:** `investigate_vision_alert(alert_id)`; para origem ambígua, `investigate_case(reference)`. Não repita a chamada para obter campos que ela não devolve. Não troque de entrada após um erro, porque as duas chamam o mesmo coletor.
2. **Leitura, nesta ordem:**
   1. `extraction`: separe campo ausente, vazio, formato não reconhecido e corte da ponte;
   2. `anchor` e `clocks`: base da âncora e se ela é provisória;
   3. `auto_pivots`: relações `linked`, `identifier_match` e `context`, os estados e `continuation`;
   4. `insights`, `hypothesis_checks` e só depois `enrichment`;
   5. `dump_analysis`, `qradar_correlation` e `assessment`.
3. **Fase XDR.** É automática quando o pedido citar XDR Data Explorer, logs ou comandos, ou quando o Workbench trouxer poucos dados:
   1. chame `trend_read_search_resource(source=...)` antes da primeira consulta de cada fonte;
   2. execute as fases de `xdr_followup` com `trend_search_data`, nos parâmetros planejados;
   3. comece pelo endpoint principal do alerta, antes dos ativos de contexto;
   4. ajuste filtro e `select` só para campos do schema vivo ou dos registros.
4. **Continuação:** `search_partition` na janela devolvida; `refine_filters` estreitando filtro, `select`, `top`, `limit` ou janela. Não repita parâmetros idênticos sem progresso, e mantenha um registro cumulativo de fase, parâmetros, estado, registros e pendências.
5. **O que o XDR acrescentou:** compare `evidence_digest.identifiers` com `seeds.identifiers`.
   - Um ator só é uma execução com `processHashId` no mesmo endpoint; sem ele, cada registro é uma observação separada.
   - `image_aggregates` não é execução.
   - Os comandos mantêm cada ocorrência.
6. **Vínculos:**
   - Uma execução comprovada no host não é a execução do alerta enquanto o vínculo por uuid ou identificadores do mesmo registro não estiver demonstrado.
   - Uma detecção próxima no tempo é candidata.
   - Um OAT específico da instância não é descartado por uma busca ampla de registry ou de endpoint que não o retornou; registre cada consulta no seu escopo.
7. **QRadar:** separe leads de offense (índice de endereço), eventos, flows e a pista textual de hostname.
   - Cite search ID, AQL e cláusula temporal.
   - Histórico sem fuso verificado aparece como plano (`run_with_verified_timezone`).
   - Um offset no payload de um equipamento não verifica o fuso do console.
   - Várias interfaces privadas candidatas são verificações separadas, não um mapeamento confirmado.
8. **Dump:** separe intenção, execução, arquivo `.dmp` e alvo. Invocação não comprova arquivo gerado nem sucesso.

## Evidência esperada e falhas

- **Estados:** `complete_in_window`, `partial`, `limited`, `empty`, `unavailable` e `not_started` têm significados distintos (`soc-core.md`).
- **Resultados vazios e não executados:** `network` ou `detections` vazios valem só para a consulta, o filtro e a janela executados. Não indicam falta de cobertura nem inocuidade. Etapa em `budget.phase_log` ou `lead_queries` sem execução é "não executado", nunca "nenhum resultado".
- **Falhas de conexão e de resumo:** com falha de inicialização do QRadar, analise a evidência Trend e declare a correlação não executada. `connection_lifecycle.report_preserved=true` não é falha de coleta. Com `evidence_digest.state=failed`, leia `records[].data`.
- **Identificadores:** `processHashId` pode ter 19 dígitos ou ser negativo; cite-o inteiro.

## Continuação, escalonamento e parada

- Continue partições, refinamentos e o mesmo search ID enquanto puderem mudar a conclusão.
- Delegue ao threat-hunter só uma hipótese delimitada, por exemplo "a conexão X é desta instância?", com contrato e fração do orçamento.
- Pare quando a próxima evidência depender de fonte inacessível ou de autorização externa. Os fatos técnicos são entregues assim mesmo.

## Saída

Entregue nesta ordem:

1. O que aconteceu, com cronologia e proveniência.
2. O que o XDR acrescentou.
3. Correlações confirmadas e candidatas, com critérios.
4. Hipóteses testadas.
5. Conclusão técnica e confiança por achado.
6. Pendências externas e o impacto de cada uma.

Mantenha duas avaliações separadas:

- **Assessment da coleta inicial:** `assessment`, com o seu `scope` e `note_pt`, sem alteração.
- **Parecer do agente:** com as evidências complementares, citadas uma a uma.

Autorização pendente não oculta os fatos e não sustenta Benign True Positive. Nenhuma nota é publicada.

## Tools permitidas

- `investigate_vision_alert`, `investigate_case`, `trend_find_alerts`
- `investigate_vision_event` (somente case-investigator)
- `trend_read_search_resource`, `trend_search_data`
- `qradar_read_aql_resource`, `qradar_validate_aql`, `qradar_start_aql`, `qradar_get_search_status`, `qradar_get_search_results`, `qradar_run_aql`
- `upstream_tools`, `upstream_tool_details`, `upstream_query`

## Referências

`trend-search-conventions.md` (Workbench, Search, OAT, Insights, dump, classificação, descoberta sem ID, coleta parcial e identificadores) e `qradar-aql-conventions.md`.
