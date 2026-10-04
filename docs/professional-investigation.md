# Investigação profissional de offense ("investigue a offense X")

`investigate_offense_case(offense_id)` conduz a investigação inteira e grava um caso local retomável. O fluxo:

1. **Caso e escopo:** identifica o caso (`offense-<id>`), o escopo autorizado (pivôs de leitura necessários, dentro dos limites da ponte) e as fontes disponíveis, e grava o caso antes de qualquer consulta. Um `case_id` de outra offense é recusado.
2. **Metadados:** faz um snapshot dos metadados da offense, com o horário da coleta.
3. **Registros do gatilho:** coleta os registros ligados à offense (INOFFENSE, flows, censo, regras, janelas Linux, lockout, host, cadeia de processos, PowerShell, integridade e contexto QRadar). Jobs Ariel já conhecidos da mesma offense e da mesma consulta são retomados no cursor salvo, sem recriar a busca. O caso é gravado antes de criar cada job, ao receber o search ID e após cada página.
4. **Comportamento × rótulo:** separa o comportamento observado do nome da regra ou da offense. O comportamento vem só dos registros.
5. **Hipóteses concorrentes:** maliciosa, autorizada/operacional, erro de detecção e erro de atribuição, cada uma com testes executados e a evidência que a confirmaria.
6. **Próximos pivôs:** cada pivô registra hipótese, evidência motivadora, fonte, filtros, janela, custo, resultados que apoiariam ou contradiriam e critério de parada. A prioridade é:
   - registros do gatilho;
   - identificadores fortes;
   - processo/sessão;
   - contexto.

   Falha determinística (`requires_resolution`) não é repetida. Falha transitória (`retryable`) tem uma nova tentativa. Pivô já executado com o mesmo motivo é `skipped_repeat`.
7. **Correlação:** usa os alertas Trend relacionados, com profundidade de alerta (até dois, orçamento compartilhado, sem recursão). Os alertas são encontrados por IP e horário da offense; isso os torna candidatos, não o mesmo incidente. O vínculo só é `demonstrated` quando um registro de processo da offense (consulta INOFFENSE) e o alerta compartilham hash completo ou linha de comando exata no mesmo host. Os resultados ficam gravados no caso. Cada registro fica no nível de vínculo demonstrado:
   - associado à offense;
   - vinculado ao alerta;
   - identificador demonstrado;
   - candidato;
   - contexto.
8. **Avaliação:** examina a cobertura e as contradições. Cada disposição e cada motivo do catálogo real tem requisitos próprios.
9. **Entrega:** decisão, confiança justificada sem pontuação numérica, pendências, próxima ação e nota em português para revisão humana.

## Decisão e fechamento

- **Disposições:** atividade maliciosa confirmada; atividade legítima/autorizada que disparou a detecção; erro de detecção comprovado; ou inconclusiva. Uma decisão administrativa explícita é avaliada à parte.
- **Relação com o catálogo:** as disposições não equivalem automaticamente a motivos do catálogo local. `relation_to_catalog` explica a relação.
- **Motivos customizados:** só são avaliados com definição local (`SOC_BRIDGE_CLOSING_REASONS`, JSON com `requires` e `definition`).
- **Escopo das confirmações:** autorização, malícia confirmada e erro de detecção exigem escopo, além de fonte e referência:
  - atividade, entidades e janela com fuso explícito (`Z` ou `-03:00`); horário sem fuso é recusado, nunca lido como UTC;
  - `process_execution`: `processes` obrigatório (nome ou caminho completo), `command_lines` e `parent_processes` opcionais;
  - `script_execution`: `script_block_ids` obrigatório.

  Cada instância observada é avaliada por entidade, processo/cadeia e janela: autorizar `powershell.exe` no host-a não cobre processos no host-b nem outros comandos no host-a. As instâncias não cobertas ficam listadas (`uncovered_instances`). Uma autorização genérica de host, conta ou aplicação não cobre toda atividade observada. Instância fora da janela do registro vira contradição não resolvida.
- **Alertas Trend:** um alerta True Positive com vínculo demonstrado confirma atividade maliciosa e contradiz as disposições benignas. Com relação só por IP/horário (`candidate`), ele não confirma malícia nem corrobora a coleta QRadar; vira contradição não resolvida contra as disposições benignas e gera o pivô `verify_alert_link`.
- **Reavaliação:** usa a coleta QRadar e os resultados Trend gravados; uma reavaliação nunca perde evidência de malícia por não consultar a Trend de novo.
- **Confiança:**

  | Nível | Critério |
  | --- | --- |
  | alta | requisitos demonstrados pela ponte e corroborados por segunda fonte que descreve comprovadamente a mesma atividade |
  | moderada | sustentada, mas dependente de registro externo ou de uma única fonte |
  | baixa | nada sustentado |

## Exemplos de pedidos no Kiro

- Listar: "Liste as offenses abertas por prioridade" (`qradar_list_offenses`) ou "Quais casos locais existem?" (`list_cases`).
- Investigar: "Investigue a offense 12345."
- Continuar: "Continue o caso offense-12345" (mesmo `case_id`, retoma jobs e pivôs `planned`).
- Reavaliar: "Reavalie o caso offense-12345 com a mudança CHG-1234, que autoriza a execução de backup.exe no host ws-01 entre 14h e 16h UTC" (`reassess_case` com `scope` incluindo `processes`).
- Diagnosticar: "Rode o diagnóstico da ponte" (`bridge_diagnostics`) ou, no terminal, `soc-bridge doctor`.

## Limites

- **Validação:** testado somente com dados sintéticos; nenhuma execução contra QRadar ou Vision One reais.
- **Fontes fora da ponte:** autorização, mudanças, testes da CRE, remediação e inventários exigem registros citados pelo analista.
- **Pivôs propostos:** particionar consultas, investigar alertas não aprofundados e verificar o vínculo de um alerta candidato são propostos, não executados automaticamente.
- **Vínculo Trend:** depende de registros de criação de processo (Sysmon 1/4688 com hash ou linha de comando) nos eventos da offense. Sem eles, alertas relacionados permanecem candidatos.
- **Armazenamento:** veja [casos locais](case-store.md).
