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
7. **Correlação:** usa os alertas Trend relacionados, com profundidade de alerta (até dois, orçamento compartilhado, sem recursão). Os alertas são encontrados por IP e horário da offense; isso os torna candidatos, não o mesmo incidente. O vínculo só é `demonstrated` quando o processo QRadar da offense (consulta INOFFENSE) é a própria instância Trend que sustenta o veredito malicioso ou seu pai/filho demonstrado (detalhes em "Alertas Trend"). As tentativas e os fatos ficam gravados no caso, por alerta. Cada registro fica no nível de vínculo demonstrado:
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
  - `process_execution`: `processes` (nome ou caminho completo) e ao menos um descritor de comportamento — `command_lines` (texto exato), `script_paths`, `artifact_hashes` (não aceito sozinho para intérpretes como PowerShell, cmd, Python e bash), `process_instances` (ProcessGuid) ou `breadth: "any_behavior_of_named_processes"` com `breadth_basis` citando o registro; `parent_processes` opcional;
  - `privilege_use`: `commands` (comandos sudo exatos), `identity_switch: true` (su) ou `breadth: "any_privileged_command_of_named_accounts"` com `breadth_basis`; `run_as` opcional;
  - `script_execution`: `script_block_ids` obrigatório.

  Cada instância observada é avaliada por entidade, comportamento/cadeia e janela: autorizar o backup `-File C:\ops\backup.ps1` no host-a não cobre processos no host-b, outro script, o mesmo script com argumentos adicionais nem um `-EncodedCommand` no host-a; autorizar `systemctl status oracle-db` via sudo não cobre `/bin/bash` da mesma conta. Linhas de comando são comparadas como texto original (maiúsculas e espaços contam). As instâncias não cobertas ficam listadas (`uncovered_instances`); as não avaliadas aparecem em `instances_not_evaluated` com quantidade, motivo e ação, e nunca contam como cobertas. Autorização abrangente só vale quando declarada pelo registro externo e aparece no relatório e na nota. Instância fora da janela do registro vira contradição não resolvida.
- **Alertas Trend:** a comparação usa os registros Trend que sustentam o veredito (instância executada com hash de veredito malicioso), não os observables do alerta.
  - **Hashes:** comparados por algoritmo (sha256, sha1, md5) e por papel/artefato, com a fonte. Cada comparação é `equal`, `conflict` (digests completos do mesmo algoritmo diferentes), `incomplete` (cortado ou inválido), `not_comparable` (algoritmos diferentes) ou `absent`. Um conflito, assim como PIDs, linhas de comando ou caminhos conhecidos diferentes, impede a identidade mesmo que os outros sinais coincidam e aparece como contradição `link_conflict` no relatório e na nota; ele não prova benignidade.
  - **Mesma execução:** mesmo host, sem conflito, horários de execução compatíveis (±2 s; Sysmon `UtcTime` ou horário do dispositivo), e hash completo igual com PID igual ou linha de comando idêntica — ou, sem hash comparável, caminho idêntico com PID igual.
  - **Cadeia:** por identidade de instância, não por PID. Pai: o processo QRadar é a instância pai registrada pela Trend (para um objeto recém-lançado, o pai é o ator do registro, não o pai do ator). Filho: o `ParentProcessGuid` do processo QRadar aponta para o registro QRadar, no mesmo endpoint, da instância maliciosa; esse registro pode vir do contexto do host e é rotulado como não INOFFENSE. PID reutilizado, PID do pai sem GUID ou GUID de outro endpoint deixam o vínculo candidato, mesmo que o pai legítimo tenha ficado ativo por horas. Identificadores de instância da Trend e GUIDs do Sysmon não são comparados entre si.
  - **Candidato:** hash de arquivo isolado, hash do processo pai ou de objeto, hashes de um endpoint com o nome de outro, ou o horário de criação do alerta não demonstram vínculo; o alerta continua `candidate`, não confirma malícia nem corrobora, vira contradição não resolvida contra as disposições benignas e gera o pivô `verify_alert_link`.
- **Revisão de fatos:** uma nova coleta inconclusiva, timeout ou falha não apaga fatos anteriores. Fatos só são refutados por evidência pertinente (nova avaliação sustentada como False Positive ou Benign True Positive, ou registro `trend_finding_refuted` do analista), com fundamento, fonte e fatos substituídos registrados.
  - **Só o vínculo:** refutar apenas um fato `qradar_link` derruba a associação com a offense e mantém o True Positive do alerta; outros vínculos independentes continuam valendo.
  - **Mesma evidência:** reler, recalcular ou recoletar os mesmos registros (outra execução ou outro job Ariel) não desfaz a refutação; a coincidência aparece como contradição `refuted_link_still_matched`.
  - **Identidade, conteúdo e proveniência:** cada fato separa o ID, o conteúdo probatório (hashes completos, PID, horário de início, imagem, linha de comando completa, instância QRadar, GUIDs da cadeia) e a proveniência (execuções, jobs, linhas, fontes, metadados, valores incompletos).
  - **Revisão da refutação:** nenhuma observação nova restabelece um fato refutado sozinha — nem a mesma evidência, nem metadados ou hashes incompletos, nem identificadores alterados; a observação fica registrada em `observations_after_refutation` para revisão, e só um registro `trend_finding_reinstated` fundamentado restabelece o fato. Vínculos independentes (outra instância ou outro elo da cadeia) são fatos novos.
  - **Vínculo contradito:** quando evidência atual contradiz os identificadores de um vínculo gravado (hash completo, PID ou horário da instância vinculada), ele fica `contradicted`, com histórico e contradição `link_contradicted`, e deixa de sustentar a conclusão até ser demonstrado de novo sem conflito. Timeout, coleta inconclusiva ou Trend não solicitada não contradizem nada.
  - **Vínculos antigos:** vínculos gravados por critérios anteriores que não se confirmam com os atuais ficam `needs_revalidation`, preservados no histórico e fora da decisão.
  - **Identidade e contradições:** a ponte verifica todos os registros atuais da instância QRadar vinculada, inclusive horários fora da tolerância de descoberta. Um registro compatível não supera outro conflitante do mesmo host e GUID. UUID de evento Trend identifica uma observação, não uma execução: outras observações da mesma instância reutilizam o fato e sua refutação. A identidade usa endpoint e identificador de instância Trend; sem esse identificador, usa PID e início exato da execução. Identificadores Trend e GUIDs Sysmon permanecem em namespaces distintos. IDs antigos de fatos e referências dos registros ficam preservados.
- **Reavaliação:** usa a coleta QRadar e os fatos Trend gravados, não apenas o último relatório.
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
- **Vínculo Trend:** depende de registros de criação de processo (Sysmon 1/4688 com PID ou linha de comando e horário) nos eventos da offense e de registros Trend com a instância executada (PID, horário de início, hash com veredito). Sem eles, alertas relacionados permanecem candidatos.
- **Scripts:** `script_paths` reconhece as formas comuns de chamada (`-File`, primeiro argumento); sintaxes incomuns não são cobertas e exigem a linha de comando exata.
- **Limites de análise:** até 5000 criações de processo, script blocks e comandos sudo/su por classe; acima disso, as instâncias excedentes são declaradas não avaliadas.
- **Armazenamento:** veja [casos locais](case-store.md).
