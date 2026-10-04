---
inclusion: always
---

# Fluxo profissional de caso ("investigue a offense X")

1. **Identificar.** Chame `investigate_offense_case(offense_id)`. O pedido autoriza os pivôs de leitura necessários dentro dos limites da ponte; não peça permissão para cada consulta nem pergunte dados que as tools obtêm.
2. **Ler o caso.** Use `decision`, `observed_behavior` (comportamento ≠ nome da regra), `decisive_evidence` (com referências de consulta/search ID/linha ou alerta), `hypotheses`, `contradictions`, `coverage`, `confidence`, `next_action` e `note_pt`.
3. **Continuar.** Pivôs `planned` (retomar o mesmo search ID, iniciar consulta que nunca existiu) são executados chamando `investigate_offense_case` com o mesmo `case_id`. O caso é gravado antes da coleta, antes de criar cada job, ao receber o search ID e após cada página; depois de interrupção ou cancelamento, chame de novo com o mesmo `case_id` e a ponte continua do cursor salvo. `requires_resolution` (criação incerta, permissão, rejeição determinística) não é repetido: explique a causa. `rerun_queries` só com motivo explícito (job expirado ou criação incerta verificada). `skipped_repeat` exige razão nova.
   - Um `case_id` pertence a uma offense: a ponte recusa usá-lo para outra. Para outra offense, use outro `case_id` (padrão `offense-<id>`).
4. **Pedir ao analista somente o indispensável.** Itens `requires_analyst` dizem o dado, a fonte e a validação (ex.: testes da CRE no editor de regras; registro de autorização). Não invente alternativa equivalente.
5. **Reavaliar.** Com registros do analista, chame `reassess_case(case_id, confirmations=[...])`. A reavaliação reutiliza a coleta QRadar e os resultados Trend gravados no caso, sem consultas novas.
   - Autorização, malícia confirmada e erro de detecção precisam de `scope` além de fonte e referência: atividade, entidades e janela com fuso explícito (`Z` ou `-03:00`; horário sem fuso é recusado). Para `process_execution`, informe `processes` (e, se o registro restringir, `command_lines` e `parent_processes`); para `script_execution`, `script_block_ids`.
   - Cada instância observada é avaliada separadamente: autorizar `powershell.exe` em host-a não cobre processos em host-b nem outros comandos em host-a. Leia `uncovered_instances` e peça registro somente para o que ficou descoberto.
   - Confirmações ficam marcadas como externas e não verificadas.
6. **Decidir.** Recomende disposição e motivo somente quando `ready_to_close`/`disposition` estiverem sustentados; caso contrário, diga o requisito pendente e a próxima verificação. Contradição não resolvida bloqueia as conclusões que dependem dela, sem impedir o relato de fatos confirmados nem a avaliação separada de uma decisão administrativa.
   - Alerta Trend True Positive só confirma malícia da offense com `link = demonstrated` (hash completo ou linha de comando exata compartilhados com um registro de processo da offense, no mesmo host). Relação só por IP/horário é `candidate`: não confirma malícia, não corrobora e bloqueia fechamento benigno até o pivô `verify_alert_link` demonstrar ou excluir o vínculo.
7. **Nunca executar.** A ponte e o Kiro não fecham offenses, não publicam notas, não alteram regras e não executam contenção.

Casos ficam em `reports/cases` (fora do Git), com retenção e exclusão documentadas em `docs/case-store.md`. `list_cases` lista; `get_case` lê a revisão atual; revisões anteriores são preservadas.
