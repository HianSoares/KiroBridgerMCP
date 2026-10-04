---
inclusion: always
---

# Fluxo profissional de caso ("investigue a offense X")

1. **Identificar.** Chame `investigate_offense_case(offense_id)`. O pedido autoriza os pivôs de leitura necessários dentro dos limites da ponte; não peça permissão para cada consulta nem pergunte dados que as tools obtêm.
2. **Ler o caso.** Use `decision`, `observed_behavior` (comportamento ≠ nome da regra), `decisive_evidence` (com referências de consulta/search ID/linha ou alerta), `hypotheses`, `contradictions`, `coverage`, `confidence`, `next_action` e `note_pt`.
3. **Continuar.** Pivôs `planned` (retomar o mesmo search ID, iniciar consulta que nunca existiu) são executados chamando `investigate_offense_case` com o mesmo `case_id`. `requires_resolution` (criação incerta, permissão, rejeição determinística) não é repetido: explique a causa. `rerun_queries` só com motivo explícito (job expirado ou criação incerta verificada). `skipped_repeat` exige razão nova.
4. **Pedir ao analista somente o indispensável.** Itens `requires_analyst` dizem o dado, a fonte e a validação (ex.: testes da CRE no editor de regras; registro de autorização). Não invente alternativa equivalente.
5. **Reavaliar.** Com registros do analista, chame `reassess_case(case_id, confirmations=[...])`. Autorização, malícia confirmada e erro de detecção precisam de `scope` (atividade, entidades, janela) além de fonte e referência; autorização genérica de host/conta/aplicação não cobre toda atividade observada. Confirmações ficam marcadas como externas e não verificadas.
6. **Decidir.** Recomende disposição e motivo somente quando `ready_to_close`/`disposition` estiverem sustentados; caso contrário, diga o requisito pendente e a próxima verificação. Contradição não resolvida bloqueia as conclusões que dependem dela, sem impedir o relato de fatos confirmados nem a avaliação separada de uma decisão administrativa.
7. **Nunca executar.** A ponte e o Kiro não fecham offenses, não publicam notas, não alteram regras e não executam contenção.

Casos ficam em `reports/cases` (fora do Git), com retenção e exclusão documentadas em `docs/case-store.md`. `list_cases` lista; `get_case` lê a revisão atual; revisões anteriores são preservadas.
