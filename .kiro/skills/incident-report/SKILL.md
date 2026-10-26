---
name: incident-report
description: "Redigir relatório de investigação SOC rastreável a partir de evidências recebidas ou do caso persistido (offense ou Workbench), com proveniência, confiança por achado, lacunas e assessment inicial separado do parecer com evidências posteriores, sem coletar nem fabricar telemetria."
---

# Relatório de incidente

Regras comuns: `soc-core.md`.

## Quando usar

- O case-investigator delegou a redação com o contrato de passagem.
- O analista pede um relatório de um caso persistido (`get_case`) ou de um resultado da ponte que ele forneceu.

## Quando não usar

- Para coletar mais dados: devolva as lacunas ao case-investigator.
- Para recomendar contenção: isso é do response-advisor.

## Entradas mínimas e descoberta automática

- **Offense:** o `case_id` (ou `list_cases` para encontrá-lo), e depois `get_case(case_id)` na revisão mais recente.
- **Workbench sem caso persistido:** só as evidências do contrato ou do relatório colado (alerta, `assessment` com `scope`, consultas, `evidence_digest`, correlações). Não existe `case_id` nesse caso; não o peça.
- **Demonstração:** `investigate_demo()`, marcada como fabricada.

## Procedimento

1. **Origem:** fonte, tool, parâmetros, horário de geração, referência e se a coleta terminou. Coleta parcial não vira relatório de ausência.
2. **Consultas executadas, por fonte:** filtro ou pivô, janela e fuso, estado, linhas, página e cap. Uma fonte não consultada aparece como "não executada"; falha nunca vira zero resultados.
3. **Fatos:** `confirmado`, `candidato` ou `não verificado`, cada um com fonte, horário e identificador inteiro. Cronologia só com timestamps confiáveis; correlação temporal não é causalidade.
4. **Hipóteses concorrentes:** os testes que as confirmariam ou refutariam, impacto observado versus potencial, ATT&CK só para o comportamento sustentado, e confiança por achado com o critério limitante. Causa raiz só até o último elo comprovado.
5. **Duas avaliações separadas:**
   - **Assessment da coleta inicial:** o `assessment` da tool, com o seu `scope`, sem reescrever;
   - **Parecer com evidências complementares:** cada evidência posterior citada.
6. **"O que falta e onde obter":** `Dado faltante | Por que a ponte não trouxe | Onde e como verificar | Status`.
7. **Recomendações:** contenção, erradicação, recuperação e detecção, sempre como ações humanas fora do Kiro.
8. **Decisão recomendada:**
   - motivo do catálogo real (nome e ID) só quando sustentado; caso contrário, manter pendente com o impedimento;
   - nota sugerida em pt-BR, não publicada;
   - `False-Positive, Tuned` exige tuning aplicado e verificado;
   - CLOSED e comportamento compatível não substituem a justificativa.

## Evidência esperada e falhas

- `final_benign_verdict_permitted=false` não impede relatar fatos positivos comprovados.
- Autorização pendente não oculta os fatos técnicos e não sustenta classificação benigna.
- Dados reais destinados a um portfólio público são omitidos ou mascarados por completo.

## Continuação, escalonamento e parada

- Não colete. Se faltar evidência decisiva, liste-a como pendência e indique o case-investigator.
- Não peça uma nova coleta esperando colunas novas sem um pivô planejado.

## Saída

1. Resumo executivo.
2. Gatilho e escopo, com fuso.
3. Tabela de consultas.
4. Cronologia UTC com fonte por linha.
5. Fatos e vínculos.
6. Hipóteses.
7. Assessment inicial e parecer complementar.
8. Lacunas.
9. Recomendações humanas.
10. Decisão e nota.

## Tools permitidas

- `list_cases`, `get_case`, `investigate_demo`

## Referências

`case-workflow.md` (campos do caso) e `offense-verification.md` (motivos de fechamento e nota).
