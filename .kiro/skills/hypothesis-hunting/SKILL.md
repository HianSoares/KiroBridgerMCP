---
name: hypothesis-hunting
description: "Testar uma hipótese específica de comportamento adversário e sua alternativa legítima com entidades, janela e evidências recebidas: consultas AQL e Trend Search focadas, cobertura e implicação para a hipótese, sem refazer a coleta inicial."
---

# Hunting por hipótese

Regras comuns: `soc-core.md`.

## Quando usar

- O case-investigator delegou uma pergunta discriminante.
- O analista quer testar uma hipótese com uma entidade, um filtro ou uma referência concreta.

## Quando não usar

- Sem ponto de partida concreto: explique que a ponte não faz varredura global e peça uma entidade, um evento ou um filtro.
- Para decidir o caso ou fechar a offense: isso é do case-investigator.

## Entradas mínimas e descoberta automática

- **Delegado:** use o contrato de passagem de `soc-core.md` (pergunta, entidades com fonte, janela, referências, fatos, vínculos candidatos, contradições, cobertura, pendências e orçamento). Não refaça a coleta inicial que o contrato já resume.
- **Direto:** com uma referência, use a entrada compatível uma vez. Com host, hash ou filtro, vá direto ao Search (`trend_read_search_resource` e depois `trend_search_data`) sem exigir ID WB.

## Procedimento

1. **Hipótese falsificável:** ativo, comportamento, janela e fuso, resultado esperado e explicação legítima.
2. **Previsões:** o que cada hipótese prevê nas fontes e qual consulta separa uma da outra.
3. **Consultas focadas, dentro da fração de orçamento recebida:**
   - AQL pelas tools `qradar_*`: leia os resources e os campos reais, e mantenha o search ID;
   - Search por fonte, filtro e janela;
   - `upstream_query` para dados não coletados pelas entradas curadas.
4. **Comparação:** confronte observações com previsões por papel e instância. PID, caminho, ferramenta dual-use ou ausência numa busca parcial não são veredito.
5. **ATT&CK:** como hipótese, nunca como checklist, respeitando direção e fase.
   - Varredura de origem externa → T1595.
   - Varredura a partir de ativo interno → T1046, que também pode ser inventário legítimo.
   - Falhas repetidas de login → T1110, com a sub-técnica pelo padrão observado; T1078 só com login bem-sucedido atribuído à mesma origem.
   - Transferência → exfiltration-assessment.
   - O nome da regra ou do modelo não confirma a técnica.

| Hipótese | O que a ponte pode mostrar | O que exige fonte externa |
| --- | --- | --- |
| Varredura externa (T1595) | Ariel: muitos destinos/portas distintos para a mesma origem na amostra | se um `accept` virou sessão de aplicação |
| Brute force/spraying (T1110.00x) | Ariel: username e falha/sucesso por origem | identidade e autoridade das contas |
| Escalação local (T1078.003/T1548.003) | Ariel: sequência PAM e payload por AQL | autorização da sessão |
| Exfiltração (T1567.002/T1048) | Trend Search: comando, instância, conexões atribuídas e contadores só com semântica verificada; QRadar flows por tupla e janela | conclusão da operação, autorização, DNS/proxy |
| Web/C2 (T1071.001, T1189, T1566.002) | FortiGate `action`/`subtype`/`policyid`; Trend `act` | conteúdo entregue, processo requisitante |

## Evidência esperada e falhas

- Consultas vazias, parciais ou não executadas seguem os estados de `soc-core.md`.
- Campo ausente, permissão ou retenção insuficiente continuam lacunas, nunca resultado simulado.

## Continuação, escalonamento e parada

- Pare ao responder a pergunta discriminante, ao esgotar a fração de orçamento ou quando a próxima evidência exigir fonte externa.
- Não amplie o escopo para "todo o ambiente".
- Não crie nem reavalie casos; proponha os pivôs ao case-investigator.
- A correlação com campos copiados de um View event (`investigate_vision_event`) é do case-investigator; registre-a como próximo passo.

## Saída

Para o investigador:

- hipótese e alternativa;
- consultas executadas (parâmetros, estado, search ID ou janela);
- resultados com referências;
- cobertura;
- implicação para a hipótese (apoia, enfraquece ou inconclusiva), com confiança e motivo;
- orçamento consumido;
- pendências.

## Tools permitidas

- `trend_read_search_resource`, `trend_search_data`
- `qradar_read_aql_resource`, `qradar_validate_aql`, `qradar_start_aql`, `qradar_get_search_status`, `qradar_get_search_results`, `qradar_run_aql`
- `upstream_tools`, `upstream_tool_details`, `upstream_query`
- `investigate_case`, `investigate_offense`, `investigate_vision_alert`, `investigate_epm_uac`, `investigate_web_reputation` (só quando usado diretamente, sem contrato)
- `list_cases`, `get_case`

## Referências

`qradar-aql-conventions.md`, `trend-search-conventions.md`, `upstream-access.md` e `investigation-methodology.md`.
