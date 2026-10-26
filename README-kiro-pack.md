# SOC Bridge — pacote Kiro

O pacote `.kiro/` (agents, skills, steering e specs) conduz investigações no Kiro sobre o MCP `soc-bridge-readonly`. A ponte expõe 33 tools; a lista atual vem do código (`soc_bridge.capabilities.public_tools`), não de uma lista fixa. Compatibilidade e evidências: [docs/kiro-pack-compatibility.md](docs/kiro-pack-compatibility.md).

## Componentes e responsabilidades

| Componente | Responsabilidade |
| --- | --- |
| `case-investigator` | Investigador principal. Responde por objetivo, plano, prioridades, orçamento, escolha das skills e coleta. Continua as leituras autorizadas, delega tarefas delimitadas e consolida. É o único que grava casos locais e o único que delega. |
| `threat-hunter` | Testa uma hipótese e a alternativa legítima a partir do contrato de passagem. Devolve consultas, resultados, cobertura e implicação. Não refaz a coleta inicial, não grava casos nem arquivos e não delega. |
| `report-writer` | Redige a partir das evidências recebidas ou do caso persistido, inclusive para alerta Workbench sem caso. Não coleta. Separa o assessment inicial do parecer com evidências posteriores. |
| `response-advisor` | Sem tools e sem MCP. Recomenda ações humanas proporcionais a risco, impacto, confiança e reversibilidade; confiança alta, sozinha, não justifica contenção disruptiva. |
| `steering/soc-core.md` (always) | Fonte principal das regras comuns: escopo, leitura versus gravação local, roteamento, autonomia, orçamento e parada, continuidade de jobs, estados de coleta, evidência, contrato de passagem e segurança. |
| Steering de domínio (`auto`) | `case-workflow`, `offense-verification`, `qradar-aql-conventions`, `trend-search-conventions`, `upstream-access` e `investigation-methodology`. São carregados pelos agentes via `resources`; no agente padrão do Kiro, sob demanda. |
| `product.md`, `tech.md` (`fileMatch`) | Contexto de desenvolvimento, carregado só ao trabalhar em `src/`, `tests/` ou `scripts/`. |
| Skills | `offense-investigation`, `trend-alert-investigation`, `exfiltration-assessment`, `epm-uac-investigation`, `web-reputation-fortigate`, `ad-users-scope`, `upstream-tool-access`, `hypothesis-hunting` e `incident-report`. Todas têm as mesmas seções: quando usar e quando não usar, entradas, procedimento, evidência e falhas, continuação e parada, saída e tools permitidas. |
| Specs | Requisitos e registro de desenvolvimento. Não são carregadas nas investigações. A melhoria atual está em `specs/kiro-operational-pack`. |

## Configuração

1. Instale a ponte e configure o MCP como no [guia de instalação](docs/guia-instalacao.md) (ou no [guia WSL](docs/guia-wsl.md)).
2. Atualize juntos o Python instalado e os arquivos `.kiro/` versionados. Não sobrescreva um `mcp.json` funcional nem as suas preferências de `autoApprove`.
3. Reconecte o MCP e abra um chat novo para recarregar schemas, agents, skills e steering.
4. Escolha o agente `case-investigator` para investigações.

## O que é automático (e sob quais condições)

- **Coleta e continuação:** um pedido claro ("investigue a offense X", "investigue o alerta WB-X") autoriza as leituras pertinentes. O agente executa a entrada, continua jobs pelo mesmo search ID, pivôs planejados e fases `xdr_followup`, e entrega sem perguntar se deve prosseguir.
- **Perguntas ao analista:** só para dado indispensável que nenhuma tool obtém ou para decisão externa (autorização, risco, resposta).
- **Delegação:** o `case-investigator` pode delegar para `threat-hunter`, `report-writer` e `response-advisor` pelas entradas `subagent/<nome>`, sempre com o contrato de passagem. Se a delegação não estiver disponível, a etapa é feita no investigador e isso é declarado.
- **Gravação local:** `investigate_offense_case` e `reassess_case` gravam casos em `reports/cases`; `upstream_download` grava em `reports/downloads`. Nada altera QRadar ou Trend, e nenhuma tool fecha, publica, bloqueia, isola ou envia mensagens.

## Como iniciar

No agente `case-investigator`:

> Investigue a offense 12345.

> Investigue o alerta WB-EXEMPLO-0001 e use o XDR Data Explorer.

Os IDs acima são fictícios. Para treinar sem credenciais, use `investigate_demo`.

## Orçamento, continuidade e parada

- O agente declara objetivo e orçamento (chamadas, jobs Ariel, janelas) e registra o consumo.
- Subagentes recebem uma fração explícita e devolvem o consumo; delegar não cria orçamento novo.
- A consulta principal vem antes de qualquer aprofundamento opcional.
- Parâmetros idênticos sem progresso não se repetem.
- A investigação para quando os pivôs pertinentes terminam, quando a próxima evidência depende de fonte inacessível ou de decisão externa, ou quando o orçamento acaba. Nesse caso, a entrega lista o que ficou pendente com os parâmetros para retomar.
- O `budget` interno de cada tool continua valendo.

## Validação

| Nível | Situação |
| --- | --- |
| Estrutura e configuração | `tests/test_kiro_pack_contract.py`: schema 1.4.26, resolução de recursos como na 1.4.26, tools e delegação, compatibilidade skill↔tool, roteamento, contrato de passagem, inclusão de steering e rastreabilidade das specs. `tests/test_pack_consistency.py`: referências a tools, contagens e regras do caso. |
| Integração sintética | Cenários de `tests/fixtures/kiro_scenarios.json` verificáveis pelo código existente (identidade de execuções, IDs maiores que 2^53, estágios de transferência, contadores sem soma, vínculo candidato, vazio limitado à janela), mais os testes da ponte. |
| Kiro real | **Pendente:** ativação de skills e steering `auto`, delegação e qualidade das respostas. Os testes não demonstram comportamento do modelo. |

### Roteiro de validação no Kiro (quando houver créditos)

Use dados de laboratório ou fictícios e anote, para cada pedido, as tools chamadas, as skills ativadas, as delegações e a resposta.

1. **Carregamento.** Abra o `case-investigator` e confira no painel se as skills e o `soc-core.md` aparecem. Peça "quais skills você tem?". Esperado: as sete skills do perfil.
2. **Offense.** "Investigue a offense <ID de laboratório>". Esperado:
   - `investigate_offense_case` uma vez e continuação dos pivôs planejados;
   - nenhuma pergunta "quer que eu prossiga?";
   - entrega com estados das consultas e "O que falta e onde obter".
3. **Workbench + XDR.** "Investigue o alerta <WB de laboratório> e use o XDR Data Explorer". Esperado:
   - `investigate_vision_alert`, depois `trend_read_search_resource` e `trend_search_data` nas fases;
   - entrega na ordem da skill, com o assessment inicial separado.
4. **Delegação.** Peça para testar uma hipótese delimitada. Esperado:
   - chamada `subagent/threat-hunter` com o contrato;
   - retorno com consultas, cobertura e orçamento consumido;
   - nenhuma afirmação de execução sem retorno.
5. **Relatório e resposta.** Peça o relatório (`subagent/report-writer`) e o plano (`subagent/response-advisor`). Esperado: nenhuma coleta pelo redator e nenhuma ação executada pelo consultor.
6. **Falhas.** Com uma fonte desconectada, os fatos já coletados se mantêm e a correlação aparece como não executada.

Se tudo funcionar, marque a tarefa 6 de `specs/kiro-operational-pack/tasks.md` com a data e a versão do Kiro. Se não funcionar, registre o desvio e ajuste o pacote; não ajuste os testes para esconder o desvio.

## Limitações

- A delegação por `subagent/<nome>` foi derivada do código da IDE 1.4.26 e não aparece na documentação. A execução real não foi validada.
- Não confirmei se `disclose_context` precisa estar listada explicitamente. Ela está listada por segurança.
- O orçamento compartilhado é uma regra do pacote, não um limite imposto pela ponte entre chamadas (veja `BRIDGE-BACKLOG.md`).
- O Kiro CLI não foi verificado.
- Dados reais nunca entram no pacote: exemplos e testes usam valores fictícios.
