# Cobertura investigativa: leituras, prioridades, decisão e fechamento

Este guia descreve o que a ponte lê nos MCPs oficiais, quando cada leitura roda e como o relatório chega a uma decisão. A lista completa, tool a tool, está na [matriz de cobertura](coverage-matrix.md), gerada a partir dos handlers oficiais:

- IBM QRadar MCP `f51c007`: 83 tools, 51 GET, **34 integradas**.
- Trend Vision One MCP `2d13740`: 349 tools, 211 de leitura, **39 integradas**.

Uma tool presente no catálogo pode não existir na instalação conectada (toggles, toolsets, licença ou permissão). A ponte verifica isso em tempo de execução e informa `tool_absent`, que é diferente de resultado vazio. Nenhuma investigação chama todas as tools: cada leitura tem um gatilho, como uma entidade do caso, uma hipótese ou evidência já coletada.

## Fases e orçamento

As investigações de alerta seguem quatro fases sob um prazo monotônico compartilhado, com limites de chamadas, registros, partições e tamanho de resposta:

1. **Coleta principal.** Detalhe do alerta e Insights que referenciam o alerta. Depois vem o Search pelos identificadores mais discriminantes: hash e caminho no endpoint do alerta, em seguida as instâncias de processo encontradas. Só depois vêm OAT e a atividade ampla do endpoint.
2. **Hipóteses.** Análise de ferramenta de dump e consulta do hash nas listas de Suspicious Objects e Exceptions. Inclui também resultados de sandbox já existentes e seus objetos, tarefas de resposta do endpoint e seus resultados, identidade e disponibilidade de telemetria.
3. **Correlação.** Índices de endereço do QRadar e consultas Ariel com orçamento próprio.
4. **Enriquecimento opcional.** Notas, inventário (endpoint e EIQS), CREM (risco e CVEs), modelos e filtros DMM, cases e seus conteúdos, auditoria, e-mail, rede, container e mobile.

Correlação, hipóteses e enriquecimento têm reserva própria. Leituras amplas não podem consumir o que a correlação precisa. Uma etapa sem orçamento aparece como `not_started`/`not_executed`, com motivo, e nunca como vazia. `budget.phase_log` registra a ordem real.

## Valores preservados

As respostas opcionais mantêm valores, identificadores e relações dentro de limites de profundidade, itens, chaves e tamanho. O campo `preservation` informa o que foi cortado, e `items_omitted` informa os itens além do limite. A versão anterior reduzia os Insights a nomes de campos. Agora entidades, indicadores e highlights chegam com valores.

## Insights

O relatório só considera um insight relacionado quando o conteúdo dele traz o ID do alerta (critério e caminho JSON informados). Sem ID de insight no alerta, a ponte lista os insights criados na janela do alerta (filtro `createdDateTime` documentado no handler) e confere até três. Um ID Workbench nunca é usado como ID de insight.

Entidades e indicadores do insight entram como **candidatos**: estão relacionados ao insight, mas não foram demonstrados para o alerta. São usados nos leads QRadar e nas consultas de hash, com rótulo próprio.

## Paginação

A paginação segue o que o handler oficial realmente encaminha:

| Fonte | Mecanismo |
| --- | --- |
| Search | Partições de tempo; não há cursor. |
| OAT | `nextBatchToken`. |
| Inventário de endpoints e dispositivos CREM | `skipToken`, extraído do `nextLink` da própria API. |
| Notas do Workbench | Só a primeira página: o `skipToken` é declarado, mas não encaminhado. |
| QRadar | Cabeçalho Range por offset/limit. |

Quando o handler não aceita continuação, o resultado diz isso e indica um filtro ou uma janela mais estreita. Resultados parciais, filtros, janelas, search IDs, cursores e a página que falhou são preservados.

## Contexto QRadar

`qradar_verify_offense` (só QRadar) lê o contexto ligado a identificadores da offense:

- **Notas:** dado não confiável.
- **Tipo da offense.**
- **Hierarquia de rede:** a correspondência de CIDR é calculada localmente.
- **Assets do IP:** o IP é conferido localmente; é um snapshot.
- **Log sources e tipos.**
- **QIDs e categorias dos eventos coletados.**

`qradar_read_context` faz leituras pedidas pelo investigador, com argumentos validados:

- **Por nome:** regras, building blocks, buscas salvas, log sources e coleções de referência. Os nomes são comparados localmente, sobre páginas limitadas.
- **Por ID:** QID, mapeamentos DSM, building block, log source e caso forense.
- **Valor exato em map/table:** até 500 elementos.
- **Outros:** vulnerabilidades QVM por busca salva, geolocalização de IP público e asset de um IP.

Limites dessas leituras:

- Metadados de regra não são os testes completos da CRE.
- Reference sets não têm leitura de entradas no upstream.
- Uma entrada de allowlist nunca encerra um caso sozinha.

As mutações do catálogo QRadar ficam bloqueadas: fechamento, notas, atribuição, reference data, configuração, DSM/QID, exclusão de buscas e lookups DNS/WHOIS externos. A criação de buscas Ariel continua permitida.

## Offense → alertas Trend

`investigate_offense` aprofunda até dois alertas relacionados pelo mesmo fluxo de alerta (`deepened_alerts`). O critério é: alerta criado no intervalo da offense (±1 h) e IP da offense em uma entidade do impact scope. As garantias são:

- orçamento dividido entre os alertas;
- cache de leituras compartilhado, com o detalhe do alerta reutilizado;
- nenhuma consulta QRadar dentro dos alertas aprofundados, o que impede a recursão.

`qradar_verify_offense` continua só QRadar. `trend_find_alerts` continua independente do QRadar.

## Decisão por conclusão

O relatório usa um vocabulário fixo de status:

| Status | Significado |
| --- | --- |
| confirmado | Demonstrado pelos registros ou por registro citado pelo analista. |
| compatível | Consistente, mas não demonstra. |
| candidato | Vínculo possível, não demonstrado. |
| não verificado | Não checado ou fora do alcance das fontes. |
| não retornou nas consultas executadas | Não é prova de ausência. |
| não executado | A leitura não rodou; nada se conclui. |

Cada conclusão tem requisitos próprios (`decision_matrix`), e uma lacuna só bloqueia as conclusões que precisam dela:

- **True Positive:** atividade de processo observada no registro vinculado ao alerta e resultado de sandbox de alto risco com o hash completo igual ao do processo. O processo deve ter caminho, PID, instância e horário de início observáveis. Um objeto só conta como processo recém-iniciado quando seu início coincide com o evento (até 5 s). Hash de pai, arquivo detectado ou objeto acessado sem essa evidência não comprova execução. O digest precisa aparecer no resultado retornado; o filtro enviado e o prefixo de 12 caracteres da chave do relatório não bastam.
- **Benign True Positive:** execução observada e fonte de autorização.
- **False Positive:** evidência positiva de que o comportamento não ocorreu, com cobertura completa.

Não há pontuação numérica na decisão. A confiança segue os requisitos: requisitos atendidos, âncora confiável e cobertura completa resultam em confiança alta. O rank de alertas na offense é só ordenação, com pesos descritos em `rank_criteria`.

A execução de um artefato identificado como malicioso não confirma automaticamente todas as ações do nome do alerta: dumping de credenciais, escrita de arquivo e exfiltração continuam exigindo suas evidências próprias.

Na fase de correlação, Ariel é consultado antes da enumeração de leads de offenses. Consultas de contexto mantêm as linhas anteriores e a posição da página não lida em caso de orçamento/timeout. Comparações de reference data usam a resposta original antes dos cortes de exibição. Resposta inesperada não é resultado vazio, e uma primeira página que atinge o limite não é declarada exaustiva.

## Fechamento no QRadar

`closure_assessment` avalia cada motivo do catálogo vivo:

| Motivo | Requisitos |
| --- | --- |
| Non-Issue | Autorização e coleta relevante completa. |
| False-Positive, Tuned | Erro de detecção, revisão da CRE, tuning e coleta completa. |
| Duplicate | Offense primária referenciada. |
| Policy Violation | Política confirmada e coleta relevante completa. |
| Resolved | Remediação verificada. |

Motivos personalizados exigem definição local.

`qradar_assess_closure` repete a coleta e aceita `confirmations` com registros que a ponte não consegue ler: autorização, offense primária, remediação e similares. Esses registros ficam marcados como fornecidos pelo analista. A cobertura da coleta não pode ser confirmada manualmente.

Um motivo só é recomendado quando todos os requisitos estão atendidos e ele existe no catálogo; nenhum ID é inventado. A nota em português cita evidências, janela, consultas, justificativa e pendências. Nada é fechado nem publicado.

Consultas obrigatórias ausentes também impedem confirmar a coleta, mesmo que as demais tenham terminado. `blocking_requirements` contém os impedimentos do motivo avaliado; `other_unresolved_requirements` preserva as limitações que não o bloqueiam. Por exemplo, uma duplicata citada pelo analista pode ser recomendada com buscas ainda pendentes, que continuam explícitas na nota.

## Atualização

A ponte agora carrega o toolset `eiqs` da Trend. Uma imagem Docker antiga em cache que não conheça esse toolset falha ao iniciar com o erro `unknown toolset`. Nesse caso, rode `docker pull ghcr.io/trendmicro/vision-one-mcp-server`.

Depois de atualizar o código e o pacote, reconecte `soc-bridge-readonly` no Kiro e abra um chat novo, para carregar as 20 tools e as instruções atualizadas.

## O que foi e o que não foi validado

Os testes usam apenas dados sintéticos. Eles cobrem:

- preservação de Insights e truncamento;
- gatilhos e argumentos das novas leituras;
- estados de tool ausente, permissão, licença e formato inesperado;
- paginação real, falta de suporte e retomada;
- reserva de orçamento;
- aprofundamento sem recursão;
- suficiência por conclusão;
- bloqueio de mutações;
- schemas e diagnóstico WSL.

Não houve execução contra QRadar ou Vision One reais. A sintaxe de alguns filtros server-side ainda precisa de confirmação no ambiente real:

- filtro de assets por IP;
- `createdDateTime` dos insights;
- `userDisplayName` da busca de identidade.

Uma rejeição desses filtros aparece como `request_rejected`, e os resultados são sempre conferidos localmente.
