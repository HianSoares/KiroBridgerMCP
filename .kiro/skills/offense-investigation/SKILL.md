---
name: offense-investigation
description: Investigar offense do QRadar por ID, inclusive quando não há alerta Workbench, interpretando Ariel e Trend Search retornados pela ponte.
---

# Offense do QRadar

## Quando ativar

Quando o analista fornecer um número positivo de offense ou pedir investigação de offense sem alerta correspondente na Trend. Para uma referência cuja origem não foi definida, use `investigate_case(reference)`.

## Passo a passo

1. Confirme que a referência é um inteiro positivo. Chame `investigate_offense` com `{"offense_id": 12345}` (ID fictício). Se for texto ambíguo, use `investigate_case` com `{"reference": "12345"}`.
2. Extraia offense, origem dos IPs, resumo, estado, janela UTC e horário local, log sources, consultas Ariel executadas, seus estados, linhas/página/limite, detecções/atividades Trend Search e alertas Workbench. Não preencha campos não retornados.
3. Mesmo se Workbench não trouxer alerta, examine se houve buscas de atividade/detecção de endpoint e eventos Ariel. Caso alguma não tenha ocorrido, relate a razão ou “razão não informada”; não conclua que o endpoint estava inativo.
   A correção desse fluxo foi validada no caso de exemplo 90210. O caso de exemplo 90211 permanece não testado para essa validação.
4. Para cada possível vínculo QRadar↔Trend, compare entidade, IP de origem, destino/porta, host, timestamp e identificação histórica da interface conforme disponíveis. Rótulo padrão: `candidato`; só descreva o que cada fonte confirmou de modo separado.
5. Monte hipóteses concorrentes (atividade maliciosa, administração autorizada, ruído/detecção equivocada) e uma observação que refutaria cada uma. Investigue “por quês” até onde os dados permitirem, sem fabricar causa raiz.
6. Entregue relatório: consultas de Ariel e Trend que realmente constam da saída; estado, janela, limite, resultados; fatos/candidatos/não verificados; impacto, confiança, próximos pivôs; recomendações humanas de contenção → erradicação → recuperação, se cabíveis.
   Se `username` vier vazio em eventos PAM, não reexecute a mesma tool esperando colunas diferentes. Identifique a lacuna e indique inspeção manual de `sourceUserName`, `targetUserName`, hostname e payload no Log Activity do QRadar.

## Tools permitidas

`investigate_offense(offense_id: integer)`; `investigate_case(reference: string)` apenas para referência de origem ambígua. A ponte executa as consultas internas; o Kiro não escreve AQL.

## Critério de conclusão

O relatório mostra a offense e todas as fontes consultadas, inclusive buscas vazias ou indisponíveis, com limites do próprio retorno. A melhoria de contexto Ariel/endpoint foi validada no caso de exemplo 90210; se faltar na execução atual, descreva a falha ou diferença de versão observada, sem atribuir uma causa sem evidência.
