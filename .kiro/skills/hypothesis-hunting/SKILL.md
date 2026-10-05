---
name: hypothesis-hunting
description: Fazer threat hunting por hipótese MITRE ATT&CK usando referências concretas e AQL personalizada com limites pelas tools da ponte; Search independente limitada por fonte/filtro/janela.
---

# Hunting por hipótese

## Quando ativar

O analista quer testar uma hipótese de comportamento adversário, com uma offense, alerta, evento, host ou filtro concreto como ponto de partida.

## Passo a passo

1. Escreva a hipótese falsificável: ativo, comportamento, intervalo/fuso, resultado esperado e explicação legítima. Se não houver referência, evento ou entidade/filtro concreto, explique que o MCP não faz varredura global e solicite um ponto de partida; `investigate_demo()` serve apenas para treino.
2. Mapeie ATT&CK como hipótese, não veredito, respeitando direção e fase. Varredura **de origem externa** contra o perímetro → T1595 Active Scanning (Reconnaissance; .001 Scanning IP Blocks, .002 Vulnerability Scanning). Varredura **a partir de ativo interno** → T1046 Network Service Discovery (Discovery), o que pressupõe ativo interno sob controle adversário ou ferramenta legítima de inventário/varredura de vulnerabilidade, hipótese a refutar. Falhas repetidas de login → T1110 Brute Force, com sub-técnica pelo padrão observado (.001 Password Guessing: muitas senhas, poucas contas; .003 Password Spraying: poucas senhas, muitas contas; .004 Credential Stuffing: pares vazados); só avance a T1078 Valid Accounts com login bem-sucedido atribuído à mesma origem. Transferência externa → ver `exfiltration-assessment`. O nome da regra QRadar ou do modelo Workbench não confirma a técnica; cite o campo observado que sustenta o mapeamento.
3. Escolha só uma entrada válida: `investigate_offense(offense_id)` para offense, `investigate_vision_alert(alert_id)` para Workbench, `investigate_case(reference)` para origem ambígua; UAC e reputação web usam suas tools especializadas. Para testes adicionais, use AQL personalizada pelas tools qradar_* conforme qradar-aql-conventions; para logs Trend, leia `trend_read_search_resource` e consulte `trend_search_data` com fonte, filtro e janela; não exija ID WB.
4. Extraia consultas realmente executadas, estados, janelas UTC/local, limites e resultados. Teste se houve atividade de endpoint mesmo quando não apareceu Workbench; se faltou busca, marque lacuna.
5. Compare observações a previsões, separando o que a ponte pode mostrar do que exige fonte externa:

   | Hipótese | O que a ponte pode mostrar | O que exige fonte externa |
   | --- | --- | --- |
   | Varredura externa (T1595) | Ariel: muitos `destinationport`/`destinationip` distintos para a mesma `sourceip` na amostra; nomes de evento deny/accept | se um `accept` virou sessão de aplicação |
   | Brute force/spraying (T1110.00x) | Ariel: `username` e evento de falha/sucesso por origem, na amostra | identidade/autoridade das contas, dados ausentes na retenção |
   | Escalação local (T1078.003/T1548.003) | Ariel: sequência PAM e payload selecionado por AQL, origem/alvo quando registrados | autorização da sessão, campos não armazenados |
   | Exfiltração (T1567.002/T1048) | Trend: `processCmd`, `dst`/`dpt` se a busca por hash de processo retornar | bytes, sucesso, destino resolvido (proxy/DNS) |
   | Web/C2 (T1071.001, T1189, T1566.002) | FortiGate `action`/`subtype`/`policyid`; Trend `blocking`/`act` | conteúdo entregue, processo requisitante, origem do link |

   Use apenas campos retornados; dados insuficientes deixam hipótese `não verificada`.
6. Traga hipótese concorrente legítima, critério de refutação e próximo pivô externo. Classifique confiança; sugira uma melhoria de detecção e uma melhoria da ponte quando cobertura impedir a avaliação.

## Tools permitidas

`investigate_case`, `investigate_offense`, `investigate_vision_alert`, `investigate_epm_uac`, `investigate_web_reputation` conforme referência e campos disponíveis; `investigate_demo` só para demonstração. As seis tools qradar_* do front matter do threat-hunter permitem ler resources, validar/executar SELECTs limitados, acompanhar search IDs e paginar eventos/flows/payload conforme qradar-aql-conventions.

A correlação por IP e timestamp exatos copiados de um View event (`investigate_vision_event`) é escopo do `case-investigator`, não do hunting. Quando a hipótese depender desse pivô, registre-o como próximo passo e indique que o analista o execute no `case-investigator` com `alert_id`, IP exato e horário com fuso explícito; não simule o resultado.

## Critério de conclusão

Há hipótese, evidência pró/contra, explicação alternativa, mapeamento ATT&CK condicionado, limite do método e ação de coleta necessária. Hunting sem referência fica como plano, não como busca supostamente executada.

## Pivôs registrados no caso

Quando houver caso (`get_case`), parta de `hypotheses` e `pending`: cada pivô traz hipótese, evidência motivadora, fonte, filtros, janela, custo, resultados que apoiariam/contradiriam e critério de parada. Proponha somente pivôs com possibilidade concreta de mudar a avaliação.

Um host, hash ou filtro com hipótese concreta também permite Search independente, sem alerta WB. Leia `trend_read_search_resource`, use `trend_search_data`, declare a janela padrão quando aplicável e siga as continuações. Teste hipóteses com os papéis e instâncias nativos; nunca trate um PID, caminho, ferramenta dual-use ou ausência em busca parcial como veredito.
