---
name: hypothesis-hunting
description: Fazer threat hunting por hipótese MITRE ATT&CK usando referências concretas nas sete tools, sem AQL ou Trend Search livres.
---

# Hunting por hipótese

## Quando ativar

O analista quer testar uma hipótese de comportamento adversário, com uma offense, alerta ou evento concreto como ponto de partida.

## Passo a passo

1. Escreva a hipótese falsificável: ativo, comportamento, intervalo/fuso, resultado esperado e explicação legítima. Se não houver referência ou evento individual, explique que o MCP não faz varredura global e solicite um ponto de partida; `investigate_demo()` serve apenas para treino.
2. Mapeie ATT&CK como hipótese, não veredito, respeitando direção e fase. Varredura **de origem externa** contra o perímetro → T1595 Active Scanning (Reconnaissance; .001 Scanning IP Blocks, .002 Vulnerability Scanning). Varredura **a partir de ativo interno** → T1046 Network Service Discovery (Discovery), o que pressupõe ativo interno sob controle adversário ou ferramenta legítima de inventário/varredura de vulnerabilidade, hipótese a refutar. Falhas repetidas de login → T1110 Brute Force, com sub-técnica pelo padrão observado (.001 Password Guessing: muitas senhas, poucas contas; .003 Password Spraying: poucas senhas, muitas contas; .004 Credential Stuffing: pares vazados); só avance a T1078 Valid Accounts com login bem-sucedido atribuído à mesma origem. Transferência externa → ver `exfiltration-assessment`. O nome da regra QRadar ou do modelo Workbench não confirma a técnica; cite o campo observado que sustenta o mapeamento.
3. Escolha só uma entrada válida: `investigate_offense(offense_id)` para offense, `investigate_vision_alert(alert_id)` para Workbench, `investigate_case(reference)` para origem ambígua; UAC e reputação web usam suas tools especializadas. Não há AQL livre nem Trend Search livre.
4. Extraia consultas realmente executadas, estados, janelas UTC/local, limites e resultados. Teste se houve atividade de endpoint mesmo quando não apareceu Workbench; se faltou busca, marque lacuna.
5. Compare observações a previsões: processo e sequência de destinos/portas para scanning; origem, usuários e sucesso temporal para brute force; comando, bytes/destino e sessão atribuível para exfiltração. Use apenas campos retornados; dados insuficientes deixam hipótese `não verificada`.
6. Traga hipótese concorrente legítima, critério de refutação e próximo pivô externo. Classifique confiança; sugira uma melhoria de detecção e uma melhoria da ponte quando cobertura impedir a avaliação.

## Tools permitidas

`investigate_case`, `investigate_offense`, `investigate_vision_alert`, `investigate_vision_event`, `investigate_epm_uac`, `investigate_web_reputation` conforme referência e campos disponíveis; `investigate_demo` só para demonstração.

## Critério de conclusão

Há hipótese, evidência pró/contra, explicação alternativa, mapeamento ATT&CK condicionado, limite do método e ação de coleta necessária. Hunting sem referência fica como plano, não como busca supostamente executada.
