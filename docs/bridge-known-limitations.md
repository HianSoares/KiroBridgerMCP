# soc-bridge-readonly — pendências conhecidas (melhorias da ponte)

Este arquivo registra limitações conhecidas da ponte `soc-bridge-readonly` para
tratamento futuro. É backlog de engenharia da ponte (código Python), **fora do
escopo** do pacote de steering/skills e do fluxo somente-leitura do agente.
Não altera o comportamento atual das sete tools.

## 1. Consulta Ariel com SELECT fixo e sem filtro por tipo de evento

Registrado em: 2026-01 (exemplo)
Contexto de origem: investigação da offense QRadar 90210 (exemplo) (Suspicious
SSH Root Login / Privilege Escalation Succeeded), janela focada ~14:39:13Z–
14:41:13Z. Eventos "PAM Su User Impersonation", "Privilege Escalation Succeeded"
e "PAM Session Closed" apareceram na fonte, mas sem identidade de usuário.

### Limitação observada

As consultas Ariel montadas internamente pela ponte usam um SELECT fixo e um
filtro fixo por IP exato (com predicado de milissegundos para janelas focadas).
Colunas atualmente retornadas:

```
starttime, sourceip, sourceport, destinationip, destinationport,
username, QIDNAME(qid) AS event_name, LOGSOURCENAME(logsourceid) AS log_source
```

Consequências:

- Não é possível filtrar a busca por nome/QID de evento (ex.: restringir a
  eventos PAM/escalação). A amostra é dominada por tráfego de rede (Forward
  Traffic) e pode atingir o cap de 100 antes de exibir os eventos PAM.
- O único campo de usuário no SELECT é `username` (propriedade normalizada), que
  veio vazio para os eventos PAM/escalação do caso de exemplo 90210.
- Não há `sourceUserName`, `targetUserName` nem payload bruto no retorno — logo,
  quem executou `su`/root (origem) e a conta-alvo (destino) não são recuperáveis
  pela ponte, mesmo que existam no evento QRadar.

### Impacto

Investigações de escalação de privilégio / sessão PAM não conseguem, apenas pela
ponte, atribuir usuário de origem e conta-alvo. Hoje esses campos exigem consulta
manual no QRadar Log Activity (Username, Source Username, Target Username,
propriedades custom de usuário do DSM e o Payload bruto do evento).

### Melhoria proposta (a avaliar, mantendo read-only e limites)

- Permitir um pivô opcional por `event_name`/QID nas consultas de escalação,
  ainda com LIMIT e janela limitados.
- Incluir no SELECT campos de identidade quando disponíveis
  (`sourceUserName`/`targetUserName` ou propriedades custom equivalentes) e,
  opcionalmente, um trecho do payload para eventos PAM/su/SSH.
- Exige revisão de design e nova verificação da allowlist upstream após a
  mudança (a allowlist permanece somente-leitura).

### Contorno atual (manual, fora do Kiro)

Consultar no QRadar Log Activity, filtrando por Log Source do host e pela janela
(confirmar antes o fuso do console; a ponte usa offset presumido -3), com Event
Name em {"PAM Su User Impersonation", "Privilege Escalation Succeeded",
"PAM Session Closed"} e abrindo o Payload para ler usuário de origem e conta-alvo.
Correlacionar a sessão PAM (impersonation → escalation → session closed) pelo
mesmo host/tempo.

## 2. Ausência de search ID nas consultas Ariel retornadas pela ponte

Registrado em: 2026-01 (exemplo)
Contexto de origem: investigação da offense QRadar 90210 (exemplo). As três consultas
Ariel do relatório traziam AQL, estado (COMPLETED), janela UTC, amostra/total e
cap, mas **não** um search ID.

### Limitação observada

O relatório da ponte, em algumas execuções (ex.: `investigate_offense`), não
inclui o identificador da busca Ariel (search ID) das consultas executadas.
Outras execuções observadas em `investigate_vision_event` chegaram a exibir
Search IDs, então a apresentação não é consistente entre os fluxos.

### Impacto

- Dificulta rastrear/reabrir a mesma busca no QRadar para auditoria ou para
  paginar além da primeira página / do cap.
- Reduz a reprodutibilidade: o analista não tem o handle exato da consulta que a
  ponte executou, apenas o AQL reconstruído no texto.

### Melhoria proposta (a avaliar, mantendo read-only e limites)

- Padronizar a inclusão do search ID (quando o upstream QRadar o fornecer) em
  todas as seções de eventos Ariel, em todos os fluxos que executam Ariel.
- Quando o search ID não estiver disponível, declarar explicitamente
  "search ID não informado", em vez de omitir.

### Contorno atual (manual, fora do Kiro)

Reproduzir a busca no QRadar Log Activity a partir do AQL, janela e filtros
exibidos no relatório, confirmando antes o fuso do console (a ponte usa offset
presumido -3).

## 3. Sem consultas agregadas de contagem/inventário de usuários do AD

Registrado em: 2026-01 (exemplo)
Contexto de origem: pedido para "avaliar quantos usuários há no AD pelo QRadar".

### Limitação observada

As sete tools do `soc-bridge-readonly` fazem coleta pontual e limitada por
IP/host/hash/evento, com resultados de primeira página. Não há AQL livre nem
consulta agregada. Portanto:

- Não é possível obter contagem total de contas do Active Directory pela ponte.
- Só é possível observar usuários que aparecem em eventos individuais
  coletados numa janela específica (amostra limitada), o que nunca representa o
  inventário do diretório (inclui inativas, de serviço, desabilitadas etc.).

### Impacto

- Perguntas de inventário/contagem de usuários do AD não são respondíveis pela
  ponte e não devem ser inferidas a partir de eventos observados.
- Risco de leitura equivocada: "N usuários vistos em eventos" ≠ "N usuários no
  AD".

### Fonte correta (fora do escopo da ponte)

- Active Directory diretamente: `(Get-ADUser -Filter *).Count` (total) ou
  `(Get-ADUser -Filter {Enabled -eq $true}).Count` (habilitadas); console ADUC
  ou consulta LDAP.

### Melhoria proposta (opcional, a avaliar)

- Se algum dia for desejável responder "usuários distintos observados em eventos"
  numa janela, isso exigiria uma capacidade agregada nova, ainda read-only e
  limitada, e continuaria sendo amostra de atividade — não inventário do AD.
  Deve ser explicitamente rotulada como tal para não ser confundida com contagem
  do diretório.
