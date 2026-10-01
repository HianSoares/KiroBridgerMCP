---
name: epm-uac-investigation
description: Investigar UacAudit do CyberArk EPM recebido no QRadar via EPM_API e comparar candidatos da Trend sem presumir elevação concedida.
---

# CyberArk EPM UacAudit

## Quando ativar

Há `lastEventId` e `lastEventDate` de um registro UacAudit EPM_API; a intenção é identificar melhor executável, host e contexto.

## Passo a passo

1. Obtenha o ID exato e o horário com fuso; confirme o offset QRadar. Chame `investigate_epm_uac` com `{"last_event_id":"uac-exemplo-001","last_event_date":"2026-01-15T12:00:00Z","qradar_utc_offset_hours":-3}` somente se o offset `-3` tiver sido confirmado. `endpoint_host` é opcional e só entra se verificado independentemente.
2. Liste campos do EPM observados: nome, caminho, hash, publisher, host, agente, usuário, `policyAction`, primeiro/último horário, arrival e estado de agregação, sem inferir contagem de concessões a partir de `totalEvents`, `skipped` ou `Collect UAC actions`.
3. Descreva busca suplementar por agente, quantidade de hosts distintos e qualidade desse vínculo. Se o relatório trouxer buscas por pasta temporária na Trend, reporte cada consulta, janela, linhas e se houve **caminho completo exato + horário**. Conclusão de consulta sem linha não é prova de inexistência.
4. Se surgir candidato, separe host/hash do EPM versus da Trend. `updater.exe` ou outro nome genérico nunca confirma identidade do binário. Pergunte por ação efetiva, assinatura, hash, processo pai e linha de comando em fonte apropriada se faltarem.
5. Formule hipóteses: atualizador legítimo, tentativa não concedida, elevação efetiva, execução maliciosa; anote o evento necessário para refutar ou confirmar cada uma. Não mapeie T1548.002 (Bypass User Account Control) a partir de um UacAudit: o registro indica pedido de elevação pelo caminho do UAC, e bypass é justamente evitar esse caminho. T1548.002 exige evidência de bypass (binário auto-elevado como `fodhelper.exe`/`eventvwr.exe` com chave de registro sequestrada, processo elevado sem prompt correspondente).

## Tool permitida

`investigate_epm_uac(last_event_id: string, last_event_date: string, endpoint_host?: string, qradar_utc_offset_hours?: integer)`.

## Critério de conclusão

O relatório distingue evento agregado, concessão de privilégio e execução do processo, além de explicitar quando a Trend não foi consultada e por quê. Sem hash/host confiável, a identidade fica `não verificada`.
