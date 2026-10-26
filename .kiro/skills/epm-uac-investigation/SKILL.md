---
name: epm-uac-investigation
description: "Investigar evento UacAudit do CyberArk EPM recebido no QRadar (log source EPM_API) por lastEventId e lastEventDate, comparar candidatos da Trend por agente e caminho exato e distinguir pedido de elevação, concessão e execução."
---

# CyberArk EPM UacAudit

Regras comuns: `soc-core.md`.

## Quando usar

Há `lastEventId` e `lastEventDate` de um registro UacAudit EPM_API, e a intenção é identificar o executável, o host e o contexto.

## Quando não usar

- Sem o ID exato do evento EPM: peça-o, porque nenhuma tool o descobre a partir do nome do arquivo.
- Elevação Linux por sudo/su: use offense-investigation.

## Entradas mínimas e descoberta automática

- **Obrigatórios:** ID exato e horário com fuso. `qradar_utc_offset_hours` só depois de confirmar o offset do console; o padrão `-3` não é uma medição.
- **Opcional:** `endpoint_host`, somente se verificado de forma independente.
- **Descoberta automática:** a tool busca outros registros EPM_API do mesmo `lastEventAgentId` numa janela limitada. Sem host resolvido e com subpasta Temp distintiva mais nome de arquivo, faz buscas Trend pelo caminho completo perto do primeiro e do último horário.

## Procedimento

1. Chame `investigate_epm_uac({"last_event_id":"uac-exemplo-001","last_event_date":"2026-01-15T12:00:00Z","qradar_utc_offset_hours":-3})` com valores fictícios substituídos pelos reais e o offset confirmado.
2. **Campos do EPM observados:** nome, caminho, hash, publisher, host, agente, usuário, `policyAction`, primeiro e último horário, arrival e agregação.
   - `firstEventDate`, `lastEventDate` e `arrivalTime` são relógios distintos.
   - `totalEvents`, `skipped` e `Collect UAC actions` não contam concessões.
   - Nomes genéricos, hash vazio, `fileSize=0` e `fileQualifier` opaco não identificam o binário.
3. **Hostname em outros registros do mesmo agente:** é candidato vinculado ao agente, não o host confirmado do evento original.
4. **Buscas por caminho:**
   - Relate cada consulta: janela, linhas da primeira página e contagens de caminho exato, exato fora da janela, parcial e ausente.
   - "8/8 consultas concluídas" diz só que as requisições terminaram.
   - Linhas de consultas diferentes podem duplicar um evento.
   - Host ou hash da Trend vindo de caminho exato é candidato, nunca vínculo com o EPM nem prova de elevação.
5. **Hipóteses:** atualizador legítimo, tentativa não concedida, elevação efetiva ou execução maliciosa, com o evento que confirmaria ou refutaria cada uma.
6. **ATT&CK:** não mapeie T1548.002 (Bypass User Account Control) a partir de um UacAudit. O registro indica pedido de elevação pelo caminho do UAC, e bypass é evitar esse caminho; exige evidência específica, como binário auto-elevado com chave de registro sequestrada ou processo elevado sem prompt.

## Evidência esperada e falhas

- **Busca QRadar pelo ID:** a busca exata roda mesmo quando a busca Trend por hostname é pulada. Diga qual das duas rodou: busca por hostname e busca por caminho são diferentes.
- **Busca por caminho sem candidato:** nenhuma linha não prova a inexistência do arquivo.
- **Resultado ambíguo:** busca capada, incompleta ou com vários hosts pede confirmação independente do hostname.

## Continuação, escalonamento e parada

- Sem evidência exata, peça um host ou hash verificado em vez de ampliar para o nome genérico.
- Pare quando a identidade depender de fonte externa (console EPM, inventário) e diga qual.

## Saída

- Distinga evento agregado, pedido de elevação, concessão e execução do processo.
- Diga quando a Trend não foi consultada e por quê.
- Sem hash ou host confiável, a identidade fica `não verificada`.

## Tools permitidas

- `investigate_epm_uac`

## Referências

`soc-core.md` (estados e evidência).
