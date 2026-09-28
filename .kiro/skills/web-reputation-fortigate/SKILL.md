---
name: web-reputation-fortigate
description: Correlacionar um evento de Web Reputation Trend com logs FortiGate no QRadar e verificar se o IP é historicamente atribuível ao endpoint.
---

# Web Reputation ↔ FortiGate

## Quando ativar

O analista apresenta uma linha individual de reputação web com URL/domínio e horário; idealmente, também UUID, host e GUID. URL da tela de filtros não substitui o evento individual.

## Passo a passo

1. Registre URL/domínio exato e `event_time` com offset explícito; confirme fuso do portal e offset do QRadar. Se houver host/GUID/UUID, preserve esses identificadores sem fornecer um IP presumido.
2. Chame `investigate_web_reputation` com `{"url_or_domain":"https://example.invalid/","event_time":"2026-01-15T09:00:00-03:00","endpoint_host":"HOST-DEMO","endpoint_guid":"00000000-0000-4000-8000-000000000000","event_id":"evento-demo","qradar_utc_offset_hours":-3}` apenas quando `-3` for confirmado. O exemplo é fictício; omita parâmetros opcionais que não foram obtidos.
3. Classifique o IP: confirmado no evento exato, candidato de atividade próxima, ou inventário atual. O IP de inventário não demonstra interface ativa histórica. Se a tool não atribuir IP, reporte separadamente qualquer busca QRadar por domínio sem atribuí-la ao endpoint.
4. Compare logs FortiGate por domínio/URL, `srcip`, timestamp e `action`; se constarem, `subtype`, `policyid`, `dstip` e log source. Separe webfilter `blocked`, `allowed` e `traffic accept`; `accept` de conexão não prova acesso ao conteúdo nem autorização do filtro web.
5. Verifique lacunas: DHCP/NAT histórico, proxy, DNS/SNI, usuário/processo no host; limitações de primeira página, estado e janelas de todas as buscas. Não recomende bloquear IP de sinkhole ou destino compartilhado sem validação de propriedade.
6. Produza recomendação para revisão humana da equipe de rede **somente se** houver evidência de permissão pertinente; nunca envie mensagem nem modifique regra.

## Tool permitida

`investigate_web_reputation(url_or_domain: string, event_time: string, endpoint_guid?: string, endpoint_host?: string, endpoint_ip?: string, event_id?: string, qradar_utc_offset_hours?: integer)`.

## Critério de conclusão

O relatório separa “domínio observado no firewall” de “tráfego atribuível ao endpoint”; indica ação observada e não extrapola resultados vazios para o restante da janela.
