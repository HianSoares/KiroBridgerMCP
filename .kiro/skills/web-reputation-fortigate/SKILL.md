---
name: web-reputation-fortigate
description: "Correlacionar um evento individual de Web Reputation da Trend com logs FortiGate no QRadar: domínio/URL, horário com fuso, IP historicamente atribuível ao endpoint, ação do firewall e limites de NAT, proxy e SNI."
---

# Web Reputation ↔ FortiGate

Regras comuns: `soc-core.md`.

## Quando usar

Uma linha individual de reputação web com URL ou domínio e horário; idealmente também UUID, host e GUID.

## Quando não usar

- URL da tela de filtros do portal: não é um evento individual. Peça a linha do evento.
- Transferência de dados por processo: use exfiltration-assessment.

## Entradas mínimas e descoberta automática

- **Obrigatórios:** URL ou domínio exato e `event_time` com offset explícito. Se o portal mostrar só o relógio, confirme o fuso de exibição.
- **Opcionais:** host, GUID e UUID, quando vierem do mesmo evento. Omita `endpoint_ip` na primeira chamada.
- **Descoberta automática:** a tool procura o IP do evento na Vision One.
  - Um IP único em atividade adjacente do host é candidato; o IP do inventário atual não estabelece o IP no horário do evento.
  - Se a busca ampla do host chega a 50/50, a tool tenta janelas menores e relata a cobertura.
  - Sem IP único, faz uma busca QRadar só por domínio.

## Procedimento

1. Chame `investigate_web_reputation({"url_or_domain":"https://example.invalid/","event_time":"2026-01-15T09:00:00-03:00","endpoint_host":"HOST-DEMO","endpoint_guid":"00000000-0000-4000-8000-000000000000","event_id":"evento-demo","qradar_utc_offset_hours":-3})` só com o offset confirmado. Os valores do exemplo são fictícios; omita parâmetros que não foram obtidos.
2. **Classifique o IP:** confirmado no evento exato, candidato de atividade próxima ou inventário atual.
3. **Logs FortiGate:** compare domínio/URL, `srcip`, horário e `action`; se constarem, `subtype`, `policyid`, `dstip` e log source.
   - Separe webfilter `blocked`, `allowed` e `traffic accept`. Um `accept` de conexão não prova acesso ao conteúdo nem autorização do filtro web.
   - Sem inspeção SSL, o webfilter vê em HTTPS só o hostname (SNI ou certificado), então a comparação é de domínio.
   - No FortiGate que faz SNAT, `srcip` é o endereço interno pré-NAT; atrás de proxy explícito, `srcip` é o proxy.
   - Bytes de sessão do FortiGate são do IP e da sessão, não de um processo.
4. **Matches por domínio sem IP atribuído** são leads de domínio independentes, não tráfego do endpoint. Diga por que a atribuição parou e peça um IP histórico verificado de forma independente; não invente um.
5. **Leitura das páginas:** 8 linhas de um limite de 100 com estado COMPLETED não é página truncada; diga só que a consulta por texto de domínio pode não alcançar outras fontes. Um `dstip` não é o servidor real do domínio sem evidência DNS.

## Evidência esperada e falhas

- Resultados vazios valem só para o filtro e a janela executados.
- Lacunas típicas: DHCP/NAT histórico, proxy, DNS/SNI, usuário e processo no host.

## Continuação, escalonamento e parada

- A tool gera um rascunho para a equipe de rede só quando um registro de permissão do webfilter corresponde. Um relatório só de bloqueios pede verificação, não um novo pedido de bloqueio.
- Nunca envie o rascunho nem mude regras.
- Não recomende bloquear IP de sinkhole, CDN ou destino compartilhado sem validação de propriedade.

## Saída

Separe "domínio observado no firewall" de "tráfego atribuível ao endpoint". Indique a ação observada e não extrapole resultados vazios para o resto da janela.

## Tools permitidas

- `investigate_web_reputation`

## Referências

`soc-core.md` (rede, NAT e estados).
