---
name: trend-alert-investigation
description: Investigar alerta Workbench do Trend Vision One por ID e correlacionar com QRadar sem confundir detecção próxima com vínculo verificado.
---

# Alerta Workbench Trend

## Quando ativar

O analista informa um ID exato de alerta Workbench ou copia campos de um único View event.

## Passo a passo

1. Com somente o ID, chame `investigate_vision_alert` com `{"alert_id": "WB-EXEMPLO-0001"}` (exemplo ilustrativo). Se a origem do texto for incerta, `investigate_case({"reference": "WB-EXEMPLO-0001"})`.
2. Descreva o alerta, criação/atualização, entidade explícita no detalhe e Discovery status. Mostre buscas de detecção e endpoint que o retorno indicar, com campo de pesquisa, janela, página, cap, estado e linhas.
3. Se o Workbench omitir host/IP/hash e a ponte descobrir uma detecção próxima, trate host, hash, IP e horário como candidatos; identifique a fonte e explique que não há vínculo View event verificado.
4. Liste índices de offense e eventos Ariel executados apenas se constarem no retorno. Verifique horário da offense antes de ligar um IP compartilhado ao alerta. Diferencie detecção de arquivo, processo executado, acesso a configuração e tráfego atribuído ao processo.
5. Se o analista fornecer campos do **mesmo** View event, confirme timezone explícito e IP exato; chame `investigate_vision_event` com `{"alert_id":"WB-EXEMPLO-0001","endpoint_ip":"192.0.2.10","event_time":"2026-01-15T12:00:00Z","endpoint_host":"HOST-DEMO","file_hash":"" ,"qradar_utc_offset_hours":-3}` somente após verificar o offset do console. IP e host aqui são fictícios e continuam `não verificados` pela ponte. Omita campos opcionais sem valor em chamadas reais.
6. Escreva fatos confirmados na fonte, candidatos de correlação e lacunas; recomendações para analista sem executar resposta.

## Tools permitidas

`investigate_vision_alert(alert_id: string)`, `investigate_case(reference: string)` e, quando o analista trouxer campos obrigatórios exatos, `investigate_vision_event(alert_id: string, endpoint_ip: string, event_time: string, endpoint_host?: string, file_hash?: string, file_path?: string, process_path?: string, qradar_utc_offset_hours?: integer)`.

## Critério de conclusão

Cada pivô mantém proveniência, timezone e limite. A ausência de ID de View event validado impede apresentar uma detecção próxima como parte confirmada do Workbench.
