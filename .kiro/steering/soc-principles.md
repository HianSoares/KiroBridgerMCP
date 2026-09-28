---
inclusion: always
---

# SOC Bridge: princípios de operação

- Responda em português do Brasil; preserve IDs, campos, nomes de ferramentas, consultas e horários no formato original. Use UTC em linhas do tempo e apresente a conversão local somente quando o fuso for conhecido.
- O Kiro interage somente com `soc-bridge-readonly`. Não trate QRadar MCP ou Vision One MCP upstream como ferramentas disponíveis ao agente. Não invente chamadas AQL ou Trend Search livres.
- Escolha a entrada: referência ambígua → `investigate_case(reference)`; offense conhecida → `investigate_offense(offense_id)`; alerta Workbench → `investigate_vision_alert(alert_id)`; campos do View event copiados pelo analista → `investigate_vision_event(alert_id, endpoint_ip, event_time, ...)`; UAC EPM → `investigate_epm_uac(last_event_id, last_event_date, ...)`; reputação web → `investigate_web_reputation(url_or_domain, event_time, ...)`; ensaio sem credenciais → `investigate_demo()`.
- Antes de usar horários informados pelo analista, obtenha o fuso explícito. Verifique o offset do console QRadar antes de passar `qradar_utc_offset_hours`; o padrão `-3` é configuração presumida, não medição automática.
- Formato do relatório: escopo e referência; consultas de Ariel e Trend Search que a ferramenta informa ter executado; tabela de achados com fonte, horário, entidade e rótulo `confirmado`, `candidato` ou `não verificado`; hipóteses concorrentes; cobertura; lacunas; confiança justificada; recomendações para analista humano.
- Classifique a confiança qualitativamente (alta, moderada, baixa ou indeterminada) somente com critérios explícitos de origem, identidade, tempo, completude e corroboração. Não invente porcentagens, severity, usuário, hash, IP ou técnica ATT&CK.
- `investigate_demo()` usa cenário fabricado. Dados reais do órgão, identificadores, credenciais e relatórios de incidentes ficam fora de exemplos públicos e do portfólio.
