---
inclusion: always
---

# SOC Bridge: princípios de operação

- Responda em português do Brasil; preserve IDs, campos, nomes de ferramentas, consultas e horários no formato original. Use UTC em linhas do tempo e apresente a conversão local somente quando o fuso for conhecido.
- O Kiro interage somente com `soc-bridge-readonly`. Não trate QRadar MCP ou Vision One MCP upstream como ferramentas disponíveis ao agente. Use AQL personalizada somente pelas tools qradar_* expostas pela ponte, conforme qradar-aql-conventions. Use Search independente somente por `trend_read_search_resource` e `trend_search_data`, com fonte/filtro/janela; não invente tools upstream.
- Escolha a entrada: referência ambígua → `investigate_case(reference)`; offense conhecida → `investigate_offense(offense_id)`; alerta Workbench → `investigate_vision_alert(alert_id)`; campos do View event copiados pelo analista → `investigate_vision_event(alert_id, endpoint_ip, event_time, ...)`; UAC EPM → `investigate_epm_uac(last_event_id, last_event_date, ...)`; reputação web → `investigate_web_reputation(url_or_domain, event_time, ...)`; ensaio sem credenciais → `investigate_demo()`.
- Antes de usar horários informados pelo analista, obtenha o fuso explícito. Verifique o offset do console QRadar antes de passar `qradar_utc_offset_hours`; o padrão `-3` é configuração presumida, não medição automática.
- Formato do relatório: escopo e referência; consultas de Ariel e Trend Search que a ferramenta informa ter executado; tabela de achados com fonte, horário, entidade e rótulo `confirmado`, `candidato` ou `não verificado`; hipóteses concorrentes; cobertura; lacunas; confiança justificada; recomendações para analista humano.
- Classifique a confiança qualitativamente (alta, moderada, baixa ou indeterminada) somente com critérios explícitos de origem, identidade, tempo, completude e corroboração. Confiança qualifica a **conclusão ou hipótese**, não a observação (que já tem rótulo `confirmado`/`candidato`/`não verificado`). Não invente porcentagens, severity, usuário, hash, IP ou técnica ATT&CK.
  - **alta:** apoiada em observação `confirmado` que liga diretamente comportamento e entidade (mesmo host/GUID, processo/hash e horário no mesmo registro, ou duas fontes independentes concordando em entidade e tempo); a coleta relevante não está capada nem falhou; as alternativas foram refutadas por observação específica.
  - **moderada:** comportamento `confirmado`, mas o vínculo com entidade ou tempo depende de ao menos um `candidato` (IP sem mapeamento histórico, detecção próxima, janela ancorada na criação do alerta) ou uma alternativa plausível segue não refutada.
  - **baixa:** depende principalmente de `candidato`/`não verificado`, de nome de regra/modelo, de fonte única ou de amostra capada/janela que pode não conter o gatilho.
  - **indeterminada:** coleta essencial falhou ou não foi executada, ou as fontes se contradizem sem desempate.
  Na justificativa, cite o critério que limitou o nível (ex.: “moderada: comportamento confirmado; vínculo IP→host é candidato sem DHCP”).
- `investigate_demo()` usa cenário fabricado. Dados reais do órgão, identificadores, credenciais e relatórios de incidentes ficam fora de exemplos públicos e do portfólio.
