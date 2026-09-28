---
inclusion: always
---

# Interpretar Workbench e Trend Search da ponte

O Kiro não dispõe de Trend Search livre. `investigate_case`, `investigate_offense`, `investigate_vision_alert`, `investigate_vision_event`, `investigate_epm_uac` e `investigate_web_reputation` podem executar buscas internas limitadas; relate apenas as chamadas e resultados que a tool efetivamente declarar.

- Separe **Workbench** (resumo, disposição e entidades do alerta) de **Search** (detecções e atividades de endpoint). “Nenhum alerta” não descreve Search; “Search não executado” não é “nenhuma atividade”.
- Para cada busca, registre fonte, campo de consulta e valor, janela com fuso, estado, linhas na página inspecionada, total quando disponível e se a página atingiu o limite. Se a tool não incluir esses metadados, diga que não foram informados.
- Preserve a distinção entre IP do evento, IP obtido de atividade próxima e IP do inventário atual. Host/GUID exato com IP em janela focada ainda pode ser candidato; identidade de interface e vínculo com o evento precisam ser demonstrados.
- Uma detecção próxima por modelo/tempo pode fornecer host e hash candidatos, mas não prova ser o View event do alerta. IDs exatos, hash, caminho, processo e horário devem ser corroborados no registro específico.
- Hash de arquivo detectado, hash de processo ativo, processo pai, arquivo objeto e caminho completo representam entidades diferentes. `processFilePath` de software de proteção que examinou um arquivo não demonstra que o binário examinado foi executado.
- Para EPM UAC, uma busca por segmento de pasta que conclui com zero linhas não demonstra ausência do arquivo. Somente caminho completo e horário verificados criam candidato; hash ausente e nome genérico não identificam o executável.
- Para Web Reputation, use um evento individual com URL/domínio e `event_time` com timezone explícito. Uma página filtrada do portal não é um evento. Compare o domínio e horário do evento com webfilter/traffic FortiGate, mas mantenha separado o vínculo do IP ao endpoint.
- Não transforme status `Benign True Positive`, score, severidade ou rank em conclusão própria. Para exfiltração, exija evidência de comando, conexão, destino e volume/resultado de transferência que atribua a ação ao processo.

Não invente campos, contagens, caps, janelas nem nomes de consultas que não apareçam na execução. Descreva o que faltou e indique a fonte onde o analista pode confirmar.
