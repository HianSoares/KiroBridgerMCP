---
name: exfiltration-assessment
description: Avaliar suspeita de exfiltração, backup ou sincronização (RClone e similares) a partir de alerta Workbench, offense ou host, com fase XDR Data Explorer automática, estágios separados (binário, configuração, comando, conexão, transferência) e volume sem estimativa inventada.
---

# Suspeita de exfiltração, backup ou transferência

## Quando ativar

Um alerta, offense ou hipótese envolve utilitário de nuvem, cópia, sync, backup, envio externo ou staging de dados.

## Passo a passo

1. **Investigação inicial, uma vez.** Com um ID Workbench, chame `investigate_vision_alert({"alert_id":"WB-EXEMPLO-0002"})`. Se a origem for ambígua, chame `investigate_case({"reference":"WB-EXEMPLO-0002"})`. Para offense, chame `investigate_offense_case`. Os IDs são fictícios. Não repita a investigação inicial para obter campos que ela não retorna.
2. **Sementes com proveniência.** Leia `xdr_followup.seeds` no relatório: endpoints (nome, GUID, IPs), usuários, hashes, instâncias de processo, comandos e horários, cada um com a sua fonte. Não peça host, GUID ou IP ao analista quando eles estiverem nas sementes ou puderem sair dos registros Search, por exemplo `endpointIp`.
3. **Fase XDR explícita.**
   - Antes da primeira consulta de cada fonte, chame `trend_read_search_resource(source=...)` e use só campos do schema vivo.
   - Execute cada item de `xdr_followup.phases` com `trend_search_data` e os parâmetros indicados: série de comandos, atividade posterior, detecções, Network Activity Data, atividade e filhos da instância, e, para transferência, comandos, launcher e configuração da ferramenta.
   - Ajuste a fonte, o filtro ou o `select` quando o schema vivo ou os registros mostrarem outro campo.
4. **Continuação.**
   - Siga `continuation_plan`: `search_partition` com a janela devolvida, e `refine_filters` estreitando o filtro, o `select`, o `top` ou o `limit`.
   - Não repita parâmetros idênticos que não possam trazer progresso.
   - Mantenha um registro cumulativo: fase, parâmetros, estado, registros e pendências.
5. **O que o XDR acrescentou.** Compare `evidence_digest.identifiers` de cada consulta com `xdr_followup.seeds.identifiers` e liste os novos comandos, instâncias, usuários, destinos e IPs com o uuid/`record_index` de cada um.
6. **Aprofundar a hipótese.** Responda, quando a fonte permitir, às perguntas de `xdr_followup.transfer`:
   - comando, processo pai, usuário e instância (`evidence_digest.actors` e `commands`);
   - origem e destino dos arquivos (`file_objects`);
   - atividade posterior à execução;
   - conexões atribuíveis ao processo: `connections[].attribution` diz se o ator do registro é a instância;
   - destino remoto, resultado e indicadores de transferência.
7. **Estágios.** Binário presente, acesso à configuração, comando iniciado, conexão atribuída e transferência concluída são estágios diferentes. Relate o último estágio que a evidência alcança e a fonte que alcançaria o próximo.
   - Ler ou escrever `rclone.conf` não é transferência. O tipo de remote está no conteúdo do arquivo, que a ponte não lê.
   - Software de segurança que examina `rclone.exe` não é execução de `rclone.exe`.
   - Ausência por nome não exclui cópia renomeada. O discriminante é a linha de comando (`copy|sync|move <origem> <remote>:<destino>`, `--config`).
8. **Volume.** Antes de declarar volume não quantificável, verifique as fontes:
   - **Trend:** `evidence_digest.transfer_counters` e `evidence_digest.volume` listam todo campo de bytes/pacotes devolvido. Os campos de consulta auditados das fontes endpoint e network não incluem contador de bytes.
   - **QRadar flows:** só quando houver IP do host e a cobertura de flows for pertinente. Chame `qradar_read_aql_resource` para os campos de flows desta implantação e depois `qradar_run_aql` na janela, seguindo qradar-aql-conventions.
   - **Com contadores:** preserve campo, direção como nomeada, unidade, intervalo e identidade da sessão. Leituras repetidas da mesma sessão podem ser cumulativas, e a ponte nunca as soma. Tráfego de IP compartilhado ou NAT não é do processo só por IP e horário; é preciso a mesma tupla da conexão do processo.
   - **Não são bytes transferidos:** tamanho de arquivo, quantidade de eventos e porta de destino.
   - **Sem contador utilizável:** declare quais fontes e consultas foram feitas e qual campo falta. Não estime.
9. **Hipóteses.** Configuração legítima, execução sem transferência, transferência autorizada (backup ou sync sancionado) e exfiltração. Cite o que confirma ou refuta cada uma.
   - ATT&CK depende do estágio comprovado. Um artefato isolado sustenta no máximo Rclone (S1040) como ferramenta observada.
   - Com transferência demonstrada: armazenamento em nuvem → T1567.002; SFTP → T1048.002; FTP ou outro protocolo sem criptografia → T1048.003.
   - T1560.001, T1074 e T1030 exigem evidência própria.

## Entrega (nesta ordem)

1. O que aconteceu, sustentado pelas evidências, com fonte, uuid/search ID e horário.
2. O que a fase XDR acrescentou à coleta inicial.
3. Correlações confirmadas e candidatas, com o critério de cada uma.
4. Hipóteses testadas e o resultado de cada teste.
5. Conclusão técnica, estágio alcançado e confiança.
6. Pendências externas e o impacto específico de cada uma, por exemplo: o registro de autorização decide entre backup sancionado e exfiltração, mas não muda os fatos técnicos.

Separe as duas avaliações:

- **Assessment da coleta inicial:** `assessment` do relatório, com o seu `scope`. Não o altere e não diga que ele avaliou registros posteriores.
- **Parecer do agente:** incorpora as evidências complementares, citadas uma a uma.

A falta de registro de autorização não impede descrever os fatos técnicos confirmados e não autoriza classificar como Benign True Positive.

## Tools permitidas

- **Investigação inicial:** `investigate_vision_alert(alert_id)` e `investigate_case(reference)`. No case-investigator também `investigate_offense_case(offense_id)` e `investigate_vision_event(...)`, este último só com campos exatos de um View event. Use apenas as tools do front matter do agente em uso.
- **XDR Data Explorer:** `trend_read_search_resource(source)` e `trend_search_data(query, source, start_date_time, end_date_time, select, top, limit, max_calls)`.
- **QRadar, perfil que os expõe:** `qradar_read_aql_resource`, `qradar_validate_aql`, `qradar_run_aql`, `qradar_start_aql`, `qradar_get_search_status` e `qradar_get_search_results`.
- **Outras leituras dos MCPs oficiais:** `upstream_tools`, `upstream_tool_details` e `upstream_query`, conforme upstream-access.

Não há tool de captura de pacote, bloqueio, isolamento ou alteração neste fluxo.

## Critério de conclusão

O parecer distingue cada estágio (binário, configuração, comando, conexão atribuída, transferência concluída) e o volume com a sua origem, ou a falta dele com os campos e consultas verificados. Cada lacuna traz a fonte e a consulta que a resolveria.
