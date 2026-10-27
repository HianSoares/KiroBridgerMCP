---
name: exfiltration-assessment
description: "Avaliar suspeita de exfiltração, backup ou sincronização (RClone e similares) a partir de alerta Workbench, offense ou host: fase XDR automática, estágios separados (binário, configuração, comando, conexão, tráfego, conclusão), atribuição processo↔rede, volume sem estimativa e autorização pendente sem classificação benigna."
---

# Exfiltração, backup ou transferência

Regras comuns: `soc-core.md`. Detalhes de domínio: `trend-search-conventions.md` e `qradar-aql-conventions.md`.

## Quando usar

Alerta, offense ou hipótese com utilitário de nuvem, cópia, sync, backup, envio externo ou staging de dados.

## Quando não usar

- Só para contar usuários ou ativos: use ad-users-scope.
- Reputação de URL isolada, sem transferência: use web-reputation-fortigate.

## Entradas mínimas e descoberta automática

- **Entrada mínima:** a referência do caso (`WB-`, offense ou host com janela).
- **Descoberta automática:** sementes com proveniência em `xdr_followup.seeds` e fases em `xdr_followup.phases`. Não peça host, GUID ou IP que as sementes ou os registros trazem (por exemplo `endpointIp`).

## Procedimento

1. **Coleta inicial, uma vez:** `investigate_vision_alert(alert_id)` ou `investigate_case(reference)`. No case-investigator, também `investigate_offense_case(offense_id)`. Os IDs dos exemplos são fictícios.
2. **Fase XDR:** chame `trend_read_search_resource` por fonte e execute as fases com `trend_search_data`.
   - Ordem: série de comandos e atividade posterior do endpoint principal, depois instância e filhos, depois as fases de transferência (comando, launcher e configuração da ferramenta).
   - Siga `continuation_plan` sem repetir parâmetros idênticos.
3. **O que o XDR acrescentou:** compare `evidence_digest.identifiers` com `seeds.identifiers` e cite uuid e `record_index`.
4. **Perguntas da hipótese (`xdr_followup.transfer`):**
   - comando, processo pai, usuário e instância (`actors`, `commands[].occurrences`);
   - origem e destino dos arquivos (`file_objects`);
   - atividade posterior à execução;
   - conexões atribuíveis (`connections[].attribution`);
   - destino remoto, resultado e indicadores de transferência.
5. **Estágios.** São fatos diferentes, nunca equivalentes. Relate o último estágio que a evidência alcança:
   1. **binário presente:** evento de arquivo ou detecção;
   2. **configuração acessada:** `rclone.conf` lido ou escrito pela instância. Não é transferência, e o tipo de remote está no conteúdo do arquivo, que a ponte não lê;
   3. **mount ou comando iniciado:** linha de comando, pai, usuário e instância. `rclone mount` expõe um remoto como unidade, mas não prova cópia;
   4. **conexão atribuída:** evento de rede cujo ator é a mesma instância;
   5. **tráfego observado:** contadores verificados da sessão atribuída, por exemplo flows QRadar com a mesma tupla e o mesmo horário;
   6. **operação concluída:** resultado do aplicativo da mesma execução (log, código de saída ou mensagem de conclusão) ou confirmação no destino. Contadores sozinhos nunca chegam aqui.
6. **Nomes e remotos:**
   - O nome do remoto (`Google_Drive`, `backup`, `s3`) é um rótulo da configuração. Não prova o backend, a conta (pessoal ou corporativa) nem o dono.
   - Software de segurança que examina `rclone.exe` não executa `rclone.exe`.
   - Ausência por nome não exclui cópia renomeada; o discriminante é a linha de comando (`copy|sync|move <origem> <remote>:<destino>`, `--config`).

### Atribuição processo↔rede

- **Uma conexão é do processo** quando o registro de rede tem como ator a mesma instância (`processHashId`) no mesmo endpoint. Um registro de host sem ator não é atribuível a uma execução.
- **Firewall, FortiGate e flows:** bytes do host (`srcip`, `sentbyte`, `sourcebytes`) são tráfego do IP, não do processo.
  - A atribuição exige tupla (IP e porta de origem, destino, porta e protocolo) e horário coincidentes com uma conexão da instância.
  - NAT, proxy explícito e IP compartilhado mantêm o vínculo `candidato`.
- **Sessões:** tuplas diferentes são sessões diferentes. Respeite início e fim de cada sessão. Contadores cumulativos ou leituras repetidas da mesma sessão nunca são somados.

### Volume

1. **Trend:** `evidence_digest.transfer_counters` só contém campos com semântica de contador verificada. Os contratos auditados não verificam nenhum campo de bytes; `memoryBytes`, `fileBytesWritten` e `packetLossRate` ficam em `unclassified_metrics`, sem unidade, direção ou total.
2. **QRadar flows:** com IP do host e cobertura pertinente, chame `qradar_read_aql_resource` (campos de flows da implantação) e depois `qradar_run_aql` na janela.
3. **Contadores verificados:** preserve campo, direção, unidade, intervalo e identidade da sessão. A ponte nunca as soma quando há leituras repetidas.
4. **O que não é volume transferido:** tamanho de arquivo, quantidade de eventos e porta de destino.
5. **Sem contador utilizável:** declare as fontes e consultas feitas e o campo que falta. Não estime.

### Hipóteses e autorização

- **Hipóteses:** configuração legítima, execução sem transferência, transferência autorizada (backup ou sync sancionado) e exfiltração. Cite o que confirma ou refuta cada uma.
- **Autorização:** finalidade compatível com backup (comando, destino, agendamento, conta de serviço) não prova autorização. Separe execução confirmada, finalidade compatível e autorização pendente.
- **O que não fazer sem validação:** sem registro de autorização validado e sem o comportamento esperado conferido (host, conta, comando, destino e horário), não classifique como Benign True Positive e não recomende exceção, exclusão, allowlist ou tuning, nem mesmo provisória ou temporária. Recomende validar a autorização e manter pendente.
- **ATT&CK por estágio comprovado:** um artefato isolado sustenta no máximo Rclone (S1040). Com transferência demonstrada: nuvem → T1567.002; SFTP → T1048.002; FTP ou protocolo sem criptografia → T1048.003. T1560.001, T1074 e T1030 exigem evidência própria.

## Evidência esperada e falhas

- Coleta parcial, `limited` e `empty` seguem `soc-core.md`.
- Network ou detections vazios valem só no escopo da consulta executada.
- Fonte indisponível não apaga os estágios já comprovados.

## Continuação, escalonamento e parada

- Continue as fases e as partições.
- Delegue ao threat-hunter só a pergunta discriminante (por exemplo, atribuição de uma conexão à instância), com contrato e fração do orçamento.
- Pare quando a próxima evidência exigir log do aplicativo, confirmação no destino ou registro de autorização. Diga o impacto de cada um: o registro de autorização decide entre backup sancionado e exfiltração, mas não muda os fatos técnicos.

## Saída

1. O que aconteceu (fonte, uuid ou search ID, horário).
2. O que o XDR acrescentou.
3. Correlações confirmadas e candidatas.
4. Hipóteses testadas.
5. Conclusão técnica, estágio alcançado, volume com origem ou campo faltante, e confiança por achado.
6. Pendências externas e o seu impacto.

Mantenha separados o assessment da coleta inicial (`assessment.scope`, sem alteração) e o parecer do agente com as evidências complementares. A falta de registro de autorização não impede descrever os fatos técnicos confirmados.

## Tools permitidas

- `investigate_vision_alert`, `investigate_case`
- `investigate_offense_case`, `investigate_vision_event` (somente case-investigator)
- `trend_read_search_resource`, `trend_search_data`
- `qradar_read_aql_resource`, `qradar_validate_aql`, `qradar_start_aql`, `qradar_get_search_status`, `qradar_get_search_results`, `qradar_run_aql`
- `upstream_tools`, `upstream_tool_details`, `upstream_query`

Nenhuma tool de captura, bloqueio, isolamento ou alteração faz parte deste fluxo.

## Referências

`trend-search-conventions.md` (`xdr_followup`, `evidence_digest`, coleta parcial e identificadores) e `qradar-aql-conventions.md` (flows e AQL).
