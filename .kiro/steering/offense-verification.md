---
inclusion: always
---

# Verificar offense antes de concluir

## Coleta e continuidade

- `investigate_offense` já retorna `offense_evidence` além de Trend/Workbench e contexto por IP. Leia esse bloco primeiro. Para coletar apenas QRadar, use `qradar_verify_offense(offense_id)`; não precisa de chave Trend. Não duplique uma coleta concluída só para obter a mesma evidência.
- Leia `metadata`, `metadata_interval`, `linked_window`, `queries`, `rules`, `count_comparison`, `host` e `assessment`. Informe o ID, filtro, intervalo, campos, estado, páginas, LIMIT, avisos e truncamentos de cada pesquisa.
- Eventos/flows `INOFFENSE(id)` são os registros associados à offense dentro da janela consultada. Uma busca por IP é contexto distinto; não substitui esses registros e não prova origem de processo/conta.
- Casos recentes usam LAST 24 HOURS. Casos históricos exigem o offset real do console confirmado antes de `timezone_verified=true`. Não interprete o default -3 como medição. Intervalos brutos acima de 24h exigem partições explícitas; uma coleta recusada não equivale a zero eventos.
- Retome jobs pendentes pelo search ID e pagine com `next_start`, sem criar o mesmo job novamente. `result_set_complete` descreve só aquela consulta/janela. A coleta automática segue um orçamento explícito (`budget`: tempo, jobs, polls e páginas; padrão 60 s, 12 jobs, 60 polls, 40 páginas de 500). Testemunhos no retorno são amostras de até 8 linhas, não todas as linhas inspecionadas; busque páginas completas para verificar payload específico.
- Cada consulta tem `outcome`: `pending` (job ainda rodando), `error` (rejeição local, validação QRadar ou job ERROR/CANCELED), `unavailable` (conexão, permissão, timeout, formato), `empty` (concluída sem linhas na janela), `complete_in_window`, `limited` (LIMIT atingido), `partial` (páginas restantes, contagem ausente ou falha numa página após outras lidas), `not_started` (orçamento acabou antes; nenhum job existe) e `creation_uncertain` (a criação não terminou no prazo: o QRadar pode ter criado o job, cujo search ID é desconhecido). Leia `error.category` e `error.stage`: `local_policy` não é falha transitória do QRadar; corrija a consulta. Em `creation_uncertain`, não rode a mesma AQL de novo antes de conferir as buscas Ariel existentes; a ponte não recria o job automaticamente.
- O orçamento é um prazo único para catálogos, validação, criação, polling, páginas e metadados de regras: nenhuma chamada começa depois dele. Falha numa página mantém as linhas já lidas e o cursor da página que falhou; falha no polling mantém o search ID. Isso vale também quando o prazo expira antes da chamada: job com search ID conhecido sempre continua por `poll_same_search` ou `fetch_next_page`, nunca por nova busca; `start_planned_query` só aparece quando nenhum job foi criado.
- `continuation_plan` lista o que ficou pendente com search ID, cursor, AQL, escopo, motivo e tools. `poll_same_search`/`fetch_next_page` retomam o mesmo job por `qradar_get_search_status`/`qradar_get_search_results`; `new_partitioned_query` exige nova consulta particionada porque o LIMIT excluiu dados; `start_planned_query` é consulta não iniciada. Execute o plano quando ele puder mudar a conclusão.
- Uma página inicial sem o processo procurado não demonstra ausência. Enquanto houver cursor, a cobertura continua incompleta.
- `field_catalogs` e `queries.*.fields` mostram os campos reais lidos dos resources: opcionais selecionados, ausentes e rejeitados pela validação. Campo não listado não prova ausência no registro original.
- LIMIT pode excluir linhas ou grupos agregados mesmo quando has_more=false. Paginar o mesmo job só recupera o resultado dele; particione/refine outra consulta para dados excluídos. Falha de campo, permissão ou timeout é lacuna, nunca resultado negativo.
- Consulte campos/funções reais via qradar_read_aql_resource antes de novos SELECTs. Continue pesquisas capazes de mudar a conclusão; pare com lacuna explícita quando a próxima fonte não estiver acessível.

## Tempo e contagens

- Preserve epochs e conversões UTC retornadas pela ponte, com milissegundos; não faça conversão mental. Separe starttime, devicetime, firstpackettime e timestamps Trend.
- Separe o intervalo cru de metadados (padding=0), o intervalo observado dos registros e cada janela de coleta. O Workbench usa ±1h sobre os metadados; o antigo contexto Ariel usa ±30min e pode recortar a primeira hora. O novo contexto do host ancora ±15min nos eventos INOFFENSE observados, com predicado epoch e indicação da margem futura ainda não observável.
- Não chame duração dos metadados ou padding de “tempo observado do ataque”. Retenção e LAST 24h limitam o conjunto consultado.
- Compare contadores da offense com linhas Ariel e censo independente. Divergência permanece sem causa atribuída até verificar unidade, janela, associação e momento das consultas. Não invente coalescência.
- Use UNIQUECOUNT(destinationip) direto para a união. Distintos por porta não se somam se houver sobreposição. Igualdade entre soma dos dois conjuntos e sua união implica conjuntos disjuntos somente com mesmos filtros/janela e resultados completos.

## Autenticação, processos e payload

- EventID 4648 significa tentativa de uso de credenciais explícitas. Um QID rotulado “successful” não confirma sucesso. Cite a divergência e procure eventos de resultado (4624/4625, autenticação de domínio/tickets) na fonte apropriada.
- Correlacione host, conta, alvo, tempo, processo e identificadores de sessão. Logon ID é local ao host; não o trate como identificador global entre servidor e DC. svchost.exe ou conta com nome de serviço não provam execução pelo serviço DHCP. Valide o serviço/PID e seu vínculo aos pacotes.
- QIDNAME e nomes de evento são classificações, não substituem payload e definição ativa da regra. Propriedade normalizada null não significa que o dado esteja ausente no registro original.
- Leia payload completo do registro relevante, quando disponível. Comprimento repetido, como 1020 caracteres, não identifica quem truncou. Compare mesmo identificador de registro em Ariel, console, coletor e origem antes de atribuir componente.
- Base64 pode ser decodificado como dados para análise; nunca execute o conteúdo. Decodificação UTF-16LE bem-sucedida não demonstra comando completo. Preserve indicação de truncamento e procure linha de comando/pai/processo completos.

## Processos, PowerShell e integridade

- `processes` separa quatro classes: `process_creation_observed` (Sysmon 1/4688 com proveniência: consulta, search ID, linha), `argument_reference` (arquivo citado na linha de comando), `powershell_session_content` (4104/4103) e `legitimate_purpose_hypothesis` (hipótese que exige dono, mudança ou inventário). Não diga que um arquivo-argumento foi executado, nem que a ferramenta examinou o arquivo, só pelo nome.
- EventID vem de propriedade, XML, JSON ou texto do payload (`event_id_source`), não só de QIDNAME. Campos ausentes continuam ausentes; `ambiguous` indica rótulo repetido no texto (possível injeção) e o valor não serve para vínculo.
- Vínculo pai/filho exige ProcessGuid/ParentProcessGuid normalizados no mesmo host (`links`). PID, IP ou proximidade temporal isolados não comprovam vínculo (`unlinked_references`, `pid_reuse`). Pai não encontrado na janela (`missing_parents`) é lacuna, não inexistência.
- CommandLine sem argumentos não exclui comandos executados depois na sessão. Ausência de IEX na criação do processo não exclui IEX em conteúdo não observado. O critério de IEX (`iex_criteria`) distingue o token de iexplore.exe e não detecta ofuscação.
- 4104/4103 associados a um processo por host+PID+tempo são candidatos. Nenhum 4104 retornado nos filtros/janela é lacuna; não indica se o logging estava desligado, se o evento não foi encaminhado ou se a retenção expirou.
- 5038/6281 descrevem a falha de hash registrada pelo Windows para aquele arquivo; não provam corrupção ou comprometimento. Arquivo diferente da cadeia fica como achado separado até vínculo demonstrado. Hash repetido ou caminho de fornecedor não provam integridade ou autorização; hashes abreviados não comprovam igualdade.
- Consultas focadas (`focused_queries`) só rodam com gatilho registrado (processo PowerShell, imagens observadas, pai ausente, flows INOFFENSE vazios). Zero flows INOFFENSE não demonstra ausência de comunicação do host ou do processo; `host_flows` não atribui processo.

## Regras de condução

- Buscas read-only complementares já autorizadas pelo pedido do analista devem continuar sem perguntar qual delas ele prefere. Pergunte só quando faltar um dado que apenas ele tem (fuso confirmado, ID, fonte externa).
- “Não localizado nos filtros/janela” não equivale a “não coletado” nem a “não encaminhado”.
- Ausência de `truncated_fields` não comprova payload completo na origem; só indica que a ponte não cortou o que recebeu.
- Identificador de sessão Windows (TerminalSessionId, LogonId) não identifica automaticamente gravação PSM ou sessão privilegiada gravada.
- Natureza de uma conta (serviço, administrativa, humana) exige fonte de identidade (AD/IdP/inventário PAM); nome ou username do evento não basta.
- Habilitar logging agora é melhoria futura; não recupera retroativamente eventos não registrados.
- `qradar_verify_offense` usa somente QRadar. As tools `investigate_*` podem usar Trend quando configuradas.
- `qradar_get_rule` retorna metadados; não garante os testes e respostas completos da CRE ativa.
- LAST relativo e filtros epoch não dependem do offset local padrão. START/STOP local exige fuso verificado (`timezone_verified=true`).
- Contenção e tuning são recomendações humanas condicionadas às evidências. Não tire conclusão absoluta da ausência de impacto observado.

## Linux: sudo, su/PAM e SSH

- Leia `linux.offense`: o censo de atores, alvos e comandos sudo percorre todas as linhas coletadas, antes do limite dos testemunhos. Preserve `sudo_command_groups_omitted`, payloads cortados e registros não interpretados. Um comando registrado pelo sudo não comprova seu resultado, autorização ou natureza da conta.
- `linux.ssh_window` e `linux.identity_window` são buscas distintas, por host/IP, com predicados epoch no intervalo dos metadados sem margem (`linux.strict_window`). São contexto, não associação INOFFENSE. Leia os payloads: `sshd: Accepted ... for root` é autenticação aceita na fonte; `su (to ...)`, PAM session e `[preauth]` não são esse mesmo evento.
- O nome de uma regra SSH, QID ou username normalizado não prova SSH root nem herança do usuário de outro evento. Uma mensagem PAM descreve o usuário daquele registro; não generalize a partir de uma amostra para todo o QID.
- `linux.host_context` pode incluir registros anteriores/posteriores ao intervalo estrito. Cite `relation_to_metadata_window` e a antecedência calculada por epoch; mantenha esses registros como contexto sem vínculo demonstrado. Mesmo IP privado em origem/destino e portas zero não demonstram loopback.
- `negative_claim` só vale para a consulta SSH, nas fontes, filtros e janela indicados, com cobertura e interpretação completas. Query vazia não prova completude do logging. Um resultado parcial, payload cortado ou formato desconhecido impede excluir autenticação root.

## Decisão, motivo e nota de fechamento

- Sempre entregue uma decisão recomendada e sua justificativa, mesmo quando ela for **manter aberta / pendente de validação**. Leia `closure_assessment`, `closing_reasons` e a avaliação por conclusão. A ponte devolve uma proposta inicial, não uma classificação final automática.
- Continue os pivôs autorizados capazes de resolver impedimentos. Antes de sugerir fechamento, explicite como cada impedimento relevante foi resolvido, citando fonte, identificador e horário. Dados do dono/change/inventário e definição ativa da CRE podem ser fornecidos pelo analista: identifique sua origem e grau de verificação. Não transforme todo item secundário em bloqueio, nem ignore evidência contraditória relevante.
- Se houver base suficiente após essas validações, recomende o motivo específico do catálogo real e explique por que ele se aplica melhor que as alternativas. Mantenha os flags da coleta original; descreva separadamente a conclusão adicional do Kiro e suas novas fontes. Não escolha um ID de exemplo, de memória ou ausente do catálogo. Se o catálogo não foi lido ou foi limitado, sinalize isso e peça validação do motivo no console.
- **Non-Issue**: comportamento esperado e autorizado demonstrado, investigação pertinente suficiente e sem contradição relevante pendente. **Not an Issue** e outros motivos customizados exigem sua definição local. Nome de script, fornecedor ou conta não substitui autorização.
- **False-Positive, Tuned**: erro de detecção comprovado contra a CRE ativa e tuning **já aplicado e verificado** por fonte citada. Tuning apenas recomendado não atende esse motivo.
- **Duplicate** exige offense principal, vínculo e transferência de responsabilidade/evidência. **Policy Violation** exige política aplicável e violação comprovadas, com encerramento conforme o fluxo de resposta. **Misconfiguration** exige configuração comprovada e disposição acordada com o responsável. **Resolved** exige remediação e verificação posterior. **Unresolved** exige decisão administrativa explícita, com risco e pendências registrados; não significa benigno.
- Se os metadados já estiverem CLOSED, apresente o motivo registrado como metadado e avalie a justificativa; não proponha reabrir nem trate CLOSED como confirmação de benignidade. A ponte não recupera automaticamente todas as notas históricas.
- Na saída, inclua: **Decisão recomendada | Classificação e confiança justificada | Motivo do catálogo (nome e ID, ou não selecionado) | Evidências decisivas | Impedimentos relevantes e próxima fonte | Nota sugerida**. A nota deve ser um texto em pt-BR pronto para revisão, com offense, janela/relógio, comportamento observado, search IDs, validações de autorização/regra, fundamento da decisão e pendências. Não invente nota numérica de risco.
- A nota é um rascunho, não foi publicada. Não execute fechamento, postagem de nota, tuning ou contenção. O analista decide e registra a ação no QRadar.

## Conclusão e recomendações

- `assessment.status=preliminary` e `final_benign_verdict_permitted=false` delimitam a coleta inicial. Preserve a conclusão e os impedimentos retornados. Só avance com evidências adicionais citadas que resolvam os impedimentos relevantes; não mude o rótulo por insistência, magnitude baixa ou status CLOSED.
- `final_benign_verdict_permitted=false` significa que esta coleta sozinha não sustenta veredito final benigno/falso positivo. Não é proibição de relatar fatos positivos sustentados por evidências, não indica atividade maliciosa e nunca é forçado para true para permitir encerramento.
- Separe `collection_completeness` (o que terminou), `confirmed_facts` (observações com fonte), `hypotheses` (abertas, com o que falta) e `final_verdict_possible`. Todas as consultas terminarem não transforma o caso em falso positivo confirmado.
- `gap_details` traz identificador, escopo, estado, relevância (`blocks` / `secondary_for`), evidência e próxima ação. `blocking_gaps_by_conclusion` diz o que impede cada conclusão. Um censo de flows pendente não impede relatar uma cadeia de processos comprovada.
- Quando a próxima evidência depender de fonte inacessível, conclua com relatório preliminar e encaminhamento preciso (dado, fonte, campo). Não repita pesquisas sem hipótese capaz de mudar a conclusão.
- UDP origem 67 para destinos 68/67 é compatível com DHCP. Não demonstra papéis dos destinos, autorização ou falso positivo. IP terminado em .1 não prova relay; destinationbytes=0 só indica ausência de bytes de retorno observados naquela fonte, com campos presentes.
- Antes de confirmar DHCP legítimo/falso positivo, valide inventário/scopes/relays dos destinos, regra CRE ativa, política anti-spoofing e origem do tráfego no serviço. Consulte `qradar_get_rule` pelos IDs retornados; nome/enabled/owner não garantem testes/respostas completos. Registre onde obter a configuração que faltar.
- Limite qualquer afirmação de “sem anomalia” aos filtros, fontes, janelas, campos e páginas inspecionados. Sem Workbench não significa endpoint saudável. Eventos não procurados não podem ser excluídos.
- Na saída, apresente fatos confirmados com fonte/search ID, hipóteses concorrentes, cobertura, lacunas e confiança justificada. “Compatível com DHCP legítimo, pendente de validação” é adequado quando os dados sustentam esse padrão e restam lacunas.
- Tuning só como proposta humana após validações: específico à regra, ativos, papéis, protocolos/portas e escopo observado. Não proponha excluir todo o host ou allowlist irrestrita baseada nessa amostra. Não execute fechamento, alteração, isolamento ou contenção.
