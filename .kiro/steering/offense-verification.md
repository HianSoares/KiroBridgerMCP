---
inclusion: always
---

# Verificar offense antes de concluir

## Coleta e continuidade

- `investigate_offense` já retorna `offense_evidence` além de Trend/Workbench e contexto por IP. Leia esse bloco primeiro. Para coletar apenas QRadar, use `qradar_verify_offense(offense_id)`; não precisa de chave Trend. Não duplique uma coleta concluída só para obter a mesma evidência.
- Leia `metadata`, `metadata_interval`, `linked_window`, `queries`, `rules`, `count_comparison`, `host` e `assessment`. Informe o ID, filtro, intervalo, campos, estado, páginas, LIMIT, avisos e truncamentos de cada pesquisa.
- Eventos/flows `INOFFENSE(id)` são os registros associados à offense dentro da janela consultada. Uma busca por IP é contexto distinto; não substitui esses registros e não prova origem de processo/conta.
- Casos recentes usam LAST 24 HOURS. Casos históricos exigem o offset real do console confirmado antes de `timezone_verified=true`. Não interprete o default -3 como medição. Intervalos brutos acima de 24h exigem partições explícitas; uma coleta recusada não equivale a zero eventos.
- Retome jobs pendentes pelo search ID e pagine com `next_start`, sem criar o mesmo job novamente. `result_set_complete` descreve só aquela consulta/janela. A coleta automática limita a 10 páginas de 500 linhas; testemunhos no retorno são amostras de até 8 linhas, não todas as linhas inspecionadas. Busque páginas completas para verificar payload específico.
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

## Conclusão e recomendações

- `assessment.status=preliminary` e `final_benign_verdict_permitted=false` delimitam a coleta inicial. Preserve a conclusão e os impedimentos retornados. Só avance com evidências adicionais citadas que resolvam os impedimentos relevantes; não mude o rótulo por insistência, magnitude baixa ou status CLOSED.
- UDP origem 67 para destinos 68/67 é compatível com DHCP. Não demonstra papéis dos destinos, autorização ou falso positivo. IP terminado em .1 não prova relay; destinationbytes=0 só indica ausência de bytes de retorno observados naquela fonte, com campos presentes.
- Antes de confirmar DHCP legítimo/falso positivo, valide inventário/scopes/relays dos destinos, regra CRE ativa, política anti-spoofing e origem do tráfego no serviço. Consulte `qradar_get_rule` pelos IDs retornados; nome/enabled/owner não garantem testes/respostas completos. Registre onde obter a configuração que faltar.
- Limite qualquer afirmação de “sem anomalia” aos filtros, fontes, janelas, campos e páginas inspecionados. Sem Workbench não significa endpoint saudável. Eventos não procurados não podem ser excluídos.
- Na saída, apresente fatos confirmados com fonte/search ID, hipóteses concorrentes, cobertura, lacunas e confiança justificada. “Compatível com DHCP legítimo, pendente de validação” é adequado quando os dados sustentam esse padrão e restam lacunas.
- Tuning só como proposta humana após validações: específico à regra, ativos, papéis, protocolos/portas e escopo observado. Não proponha excluir todo o host ou allowlist irrestrita baseada nessa amostra. Não execute fechamento, alteração, isolamento ou contenção.
