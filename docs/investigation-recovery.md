# Investigação, falhas e retomada

Um pedido claro no chat autoriza as leituras necessárias. O Kiro deve escolher a
tool real, executar, interpretar, continuar as buscas pertinentes e entregar
decisão recomendada, razão, confiança justificada e nota para revisão humana.
Não é necessário aprovar novamente cada consulta ou pedir a montagem do relatório.

- Offense por ID: `investigate_offense_case` e o mesmo `case_id` nas continuações.
- Offenses abertas sem descrição: `qradar_list_offenses(status="OPEN")` e todos os
  cursores do escopo solicitado; prioridade é a ordem pelos metadados, não veredito.
- Offenses com a mesma descrição: `qradar_investigate_offenses` e seus lotes/cursores.
- Alertas Trend abertos: `trend_find_alerts(status="OPEN")`; o padrão seleciona
  as últimas 24h, incluindo Open/In Progress, e não todo o histórico aberto.
- Alertas conhecidos: `investigate_vision_alert`, um por vez. Falha em um alerta
  não deve impedir a investigação independente dos demais.

## Relatório preservado ao encerrar conexões

O coletor pode terminar e, depois, o SDK falhar ao fechar uma sessão ou transporte.
As entradas de investigação preservam o relatório e acrescentam
`connection_lifecycle.shutdown_errors`, com fonte, componente e motivo seguro.
Esse aviso não muda os estados de cobertura nem invalida evidências observadas.
Não execute de novo as buscas concluídas só porque o encerramento falhou.

Cada recurso é encerrado na mesma task que o abriu, como exigem os cancel scopes
do SDK. A espera tem limite de dez segundos por recurso. Erros comuns ao encerrar
não impedem as tentativas de fechar os recursos restantes. Cancelamento continua
sendo cancelamento, e falha de encerramento não substitui um erro anterior de coleta.

## Evidência parcial e diagnósticos

Na entrada de alerta WB, a Trend é a fonte primária. Se a conexão/inicialização
do QRadar falhar, seus recursos são encerrados antes de continuar a coleta
Trend. O relatório preserva a evidência Trend e declara a correlação QRadar como
não executada, com a falha de conexão/permissão identificada. Falha de
inicialização da própria Trend não produz um relatório inventado.

Depois do detalhe Workbench validado, falhas em fases secundárias são relatadas
em `collection.errors`, preservando os resultados anteriores. Search/OAT mantém
os registros e pivôs concluídos antes de uma interrupção. A correlação Ariel
mantém checkpoints antes da criação, ao receber o search ID e após cada página.
`collection.state=returned` significa que o coletor retornou, não que todas as
fontes/janelas foram consultadas integralmente. Leia cada consulta, cap e plano.

Erros de permissão, licença, parâmetros rejeitados, conexão e formato são lacunas
diferentes. A ponte não deduz qual produto causou um erro quando a fonte não foi
identificada. Nenhum desses estados significa zero atividade nem falso positivo.

`bridge_diagnostics` verifica conexão, inicialização e descoberta; não repara uma
sessão anterior nem comprova acesso a todas as APIs. Seu ledger acumula chamadas
desde o início do processo. No relatório de alerta, `call_outcomes` pertence àquela
tentativa; `reused_read` indica reutilização, sem uma chamada nova. O orçamento
mostra separadamente leituras/registros/partições reutilizados: eles não consomem
o teto de novas leituras e não podem impedir o avanço na retomada.

## Retomar um alerta

Na mesma ponte em execução, uma chamada do mesmo alerta com os mesmos parâmetros
e credenciais reutiliza leituras bem-sucedidas e continua jobs Ariel conhecidos.
Chamadas do mesmo alerta são serializadas. Criação, validação, polling e resultados
Ariel nunca são memoizados: a continuação consulta o estado/página do mesmo job.
Uma criação incerta continua incerta; a ponte não cria automaticamente outra busca.

O estado é separado por alerta, endpoint MCP, região, credenciais e parâmetros.
Credenciais entram somente na impressão digital da chave de isolamento, nunca
em mensagens ou arquivos. Leituras reutilizadas são cópias e pertencem à janela
do primeiro snapshot; `resumption` declara o início do snapshot e a tentativa atual.

**Este estado é temporário:** até quinze minutos de inatividade, quatro alertas
por event loop, com oito MiB de leituras memoizadas por alerta. O limite existente
do coletor restringe jobs/linhas, que são guardados separadamente das leituras.
Reinício, expiração e remoção por limite eliminam a memória. Não é armazenamento
durável de casos Trend. Alertas em execução ou aguardando a sua vez não são removidos.

Depois da perda desse estado, use os planos já devolvidos: `qradar_get_search_status`
e `qradar_get_search_results` com o search ID/cursor. Não repita a investigação
inteira às cegas. Os planos de continuação são exibidos integralmente em Markdown,
mesmo quando as amostras de evidência são abreviadas. Consultas retomadas diretamente
pelas tools AQL devem ser citadas junto ao relatório; não são incorporadas
automaticamente a um relatório de alerta anterior.

Para `creation_uncertain`, verifique os jobs Ariel antes de tentar criar outra
busca. Para `limited`, a paginação do mesmo job não recupera dados excluídos pelo
LIMIT: uma nova partição/refinamento exige hipótese e escopo explícitos.

## Limites de conclusão

A autonomia é de investigação. A ponte não altera offenses, publica notas,
isola endpoints ou executa contenção. Lacunas só bloqueiam as conclusões que
dependem delas; registros observados continuam válidos. A correlação iniciada pelo alerta usa os mesmos critérios conservadores de
identidade de execução dos casos: hashes completos divergentes e identificadores
conhecidos conflitantes impedem confirmação, mesmo com PID/caminho próximos.
Nome de alerta, caminho
de ferramenta, conta ou conexão bem-sucedida não demonstram autorização, malícia
ou exfiltração. A razão e a nota devem citar evidência decisiva e o que permanece pendente.

Os testes usam dados sintéticos, incluindo um subprocesso stdio com o SDK real
e uma API HTTP local que retorna 401 para verificar a continuação da Trend.
A causa de uma falha específica do ambiente ainda depende dos logs locais
sanitizados; o projeto não acessa credenciais ou telemetria reais durante os testes.
