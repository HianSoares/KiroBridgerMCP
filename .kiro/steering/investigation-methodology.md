---
inclusion: always
---

# Método de investigação

1. **Enquadrar:** registre referência, gatilho exato, fonte, relógio e fuso, ativo, usuário e severidade conforme recebidos. Uma referência não é evidência de execução maliciosa.
2. **Coletar antes de concluir:** chame a tool de entrada adequada. Extraia do relatório quais consultas Ariel, Workbench, Trend Search e outras realmente foram executadas, seus estados e seus limites. Em offense sem Workbench, examine a seção de Ariel e atividade/detecções de endpoint; se ausentes, anote a lacuna. Esse fluxo foi validado no caso de exemplo 90210: ausência de alerta Workbench e busca Trend por IP com zero linhas foram relatadas separadamente; o caso de exemplo 90211 não foi usado para validar a correção.
3. **Separar fato de hipótese:** marque cada alegação como `confirmado` (campo observado na fonte), `candidato` (correlação ainda não atribuída) ou `não verificado` (manual, ausente ou não corroborado). Proponha hipóteses maliciosa, legítima e de erro de detecção e diga o teste que sustentaria ou refutaria cada uma.
4. **Pivotar com escopo:** correlacione IP, usuário, host, hash, processo e domínio apenas nas consultas que a ponte realmente fez. Para cada pivô, declare janela, fuso, filtro, estado, linhas e truncamento conforme o relatório; campos manuais de `investigate_vision_event` continuam não verificados pela ponte.
5. **Causa raiz:** faça perguntas dos “5 porquês” como roteiro. Só apresente vetor inicial, privilégio obtido e falha de controle como causa confirmada se houver evidência específica. Se interromper por falta de dados, informe a próxima fonte e o campo necessário.
6. **Classificar:** descreva severidade observada versus severidade avaliada, impacto demonstrado versus potencial, técnica MITRE ATT&CK quando sustentada e confiança qualitativa. Não transforme rótulo do produto em veredito próprio.
7. **Recomendar, sem executar:** proponha contenção, depois erradicação e recuperação para revisão humana, indicando pré-condições e risco de impacto. Não instrua o Kiro a fazer mudanças em ferramentas ou ativos.
8. **Melhorar detecção:** indique tuning específico, IOC verificável, fonte de log ausente e lição aprendida. Se uma busca necessária não existir entre as sete tools, registre a capacidade como sugestão de melhoria da ponte, fora do fluxo executável.

Termine com uma seção “O que falta e onde obter”: por exemplo linha de comando do processo na Trend, DHCP histórico para vínculo IP/host, NAT/proxy para origem, ou justificativa da disposition no Workbench. “Sem alerta Workbench” e “sem atividade no endpoint” são afirmações diferentes.

**Limite da ponte:** as sete tools não expõem AQL livre nem payload bruto. Em `investigate_offense`, o SELECT Ariel é fixo (`starttime`, `sourceip`, `sourceport`, `destinationip`, `destinationport`, `username`, `QIDNAME(qid)`, `LOGSOURCENAME(logsourceid)`). Se um evento PAM de escalação tiver `username` vazio, reexecutar a mesma tool não recupera `sourceUserName`, `targetUserName`, hostname ou payload. Registre a identidade como não verificada e direcione o analista ao Log Activity do QRadar para inspecionar manualmente esses campos no evento.
