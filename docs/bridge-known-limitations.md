# Limites de coleta da ponte

As sete tools `investigate_*` fazem coleta limitada. `investigate_offense` agora
acrescenta registros INOFFENSE, flows, censo COUNT/UNIQUECOUNT e regras à coleta
antiga por IP, rotulada como contexto. Identidade não atribuída continua
não verificada; repetir a mesma chamada não resolve falta de armazenamento.

Seis tools `qradar_*` permitem AQL personalizada, campos reais do DSM,
payload selecionado, flows, agregações e paginação por search ID. Veja
[fluxo, atualização e limites](dynamic-aql.md). `investigate_offense` também
exibe o search ID de cada busca Ariel quando fornecido pelo upstream.

`qradar_verify_offense` coleta somente no QRadar; `qradar_get_rule` lê metadados
de regras. As 15 tools e as avaliações preliminares seguem o
[fluxo de verificação](offense-verification.md). Metadados não incluem
necessariamente os testes/respostas completos da regra ativa.

Alertas Trend seguem o [fluxo de investigação de alertas](trend-alert-investigation.md),
que também lista as lacunas que dependem do MCP oficial da Trend (Search sem token
de continuação, notas sem paginação encaminhada, Search sem campo `uuid`, DMM sem
filtro por nome, insights apenas por ID de insight).

## Limites que continuam relevantes

- Campos customizados variam por implantação. Leia os resources; não presuma
  `sourceUserName`/`targetUserName` ou um Event ID Windows normalizado.
- Payload depende de armazenamento, retenção e permissões. Não pode ser
  reconstruído pela ponte quando ausente. Campos truncados são sinalizados.
- `starttime` e `devicetime` têm relógios diferentes. START/STOP usa o fuso
  do console; o padrão -3 dos coletores fixos não é uma medição do ambiente.
- Consultas individuais permitem até 24h; agregadas sem payload até 30 dias
  com justificativa. LIMIT restringe retorno, não custo total da varredura.
  Jobs pendentes podem ser retomados; resultado paginado não prova cobertura
  integral. As consultas próprias não passam a integrar automaticamente o
  relatório anterior: o Kiro deve citar ambos os retornos e suas fontes.
- Contar usuários observados em eventos não é contar objetos do Active
  Directory. Total de contas, contas habilitadas e escopo de domínio/floresta
  exigem inventário LDAP/AD ou outra fonte com autoridade sobre esse escopo.
- Flows, quando coletados, não demonstram conteúdo de aplicação ou o processo
  responsável. Muitos destinos UDP/67/68 não comprovam DHCP legítimo.
- A extração de processos reconhece propriedades listadas nos resources e três
  formatos de payload (XML de evento Windows, JSON e texto Sysmon/4688/4104/5038).
  Formatos de DSM diferentes podem deixar campos ausentes; isso é lacuna, não
  ausência no registro original. Rótulo repetido no texto torna o campo ambíguo.
- Vínculos pai/filho dependem de ProcessGuid/ParentProcessGuid e host no mesmo
  registro; Security 4688 sem GUID não gera vínculo. A busca de pai fica na janela
  do host (±15 min dos eventos INOFFENSE) e se limita a quatro consultas.
- O critério de IEX não detecta ofuscação (backticks, concatenação, aliases
  criados em tempo de execução). Associação de 4104 a processo por host+PID+tempo
  é candidata. Nenhum 4104 retornado não indica o estado do logging na origem.
- O orçamento padrão (60 s, 12 jobs, 40 páginas) pode encerrar a coleta antes
  das consultas focadas; o `continuation_plan` indica o que retomar.
- A ponte não consulta inventário de identidade, DHCP, PSM ou política de
  firewall. Natureza de conta, gravação de sessão e autorização continuam
  dependendo dessas fontes.
- A ponte não fecha offenses, altera regras, cria notas, isola endpoints nem
  executa contenção. As buscas AQL criam jobs de consulta no Ariel.

Os testes são sintéticos, incluindo transporte MCP HTTP local. Disponibilidade
das fontes, dados históricos e permissões precisam ser verificados na instalação.
