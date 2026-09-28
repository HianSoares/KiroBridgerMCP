# kiro-pack/BRIDGE-BACKLOG.md

# Sugestão de melhoria da ponte soc-bridge-readonly

**Origem:** limite observado na offense 90210 (exemplo); eventos “PAM Su User Impersonation” e “Privilege Escalation Succeeded” retornaram `username` vazio.

**Mudança proposta, fora das configurações do Kiro:** oferecer pivô de leitura limitado por QID/`event_name` com janela e `LIMIT` obrigatórios; nas consultas de escalação, ampliar o SELECT para incluir `sourceUserName`, `targetUserName` e payload bruto (além de hostname quando disponível). Validar nomes e disponibilidade reais dessas propriedades na implantação QRadar antes de implementá-las. Rotular campo ausente, dado truncado e identidade não verificada separadamente.

**Critério de aceite:** diante de evento PAM com `username` vazio, a ponte consulta, dentro da janela autorizada, o evento correto e retorna a identidade com referência explícita ao campo e log source, ou informa com clareza que ela continua indisponível. Nenhuma ação de resposta nem busca ambiental irrestrita.

---

# Sugestão futura: roteamento determinístico de agent por padrão de entrada

**Origem:** operação atual depende da heurística da sessão para decidir entre a
sessão padrão e os agents do pacote (case-investigator, threat-hunter,
report-writer, response-advisor). Não há mecanismo que garanta, de forma
determinística, que um pedido caia sempre no agent correto. A convenção
combinada com o usuário (investigação livre; playbook/resposta sempre via
response-advisor por causa da barreira `tools: []`) é comportamental, não
estrutural.

**Ideia proposta, fora das configurações atuais do projeto:** um mecanismo
determinístico — hook ou configuração — que force o roteamento por padrão de
entrada, por exemplo:
- referência de offense / alerta WB- / evento / UAC / reputação web →
  agent de investigação (ex.: case-investigator);
- pedido de contenção/erradicação/recuperação/playbook de resposta →
  sempre response-advisor (`tools: []`, `includeMcpJson: false`), nunca a
  sessão padrão nem um agent com tools.

**Motivação:** transformar a barreira de resposta em garantia estrutural
(não apenas comportamento esperado do modelo), reduzindo o risco de um pedido
de ação ser respondido por um contexto que tenha tools disponíveis.

**Pontos a avaliar antes de implementar:**
- Qual gatilho/tipo de hook seria adequado (ex.: promptSubmit) e como classificar
  a intenção de entrada com segurança, tratando ambiguidade como "perguntar antes".
- Como evitar falsos roteamentos (um pedido de investigação não deve ser barrado;
  um pedido de resposta nunca deve escapar para contexto com tools).
- Preservar o escopo somente-leitura e não introduzir execução de ação.
- Não alterar `.kiro/settings/mcp.json`, credenciais nem código dos servidores MCP
  sem revisão.

**Critério de aceite:** dado um padrão de entrada conhecido, o roteamento para o
agent correto ocorre sem depender da heurística da sessão; pedidos de
resposta/playbook são sempre atendidos por um perfil sem tools; entradas ambíguas
resultam em pergunta ao usuário, não em decisão automática.
