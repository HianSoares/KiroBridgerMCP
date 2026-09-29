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

---

# Regra de permissão explícita (deny) para reforçar response-advisor — TESTADA, NÃO FUNCIONOU

**Status (2026-09-29): testada em ambiente real do Kiro e descartada.** A
proteção do `response-advisor` continua sendo só `tools: []` +
`includeMcpJson: false` (já validada antes, ver histórico abaixo). **Não
reaplicar esta mesma sintaxe sem antes investigar a causa raiz** — ver
"Resultado do teste" e "Causas possíveis não investigadas" no final deste item.

**Origem:** `response-advisor` já é somente-recomendação por construção
(`tools: []`, `includeMcpJson: false`, `includePowers: false`), testado e
funcionando. Essa barreira depende inteiramente do front matter desse agent
permanecer correto; não há hoje uma segunda camada técnica independente que
pegue uma edição futura (por engano) que adicione uma tool a esse perfil. A
ideia abaixo tentou resolver isso — o registro foi mantido para não repetir a
mesma tentativa sem entender por que ela falhou.

**Ideia proposta, fora do fluxo executável atual:** adicionar um bloco
`permissions:` **agent-scoped** (embutido no próprio front matter de
`.kiro/agents/response-advisor.md`, versionado com o projeto) usando o sistema
de permissões baseado em capacidades do Kiro (`permissions.yaml`/campo
`permissions`, que substituiu o modelo antigo de trusted commands):

```yaml
permissions:
  rules:
    - capability: mcp
      match: ["*"]
      effect: deny
    - capability: shell
      match: ["*"]
      effect: deny
    - capability: fs_write
      match: ["*"]
      effect: deny
    - capability: power
      match: ["*"]
      effect: deny
```

Escopo **agent-scoped, não workspace-scoped**: a documentação do Kiro
(kiro.dev/docs/permissions/, kiro.dev/docs/custom-agents/configuration-reference/)
é explícita que uma regra workspace-scoped fica em
`~/.kiro/workspace-roots/<hash>/permissions.yaml`, **fora do repositório e não
versionável** — quem clona o projeto não a recebe. Uma regra agent-scoped, por
outro lado, é explicitamente isolada ("scoped to this agent only", sem afetar
`case-investigator`/`threat-hunter`/`report-writer`) e vive no mesmo arquivo
`.md` já versionado.

**Motivação:** transformar parte da barreira de não-resposta em garantia
técnica adicional (deny de capability), e não só em ausência de tools
declaradas — reduzindo o risco de uma edição futura no front matter reintroduzir
uma tool de mutação sem que ninguém perceba, sem depender só de revisão manual
do PR.

**Pontos que já tinham sido registrados como incerteza antes do teste** (mantidos
para referência — o item abaixo confirma que pelo menos um deles era real):
- Sintaxe `match: ["*"]` com `effect: deny` por capability inteira não tinha
  exemplo idêntico na documentação consultada (só exemplos com match mais
  específico, ex. `my-server/*`, e `exclude` em regras de `allow`) — era
  extrapolação direta da sintaxe documentada.
- Não ficou claro na documentação como o campo `permissions:` (capability-based)
  interage com o campo `tools:` já usado nos 4 agents deste projeto.
- Confirmar que capabilities `shell`/`fs_write`/`power` de fato existem e têm
  esse nome exato na versão do Kiro instalada localmente.

**Resultado do teste (2026-09-29):** aplicado o bloco exatamente como acima em
`.kiro/agents/response-advisor.md` (agent-scoped), com uma tool de teste
(`investigate_demo`) adicionada a `tools:` e `includeMcpJson: true` — sem essa
segunda mudança a chamada MCP nem chegaria a existir para a regra interceptar.
Prompt de teste pediu explicitamente para o agent chamar `investigate_demo`.
**Resultado: `investigate_demo()` executou normalmente e retornou o relatório
fabricado. A regra `deny` não bloqueou a chamada.** A proteção efetiva
continuou sendo apenas a ausência da tool/MCP (`tools: []` +
`includeMcpJson: false`), não o bloco `permissions:`. Revertido imediatamente
após o teste; nenhuma versão com `permissions:` foi commitada.

**Causas possíveis não investigadas** (qualquer tentativa futura deve elucidar
isto primeiro, em vez de reaplicar a mesma sintaxe):
- Nome de capability incorreto para este contexto (`mcp` pode não ser o nome
  usado para chamadas de tool MCP dentro de um agent, apesar de a documentação
  pública listar `mcp` como capability).
- Escopo agent-scoped (campo `permissions:` no front matter do próprio agent)
  pode não estar implementado/suportado nesta versão do Kiro, mesmo a
  documentação descrevendo-o — só o `permissions.yaml` workspace/user-scoped
  pode estar de fato funcional.
- Sintaxe de `match` pode exigir um padrão diferente de `["*"]` para "bloquear
  tudo" (ex.: precisar do nome do server explícito, `soc-bridge-readonly/*`, em
  vez de um curinga genérico).
- Ordem/precedência real do motor pode divergir do que a documentação descreve
  (`deny > ask > allow` pode não estar sendo aplicado como documentado para
  regras dentro do próprio front matter do agent, em oposição a regras em
  arquivo `permissions.yaml` separado).
- Possível defasagem entre a documentação pública e a versão do Kiro
  efetivamente instalada (já ocorreu antes com o formato de front matter deste
  projeto).

**Critério de aceite (para uma tentativa futura, não para este item):**
identificar qual das causas acima é a real (ou outra) antes de reaplicar
qualquer sintaxe de `permissions:`; só então repetir o teste do parágrafo
acima com a nova sintaxe e confirmar bloqueio efetivo antes de considerar a
proteção válida. Até lá, `tools: []` + `includeMcpJson: false` continuam sendo
a única barreira confiável do `response-advisor`.
