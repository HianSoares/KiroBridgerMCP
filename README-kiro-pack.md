# kiro-pack/README-kiro-pack.md

# SOC Bridge Investigator — pacote Kiro

Este pacote mantém o Kiro como interface para o MCP único `soc-bridge-readonly`. As configurações ficam em `kiro-pack/.kiro/` para instalação seletiva no projeto existente. Não substitua o `mcp.json` que já funciona; mescle apenas a lista de sete nomes do `autoApprove-snippet.json` após verificar no código instalado a allowlist de tools upstream. Todas as sete tools foram descritas como somente leitura, sem ações de resposta.

## Estado da validação real

Na offense QRadar **90210 (exemplo)**, `investigate_offense` distinguiu corretamente ausência de alerta Workbench de uma busca Trend por IP com zero linhas, classificou achados como confirmado/candidato/não verificado e indicou que o offset de timezone era presumido, não medido. Isso valida a correção da ponte para offense sem alerta Workbench nesse caso. A offense **90211 (exemplo) não foi testada** como validação dessa correção.

## Limite observado

Na mesma investigação apareceram eventos “PAM Su User Impersonation” e “Privilege Escalation Succeeded” com `username` vazio. O AQL interno de `investigate_offense` possui SELECT fixo de `starttime`, `sourceip`, `sourceport`, `destinationip`, `destinationport`, `username`, `QIDNAME(qid)` e `LOGSOURCENAME(logsourceid)`. As sete tools não aceitam AQL livre, filtro por QID/tipo, outras colunas ou payload bruto. Portanto, a identidade da escalação deve permanecer **não verificada** até inspeção manual dos eventos no QRadar Log Activity, especialmente `Username`, as propriedades customizadas de usuário que o DSM expuser (nomes variam por implantação, ex.: “Source Username”/“Target Username”), Log Source Time, hostname e payload.

## Instalação do bloco 3

Copie os quatro arquivos de `kiro-pack/.kiro/agents/` para a pasta `.kiro/agents/` do projeto. Atualize também os dois arquivos deste bloco em `.kiro/steering/investigation-methodology.md` e `.kiro/skills/offense-investigation/SKILL.md`. Revise a lista `tools` de cada agent no Kiro: são nomes exatos do `soc-bridge-readonly`; `response-advisor` tem lista vazia e não carrega MCP. Teste `case-investigator` com `investigate_demo` antes de investigar dados reais; no caso de exemplo 90210, confira a seção “O que falta e onde obter” sem inventar o usuário PAM.

Este README registra o status e a instalação do bloco 3. O guia completo de ordem de instalação e testes ponta a ponta será entregue no bloco de README previsto no escopo do pacote. Exemplos públicos devem usar apenas dados fictícios; a referência 90210 aqui é um registro fabricado de validação, sem detalhes de IP, host, usuário ou payload.
