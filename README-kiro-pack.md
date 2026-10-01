# SOC Bridge — pacote Kiro

Kiro continua conectado somente a `soc-bridge-readonly`. A ponte oferece sete
tools de investigação e seis tools `qradar_*` de AQL personalizada. Estas
permitem ler os resources do QRadar, validar/iniciar buscas, recuperar payload,
flows e campos selecionados, e acompanhar/paginar o mesmo search ID.

Atualize juntos o Python instalado e os arquivos `.kiro/` versionados. Versões
antigas dos agents, steering e skills proíbem AQL e descrevem payload como
inacessível. Não sobrescreva um `mcp.json` funcional nem suas preferências de
`autoApprove`: o configurador continua preservando as escolhas existentes.

`case-investigator` e `threat-hunter` incluem as seis novas tools em suas listas.
`report-writer` mantém as duas tools de redação/coleta inicial e encaminha
lacunas para o investigador. `response-advisor` mantém `tools: []` e nenhum
MCP carregado; planos de resposta continuam sujeitos à execução humana.

Teste `investigate_demo` sem credenciais. Para consultas reais, siga
[atualização, exemplos e limites de AQL](docs/dynamic-aql.md) e confirme os
campos disponíveis no deployment. Os testes automatizados usam dados fictícios,
incluindo um servidor MCP HTTP local; não representam validação no QRadar real.
