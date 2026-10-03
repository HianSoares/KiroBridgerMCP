# SOC Bridge — pacote Kiro

Kiro continua conectado somente a `soc-bridge-readonly`. A ponte oferece sete
tools de investigação, seis tools `qradar_*` de AQL personalizada e duas de
verificação (`qradar_verify_offense`, `qradar_get_rule`), duas de descoberta/lotes de offenses e `trend_find_alerts`, além de `qradar_read_context`, `qradar_assess_closure` e `qradar_list_offenses` para fila/prioridade, totalizando 21. Estas
permitem ler os resources do QRadar, validar/iniciar buscas, recuperar payload,
flows e campos selecionados, e acompanhar/paginar o mesmo search ID.

Atualize juntos o Python instalado e os arquivos `.kiro/` versionados. Versões
antigas dos agents, steering e skills proíbem AQL e descrevem payload como
inacessível. Não sobrescreva um `mcp.json` funcional nem suas preferências de
`autoApprove`: o configurador continua preservando as escolhas existentes.

`case-investigator` e `threat-hunter` incluem AQL e verificação em suas listas.
`report-writer` mantém as duas tools de redação/coleta inicial e encaminha
lacunas para o investigador. `response-advisor` mantém `tools: []` e nenhum
MCP carregado; planos de resposta continuam sujeitos à execução humana.

Teste `investigate_demo` sem credenciais. Para consultas reais, siga
[atualização, exemplos e limites de AQL](docs/dynamic-aql.md) e confirme os
campos disponíveis no deployment. Os testes automatizados usam dados fictícios,
incluindo um servidor MCP HTTP local; não representam validação no QRadar real.

Para alertas Workbench, leia a [investigação de alertas Trend](docs/trend-alert-investigation.md):
extração estruturada, descoberta independente do modelo, enriquecimentos em leitura,
correlação QRadar e classificação recomendada com nota para revisão humana.

Leia [verificação e critérios de conclusão](docs/offense-verification.md). A
coleta de offense agora devolve `continuation_plan`, classes de evidência de
processo/PowerShell/integridade e lacunas estruturadas; as instruções em
`.kiro/` explicam como continuá-la e concluir proporcionalmente.
Atualize/reconecte o MCP e abra um chat novo no Kiro para recarregar schemas e
instruções. O assessment da coleta inicial permanece preliminar quando houver
lacunas de cobertura, regra, autorização ou atribuição.

Sem ID Trend, peça "Veja se há alertas abertos na Trend nas últimas 24 horas". Os agents de investigação expõem `trend_find_alerts`; leia [limites da descoberta](docs/trend-alert-discovery.md). Reconecte o MCP e inicie novo chat após atualizar Python e `.kiro/`.

Kiro no Windows com a ponte no WSL 2: veja o [guia WSL](docs/guia-wsl.md). O
`mcp.json` desse caminho usa `wsl.exe`; reconecte o MCP depois de rodar
`scripts/configure_kiro_wsl.py`.
