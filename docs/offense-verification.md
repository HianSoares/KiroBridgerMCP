# Verificação de offense e conclusão baseada em evidências

A ponte expõe 15 tools: sete de investigação, seis de AQL e duas de verificação.
`investigate_offense` acrescenta `offense_evidence` ao relatório, além do contexto
por IP e dos resultados Trend. `qradar_verify_offense` devolve essa coleta como
JSON usando apenas QRadar; não exige chave Trend. `qradar_get_rule` consulta
metadados das regras pelos IDs que a offense retorna.

## O que a nova coleta faz

1. Preserva os metadados e seus timestamps originais sem padding.
2. Lê resources de campos e valida SELECTs de eventos e flows com INOFFENSE(id),
   incluindo portas de origem/destino, bytes, devicetime e payload quando disponíveis.
3. Faz COUNT(*) e UNIQUECOUNT(destinationip) independentes nos flows. Calcula
   a união de destinos nas linhas coletadas sem somar distintos por porta.
4. Segue páginas do mesmo search ID e registra consulta, estado, janela, LIMIT,
   páginas, quantidade, avisos e truncamentos. Compara contadores sem inventar
   explicação para divergências.
5. Consulta os IDs de regras contribuintes. O upstream pode retornar apenas
   metadados; a configuração completa de testes/respostas permanece uma lacuna.
6. Busca contexto de autenticação/processos do IP da offense em ±15min dos
   timestamps starttime observados. Usa predicados epoch em milissegundos e
   distingue essa busca contextual dos eventos associados à offense.
7. Identifica 4648 como tentativa de credenciais e decodifica EncodedCommand
   como dados UTF-16LE para análise, sem executar comandos ou garantir completude.
8. Retorna assessment preliminar com impedimentos explícitos. Porta/protocolo
   compatíveis com DHCP não bastam para classificar a atividade como autorizada.

## Como pedir ao Kiro

> Use qradar_verify_offense para a offense informada. Leia os metadados originais,
> registros INOFFENSE, flows, censo de destinos, regras e contexto do host.
> Retome search IDs pendentes, verifique os payloads relevantes e continue os
> pivôs que possam mudar a conclusão. Cite cobertura e lacunas; mantenha a
> conclusão preliminar enquanto faltar validação relevante.

Para histórico, confirme o offset efetivo do QRadar e só então informe
`qradar_utc_offset_hours` e `timezone_verified=true`. O default -3 não é medição.
Casos recentes usam LAST 24 HOURS; isso limita a associação à janela de 24h,
não garante que todo o histórico da offense tenha sido coletado. Intervalos
históricos acima de 24h exigem partições adicionais via AQL. O host pivotado
precisa de offense_source com IP válido e eventos associados com timestamp.

## Cobertura e conclusão

A coleta automática usa LIMIT 5000, páginas de até 500 e orçamento de 10 páginas
por consulta. LIMIT atingido ou record_count desconhecido impede alegar resultado
integral. O retorno conserva até oito testemunhos por consulta e até 2000
caracteres de payload por testemunho; previews cortados são marcados. Use as
páginas do search ID para inspeção detalhada. Limites de caracteres das páginas
AQL também são reportados. Resultados indisponíveis não viram zero eventos.

`assessment.final_benign_verdict_permitted=false` significa que a coleta inicial
não estabelece falso positivo. Para avançar, o analista/Kiro precisa citar
validações adicionais dos impedimentos pertinentes. Para DHCP, isso inclui
papéis dos destinos/scopes/relays, regra CRE ativa, anti-spoofing e processo/serviço
responsável pelo tráfego. Nem svchost.exe, conta de serviço, 4648, status CLOSED,
nem destinationbytes=0 substituem essas validações. Logon ID é local ao host;
correlação com DC exige contexto e identificadores apropriados.

A ponte não consulta inventário DHCP/AD ou política de firewall diretamente,
não altera regras e não executa contenção. Sem esses dados nas fontes acessíveis,
a resposta correta continua preliminar, com a próxima fonte indicada.

## Atualizar uma instalação Windows

Após a integração do PR no master, com alterações locais já preservadas:

```powershell
git pull --ff-only
& .\.venv\Scripts\python.exe -m pip install -e .
& .\.venv\Scripts\python.exe -c "import asyncio; import soc_bridge.kiro_server as s; t=asyncio.run(s.mcp.list_tools()); print('Total:', len(t)); print('\n'.join(x.name for x in t))"
```

O total esperado é 15, incluindo qradar_verify_offense e qradar_get_rule.
Reconecte/reinicie o servidor MCP no Kiro e abra um chat novo para recarregar
schemas e instruções. O nome soc-bridge-readonly continua correto: jobs Ariel
são permitidos, mudanças em offenses/regras/ativos não são.

O instalador editable não configura credenciais. O script start configura o MCP
local; o ambiente live e as chaves dos upstreams seguem o guia de instalação.
Não apague configurações/chaves existentes para atualizar o código.
