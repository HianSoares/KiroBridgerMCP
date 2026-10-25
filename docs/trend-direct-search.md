# Busca direta de logs na Trend

A ponte expõe `trend_read_search_resource` e `trend_search_data`: consultas independentes de um ID Workbench/offense, pelas APIs Search do XDR Data Explorer. Precisa de Docker e da chave/região Trend já configuradas; não precisa de QRadar. Não altera alertas, não executa comandos no endpoint e não inicia exportação/coleta de arquivos.

## No chat do Kiro

> Busque na Trend os comandos do host host.example.test entre 2026-01-01T12:00:00Z e 2026-01-01T12:30:00Z. Analise a sequência, os processos envolvidos e eventuais arquivos de dump; diferencie evidência confirmada de hipótese e continue as partições necessárias.

O Kiro lê `trend_read_search_resource(source="endpoint")` e usa a descrição de `query` do **schema vivo** para construir o filtro. Não precisa pedir um ID WB. Com um alerta conhecido, a entrada continua sendo `investigate_vision_alert`; Search direta complementa lacunas do relatório, sem repetir a coleta inteira.

Exemplo de chamada (dados fictícios; ajuste os campos conforme a fonte):

```json
{
  "query": "(endpointHostName:\"host.example.test\") and (processPid:4242 or objectPid:4242)",
  "source": "endpoint",
  "start_date_time": "2026-01-01T12:00:00Z",
  "end_date_time": "2026-01-01T12:30:00Z",
  "top": 500,
  "limit": 1000,
  "max_calls": 12
}
```

Para descobrir **outros comandos**, comece com o filtro do host na janela e depois refine por processo, instância, hash, caminho ou alvo. Restringir tudo ao nome ProcDump pode ocultar comandos relevantes. Não interprete `processPid` (ator) como `objectPid` (alvo). PID reutilizado, mesmo hostname ou proximidade temporal não demonstram a mesma execução: confira identificadores de instância, horários de início e papéis. Intenção/invocação de dump não prova sucesso; busque arquivo e operação de criação/escrita com atribuição. Ausência de arquivo numa consulta limitada não prova que nenhum dump ocorreu.

## Fontes e argumentos

| source | API Search upstream |
| --- | --- |
| endpoint | endpointActivities |
| detections | detections |
| network | networkActivities |
| identity | identityActivities |
| email | emailActivities |
| cloud | cloudActivities (CloudTrail/VPC quando disponíveis) |
| container | containerActivities |
| mobile | mobileActivities |

Os campos e a sintaxe variam por fonte. A ponte não converte AQL/SQL em Query Trend nem promete todas as fontes/funcionalidades do console XDR Data Explorer. Disponibilidade em `tools/list` não comprova permissão, licença, retenção ou coleta do host.

- `query`: expressão nativa TMV1-Query, obrigatória, até 4096 caracteres, sem caracteres de controle.
- `start_date_time`, `end_date_time`: ambos ou nenhum; ISO com `Z` ou offset explícito, intervalo positivo até 30 dias. Sem período: últimas 24h, marcado `default_window=true`. Um intervalo aceito não garante retenção correspondente.
- `select`: lista opcional de até 80 campos distintos, separados por vírgula. Vazio solicita os campos padrão do upstream; não garante todos os campos existentes na origem.
- `top`: 50, 100, 500, 1000 ou 5000; encaminhado como string exigida pelo MCP oficial.
- `limit`: 1–5000 registros devolvidos; padrão 1000. `max_calls`: 1–24 leituras; padrão 12. Prazo de coleta compartilhado: 60s, incluindo inicialização e descoberta. A criação do transporte e seu encerramento dependem também dos limites do SDK/Docker.
- `count_only=true`: solicita countOnly. Contagem não é lista de logs completa nem prova de ausência; não some contagens de partições sobrepostas.

## Evidências e continuação

Cada `records[].data` conserva o JSON nativo: comandos, hashes, instâncias e campos desconhecidos quando fornecidos pela Trend. `preservation` marca cortes de strings (16384 caracteres), listas, profundidade, chaves e tamanho; `evidence_fields_complete=false` impede afirmar conteúdo integral. Os registros têm orçamento global de aproximadamente 500 mil caracteres, além do relatório/planos. `result_set_complete` refere-se à cobertura das linhas da consulta, **não** à preservação integral dos campos ou completude de logging do endpoint.

O handler oficial não encaminha skipToken/nextLink para estas oito leituras. A ponte divide páginas cheias por tempo. Janelas podem sobrepor-se na fronteira; somente UUID nativo **e conteúdo idênticos** são unidos, com proveniência. Sem identidade suficiente, registros permanecem separados: `returned_records` não é censo de eventos únicos. Uma página cheia numa janela de até dois segundos exige refinamento, não é declarada completa.

Siga `continuation_plan`:

- `search_partition`: executar `trend_search_data` com os `parameters` devolvidos, somente na janela pendente.
- `refine_filters`: restringir fonte/host/instância/campos ou aumentar um limite disponível. Repetir parâmetros idênticos não é uma próxima página.
- `resolve_error`: corrigir a condição indicada antes de repetir. Não repetir em loop uma rejeição/permissão persistente.

Guarde os resultados anteriores e suas referências no contexto da investigação. Uma chamada de continuação devolve apenas sua janela e não incorpora automaticamente o histórico em casos persistidos. Corte, timeout, formato inválido, descoberta incompleta e falha de permissão não são resultado vazio. `any_matching_record=null` significa indeterminado; `false` só aparece após cobertura completa da consulta vazia. Uma resposta vazia vale para a conta, fonte, filtro e janela consultados, nunca para todo o ambiente.

## Atualização após merge

No PowerShell, na pasta do projeto:

```powershell
git switch master
if ($LASTEXITCODE -ne 0) { throw "Falha ao trocar de branch." }
git pull --ff-only
if ($LASTEXITCODE -ne 0) { throw "Falha ao atualizar; pare e confira o erro." }
& .\.venv\Scripts\python.exe -m pip install -e .
if ($LASTEXITCODE -ne 0) { throw "Falha na instalação." }
.\start-kiro-soc-bridge.ps1 -Live
```

Reconecte `soc-bridge-readonly` e abra um chat novo. São 28 tools. As duas novas consultas usam somente Trend; a necessidade de credenciais adicionais do launcher Live segue o guia de instalação. No WSL, use o launcher e a `.venv` Linux descritos no [guia WSL](guia-wsl.md).

## Referências oficiais verificadas

- [Handlers Search do MCP](https://github.com/trendmicro/vision-one-mcp-server/blob/main/internal/v1mcp/tools/search.go).
- [Cliente das APIs Search](https://github.com/trendmicro/vision-one-mcp-server/blob/main/internal/v1client/search.go).

As assinaturas foram conferidas nos handlers oficiais em 2026-10-05. Não foram executadas consultas a um tenant real nesta implementação; valide campos, permissões e retenção com sua instalação.
