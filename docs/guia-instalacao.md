# Guia de instalação — KiroBridgerMCP

Este guia começa com um **demo fabricado**, que não precisa de QRadar, Trend, Docker ou credenciais. Depois mostra como conectar seus próprios ambientes. O Kiro conversa somente com o MCP local `soc-bridge-readonly`; a ponte consulta os dois servidores MCP upstream e devolve evidências limitadas.

## 1. Antes de começar

| Item | Demo | Investigação real |
| --- | --- | --- |
| Python 3.11 ou superior e Git | Sim | Sim |
| Kiro IDE | Para o teste no chat | Sim |
| Docker em execução | Não | Sim, para o Vision One MCP; pode ser usado pelo QRadar MCP |
| QRadar MCP local e acesso autorizado ao QRadar | Não | Sim |
| API key Trend Vision One de leitura, na região correta | Não | Sim |

> Execute os comandos **na pasta que contém `pyproject.toml`**. Se `Test-Path .\pyproject.toml` retornar `False`, você está na pasta errada. Não copie exemplos de credenciais para o repositório.

### Windows PowerShell

```powershell
git clone https://github.com/HianSoares/KiroBridgerMCP.git
Set-Location .\KiroBridgerMCP
Test-Path .\pyproject.toml                    # deve retornar True
py -3 --version                                # use Python 3.11+
py -3 -m venv .venv
& .\.venv\Scripts\python.exe -m pip install -e .
```

O projeto usa o executável em `.venv` diretamente; não é necessário ativar o ambiente virtual. `pip install -e .` precisa ser executado apenas nesta pasta. Se houver espaços no caminho, continue usando `& .\.venv\Scripts\python.exe`.

### Linux/macOS

```bash
git clone https://github.com/HianSoares/KiroBridgerMCP.git
cd KiroBridgerMCP
test -f pyproject.toml && echo 'Pasta correta'
python3 --version                              # use Python 3.11+
python3 -m venv .venv
./.venv/bin/python -m pip install -e .
```

## 2. Faça o primeiro teste, sem credenciais

No PowerShell:

```powershell
& .\.venv\Scripts\python.exe -m soc_bridge.cli demo --output reports\demo
Get-Content .\reports\demo.md -TotalCount 20
```

No Linux/macOS:

```bash
./.venv/bin/python -m soc_bridge.cli demo --output reports/demo
sed -n '1,20p' reports/demo.md
```

**Esperado:** mensagem `Saved ...demo.md and ...demo.json` e um relatório de cenário fictício. A pasta `reports/` é ignorada pelo Git; relatórios reais também devem ficar fora do repositório.

## 3. Registre a ponte no Kiro

O arquivo `.kiro/settings/mcp.json` **não vem no clone**: ele é local e ignorado pelo Git, pois pode conter escolhas da sua instalação. Gere-o com:

```powershell
& .\.venv\Scripts\python.exe .\scripts\configure_kiro.py
```

No Linux/macOS, use `./.venv/bin/python scripts/configure_kiro.py`. O configurador registra o executável Python absoluto desta `.venv`, preserva outros MCPs e opções já existentes e define `autoApprove` apenas para `investigate_demo` em instalações novas. Ele grava **referências** `${QRADAR_MCP_TOKEN}` e `${TREND_VISION_ONE_API_KEY}`, jamais os valores das chaves. A região inicial é `us`; ajuste `TREND_VISION_ONE_REGION` para a região do seu tenant antes de uma investigação real.

Abra esta pasta no Kiro IDE. Em **MCP Servers**, confirme `soc-bridge-readonly` como conectado. No chat, peça:

> Use `investigate_demo` do `soc-bridge-readonly`. Explique o que foi observado, o que é hipótese e os limites da coleta.

**Esperado:** um relatório fabricado, sem precisar de Docker nem de API key. Se aparecer “Python was not found”, abra `.kiro/settings/mcp.json` e confirme que `command` aponta para a `.venv` deste clone; rode o configurador novamente. Não troque pelo comando genérico `python` no Windows.

Os quatro agentes do projeto estão em `.kiro/agents/`. `case-investigator` investiga; `threat-hunter` testa hipóteses; `report-writer` organiza evidências; `response-advisor` só recomenda um plano para humanos e tem `tools: []`. Para começar, mantenha o agente padrão ou selecione `case-investigator` e use o demo.

## 4. Prepare as conexões reais

Faça esta etapa somente quando o demo estiver funcionando.

1. **Docker:** instale e inicie Docker Desktop (Windows) ou Docker Engine (Linux). Confirme com `docker info --format '{{.ServerVersion}}'`. O projeto inicia a imagem `ghcr.io/trendmicro/vision-one-mcp-server` localmente por `docker run` em modo `-readonly=true`; não é preciso adicionar um segundo MCP ao Kiro. Na primeira execução, o Docker poderá baixar a imagem.
2. **QRadar:** configure e inicie o projeto upstream [IBM qradar-mcp](https://github.com/IBM/qradar-mcp) conforme as instruções dele, com conta de privilégios mínimos. A ponte espera o transporte HTTP em `http://127.0.0.1:5001/mcp` por padrão. Se você usar outra porta, altere `QRADAR_MCP_URL` **na configuração local**, mantendo `http` no loopback e o caminho `/mcp`. Confirme que o container/processo está rodando; no Windows, `Test-NetConnection 127.0.0.1 -Port 5001` deve retornar `TcpTestSucceeded: True` quando a porta padrão é usada. Porta aberta não valida autenticação.
3. **Autenticação local do QRadar MCP:** `QRADAR_MCP_TOKEN` é o token exigido pelo **servidor MCP local** quando ele opera em modo multiusuário. Ele é diferente da credencial usada pelo servidor upstream para acessar o QRadar. Se o servidor MCP local estiver em modo single-user sem token, essa variável pode ser omitida.
4. **Trend Vision One:** crie uma API key com acesso de leitura às funções Workbench e Search utilizadas, e confirme a região do tenant (`TREND_VISION_ONE_REGION`). A chave fica no ambiente do processo que inicia o Kiro, nunca no Git. Algumas buscas podem exigir permissões/entitlements adicionais; o relatório deve marcar a fonte incompleta quando isso ocorrer.

No Windows, se o comando `kiro` estiver no `PATH`, **feche completamente o Kiro** e rode na raiz do projeto:

```powershell
.\start-kiro-soc-bridge.ps1 -Live
```

O script pede a API key de forma oculta e, se aplicável, o token do MCP QRadar, e inicia o Kiro a partir do mesmo processo. Se você usa o Kiro IDE pelo ícone e não tem o comando `kiro`, configure as variáveis de ambiente no processo do IDE pelo mecanismo aprovado na sua organização; o `mcp.json` já tem referências `${VAR}`. Não cole a chave no chat nem grave valor real no `mcp.json`.

**Teste inicial real:** use um ID de offense ou alerta **autorizado**. No Kiro: “Investigue a offense `<ID>` usando `investigate_offense` e separe resultados QRadar, Workbench e Search; mostre janelas, limites e lacunas.” Para alerta Workbench, use `investigate_vision_alert(alert_id="<WB-ID>")`. Você também pode usar `investigate_case(reference="<ID>")` com apenas a referência.

## 5. Entenda o resultado

Uma busca vazia na primeira página não prova ausência de atividade. “Nenhum alerta Workbench” é diferente de “nenhum evento de endpoint na busca executada”. Um IP coincidente é candidato, não confirmação de mesmo incidente. O offset QRadar `-3` é uma configuração inicial, não a medição do fuso da sua console. Os agentes recomendam verificações e respostas para um analista humano; a ponte não bloqueia, não isola hosts e não fecha offenses.

Ao chamar uma tool do Kiro com dados reais, o relatório retornado entra no contexto do modelo configurado no Kiro. Consulte as regras de tratamento de dados da sua organização antes de usar incidentes reais.

## Problemas comuns

| Sintoma | Verificação |
| --- | --- |
| `pyproject.toml` não encontrado | Volte à raiz do clone; execute `Test-Path .\pyproject.toml`. |
| `No module named soc_bridge` | Refaça `pip install -e .` com o Python **desta** `.venv`; confira o diretório atual. |
| Kiro não mostra `soc-bridge-readonly` | Rode `scripts/configure_kiro.py` com a `.venv`, reabra a pasta no Kiro e confira MCP Servers. |
| `Python was not found` | `command` precisa apontar para `.venv\Scripts\python.exe` no Windows. |
| HTTP 401 no QRadar MCP local | Confira `QRADAR_MCP_TOKEN` no processo do Kiro e o modo de autenticação do servidor upstream. |
| Conexão recusada na porta 5001 | Confira Docker/QRadar MCP, porta publicada em loopback e `QRADAR_MCP_URL`. |
| Vision One não inicia | Confira Docker, imagem local, chave, região e permissões de leitura. |
| `investigate_demo` funciona, investigação real falha | A instalação Python/Kiro está funcional; leia a **fase da falha** indicada pela ponte para corrigir a fonte específica. |

Para executar testes locais no PowerShell:

```powershell
& .\.venv\Scripts\python.exe -m unittest discover -s tests -q
```

Veja [limitações conhecidas](bridge-known-limitations.md) e [README principal](../README.md) para detalhes da coleta. Os scripts históricos `fix-soc-bridge-mcp.ps1` e `install-alert-first-update.ps1` são de migrações anteriores; **não fazem parte da instalação de um clone novo**. O segundo depende de um ZIP externo que não acompanha o repositório.
