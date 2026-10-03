# Instalação com WSL 2 — Kiro no Windows, ponte no Linux

Este guia leva um Windows com WSL até o primeiro `investigate_demo` funcionando no Kiro, e depois ao caso real. Cenário principal:

```text
Windows → Kiro (aplicativo Windows) → wsl.exe → ponte Python no WSL 2 → Docker Desktop → QRadar MCP + Trend MCP
```

Cada etapa diz **onde executar**: 🪟 **PowerShell** do Windows ou 🐧 **Ubuntu** (terminal da distribuição WSL). Não pule a verificação “Esperado” de uma etapa; se ela falhar, corrija antes de seguir.

## 0. Qual guia usar

| Onde o Kiro roda | Onde a ponte Python roda | Guia |
| --- | --- | --- |
| Kiro instalado no Windows (menu Iniciar) | WSL 2 | **Este guia** (`configure_kiro_wsl.py`) |
| Kiro instalado no Windows | Windows | [Guia geral](guia-instalacao.md), comandos PowerShell (`configure_kiro.py`) |
| Kiro executando no próprio Linux (desktop Linux ou Kiro Linux dentro do WSL) | Mesmo Linux | [Guia geral](guia-instalacao.md), comandos Linux (`configure_kiro.py`) |

**Por que um configurador separado:** o Kiro para Windows inicia os servidores MCP como processos Windows. Ele não executa um caminho Linux como `/home/ana/projetos/KiroBridgerMCP/.venv/bin/python`. Por isso `configure_kiro.py`, quando roda no WSL, gera uma configuração que só serve a um Kiro que também roda no Linux. Abrir a pasta pelo caminho de rede `\\wsl.localhost\...` **não** move o Kiro nem seus processos para o Linux. O Kiro não documenta suporte oficial a “Remote WSL”; extensões da comunidade não foram avaliadas aqui.

`configure_kiro_wsl.py` configura apenas `soc-bridge-readonly` para chamar `wsl.exe` com argumentos separados: distribuição explícita, pasta do projeto e Python absoluto da `.venv` Linux, sem shell nem perfis (`--exec`). Sintaxe da Microsoft: [comandos do WSL](https://learn.microsoft.com/windows/wsl/basic-commands) e [arquivos e interoperabilidade](https://learn.microsoft.com/windows/wsl/filesystems).

## 1. WSL 2 e a distribuição Ubuntu 24.04

🪟 **PowerShell** (como administrador apenas se o WSL ainda não estiver instalado):

```powershell
wsl --install -d Ubuntu-24.04
```

Reinicie o Windows se for pedido. Na primeira abertura, o Ubuntu pede um **usuário e senha Linux**. Essa senha é a do `sudo` e não precisa ser a do Windows. Depois confira:

```powershell
wsl --list --verbose
```

**Esperado:** uma linha `Ubuntu-24.04` com `VERSION` **2**. Anote o nome exato da coluna `NAME`; os exemplos usam `Ubuntu-24.04`. Se você instalou com `wsl --install` sem `-d`, o nome pode ser `Ubuntu`.

| Problema | Correção |
| --- | --- |
| `VERSION 1` | `wsl --set-version Ubuntu-24.04 2`. **Pare** até aparecer 2: Docker Desktop exige WSL 2. |
| `wsl` não reconhecido ou instalação bloqueada | Política da empresa: **pare** e fale com o suporte. Não tente contornar. |
| Saída com espaços estranhos ao redirecionar | Normal em PowerShell; para texto limpo, `$env:WSL_UTF8 = '1'` antes do comando. |

## 2. Git, Python 3.11+ e venv no Ubuntu

🐧 **Ubuntu:**

```bash
sudo apt update
sudo apt install -y git python3 python3-venv
python3 --version
git --version
```

**Esperado:** `Python 3.12.x` no Ubuntu 24.04 (o projeto exige **3.11+**). Se aparecer 3.10 ou anterior (por exemplo Ubuntu 22.04), **pare** e use uma distribuição com Python 3.11+. Não instale Python de fontes não oficiais só para seguir adiante.

Não é preciso instalar `python3-pip` no sistema: a `.venv` traz o próprio `pip`. Não use `sudo pip`.

## 3. Clone no filesystem Linux, `.venv` Linux e demo

🐧 **Ubuntu**, sem `sudo`:

```bash
mkdir -p ~/projetos
cd ~/projetos
git clone https://github.com/HianSoares/KiroBridgerMCP.git
cd KiroBridgerMCP
test -f pyproject.toml && echo 'Pasta correta'
python3 -m venv .venv
./.venv/bin/python -m pip install -e .
./.venv/bin/python -m soc_bridge.cli demo --output reports/demo
```

**Esperado:** `Pasta correta` e, no fim, `Saved reports/demo.md and reports/demo.json`. O demo usa dados fabricados e não precisa de Docker nem credenciais. Não é necessário ativar a `.venv`.

Clone com o `git` do Ubuntu, dentro de `~/projetos`. A Microsoft recomenda manter no filesystem Linux os arquivos usados por ferramentas Linux, pois `/mnt/c/...` é mais lento. O Git do Linux também evita terminações de linha CRLF. Caminhos com espaços funcionam, mas uma pasta simples evita erros de digitação.

**Uma `.venv` por sistema.** A `.venv` Windows tem `Scripts\python.exe`; a Linux tem `bin/python`. Nunca copie nem reaproveite uma na outra. Se também quiser o fluxo Windows, use **outro clone** no disco do Windows.

| Problema | Correção |
| --- | --- |
| `ensurepip is not available` / `No module named venv` | `sudo apt install -y python3-venv`, depois `rm -rf .venv` e crie de novo. **Não continue com uma `.venv` incompleta.** |
| `pip install` falha por proxy ou certificado | **Pare** e peça a configuração de proxy/CA à equipe responsável. Não desative a verificação TLS. |
| `Permission denied` em arquivos do projeto | Você usou `sudo` antes. Refaça o clone sem `sudo` na sua pasta `~`. |
| `No module named soc_bridge` | Rode `./.venv/bin/python -m pip install -e .` na raiz do clone. |

## 4. Configure o Kiro do Windows para chamar a ponte no WSL

🐧 **Ubuntu**, na raiz do clone:

```bash
./.venv/bin/python scripts/configure_kiro_wsl.py
```

**Esperado:** três informações, por exemplo:

```text
Configurado /home/ana/projetos/KiroBridgerMCP/.kiro/settings/mcp.json (soc-bridge-readonly via wsl.exe, distribuicao Ubuntu-24.04).
Pasta para abrir no Kiro do Windows: \\wsl.localhost\Ubuntu-24.04\home\ana\projetos\KiroBridgerMCP
Teste no PowerShell do Windows (mesmo caminho que o Kiro usa):
  wsl.exe '--distribution' 'Ubuntu-24.04' '--cd' '/home/ana/projetos/KiroBridgerMCP' '--exec' '/home/ana/projetos/KiroBridgerMCP/.venv/bin/python' 'scripts/wsl_preflight.py' '--from-windows'
```

A entrada gerada em `.kiro/settings/mcp.json` (arquivo local, ignorado pelo Git):

```json
"soc-bridge-readonly": {
  "command": "wsl.exe",
  "args": ["--distribution", "Ubuntu-24.04", "--cd", "/home/ana/projetos/KiroBridgerMCP",
           "--exec", "/home/ana/projetos/KiroBridgerMCP/.venv/bin/python", "-m", "soc_bridge.wsl_launch"],
  "env": {
    "QRADAR_MCP_URL": "http://127.0.0.1:5001/mcp",
    "QRADAR_MCP_TOKEN": "${QRADAR_MCP_TOKEN}",
    "TREND_VISION_ONE_API_KEY": "${TREND_VISION_ONE_API_KEY}",
    "TREND_VISION_ONE_REGION": "us",
    "WSLENV": "QRADAR_MCP_URL/u:QRADAR_MCP_TOKEN/u:TREND_VISION_ONE_API_KEY/u:TREND_VISION_ONE_REGION/u:QRADAR_AQL_UTC_OFFSET_HOURS/u:QRADAR_AQL_TIMEZONE_VERIFIED/u"
  },
  "autoApprove": ["investigate_demo"]
}
```

O configurador:

- substitui apenas `command` e `args` de `soc-bridge-readonly`;
- preserva outros servidores, `autoApprove`, `disabled`, `disabledTools` e variáveis já definidas;
- acrescenta ao `WSLENV` as variáveis da ponte e mantém as outras entradas;
- numa configuração nova, aprova automaticamente **apenas** `investigate_demo`;
- não grava chaves e recusa rodar como root, a partir de uma `.venv` do Windows ou fora da `.venv` do projeto.

`soc_bridge.wsl_launch` inicia o mesmo servidor `soc_bridge.kiro_server`. Antes, ele escreve **uma linha em stderr** com o estado de cada variável (`set`, `absent`, `empty`, `unexpanded reference`), nunca o valor. O stdout fica reservado ao protocolo MCP.

Se você mover o clone, trocar de distribuição ou recriar a `.venv` em outro caminho, rode o configurador de novo.

## 5. Preflight

🐧 **Ubuntu:**

```bash
./.venv/bin/python scripts/wsl_preflight.py
```

🪟 **PowerShell** — cole a linha `wsl.exe ...` impressa pelo configurador. As duas primeiras linhas abaixo testam também a passagem de variáveis do Windows para o Linux, preservando um `WSLENV` existente:

```powershell
$env:SOC_BRIDGE_PROBE = 'ok'
$env:WSLENV = (@($env:WSLENV, 'SOC_BRIDGE_PROBE/u') | Where-Object { $_ }) -join ':'
wsl.exe '--distribution' 'Ubuntu-24.04' '--cd' '/home/ana/projetos/KiroBridgerMCP' '--exec' '/home/ana/projetos/KiroBridgerMCP/.venv/bin/python' 'scripts/wsl_preflight.py' '--from-windows'
```

O preflight só lê; ele não consulta QRadar nem Vision One e não mostra credenciais. Ele verifica:

| Verificação | O que significa |
| --- | --- |
| WSL 2, distribuição, sistema | Kernel WSL 2 e `WSL_DISTRO_NAME` |
| Projeto e Python | `pyproject.toml`, Python 3.11+ da `.venv` Linux, ausência de `.venv` Windows, aviso para `/mnt/...` |
| `soc_bridge` importado | Contagem de tools lida do código e todas marcadas como read-only |
| Servidor MCP por stdio | Handshake `initialize` + `tools/list` em que **toda linha de stdout precisa ser JSON-RPC** |
| `mcp.json` | `wsl.exe`, distribuição, `--cd` e `--exec` deste clone, `WSLENV` com `/u`, chaves literais |
| Comando do `mcp.json` via `wsl.exe` | O mesmo comando do Kiro, por interoperabilidade; detecta texto extra no stdout |
| Docker | CLI, daemon (Docker Desktop ou motor próprio da distribuição), `docker compose`, credential helper |
| Variáveis | Estado das variáveis; com `--from-windows`, se `SOC_BRIDGE_PROBE` atravessou o `WSLENV` |
| Porta do QRadar MCP | Conexão TCP à URL de loopback **a partir do WSL**; porta aberta não prova autenticação |

**Esperado:** `Nenhuma FALHA`. Avisos de Docker e de porta são aceitáveis neste ponto, porque o demo não precisa deles. Qualquer `[FALHA]`: **pare** e corrija a primeira da lista.

Para distinguir porta aberta de sessão MCP válida, depois de configurar o QRadar MCP (seção 8):

```bash
./.venv/bin/python scripts/wsl_preflight.py --check-qradar-mcp
```

Essa opção abre uma sessão MCP local e lista as tools; não executa AQL nem lê offenses. Use somente quando estiver autorizado a acessar esse QRadar MCP. Dependendo da implantação da IBM, a autenticação pode ser validada junto à console.

## 6. Abra o projeto no Kiro e rode o demo

1. 🪟 No Kiro: **File → Open Folder** e cole a pasta impressa pelo configurador (`\\wsl.localhost\Ubuntu-24.04\home\ana\projetos\KiroBridgerMCP`). O Kiro pode pedir confirmação de confiança no workspace ou no host `wsl.localhost`.
2. No painel do Kiro, aba **MCP Servers**, confira `soc-bridge-readonly` conectado.
3. Em **Output → Kiro - MCP Logs**, procure a linha `SOC Bridge via wsl.exe (Ubuntu-24.04): ...`. Ela prova que o Kiro chegou ao Linux.
4. No chat, peça:

> Chame `investigate_demo` do `soc-bridge-readonly` e indique evidências, hipóteses e limites da coleta.

**Esperado:** um caso fabricado, sem Docker e sem credenciais. Se o Kiro não abrir pastas `\\wsl.localhost`, há uma alternativa: clonar em `/mnt/c/...` (disco do Windows), abrir `C:\...` no Kiro e rodar o mesmo configurador. É mais lenta e não foi testada neste guia.

A primeira conexão pode levar alguns segundos se a distribuição estiver parada: o `wsl.exe` a inicia.

## 7. Credenciais: três ambientes diferentes

Variáveis **não** atravessam sozinhas entre Windows e Linux:

| Ambiente | De onde vêm as variáveis | Observação |
| --- | --- | --- |
| **Processo do Kiro (Windows)** | Ambiente com que o Kiro foi iniciado | `${VAR}` no `mcp.json` é expandido pelo Kiro **somente** para variáveis aprovadas em **Settings → Mcp Approved Env Vars** ([documentação do Kiro](https://kiro.dev/docs/mcp/configuration/)). |
| **Processo Linux iniciado pelo `wsl.exe`** | Somente variáveis listadas em `WSLENV` | O configurador lista as da ponte com `/u` (Windows → Linux). Uma variável listada mas indefinida no Windows chega **vazia**; `wsl_launch` a ignora e o padrão da ponte vale. `export` no terminal Ubuntu, `.bashrc` ou `.profile` **não** chegam ao Kiro nem a esse processo (`--exec` não usa shell). |
| **Contêineres** | Trend: a ponte executa `docker run -e TREND_VISION_ONE_API_KEY ...` (só o nome; o valor vai pelo ambiente do processo, não pela linha de comando). QRadar MCP: configuração própria (`config.json`/`.env` da pasta `qradar-mcp`). | A ponte envia `QRADAR_MCP_TOKEN`, se houver, no cabeçalho HTTP `SEC` ao QRadar MCP local. |

**Mecanismo recomendado:** inicie o Kiro a partir de um PowerShell em que as credenciais existam somente nesse processo. Feche o Kiro por completo antes; um Kiro já aberto não recebe variáveis novas.

🪟 **PowerShell** (ajuste a pasta):

```powershell
Set-Location $HOME
$pasta = '\\wsl.localhost\Ubuntu-24.04\home\ana\projetos\KiroBridgerMCP'
$chave = Read-Host 'API key do Vision One' -AsSecureString
$env:TREND_VISION_ONE_API_KEY = [Net.NetworkCredential]::new('', $chave).Password
$token = Read-Host 'Token do QRadar MCP (Enter se nao usar)' -AsSecureString
$texto = [Net.NetworkCredential]::new('', $token).Password
if ($texto) { $env:QRADAR_MCP_TOKEN = $texto }
Remove-Variable chave, token, texto
kiro $pasta
```

- `Set-Location $HOME` evita que `kiro.cmd` rode a partir de um caminho UNC.
- As chaves não aparecem na tela, no histórico nem na linha de comando.
- Depois que o Kiro abrir, feche essa janela do PowerShell.
- Na primeira vez, aprove `QRADAR_MCP_TOKEN` e `TREND_VISION_ONE_API_KEY` em **Mcp Approved Env Vars**.
- Se `kiro` não for reconhecido, abra um PowerShell novo. Numa instalação por usuário, o comando costuma ficar em `$env:LOCALAPPDATA\Programs\Kiro\bin\kiro.cmd`; use `& "$env:LOCALAPPDATA\Programs\Kiro\bin\kiro.cmd" $pasta` se esse arquivo existir.

As regras de token do guia geral continuam valendo: Enter no token só significa “não definir”; um `QRADAR_MCP_TOKEN` já existente no ambiente continua sendo enviado.

**Confira no Kiro**, em **Kiro - MCP Logs**: `TREND_VISION_ONE_API_KEY=set`. Se aparecer `unexpanded reference (ignored)`, a variável não foi aprovada; se aparecer `empty (ignored)`, ela não existia no processo do Kiro.

Não grave chaves no `mcp.json`, em `.bashrc` nem em arquivos do repositório. Variáveis de usuário persistentes do Windows (`setx`) ficam gravadas em texto claro no perfil; evite-as para segredos.

## 8. Docker Desktop e QRadar MCP

🪟 Instale o [Docker Desktop para Windows](https://docs.docker.com/desktop/setup/install/windows-install/) pelo canal oficial e abra-o. Em **Settings**:

1. **General → Use the WSL 2 based engine** marcado.
2. **Resources → WSL Integration**: habilite **Ubuntu-24.04** e aplique.
3. Mantenha **Linux containers** (menu do ícone do Docker).

Referência: [Docker Desktop com WSL 2](https://docs.docker.com/desktop/features/wsl/). A Docker recomenda **não** manter um Docker Engine ou CLI instalado dentro da própria distribuição junto com o Docker Desktop. Não instale um segundo daemon por padrão.

🐧 **Ubuntu** (abra um terminal novo depois de habilitar a integração):

```bash
docker info --format '{{.OperatingSystem}} {{.ServerVersion}}'
docker compose version
```

**Esperado:** `Docker Desktop <versão>` e a versão do Compose. Se aparecer o nome da sua distribuição (por exemplo `Ubuntu 24.04 LTS`), o terminal está falando com **outro** daemon, dentro do Linux. Contêineres e portas desse daemon não são os mesmos do Docker Desktop. **Pare** e decida qual usar.

Credenciais de produto, QRadar MCP e imagem Trend: siga as seções 4 a 6 do [guia geral](guia-instalacao.md). Os comandos `docker compose` podem rodar no PowerShell ou no Ubuntu, pois com a integração os dois usam o mesmo motor do Docker Desktop. No Ubuntu, use `cp config.example.json config.json` no lugar de `Copy-Item`. Mantenha a porta publicada em `127.0.0.1:5001:5000`.

Não é necessário manter o contêiner da Trend rodando: a ponte o inicia em cada investigação e ele é removido ao final (`--rm`). O QRadar MCP, por outro lado, precisa estar em execução.

## 9. Rede: `127.0.0.1` depende de onde o servidor escuta

A ponte só aceita `http://127.0.0.1:<porta>/mcp` (ou `localhost`/`::1`) e roda **no WSL**. O que conta é se `127.0.0.1:5001` responde **dentro do WSL**; o preflight testa exatamente isso.

| Onde o QRadar MCP escuta | Alcançável pela ponte no WSL em `127.0.0.1`? |
| --- | --- |
| Docker Desktop, porta publicada `127.0.0.1:5001` | Observado em teste (Windows 11, WSL 2 em modo NAT): **sim**. A documentação da Docker não descreve esse encaminhamento; confirme com o preflight. |
| Docker Engine instalado dentro da mesma distribuição | Sim, mesma rede da distribuição. Evite combinar com Docker Desktop. |
| Processo iniciado direto no Windows (Python, sem Docker) | No modo NAT padrão, **não**: segundo a Microsoft, o Linux só alcança serviços do Windows pelo IP do host, que a ponte recusa por segurança. |

Se a porta não responder no WSL, **não** publique o MCP em `0.0.0.0` e não troque a URL por um IP do host. Alternativas documentadas:

1. Rode o QRadar MCP pelo Docker Desktop (seção 8) ou pelo método Python do upstream **dentro do WSL**.
2. **Decisão sua, não automática:** o [modo de rede espelhado](https://learn.microsoft.com/windows/wsl/networking#mirrored-mode-networking) (Windows 11 22H2+, `networkingMode=mirrored` em `.wslconfig`, seguido de `wsl --shutdown`) permite alcançar servidores do Windows por `127.0.0.1`. Ele muda a rede de todas as distribuições; avalie com quem administra a máquina.

Uma porta aberta só prova que algo escuta. Para provar a sessão MCP autenticada, use `--check-qradar-mcp` (seção 5) ou uma investigação autorizada.

## 10. Primeiro caso real

Com o Kiro iniciado pela seção 7, peça `investigate_demo` de novo e depois:

> Chame `investigate_case` com `reference="<ID_AUTORIZADO>"`. Separe evidências, buscas executadas, janelas, limites e lacunas.

Leia o restante do [guia geral](guia-instalacao.md#7-passe-as-credenciais-ao-kiro-e-teste-um-caso-real) para região Trend, `QRADAR_AQL_UTC_OFFSET_HOURS` e interpretação dos resultados. Para mudar a região ou a URL, edite o `env` de `soc-bridge-readonly` no `mcp.json` (as variáveis já estão no `WSLENV`).

## 11. Problemas frequentes

| Sintoma | Causa provável e correção |
| --- | --- |
| MCP Logs: erro ao iniciar `/home/.../.venv/bin/python`, “not found” ou `ENOENT` | O `mcp.json` aponta para o Python Linux e o Kiro roda no Windows. Rode `scripts/configure_kiro_wsl.py`. |
| MCP Logs sem a linha `SOC Bridge via wsl.exe` e servidor desconectado | Rode a linha `wsl.exe ...` do configurador no PowerShell e leia a primeira `[FALHA]`. Confirme o nome da distribuição com `wsl --list --verbose`. |
| `There is no distribution with the supplied name` | `--distribution` não corresponde ao nome em `wsl --list --verbose`. Rode o configurador dentro da distribuição certa. |
| `No module named soc_bridge` | `./.venv/bin/python -m pip install -e .` na raiz do clone. |
| `ensurepip is not available` | `sudo apt install -y python3-venv`, `rm -rf .venv`, crie a `.venv` de novo. |
| `docker: command not found` no Ubuntu | Habilite a distribuição em **Resources → WSL Integration** e abra um terminal novo. |
| `docker info` mostra a distribuição, não “Docker Desktop” | Há um daemon dentro do Linux. Escolha um; a Docker recomenda remover o Engine da distribuição ao usar Docker Desktop. |
| `docker-credential-desktop.exe` não encontrado | A integração ou o PATH do Windows no WSL foi desativado. Reative a WSL Integration. |
| Variável `empty (ignored)` ou `unexpanded reference` no MCP Logs | Seção 7: inicie o Kiro pelo PowerShell com as variáveis e aprove-as em **Mcp Approved Env Vars**. |
| `Unsupported Vision One region` | Corrija `TREND_VISION_ONE_REGION` no `env` do `mcp.json`. |
| Caminho com espaços quebra o teste manual | Use a linha do configurador: cada argumento entre aspas simples. No `mcp.json`, cada argumento já é um item separado. |
| `UNC paths are not supported` ao rodar `kiro` | Execute `Set-Location $HOME` antes de `kiro <pasta>`. |
| Porta 5001 inacessível no WSL | Seção 9. Confira `docker compose ps` na pasta do QRadar MCP e a publicação `127.0.0.1:5001:5000`. |
| HTTP 401 no `--check-qradar-mcp` | Porta certa, autenticação recusada: token ausente/expirado ou configuração do QRadar MCP. Veja o guia geral. |
| `stdout contaminated` no preflight | Algo imprimiu texto fora do protocolo. Não altere `wsl_launch`; verifique mudanças locais e avisos do próprio `wsl.exe`. |
| Mudança no `mcp.json` sem efeito | Salve o arquivo; o Kiro reconecta. Se persistir, reconecte o servidor em **MCP Servers** ou reinicie o Kiro. |

## 12. O que foi e o que não foi validado

Os testes automatizados usam dados sintéticos. Neste repositório, o caminho Windows → `wsl.exe` → ponte Linux foi executado de fato numa máquina Windows 11 com WSL 2:

- handshake MCP limpo a partir de um processo Windows;
- caminho com espaços;
- `WSLENV` entregando valores e convertendo variáveis indefinidas em vazio;
- `127.0.0.1:5001` publicado pelo Docker Desktop e alcançável de dentro do WSL.

**Não foram validados:**

- a interface do Kiro abrindo `\\wsl.localhost` e expandindo `${VAR}`;
- uma instalação limpa de Ubuntu 24.04;
- o modo de rede espelhado;
- consultas reais ao QRadar ou ao Vision One.
