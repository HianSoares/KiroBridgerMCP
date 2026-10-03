# Instalação do KiroBridgerMCP — do zero ao primeiro caso

Este guia tem dois marcos independentes:

1. **Demo:** instala a ponte e comprova que o Kiro consegue chamar `soc-bridge-readonly`. Não requer Docker nem acesso a QRadar ou Trend.
2. **Caso real:** conecta a ponte ao [IBM QRadar MCP](https://github.com/IBM/qradar-mcp) e ao [Trend Vision One MCP](https://github.com/trendmicro/vision-one-mcp-server). Requer acesso autorizado aos dois produtos.

Arquitetura: `Kiro → soc-bridge-readonly (Python/stdio) → QRadar MCP (HTTP local) + Vision One MCP (Docker/stdio)`. **Configure apenas `soc-bridge-readonly` no Kiro.** A própria ponte inicia o contêiner Trend quando você chama uma investigação com Trend; o contêiner QRadar deve estar em execução antes disso. As sete tools de investigação são `investigate_case`, `investigate_offense`, `investigate_vision_alert`, `investigate_vision_event`, `investigate_epm_uac`, `investigate_web_reputation` e `investigate_demo`. Além delas, seis tools `qradar_*` expõem AQL personalizada, resources, status e paginação de eventos/flows/payload, e `qradar_verify_offense`/`qradar_get_rule` fazem a verificação de offense e leitura de metadados das regras. São 18 tools, incluindo descoberta/lotes de offenses e `trend_find_alerts`, que lista Workbench sem ID e sem conexão QRadar. Veja [AQL](dynamic-aql.md) e [verificação de evidências](offense-verification.md). As tools qradar_* usam somente QRadar, sem iniciar o Trend.

> **Dados reais:** somente pessoas autorizadas devem acessar os ambientes. Uma resposta MCP com telemetria real entra no contexto do modelo configurado no Kiro. Confirme a política de dados da sua organização antes de investigar incidentes reais. Não publique relatórios ou credenciais.

## 1. Pré-requisitos

| Componente | Demo | Caso real | Verificação |
| --- | --- | --- | --- |
| Git | Sim | Sim | `git --version` |
| Python 3.11 ou superior | Sim | Sim | `py -3 --version` no Windows; `python3 --version` no macOS/Linux |
| Kiro IDE | Para o demo no chat | Sim | Abra uma pasta no Kiro e localize **MCP Servers** |
| Docker com Linux containers | Não | Sim | `docker --version`, `docker compose version` e `docker info` |
| Acesso autorizado a QRadar e Vision One | Não | Sim | Solicite ao administrador dos produtos |

Instale o [Git](https://git-scm.com/downloads), [Python](https://www.python.org/downloads/) e o [Kiro IDE](https://kiro.dev/docs/getting-started/first-project/) pelos canais oficiais. No Windows, use PowerShell; os comandos Linux/macOS aparecem nas etapas do projeto.

Para Docker, siga a instalação oficial do seu sistema: [Windows](https://docs.docker.com/desktop/setup/install/windows-install/), [macOS](https://docs.docker.com/desktop/setup/install/mac-install/) ou [Linux](https://docs.docker.com/desktop/setup/install/linux/) (Docker Desktop ou Docker Engine com Compose). No Windows, habilite o backend **WSL 2** quando solicitado e mantenha **Linux containers** selecionado. **Abra o Docker Desktop após instalar** e espere o motor ficar pronto. Uma saída de `docker --version` confirma apenas o cliente; `docker info` precisa mostrar a seção **Server**. Se o Docker exige licença ou implantação gerenciada na sua organização, siga o processo interno antes de usá-lo.

```powershell
docker --version
docker compose version
docker info --format '{{.ServerVersion}}'
```

**Esperado:** os três comandos respondem sem “docker não é reconhecido” ou “cannot connect to the Docker daemon”. O demo abaixo funciona mesmo se Docker não estiver instalado.

## 2. Instale a ponte e rode o demo sem credenciais

Escolha uma pasta de trabalho. No **PowerShell**:

```powershell
git clone https://github.com/HianSoares/KiroBridgerMCP.git
Set-Location .\KiroBridgerMCP
Test-Path .\pyproject.toml
py -3 -m venv .venv
& .\.venv\Scripts\python.exe -m pip install -e .
& .\.venv\Scripts\python.exe -m soc_bridge.cli demo --output reports\demo
Get-Content .\reports\demo.md -TotalCount 20
```

`Test-Path` deve retornar `True`; o demo deve informar `Saved reports\demo.md and reports\demo.json`. Os dados do relatório são fabricados. Execute tudo na raiz que contém `pyproject.toml`; **não crie uma segunda `.venv` numa pasta acima**. O `&` permite executar o Python mesmo se o caminho do projeto tiver espaços.

No **macOS/Linux**:

```bash
git clone https://github.com/HianSoares/KiroBridgerMCP.git
cd KiroBridgerMCP
test -f pyproject.toml && echo 'Pasta correta'
python3 -m venv .venv
./.venv/bin/python -m pip install -e .
./.venv/bin/python -m soc_bridge.cli demo --output reports/demo
sed -n '1,20p' reports/demo.md
```

Não é necessário ativar `.venv`: os comandos usam seu executável diretamente. `reports/` é ignorada pelo Git, mas relatórios reais também devem ser tratados conforme as regras de dados da sua organização.

## 3. Configure e teste o Kiro

Ainda na raiz do projeto, gere a configuração MCP **local**:

```powershell
& .\.venv\Scripts\python.exe .\scripts\configure_kiro.py
Test-Path .\.kiro\settings\mcp.json
```

No macOS/Linux: `./.venv/bin/python scripts/configure_kiro.py`. O segundo comando PowerShell deve retornar `True`.

O script rejeita Python fora da `.venv` deste projeto. Ele cria ou atualiza apenas a entrada `soc-bridge-readonly` em `.kiro/settings/mcp.json`: aponta `command` para o Python absoluto da `.venv`, preserva outros servidores e opções já presentes e, numa configuração nova, aprova automaticamente **apenas** `investigate_demo`. Ele não instala Docker, não inicia QRadar MCP, não gera credenciais e não grava valores de token. As expressões `${QRADAR_MCP_TOKEN}` e `${TREND_VISION_ONE_API_KEY}` são **referências a variáveis de ambiente**, não chaves utilizáveis. O arquivo gerado é ignorado pelo Git.

Abra **essa mesma pasta** no Kiro IDE. Em **MCP Servers**, confira que `soc-bridge-readonly` conectou. Peça no chat:

> Chame `investigate_demo` do `soc-bridge-readonly` e indique evidências, hipóteses e limites da coleta.

**Esperado:** o Kiro recebe um caso fabricado, sem credenciais e sem Docker. Essa etapa confirma Python, instalação do pacote e transporte MCP do Kiro; ainda não testa QRadar nem Trend. Se o Kiro mostrar um pedido para resolver variáveis de ambiente que não existem no demo, não insira chaves reais para passar nesta etapa; confira primeiro a configuração e a forma como sua instalação do Kiro trata referências `${VAR}`.

## 4. Obtenha as credenciais para o caso real

Existem **duas credenciais de produto**, guardadas em locais diferentes conforme o modo de implantação:

| Credencial | Origem | Uso neste projeto |
| --- | --- | --- |
| Token de **Authorized Service** do QRadar | Criado por administrador em **Admin → Authorized Services** | A ponte tem uma regra única: se `QRADAR_MCP_TOKEN` estiver presente, envia seu valor no cabeçalho HTTP `SEC`; se estiver ausente, não envia `SEC`. A ponte não detecta o modo do QRadar MCP. O servidor da IBM decide como autenticar a requisição e, na configuração local descrita neste guia, pode usar `qradar-mcp/config.json` com `qradar.authorized_service_token`. |
| API key **Trend Vision One** | Criada em **Administration → API Keys** | Entra no ambiente do processo que inicia o Kiro como `TREND_VISION_ONE_API_KEY`; a ponte a passa ao contêiner Trend. |

**QRadar:** um administrador cria um serviço autorizado, seleciona um **User Role** e um **Security Profile** que permitam **consultar offenses e seus índices de endereços, e pesquisar eventos no Log Activity/Ariel** nos domínios, redes e log sources necessários. Se seu caso usa flows, valide a leitura de Network Activity. A composição exata do papel varia conforme a versão, o perfil de segurança e as APIs habilitadas; peça ao administrador que teste essas operações com a role proposta, sem conceder Admin por padrão. Configure expiração e copie o token no momento da criação, pois a console pode não mostrá-lo depois. Veja [IBM: adicionar serviço autorizado](https://www.ibm.com/docs/en/qsip/7.5.0?topic=services-adding-authorized-service) e [IBM: criar papel](https://www.ibm.com/docs/en/qsip/7.5.0?topic=roles-creating-user-role).

**Trend:** um administrador entra em **Administration → API Keys → Add API key**, cria uma chave com expiração e uma role própria com **Workbench: View, filter, and search** e **Search: View, filter, and search**. Para consultas de inventário de endpoint usadas em algumas investigações, valide também **Endpoint Inventory: View**. Habilite só as leituras necessárias e confirme as permissões/entitlements do tenant. Copie a chave antes de fechar o diálogo. Confirme a região real da conta no [README da Trend](https://github.com/trendmicro/vision-one-mcp-server#server-options) **e** na allowlist fixa desta ponte: `au`, `ca`, `eu`, `id`, `in`, `jp`, `mea`, `sg`, `uk`, `us`, `za`. Mesmo que a Trend aceite uma região, se ela não estiver nessa allowlist a ponte retorna `Unsupported Vision One region` **antes** de iniciar o MCP da Trend. Não invente `br` se não constar nas duas listas. Veja [Trend: criação da API key](https://docs.trendmicro.com/en-us/documentation/article/trend-vision-one-automation-center-first-steps-toward-u) e [Trend: permissões por categoria](https://docs.trendmicro.com/en-us/documentation/article/trend-vision-one-automation-center-authentication).

> A descrição da Trend no parágrafo anterior não significa que toda instalação tenha exatamente a mesma interface ou os mesmos direitos de Search. Caso sua role não exponha essas permissões, confirme com o administrador e teste uma chamada real; o resultado deve apontar falta de autorização, sem concluir ausência de eventos.

## 5. Instale e inicie o QRadar MCP da IBM

O projeto da IBM suporta Docker Compose e Python local; este guia usa o **Docker Compose do upstream** no mesmo computador onde o Kiro será executado. O QRadar MCP é um servidor HTTP separado; deixe-o ligado durante os casos reais. Consulte o [README upstream](https://github.com/IBM/qradar-mcp#deployment) para mudanças de versão.

Em um diretório de sua escolha, **fora** do clone KiroBridgerMCP:

```powershell
git clone https://github.com/IBM/qradar-mcp.git
Set-Location .\qradar-mcp
Copy-Item .\config.example.json .\config.json
Test-Path .\config.json
```

Edite `config.json` localmente. No objeto `qradar`, use `host` com a URL HTTPS do seu QRadar, preencha `authorized_service_token` com a credencial criada acima e configure `verify_ssl` para validar o certificado da console. Se seu ambiente usa CA interna, peça a cadeia confiável à equipe responsável e siga a configuração de certificados do upstream; **não publique nem envie o arquivo**. Não use simultaneamente um `sec_token` de sessão e um `authorized_service_token` sem entender a precedência documentada pela IBM.

Crie, ao lado do `docker-compose.yml`, um arquivo `.env` local com estas **duas variáveis do upstream** (valores fictícios de formato):

```dotenv
QRADAR_HOST=<FQDN_DO_QRADAR_SEM_HTTPS>
LOG_LEVEL=info
```

`QRADAR_HOST` aqui é somente o nome do servidor, sem `https://`; o Compose da IBM forma `QRADAR_CONSOLE_FQDN=https://${QRADAR_HOST}`. Já o `qradar.host` de `config.json` é a URL usada pelo cliente local. O arquivo `.env` do QRadar MCP **não** é carregado automaticamente pela ponte Python.

O Compose upstream publica por padrão `5001:5000`, potencialmente em todas as interfaces. Para instalação local, altere **a linha `ports` do `qradar-mcp/docker-compose.yml`** para `127.0.0.1:5001:5000`, mantendo acesso somente no loopback. Não confunda essa porta com a porta da console QRadar. Depois:

```powershell
docker compose config --quiet
docker compose up -d --build
docker compose ps
Test-NetConnection 127.0.0.1 -Port 5001 -InformationLevel Quiet
```

**Esperado:** `docker compose ps` mostra o serviço `qradar-mcp` **Up** e o teste TCP retorna `True`. Se der `False`, consulte `docker compose logs --tail 80 qradar-mcp`. Uma porta aberta só prova que há um serviço escutando; **não comprova autenticação nem a presença das tools**. Uma investigação real no passo 7 testará a conexão MCP autenticada.

**Alternativa avançada:** se você configurar o QRadar MCP da IBM sem `config.json` (modo multiusuário descrito no README upstream), remova o volume correspondente do Compose. A ponte continua com a mesma regra em qualquer implantação: `QRADAR_MCP_TOKEN` presente → cabeçalho HTTP `SEC`; ausente → nenhum cabeçalho `SEC`. O QRadar MCP da IBM decide como autenticar cada requisição recebida. O token não é uma segunda senha independente gerada pelo MCP. Configure também a validação TLS para a console, conforme a implantação da IBM. Não deixe a porta HTTP local acessível por outras máquinas.

## 6. Prepare o MCP da Trend Vision One

**Não é necessário clonar nem iniciar manualmente** o repositório da Trend para usar esta ponte. O código de `soc_bridge.transports` chama `docker run -i --rm -e TREND_VISION_ONE_API_KEY ghcr.io/trendmicro/vision-one-mcp-server -region <REGIÃO> -readonly=true ...` por stdio quando recebe uma investigação real. Os toolsets variam conforme o tipo de investigação (`workbench`, `search`, `endpoint`). Kiro enxerga apenas `soc-bridge-readonly`.

Com Docker já funcionando, opcionalmente faça o download da imagem antecipadamente:

```powershell
docker pull ghcr.io/trendmicro/vision-one-mcp-server
docker image inspect ghcr.io/trendmicro/vision-one-mcp-server --format '{{.Id}}'
```

**Esperado:** a imagem está disponível localmente. `docker ps` pode continuar sem contêiner Trend: ele é temporário e aparece somente durante chamadas da ponte. A chave da Trend não vai no `docker pull`; ela é transmitida ao contêiner apenas na execução da investigação. Para desenvolver ou auditar esse componente, veja as instruções e o código do [repositório upstream da Trend](https://github.com/trendmicro/vision-one-mcp-server). O README upstream informa o modo somente leitura e a lista de regiões suportadas.

## 7. Passe as credenciais ao Kiro e teste um caso real

Volte à **raiz do KiroBridgerMCP**. O `mcp.json` gerado no passo 3 contém `QRADAR_MCP_URL=http://127.0.0.1:5001/mcp`, `QRADAR_MCP_TOKEN=${QRADAR_MCP_TOKEN}`, `TREND_VISION_ONE_API_KEY=${TREND_VISION_ONE_API_KEY}` e `TREND_VISION_ONE_REGION=us` como valores iniciais. **Corrija a região no arquivo local** se o tenant não for `us`; preserve as referências `${VAR}`. Se a porta local não for 5001, ajuste `QRADAR_MCP_URL` no mesmo arquivo. A ponte só aceita URL MCP HTTP em loopback terminada em `/mcp`.

No Windows, se o comando `kiro` estiver disponível (`Get-Command kiro`), feche por completo qualquer instância aberta e execute:

```powershell
.\start-kiro-soc-bridge.ps1 -Live
```

O script volta a executar `configure_kiro.py`, preserva configurações já existentes, pede a chave Trend de forma oculta e pede o token QRadar via `Read-Host -AsSecureString`. Se você configurou o QRadar MCP da IBM para usar `config.json` e **não existe `QRADAR_MCP_TOKEN` herdado no ambiente**, pode pressionar Enter no prompt do token: a ponte não enviará `SEC`, cabendo ao servidor da IBM autenticar com a configuração dele. Se sua implantação da IBM exige credencial no cabeçalho, informe o token Authorized Service: a ponte o enviará como `SEC`. **Enter não apaga um `QRADAR_MCP_TOKEN` que já esteja definido no ambiente do processo**; nesse caso, a ponte continuará enviando o cabeçalho. O script coloca os valores no ambiente do processo que lança `kiro .` e restaura o ambiente anterior ao terminar. A credencial pode continuar na memória do processo iniciado; não a grave em arquivos, histórico nem chat.

Se `Get-Command kiro` não encontrar o executável, o script não inicia o IDE. Você pode abrir a pasta pelo ícone para o demo; para um caso real, faça o processo do Kiro receber as variáveis de ambiente pelos mecanismos aprovados em sua organização e confirme como sua versão do Kiro resolve `${VAR}` em `.kiro/settings/mcp.json`. O configurador **não** injeta a API key no IDE já aberto. Não coloque chaves literais no `mcp.json`.

Em **MCP Servers**, confirme `soc-bridge-readonly` conectado. Execute novamente `investigate_demo` para verificar a ponte. Depois use **um ID autorizado**:

> Chame `investigate_case` com `reference="<ID_DA_OFFENSE_AUTORIZADA>"`. Separe evidências de QRadar, Workbench e Search, indique as buscas executadas, janelas, limites e lacunas.

Para um alerta Trend, substitua a referência por `"<ID_WORKBENCH_AUTORIZADO>"`. **Esperado:** relatório que distingue resultados efetivamente consultados, candidatos e dados faltantes. Um resultado vazio na primeira página não significa ausência de atividade. Se a ferramenta reportar falha de coleta, não interprete como “nenhuma offense/alerta”. A primeira chamada pode demorar mais porque precisa obter a imagem da Trend.

## 8. Problemas frequentes

| Sintoma | O que conferir |
| --- | --- |
| `pyproject.toml` não encontrado | Está na raiz do clone? `Test-Path .\pyproject.toml` deve retornar `True`. |
| O configurador diz “Run with the project's .venv Python” | Execute `& .\.venv\Scripts\python.exe .\scripts\configure_kiro.py`, nunca `py` ou `python` solto. Recrie a `.venv` se mudou a pasta do projeto. |
| `No module named soc_bridge` | Refaça `& .\.venv\Scripts\python.exe -m pip install -e .` na raiz. |
| `docker` não reconhecido / `docker info` falha | Instale/inicie Docker Desktop ou Engine e abra novo terminal. No Windows, confira WSL 2 e Linux containers. |
| `docker compose ps` mostra `Exited` ou `docker start` reclama de `config.json` | Leia os logs; se o clone QRadar foi movido, o contêiner antigo pode guardar o caminho anterior do volume. Recrie-o com `docker compose up -d --force-recreate` **na pasta atual** após validar que `config.json` é um arquivo. |
| `docker compose config` reclama `QRADAR_HOST` ausente | Confira `.env` ao lado do `docker-compose.yml` no clone da IBM; não confunda com o `.env` da ponte. |
| Porta 5001 não responde | Confira Docker, `docker compose ps`, publicação `127.0.0.1:5001:5000` e `QRADAR_MCP_URL`. |
| HTTP 401 no QRadar MCP | Confira se a ponte recebeu `QRADAR_MCP_TOKEN`: presente, ela envia `SEC`; ausente, não envia. Depois confira como **o QRadar MCP da IBM** está configurado para autenticar a requisição (arquivo `config.json` ou credencial no cabeçalho), além de expiração, role e Security Profile. |
| Vision One falha na inicialização | Confira `docker info`, imagem, chave, região e role Workbench/Search; `docker pull` pode revelar problema de acesso à imagem. |
| Kiro mostra “Python was not found” | Rode novamente `configure_kiro.py`; `command` no `mcp.json` deve apontar para o Python absoluto da `.venv`. |
| O demo funciona, mas o caso real falha | A ponte local está instalada; leia **a etapa da falha** no erro para distinguir QRadar MCP, Docker/Trend, autenticação ou coleta. |
| Horários não casam | Confirme o fuso real do console QRadar. O offset inicial `QRADAR_AQL_UTC_OFFSET_HOURS=-3` é uma suposição, não uma medição; pode variar por instalação e data. |

## 9. Encerramento e limites

O QRadar MCP pode ser parado no diretório do upstream com `docker compose down` quando você terminar. O contêiner Trend é removido ao concluir cada execução (`--rm`). O projeto não faz bloqueios, não altera offenses nem envia mensagens de contenção. As tools da ponte são declaradas somente leitura; confira a allowlist no código antes de implantar e restrinja a role upstream. As consultas Ariel podem criar **jobs de busca** no QRadar, sem fechar ou modificar incidentes.

O arquivo `.env.example` da ponte é apenas referência: o Python **não carrega `.env` automaticamente**. A configuração efetiva para o Kiro está em `.kiro/settings/mcp.json` e no ambiente do processo Kiro; a autenticação local do MCP IBM pode estar em `qradar-mcp/config.json`. Evite publicar qualquer um desses arquivos com valores reais. Os scripts históricos de migração do repositório não fazem parte da instalação nova.

Para testar o pacote localmente após atualizar o código:

```powershell
& .\.venv\Scripts\python.exe -m unittest discover -s tests -q
```

Veja [README](../README.md) e [limitações conhecidas](bridge-known-limitations.md) para entender o alcance das tools de investigação e AQL e como interpretar uma correlação.

Descoberta por descrição e investigação em lotes: [guia](offense-batch-investigation.md). As duas novas tools são `qradar_find_offenses` e `qradar_investigate_offenses`.
