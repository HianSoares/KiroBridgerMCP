---
name: ad-users-scope
description: "Responder perguntas sobre quantidade de usuários: separar inventário de contas do Active Directory (sem tool na ponte) de usuários observados em logs QRadar por AQL agregada com fonte e janela explícitas, sem inventar contagens."
---

# Inventário do AD versus usuários observados

Regras comuns: `soc-core.md`.

## Quando usar

Perguntas como "quantos usuários existem no AD?" ou "quantos usuários o QRadar viu?".

## Quando não usar

Investigação de uma conta específica num incidente: use offense-investigation ou trend-alert-investigation.

## Entradas mínimas e descoberta automática

- Defina a métrica: objetos de usuário no domínio, contas habilitadas, toda a floresta ou nomes distintos observados em logs num período. Essas populações não são intercambiáveis.
- Para a contagem nos logs, a fonte e a janela vêm da pergunta. Se faltarem, declare o padrão escolhido.

## Procedimento

1. **Total de contas do AD:** a ponte não faz consulta LDAP nem inventário de diretório ou do app QRadar UBA. Peça ao analista a saída de uma consulta LDAP/AD feita fora do Kiro com acesso autorizado, especificando domínio/OU, data, contas habilitadas e escopo de floresta. Não afirme resultado de consulta cuja saída não foi recebida.
2. **Usuários observados em logs:** leia os campos (`qradar_read_aql_resource`) e rode uma AQL agregada (`qradar_run_aql`) com fonte, janela, campos reais e limites, conforme qradar-aql-conventions.
3. **Usuários de uma offense:** uma offense específica mostra usuários da sua amostra (`investigate_offense`), nunca o total do domínio.
4. **UBA:** o número importado do LDAP/AD depende de filtro e da última sincronização. Não presuma essa integração.

## Evidência esperada e falhas

- Uma contagem AQL vale para os eventos retidos e coletados daquela fonte e janela.
- Username vazio ou normalizado de forma diferente altera a contagem; declare isso.

## Continuação, escalonamento e parada

Pare na métrica que as fontes permitem. Indique o próximo dado para as demais.

## Saída

População, fonte, janela e contagem, ou o dado que falta. Nunca uma contagem inventada.

## Tools permitidas

- `qradar_read_aql_resource`, `qradar_validate_aql`, `qradar_run_aql`, `qradar_get_search_status`, `qradar_get_search_results`
- `investigate_offense`, `investigate_demo`

Nenhuma tool conta o total de contas do AD.

## Referências

`qradar-aql-conventions.md`.
