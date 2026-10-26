---
name: upstream-tool-access
description: "Usar qualquer ferramenta de leitura dos MCPs oficiais QRadar e Vision One pelo registro auditado (upstream_tools, upstream_tool_details, upstream_query) quando as investigações curadas não coletaram o dado, com objetivo, orçamento, paginação real e erros por categoria."
---

# Acesso a ferramentas dos MCPs oficiais

Regras comuns: `soc-core.md`. Detalhes de domínio: `upstream-access.md`.

## Quando usar

O objetivo exige um dado que as entradas curadas não trouxeram. Exemplos: inventário de endpoint, tarefas de resposta existentes, metadados de regras, objetos de referência, resultados de sandbox já existentes, logs de auditoria, Search por host, usuário, processo, hash ou domínio sem ID de alerta.

## Quando não usar

- Quando uma entrada curada já cobre o dado (`investigate_*`, `qradar_*`, `trend_*`).
- Para qualquer alteração: `access=change` é recusado (`policy_blocked`) e nunca faz parte da investigação.

## Entradas mínimas e descoberta automática

O objetivo e o identificador disponível. `upstream_tools` encontra candidatas por palavras e `upstream_tool_details` dá o contrato.

## Procedimento

1. Declare o objetivo, o identificador e o orçamento (por exemplo, até 3 chamadas e 2 páginas), dentro do orçamento da investigação.
2. Chame `upstream_tools` com `access="query"`.
3. Leia `upstream_tool_details`: obrigatórios, enums, `pagination`, `output` e `dependencies`. Se o contrato não retorna o campo necessário, troque de ferramenta.
4. Chame `upstream_query` com argumentos mínimos e janela explícita.
5. Leia `outcome`, `items_returned`, `items_delivered`, `output_truncated` e `pagination`. Continue só com `pagination.next_arguments`. Quando houver `pagination.recover`, repita com `skip_items` antes de qualquer `next_page_arguments`.
6. Para relatórios ou pacotes binários, use `upstream_download` (somente case-investigator). Isso grava localmente em `reports/downloads`; não abra nem execute os arquivos.

## Evidência esperada e falhas

- **Bloqueios antes da chamada:** `policy_blocked`, `tool_absent`, `discovery_incomplete` e `contract_changed` bloqueiam a chamada, e nada foi consultado.
- **Permissão e licença:** `permission` e `permission_or_license` são lacunas de acesso com a categoria exata. Não presuma licença sem a categoria correspondente.
- **Timeout e limite de taxa:** `timeout` e `rate_limited` não justificam repetição em sequência.
- **Resultado incerto:** `result_state: unknown` em `create_ariel_search` exige verificar a criação antes de criar outro job.

## Continuação, escalonamento e parada

Pare ao obter o dado, ao esgotar o orçamento declarado ou quando o contrato não oferecer o campo. Registre a lacuna.

## Saída

Ferramenta, argumentos, estado, resultado com proveniência e lacunas, com cada fato rotulado como confirmado, candidato ou não verificado.

## Tools permitidas

- `upstream_tools`, `upstream_tool_details`, `upstream_query`
- `upstream_inventory`
- `upstream_download` (somente case-investigator)

## Referências

`upstream-access.md` (paginação, limites, erros e alterações fora da investigação).
