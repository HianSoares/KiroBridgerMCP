---
name: upstream-tool-access
description: Usar qualquer ferramenta de consulta dos MCPs oficiais QRadar e Vision One pelo registro auditado (upstream_tools, upstream_tool_details, upstream_query), com objetivo, orçamento e paginação real.
---

# Acesso a ferramentas dos MCPs oficiais

## Quando ativar

Quando o objetivo exige um dado que as investigações curadas não coletaram. Exemplos:

- inventário de endpoint;
- tarefas de resposta existentes;
- metadados de regras;
- objetos de referência;
- resultados de sandbox já existentes;
- logs de auditoria;
- Search por host, usuário, processo, hash ou domínio sem ID de alerta.

## Passo a passo

1. Declare o objetivo, o identificador disponível e o orçamento (por exemplo, até 3 chamadas e 2 páginas).
2. Encontre candidatas com `upstream_tools`, usando palavras do objetivo e `access="query"`.
3. Leia `upstream_tool_details` da candidata e confira obrigatórios, enums, `pagination`, `output` e `dependencies`. Se o contrato não retorna o campo necessário, troque de ferramenta.
4. Chame `upstream_query` com argumentos mínimos e janela explícita.
5. Leia `outcome`, `items_returned`, `output_truncated` e `pagination`. Continue apenas com `pagination.next_arguments`, dentro do orçamento.
6. Para relatórios ou pacotes binários, use `upstream_download` (apenas o case-investigator). Não abra nem execute os arquivos.
7. Registre ferramenta, argumentos, resultado, proveniência e lacunas. Classifique cada fato como confirmado, candidato ou não verificado.

## Ao interpretar falhas

- `policy_blocked`: a ferramenta altera estado ou envia dados para fora. Não tente outro caminho; descreva a recomendação para decisão humana.
- `tool_absent`: a instalação não anuncia a ferramenta (toolset, toggle ou versão).
- `contract_changed`: o servidor mudou e a auditoria precisa ser atualizada.
- `permission` / `permission_or_license`: registre como lacuna de acesso com a categoria exata.
- `timeout` / `rate_limited`: não repita em sequência; registre a lacuna ou reduza o escopo.
