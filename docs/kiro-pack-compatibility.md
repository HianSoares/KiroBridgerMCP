# Compatibilidade do pacote Kiro

Versão alvo: **Kiro IDE 1.4.26**, instalado em `%LOCALAPPDATA%\Programs\Kiro`. Os arquivos `resources/app/product.json` e `package.json` registram a versão 1.4.26 e a data de build 2026-10-22. Fiz a inspeção offline, sem abrir sessões nem consumir créditos.

## Documentação oficial consultada (2026-10-26)

| Página | Atualizada em | O que confirma |
| --- | --- | --- |
| https://kiro.dev/docs/custom-agents/configuration-reference/ | 2026-10-10 | Campos do agente, incluindo `permissions`. `tools` aceita `@server/tool`, categorias (`read`, `write`, `shell`, `web`, `subagent`) e `@builtin`/`@mcp`. Recursos `file://` e `skill://` (este carrega metadados no início e o conteúdo sob demanda). `allowedTools`, `toolAliases` e `keyboardShortcut` são do CLI 2.x; `toolsSettings` está obsoleto. O formato vale para IDE 1.0 e CLI V3. |
| https://kiro.dev/docs/custom-agents/subagents/ | 2026-10-24 | O orquestrador precisa da tool `subagent`. O subagente tem histórico isolado e usa as próprias `tools`. `toolsSettings.subagent.availableAgents` e `trustedAgents` aparecem nos exemplos. |
| https://kiro.dev/docs/skills/ | 2026-10-21 | `SKILL.md` com `name` (igual ao nome da pasta; minúsculas, dígitos e hífen; até 64 caracteres) e `description` (até 1024). Agentes customizados não carregam skills por padrão: é preciso declarar `skill://` em `resources`, com caminho ou glob (por exemplo `skill://.kiro/skills/*/SKILL.md`). |
| https://kiro.dev/docs/steering/ | 2026-10-21 | Modos de inclusão `always`, `fileMatch` (com `fileMatchPattern`), `manual` e `auto` (com `name` e `description`). Agentes customizados não carregam steering automaticamente: é preciso declarar `file://` em `resources`. |
| https://kiro.dev/docs/specs/ | 2026-10-15 | `requirements.md` (ou `bugfix.md`), `design.md` e `tasks.md`, com tarefas acompanhadas pela interface de specs. |

## Evidência do código instalado (`extensions/kiro.kiro-agent/dist/extension.js`)

- **Resolução de recursos.**
  - O que vem depois de `file://` ou `skill://` é resolvido como caminho absoluto, como `~/...` ou como `path.join(pasta do workspace, caminho)`. Globs são expandidos.
  - O resolvedor de skills lê o caminho resolvido **como o próprio `SKILL.md`** e exige `name` e `description` no front matter.
  - `skill://offense-investigation`, a forma usada até aqui, resolve para `<workspace>/offense-investigation`, que não existe. Por isso as skills não carregavam para os agentes customizados. A forma correta é `skill://.kiro/skills/<nome>/SKILL.md`.
- **Schema do front matter do agente:** `name`, `description`, `tools`, `excludedTools`, `model`, `effortLevel`, `includeMcpJson`, `includePowers`, `mcpServers`, `resources`, `permissions`, `welcomeMessage`, `dispatchKind` e `hooks`. `allowedTools` e `toolsSettings` são marcados como campos exclusivos do CLI. Na IDE 1.4.26, `toolsSettings.subagent.availableAgents` não é aplicado.
- **Filtro de tools.** Uma tool entra quando um item de `tools` coincide com o id dela, com um alias ou com uma tag.
  - Cada agente customizado vira uma tool de delegação com as tags `subagent`, `@subagent` e `subagent/<id>`. Assim, `subagent/threat-hunter` libera só esse alvo.
  - Essa forma por agente vem do código, não da documentação.
- **Carregamento sob demanda.** `disclose_context` carrega skills e steering `auto`. A tool não tem tags e é reconhecida pelo id, por isso aparece explicitamente nos agentes que usam skills.
  - Não confirmei se a IDE a acrescenta por conta própria quando há recursos `skill://`. Listá-la não amplia acesso a arquivos ou produtos.
- **Modos de steering.** O prompt do sistema reconhece `always`, `fileMatch`, `manual` e `auto`; `auto` é ativado por `disclose_context`.

## Compatibilidade

| Item | Estado |
| --- | --- |
| Campos do front matter dos agentes | Confirmado: schema da 1.4.26 e documentação. |
| Caminhos `file://` e `skill://` | Confirmado: resolvedor da 1.4.26, reproduzido em `tests/test_kiro_pack_contract.py`. |
| `disclose_context` | Confirmado: tool presente na 1.4.26. A necessidade de listá-la explicitamente não foi confirmada; listá-la é seguro. |
| Delegação por `subagent/<id>` | Derivado do código da 1.4.26, não documentado. A execução real não foi validada. |
| `toolsSettings.subagent` | Não usado: campo exclusivo do CLI na IDE 1.4.26. |
| Ativação de skills e steering `auto`, delegação e qualidade das respostas | **Pendente:** exige uma sessão real do Kiro, ainda não executada por falta de créditos. |
| Kiro CLI | Não verificado. O pacote segue o formato IDE 1.0 / CLI V3, mas a delegação no CLI usaria `toolsSettings.subagent`. |

## Ao atualizar o Kiro

1. Confira a versão em `resources/app/product.json`.
2. Rode `python -m unittest tests.test_kiro_pack_contract`.
3. Repita as buscas no `extension.js` por `skill://`, `availableAgents`, `subagent/` e `disclose_context`.
4. Se o resolvedor, o schema ou as tags mudarem, ajuste o pacote e os testes juntos antes de usar o pacote.
