---
name: offense-investigation
description: "Investigar offense QRadar por ID ou por descrição, inclusive sem alerta Workbench: caso persistido, registros INOFFENSE, flows, regras, autenticação, privilégio Linux/Windows, processos, fila OPEN e decisão de fechamento com impedimentos explícitos."
---

# Offense do QRadar

Regras comuns: `soc-core.md`. Detalhes de domínio: `offense-verification.md`, `case-workflow.md` e `qradar-aql-conventions.md`.

## Quando usar

- "Investigue a offense X", lista de offenses por descrição ou fila OPEN a priorizar.
- Investigação de offense sem alerta Workbench.

## Quando não usar

- Alerta `WB-` como entrada principal: use trend-alert-investigation.
- Contagem total de contas do AD: use ad-users-scope.
- Teste de uma hipótese específica já delimitada: delegue ao threat-hunter com o contrato de passagem.

## Entradas mínimas e descoberta automática

- **Entrada mínima:** o ID da offense, ou a descrição exata.
- A ponte obtém o resto: metadados, IPs, regras, eventos, flows e alertas Trend relacionados. Não peça IP, host ou horário antes de chamar a tool.
- Peça ao analista apenas o fuso confirmado do console para uma janela histórica fixa, ou um registro externo (autorização, CRE no editor de regras).

## Procedimento

1. **Uma offense:** chame `investigate_offense_case(offense_id)`. Para continuar, chame de novo com o mesmo `case_id`; com registros do analista, `reassess_case`.
2. **Variações de entrada:**
   - Só QRadar ou sem credencial Trend: `qradar_verify_offense(offense_id)`.
   - Relatório sem persistência: `investigate_offense(offense_id)`.
3. **Várias offenses:** use `qradar_investigate_offenses(description=..., status="OPEN", match="exact")` ou descubra os IDs com `qradar_find_offenses`. Para a fila OPEN, `qradar_list_offenses(status="OPEN")`. Siga os cursores, retenha os IDs vistos e mantenha decisão e nota por offense.
4. **Ordem de leitura:** `offense_evidence` (metadados originais, janela INOFFENSE, eventos e flows, censo COUNT/UNIQUECOUNT, regras, host), depois `outcome` de cada consulta e `continuation_plan`. A coleta antiga por IP é só contexto.
5. **Continuação:** retome jobs pelo mesmo search ID e cursor, e pagine. LIMIT atingido exige uma nova consulta particionada. Execute os pivôs `planned` do caso antes de oferecer qualquer aprofundamento opcional.
6. **Regras:** consulte pelos IDs devolvidos com `qradar_get_rule`. Metadados não garantem a definição completa da CRE. Contexto adicional (`qradar_read_context`) só quando uma regra, QID, log source ou coleção puder mudar a conclusão.
7. **Hipóteses:** teste a maliciosa, a legítima, o erro de detecção e o erro de atribuição. Diga qual evidência discrimina cada uma.
8. **Alertas Trend relacionados (`deepened_alerts`):** a ligação continua `candidate` até `link = demonstrated`; nesse caso, siga case-workflow.

### Autenticação e identidade

- 4624/4625/4648/4768/4769 e eventos de VPN ou IdP descrevem tentativa, sucesso, tipo de logon e conta. 4648 é tentativa com credencial explícita; sucesso e serviço exigem correlação.
- Conta, origem e destino são campos de papéis diferentes: `source`/`target` e `subject`/`account` não se confundem.
- Username vazio em evento PAM ou de logon:
  1. mantenha a identidade `não verificada`;
  2. leia os campos da implantação (`qradar_read_aql_resource`);
  3. faça um pivô focado com `qradar_run_aql` (offense ou QID, log source, `devicetime`, propriedades reais, `UTF8(payload)`).

  Se o dado não estiver armazenado, registre a lacuna. Não invente identidade nem repita a coleta esperando colunas novas.
- O nome da conta (svc_, adm_, backup) não demonstra natureza, dono nem autorização.

### Privilégio Linux e Windows

- **Linux:**
  - `pam_unix(su:session): session opened for user <alvo> by <origem>(uid=N)` identifica origem e alvo.
  - `sudo` com `USER=<alvo> ; COMMAND=…` traz o comando.
  - Correlacione com o SSH anterior da mesma sessão. `su` não é login SSH root.
  - Leia o censo completo de `linux.offense` e as buscas SSH/su na janela estrita.
- **Windows:**
  - 4672 (privilégios especiais), 4688 com token elevado, 4732/4728 (inclusão em grupo) e UAC são classes distintas. Pedido de elevação não é elevação concedida.
  - Criação de processo, conteúdo PowerShell (4104/4103) e 5038 seguem offense-verification.
  - Vínculo pai/filho só por GUID e host.
- **ATT&CK condicional:**
  - SSH com conta válida → T1021.004 + T1078 (.003 se a conta for local);
  - abuso de `sudo` → T1548.003;
  - `su` com a senha do alvo → T1078.003.

  Só com o comportamento observado.

## Evidência esperada e falhas

- **Campos observados:** description e nome de regra não provam comportamento. Magnitude é prioridade do produto, e CLOSED é estado, não veredito. severity, credibility, relevance e closing_reason_id só valem quando retornados.
- **Contagens e tempos:** divergências de contagem ficam sem causa atribuída até verificar unidade, janela e momento. Tempo cru, tempo observado e padding são valores distintos.
- **Payload:** null não prova ausência no payload.
- **Estados:** `pending`, `error`, `unavailable`, `empty` e `partial` seguem a tabela de estados de `soc-core.md`. Uma falha numa página preserva as linhas e o cursor.

## Continuação, escalonamento e parada

- Continue os jobs conhecidos e os pivôs `planned` acessíveis.
- Delegue ao threat-hunter só uma hipótese discriminante delimitada, com fração explícita do orçamento.
- Pare quando a próxima evidência exigir fonte inacessível ou registro externo. Liste-a em "O que falta e onde obter".

## Saída

- Decisão recomendada, razão e confiança por achado.
- Motivo do catálogo real (`closing_reasons`, nome e ID) somente quando `ready_to_close` estiver sustentado; caso contrário, manter pendente com o impedimento.
- Fatos com search ID e linha, consultas e cobertura, hipóteses e lacunas (`gap_details`).
- Nota sugerida em pt-BR, não publicada. `False-Positive, Tuned` exige tuning aplicado e verificado.

## Tools permitidas

- `investigate_offense_case`, `reassess_case`, `list_cases`, `get_case`, `bridge_diagnostics` (somente case-investigator)
- `investigate_offense`, `investigate_case`
- `qradar_verify_offense`, `qradar_get_rule`, `qradar_find_offenses`, `qradar_investigate_offenses`, `qradar_list_offenses`, `qradar_read_context`, `qradar_assess_closure`
- `qradar_read_aql_resource`, `qradar_validate_aql`, `qradar_start_aql`, `qradar_get_search_status`, `qradar_get_search_results`, `qradar_run_aql`

## Referências

`offense-verification.md` (coleta, tempo, processos, Linux, fechamento e lotes), `case-workflow.md` (caso, confirmações e vínculo com alertas) e `qradar-aql-conventions.md` (AQL e jobs).
