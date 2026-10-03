# Casos locais: armazenamento, retenção e exclusão

`investigate_offense_case` e `reassess_case` gravam um arquivo JSON por caso. Por padrão o diretório é `reports/cases/`, que o Git ignora; pode ser outro com `SOC_BRIDGE_CASE_DIR`. Essas são as únicas escritas da ponte, e são locais: nenhum objeto do QRadar ou da Trend é alterado.

## O que o caso contém

- **Identificação:** ID do caso (padrão `offense-<id>`), referências de offense e alertas, escopo autorizado e fontes.
- **Metadados:** snapshots dos metadados da offense com o horário da coleta.
- **Consultas:** cada consulta com AQL, search ID, estado, cursor (`next_start`) e linhas coletadas (até 5000 por consulta), além do histórico de jobs substituídos.
- **Evidências consolidadas:** cada registro aparece uma vez, com todas as consultas que o devolveram (`seen_in`), o nível de vínculo e relógios separados (recepção, horário do dispositivo e execução).
- **Raciocínio:** pivôs, hipóteses, contradições e pendências.
- **Confirmações do analista:** com origem explícita, "analyst-supplied; not verified by the bridge".
- **Histórico:** decisões e revisões do relatório (até 50), sem apagar as anteriores.

Tokens, cabeçalhos de autenticação, sessões MCP e clientes de rede não são gravados. Se o valor de `QRADAR_MCP_TOKEN` ou de `TREND_VISION_ONE_API_KEY` aparecer nos dados, a gravação é recusada e nada é escrito. Chaves com nome de credencial são descartadas.

## Gravação, concorrência e retomada

- **Gravação atômica:** o arquivo é escrito como temporário e depois substituído. No Linux/WSL a permissão é `0600`.
- **Concorrência:** cada gravação confere a revisão. Se outro processo atualizou o caso, a gravação é recusada (`CaseConflict`) em vez de sobrescrever.
- **Checkpoint:** o progresso do QRadar é salvo antes da etapa Trend.
- **Retomada:** a retomada continua o mesmo job Ariel a partir do cursor salvo. Um resultado completo é reutilizado sem nova chamada.
- **Criação incerta:** uma criação incerta (`creation_uncertain`) não é recriada. Confira no QRadar se o job existe e, se necessário, peça explicitamente `rerun_queries=["<nome>"]`.
- **Sem garantia de execução única:** se o processo parar entre a criação de um job e a próxima gravação, o job pode existir no QRadar sem constar no caso. Cancelar localmente não prova que o upstream não criou o job.

## Retenção e exclusão

- Retenção padrão: 30 dias desde a última atualização. Ajuste com `SOC_BRIDGE_CASE_RETENTION_DAYS`.
- Comandos:

```bash
soc-bridge cases list
```
```bash
soc-bridge cases show offense-12345
```
```bash
soc-bridge cases delete offense-12345
```
```bash
soc-bridge cases purge
```

No Windows, rode a partir da `.venv` com `.\.venv\Scripts\soc-bridge.exe cases list` (ou `python -m soc_bridge.cli cases list`).

Os casos contêm telemetria coletada. Trate-os conforme a política de dados da organização, mantenha-os fora de repositórios e de locais públicos e exclua-os quando não forem mais necessários.
