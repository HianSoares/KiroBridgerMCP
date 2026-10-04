# Casos locais: armazenamento, retenção e exclusão

`investigate_offense_case` e `reassess_case` gravam um arquivo JSON por caso. Por padrão o diretório é `reports/cases/`, que o Git ignora; pode ser outro com `SOC_BRIDGE_CASE_DIR`. Essas são as únicas escritas da ponte, e são locais: nenhum objeto do QRadar ou da Trend é alterado.

## O que o caso contém

- **Identificação:** ID do caso (padrão `offense-<id>`), a offense à qual o caso pertence (`offense_id`), referências de offense e alertas, escopo autorizado e fontes.
- **Metadados:** snapshots dos metadados da offense com o horário da coleta.
- **Consultas:** cada consulta com offense, banco, escopo, AQL, search ID, estado, cursor (`next_start`), último checkpoint e linhas coletadas (até 5000 por consulta), além do histórico de jobs substituídos (search ID, AQL, offense, cursor e resultado).
- **Evidências consolidadas:** registros devolvidos por várias consultas são unidos somente quando têm a mesma origem (log source), horários de recepção e do dispositivo, QID e payload idêntico. Registros sem payload, log source ou horário de recepção não têm identidade suficiente e ficam separados por consulta, job e linha. Registros com o mesmo payload mas propriedades diferentes (por exemplo, `ProcessGuid`) também ficam separados. Cada registro guarda todas as consultas que o devolveram (`seen_in`), a base da identidade, o nível de vínculo e relógios separados (recepção, horário do dispositivo e execução).
- **Resultados Trend:** por alerta aprofundado e por execução:
  - **Tentativas:** estado, classificação e erro de cada coleta.
  - **Avaliações:** cada avaliação recebida, com a base estruturada do veredito (registros Search da instância executada, papel, endpoint, PID, horário de início, hashes e veredito de sandbox; observables com papel, fonte e indicador de corte).
  - **Fatos:** cada fato estabelecido (`sustained` ou `refuted`), com a execução em que surgiu e em que foi visto pela última vez, e a fonte.
  - **Revisões:** cada revisão com fundamento, fonte e fatos substituídos.
  - **Avaliação atual:** derivada dos fatos.

  Uma coleta posterior inconclusiva, com timeout, com falha ou sem Trend registra a tentativa e mantém os fatos: não observar de novo não é refutar.
- **Raciocínio:** pivôs, hipóteses, contradições e pendências.
- **Confirmações do analista:** com origem explícita, "analyst-supplied; not verified by the bridge".
- **Histórico:** decisões e revisões do relatório (até 50), sem apagar as anteriores.

Tokens, cabeçalhos de autenticação, sessões MCP e clientes de rede não são gravados. Se o valor de `QRADAR_MCP_TOKEN` ou de `TREND_VISION_ONE_API_KEY` aparecer nos dados, a gravação é recusada e nada é escrito. Chaves com nome de credencial são descartadas.

## Gravação, concorrência e retomada

- **Gravação atômica:** o arquivo é escrito como temporário e depois substituído. No Linux/WSL a permissão é `0600`.
- **Concorrência:** a leitura da revisão, a comparação e a substituição do arquivo acontecem sob um bloqueio exclusivo entre processos (arquivo `.<case_id>.lock` no mesmo diretório; `msvcrt` no Windows, `flock` no Linux/WSL). Se outro processo atualizou o caso, a gravação é recusada (`CaseConflict`) em vez de sobrescrever; duas gravações da mesma revisão não podem ambas ter sucesso. Se o bloqueio não for obtido em 15 s, nada é gravado (`CaseLocked`).
- **Isolamento por offense:** um `case_id` pertence a uma offense. Chamar `investigate_offense_case` com um `case_id` de outra offense é recusado antes de qualquer consulta. Uma consulta salva só é retomada se offense, banco, escopo e AQL forem iguais aos planejados agora; caso contrário, o job antigo não é tocado, fica no histórico e a consulta planejada roda como job novo.
- **Checkpoints:** o caso é gravado antes da primeira chamada ao QRadar, antes de cada criação de job (como `creation_uncertain`), assim que o search ID chega e após cada página (linhas e cursor da próxima página). Se a execução for cancelada, os search IDs, cursores e linhas já gravados permanecem e a execução fica marcada como cancelada.
- **Retomada:** a retomada continua o mesmo job Ariel a partir do cursor salvo. Um resultado completo é reutilizado sem nova chamada.
- **Criação incerta:** uma criação incerta (`creation_uncertain`) não é recriada. Confira no QRadar se o job existe e, se necessário, peça explicitamente `rerun_queries=["<nome>"]`.
- **Sem garantia de execução única:** se o processo parar depois que o QRadar criou o job, mas antes de a resposta chegar, o caso fica com `creation_uncertain` sem o search ID. Cancelar localmente não prova que o upstream não criou o job.
- **Reavaliação:** `reassess_case` usa a coleta QRadar e os fatos Trend gravados, sem consultas novas. Um registro `trend_finding_refuted` do analista refuta fatos de um alerta (todos, ou só um vínculo `qradar_link`) com fundamento, fonte e o conteúdo probatório refutado. Nenhuma observação nova desfaz a refutação sozinha (mesma evidência, novo job, metadados, hashes incompletos ou identificadores alterados): ela fica registrada para revisão, e só `trend_finding_reinstated` a revisa com fundamento. Um vínculo cujos identificadores são contraditos por evidência atual fica `contradicted`, com histórico, e sai da conclusão. Vínculos gravados por critérios anteriores que não se confirmam ficam `needs_revalidation`.
  A refutação acompanha a execução e a relação com a instância QRadar: mudar somente o UUID de um evento Trend não cria outro vínculo. Fatos antigos baseados em UUID mantêm seus IDs; aliases da mesma execução/relação herdam a refutação, com origem registrada. Cada fato guarda referências de observações em `provenance` (até 50). Vínculos atuais e históricos são comparados com todos os descritores atuais da instância QRadar; conflito de hash ou horário no mesmo GUID não desaparece por estar fora da tolerância temporal nem pela presença de um registro compatível.
- **Listas de análise:** o resultado gravado guarda todas as criações de processo, script blocks e comandos sudo/su (até 5000 por classe) para as decisões; os relatórios continuam mostrando no máximo 100. Linhas de comando acima de 8192 caracteres ficam marcadas como cortadas.

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

Os arquivos `.<case_id>.lock` não contêm dados e podem permanecer no diretório.

Os casos contêm telemetria coletada. Trate-os conforme a política de dados da organização, mantenha-os fora de repositórios e de locais públicos e exclua-os quando não forem mais necessários.
