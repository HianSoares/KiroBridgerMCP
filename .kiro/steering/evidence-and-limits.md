---
inclusion: always
---

# Evidência, atribuição e limites

## Escala de afirmações

| Rótulo | Uso correto |
| --- | --- |
| `confirmado` | O registro consultado contém exatamente o campo ou evento alegado; indique fonte, timestamp e identificador. Confirma a observação na fonte, não a causa do incidente. |
| `candidato` | Coincidência de IP, host, hash, domínio, usuário ou tempo que exige vínculo adicional. |
| `não verificado` | Campo fornecido manualmente, associação não demonstrada, dado indisponível ou busca não realizada. |

- A ausência de alerta Workbench não significa ausência de detecções, atividade de endpoint ou tráfego. Registre cada fonte pesquisada separadamente.
- Nunca diga “não existe” após busca vazia. Diga “não retornou no conjunto inspecionado”, com fonte, consulta, janela UTC e local, estado, primeira página, total reportado e cap exatamente como o relatório informar. Busca não executada, erro, timeout e cap não são resultados negativos.
- Diferencie evento de arquivo (`fullPath`, arquivo detectado) de processo (`processFilePath`, processo que operou). Leitura ou escrita de `rclone.conf` sustenta atividade de configuração; exfiltração requer telemetria de destino e transferência atribuível ao processo.
- Um IP de inventário é o endereço atual do ativo, não uma prova do IP no instante do evento. IP público pode representar NAT/gateway. Confirme mapeamento histórico por DHCP, proxy, NAT ou fonte equivalente antes de atribuir tráfego ao endpoint.
- Um `action=accept` do FortiGate confirma a ação registrada para aquela sessão, não entrega de conteúdo, processo originador ou falha do filtro Trend. Um `action=blocked` não prova que todas as tentativas foram bloqueadas.
- `policyAction: Collect UAC actions` do EPM é coleta; não prova concessão de elevação. `updater.exe` isolado ou hash ausente não identifica um binário.
- Distinga detecção próxima a um Workbench alert de vínculo verificado com seu View event. Campos colados pelo analista em `investigate_vision_event` não foram confirmados pelo MCP.
- Quando fontes divergem (host do Workbench ≠ host da detecção, host EPM ≠ host Trend, horário fora da janela, usuários diferentes na mesma sessão), registre cada valor como `confirmado` **na sua fonte**, marque o vínculo como `não verificado` e trate a divergência como achado. Não escolha a fonte que fecha a narrativa; diga qual dado desempataria (ID do evento, GUID, DHCP histórico, Log Source Time).
- Nunca declare falso positivo apenas pelo estado fechado, score baixo ou disposição de produto. Cite eventos e justificativa independente, indique confiança e explicite a hipótese alternativa.
- Cada resposta deve expor as consultas e os limites devolvidos pela ferramenta. Não complete janelas, caps, contagens nem resultados ausentes usando valores de outras execuções.

## Vocabulário de status de evidência

Use exatamente estes termos ao citar `requirements`/`decision_matrix`: **confirmado** (demonstrado por registros coletados ou por registro citado pelo analista, indicado como tal); **compatível** (consistente, mas não demonstra); **candidato** (vínculo possível por identificador/tempo/IP, não demonstrado); **não verificado** (não checado ou fora do alcance das fontes); **não retornou nas consultas executadas** (não é prova de ausência); **não executado** (orçamento, permissão, tool ou licença: nada se conclui). Não use pontuação como substituta da evidência; o rank de alertas da offense é só ordenação, com pesos descritos em `rank_criteria`.

## Confirmações com escopo e contradições

Uma confirmação do analista vale apenas para a atividade, as entidades, os processos e a janela que declara, com fonte e referência. Cada instância observada (cada criação de processo, cada script block, cada comando sudo ou troca de identidade, cada entidade das demais atividades) é avaliada por entidade, comportamento/cadeia e janela; as não cobertas e as não avaliadas continuam listadas. O nome de um executável ou de uma conta nunca autoriza todo comportamento dele; autorização abrangente só vale quando o registro externo a declara. Autorização genérica de host, conta ou aplicação não autoriza toda atividade observada. Horários sem fuso explícito são recusados. Registro fora da janela observada gera contradição não resolvida, que bloqueia as conclusões dependentes até ser esclarecida. Confiança é justificada por qualidade do vínculo, procedência (ponte ou registro externo), cobertura, corroboração entre fontes e contradições — nunca por número inventado. Corroboração exige que a segunda fonte descreva comprovadamente a mesma atividade (a mesma execução, ou uma cadeia pai/filho demonstrada, no mesmo host); hash de arquivo identifica um artefato, não uma execução, e a mera existência de eventos QRadar não corrobora um alerta Trend. Não observar de novo um fato não o refuta; uma refutação precisa de evidência e fica registrada com fonte e fatos substituídos.
