# Limites de coleta da ponte

As sete tools `investigate_*` mantêm sua coleta inicial fixa e limitada. Se um
evento de gatilho ou usuário não aparecer nessa amostra, a identidade continua
não verificada; repetir a mesma chamada não muda o SELECT.

As seis tools `qradar_*` agora permitem AQL personalizada, campos reais do DSM,
payload selecionado, flows, agregações e paginação por search ID. Veja
[fluxo, atualização e limites](dynamic-aql.md). `investigate_offense` também
exibe o search ID de cada busca Ariel quando fornecido pelo upstream.

## Limites que continuam relevantes

- Campos customizados variam por implantação. Leia os resources; não presuma
  `sourceUserName`/`targetUserName` ou um Event ID Windows normalizado.
- Payload depende de armazenamento, retenção e permissões. Não pode ser
  reconstruído pela ponte quando ausente. Campos truncados são sinalizados.
- `starttime` e `devicetime` têm relógios diferentes. START/STOP usa o fuso
  do console; o padrão -3 dos coletores fixos não é uma medição do ambiente.
- Consultas individuais permitem até 24h; agregadas sem payload até 30 dias
  com justificativa. LIMIT restringe retorno, não custo total da varredura.
  Jobs pendentes podem ser retomados; resultado paginado não prova cobertura
  integral. As consultas próprias não passam a integrar automaticamente o
  relatório anterior: o Kiro deve citar ambos os retornos e suas fontes.
- Contar usuários observados em eventos não é contar objetos do Active
  Directory. Total de contas, contas habilitadas e escopo de domínio/floresta
  exigem inventário LDAP/AD ou outra fonte com autoridade sobre esse escopo.
- Flows, quando coletados, não demonstram conteúdo de aplicação ou o processo
  responsável. Muitos destinos UDP/67/68 não comprovam DHCP legítimo.
- A ponte não fecha offenses, altera regras, cria notas, isola endpoints nem
  executa contenção. As buscas AQL criam jobs de consulta no Ariel.

Os testes são sintéticos, incluindo transporte MCP HTTP local. Disponibilidade
das fontes, dados históricos e permissões precisam ser verificados na instalação.
