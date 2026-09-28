---
name: ad-users-scope
description: Esclarecer a diferença entre inventário total de contas do Active Directory e usuários observados em logs QRadar; não inventar contagem com o MCP.
---

# Usuários do AD vs usuários nos logs

## Quando ativar

Perguntas como “quantos usuários existem no AD?” ou “quantos usuários o QRadar viu?”.

## Passo a passo

1. Defina a métrica: objetos de usuário no domínio, contas habilitadas, toda a floresta, ou nomes distintos observados em logs em certo período. Essas populações não são intercambiáveis.
2. Explique que as sete tools do `soc-bridge-readonly` investigam referências pontuais; nenhuma expõe contagem de diretório, consulta LDAP, AQL agregado livre ou inventário UEBA. Não chame uma tool de incidente para responder ao total.
3. Para o **total de contas**, peça ao analista a saída de uma consulta LDAP/AD executada fora do Kiro com acesso autorizado. A consulta PowerShell LDAP direta está sendo testada separadamente; não afirme que funcionou no ambiente até receber a saída. Especifique domínio/OU, data, contas habilitadas e eventual escopo de floresta.
4. Para **usuários observados em logs**, esclareça que seria necessária consulta agregada Ariel com fonte e janela definidas; esta ponte não oferece tal tool. Uma offense específica pode revelar usuários de sua amostra por `investigate_offense(offense_id)`, jamais o total de usuários ativos do domínio.
5. Se o QRadar UEBA tiver importação LDAP/AD, o número importado ainda depende de filtro e última sincronização. Não presuma essa integração nem seu escopo.

## Tool permitida

Nenhuma para contagem total. `investigate_offense(offense_id)` pode ser usada apenas para examinar usuários de uma offense conhecida, deixando explícita a amostra; `investigate_demo()` demonstra formato sem dados reais.

## Critério de conclusão

Resposta não apresenta contagem inventada, separa população e fonte, e fornece o próximo dado necessário para calcular cada métrica.
