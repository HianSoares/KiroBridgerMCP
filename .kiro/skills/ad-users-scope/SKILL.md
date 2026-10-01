---
name: ad-users-scope
description: Esclarecer a diferença entre inventário total de contas do Active Directory e usuários observados em logs QRadar; não inventar contagem com o MCP.
---

# Usuários do AD vs usuários nos logs

## Quando ativar

Perguntas como “quantos usuários existem no AD?” ou “quantos usuários o QRadar viu?”.

## Passo a passo

1. Defina a métrica: objetos de usuário no domínio, contas habilitadas, toda a floresta, ou nomes distintos observados em logs em certo período. Essas populações não são intercambiáveis.
2. Explique que a ponte oferece AQL agregada sobre logs, mas não contagem de diretório, consulta LDAP ou inventário do app QRadar User Behavior Analytics (UBA). Não chame uma tool de incidente para responder ao total.
3. Para o **total de contas**, peça ao analista a saída de uma consulta LDAP/AD executada fora do Kiro com acesso autorizado. Não afirme resultado de consulta cuja saída não foi recebida. Especifique domínio/OU, data, contas habilitadas e eventual escopo de floresta.
4. Para **usuários observados em logs**, use consulta agregada Ariel via qradar_* com fonte/janela definidas, campos reais e limites conforme qradar-aql-conventions, em perfil que exponha essas tools. Uma offense específica pode revelar usuários de sua amostra por `investigate_offense(offense_id)`, jamais o total de usuários ativos do domínio.
5. Se o app QRadar UBA tiver importação de usuários LDAP/AD, o número importado ainda depende de filtro e última sincronização. Não presuma essa integração nem seu escopo.

## Tool permitida

Nenhuma para contagem total do AD. Tools qradar_* somente para contagens de usuários observados em logs com escopo explícito. `investigate_offense(offense_id)` pode ser usada apenas para examinar usuários de uma offense conhecida, deixando explícita a amostra; `investigate_demo()` demonstra formato sem dados reais.

## Critério de conclusão

Resposta não apresenta contagem inventada, separa população e fonte, e fornece o próximo dado necessário para calcular cada métrica.
