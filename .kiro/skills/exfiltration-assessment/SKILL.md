---
name: exfiltration-assessment
description: Avaliar suspeita de exfiltração, inclusive RClone, distinguindo detecção de arquivo, configuração, execução e transferência comprovada.
---

# Suspeita de exfiltração

## Quando ativar

Um alerta/ofense envolve utilitário de nuvem, cópia, sync, envio externo ou possível staging de dados.

## Passo a passo

1. Comece pela referência conhecida: `investigate_vision_alert({"alert_id":"WB-EXEMPLO-0002"})`, `investigate_offense({"offense_id":12345})` ou `investigate_case({"reference":"WB-EXEMPLO-0002"})`. Esses IDs são fictícios.
2. Forme uma cadeia de evidências separadas: arquivo presente/detectado → processo com hash correspondente ativo → comando e usuário → arquivos acessados → conexão de rede atribuível ao processo → destino/volume/resultado. Anote explicitamente em qual elo a coleta parou.
3. Leitura ou escrita de `rclone.conf` sugere interação com configuração. Não equivale a `copy`/`sync`, conexão com remote nem transferência concluída. Processo de segurança que examina `rclone.exe` não é execução do `rclone.exe`. Ausência de `rclone.exe` por nome não exclui cópia renomeada (prática comum); no auto-pivô de “RClone Detection”, a ponte também busca `malName` `HZ_RCLONE64`/`RCLONE`, o que cobre parte das cópias renomeadas. O discriminante forte é a linha de comando (`copy|sync|move <origem> <remote>:<destino>`, `--config <caminho>`), visível só se a busca por hash de processo retornar `processCmd`; o tipo de remote (`type = s3|drive|mega|sftp…`) está no conteúdo do `rclone.conf`, que a ponte não lê.
4. Se campos de View event forem copiados, `investigate_vision_event` requer `alert_id`, IP exato e `event_time` ISO-8601 com fuso. Use host, hash, file_path/process_path somente quando obtidos do mesmo evento e identifique todos como dados manuais não verificados pela ponte.
5. Consulte no relatório o que Ariel/Trend Search executaram; não atribua tráfego de NAT/egress a processo com base em IP/tempo. Solicite linha de comando e telemetria processo-rede no endpoint; avalie DNS/proxy/firewall, destino remoto, bytes e sucesso da operação quando disponíveis ao analista.
6. Hipóteses: configuração legítima; execução sem transferência; transferência autorizada (backup/sync sancionado); exfiltração. Cite o que confirma/refuta cada uma e a confiança. ATT&CK condicionado ao elo comprovado: artefato isolado (binário, `rclone.conf`) não sustenta técnica de exfiltração; registre no máximo o Rclone (S1040) como ferramenta observada. Com transferência demonstrada, escolha pela via: remote de armazenamento em nuvem (S3, Google Drive, MEGA, Dropbox etc.) → T1567.002 Exfiltration Over Web Service: Exfiltration to Cloud Storage; SFTP → T1048.002; FTP ou outro protocolo não criptografado → T1048.003. Elos anteriores têm técnicas próprias, cada uma exigindo evidência: T1560.001 Archive via Utility, T1074 Data Staged, T1030 Data Transfer Size Limits.

## Tools permitidas

`investigate_case`, `investigate_offense`, `investigate_vision_alert` e `investigate_vision_event`, cada qual com os parâmetros obrigatórios definidos pela lista de tools. Não há tool de captura ou bloqueio de rede.

## Critério de conclusão

O veredito distingue “binário detectado”, “processo ativo” e “transferência demonstrada”; ausência de qualquer elo aparece como lacuna com fonte e consulta necessária.
