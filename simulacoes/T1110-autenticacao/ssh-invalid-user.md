# Tentativas SSH com usuário inexistente

O teste tentou acessar a VM Linux isolada com um usuário inexistente. Entre 05:44:11
e 05:44:29 UTC de 18/10/2026, foram registrados quatro eventos em `Syslog`.

O sinal observado foi `Invalid user` e conexão interrompida, não uma sequência de
senhas aceitas para teste: a VM estava configurada para autenticação por chave.
A [regra SSH](../../deteccoes/regras-analiticas/brute-force-ssh.md) considera
`Invalid user` e `Failed password`. A fonte não registra uma limpeza específica para
essas tentativas.
