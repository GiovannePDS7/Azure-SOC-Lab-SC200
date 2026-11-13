# Linux

A VM `vm-lnx-01` usava Ubuntu Server 24.04 LTS e Azure Monitor Agent. A DCR
`dcr-lnx-syslog` coletava as facilities `auth` e `authpriv` a partir de `INFO`
para a tabela `Syslog`.

O acesso SSH registrado usava chave; um teste de usuário inexistente produziu
eventos `Invalid user` e conexão interrompida. Detalhes estão na
[simulação SSH](../../simulacoes/T1110-autenticacao/ssh-invalid-user.md) e em
[solução de problemas](../../documentacao/troubleshooting.md).
