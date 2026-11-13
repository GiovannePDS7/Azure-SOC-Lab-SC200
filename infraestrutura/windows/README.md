# Windows

A VM `vm-win-01` usava Windows Server 2022 e Azure Monitor Agent. A DCR
`dcr-win-security-common` coletava eventos de segurança no conjunto Common; a DCR
`dcr-win-sysmon` coletava o canal operacional do Sysmon por XPath personalizado.

A auditoria de criação de processos estava habilitada, e a política de inclusão da
linha de comando foi ativada para enriquecer o evento 4688. As tabelas usadas eram
`SecurityEvent` e `Event`. Veja a [arquitetura](../../documentacao/architecture.md)
e as [simulações Windows](../../simulacoes/README.md).
