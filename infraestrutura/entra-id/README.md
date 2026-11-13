# Microsoft Entra ID

O diagnóstico do Microsoft Entra ID enviava auditoria e eventos de entrada para
`AuditLogs` e `SigninLogs` no workspace do laboratório.

Uma conta de teste recebeu temporariamente Directory Readers; a adição e a remoção
foram registradas e a ausência da atribuição foi verificada. Outro teste gerou
falhas de entrada `50126`. Consulte as simulações de
[função de diretório](../../simulacoes/abuso-de-privilegios/entra-directory-role.md)
e [autenticação](../../simulacoes/T1110-autenticacao/entra-failed-signins.md).

Não publique identificadores de contas, tenant ou assinatura nem credenciais de
teste. Em uma recriação, restrinja e remova as atribuições temporárias.
