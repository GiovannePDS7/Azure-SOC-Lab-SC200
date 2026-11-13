# Atribuição de função de diretório no Entra ID

Uma conta de teste recebeu temporariamente a função Directory Readers. `AuditLogs`
registrou adição e remoção de membro da função com sucesso; a ausência da atribuição
foi confirmada em Assigned roles.

A [regra de alteração de função](../../deteccoes/regras-analiticas/privileged-role-change.md)
detecta adições bem-sucedidas. A remoção é registrada separadamente e não deve ser
tratada como uma segunda adição.
