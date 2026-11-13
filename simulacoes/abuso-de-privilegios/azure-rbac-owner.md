# Atribuição da função Owner no Azure RBAC

Uma conta de teste recebeu temporariamente a função Owner apenas no grupo de recursos
do laboratório. O registro descreve uma delegação condicionada que excluía funções
administrativas privilegiadas.

`AzureActivity` registrou operações de atribuição e exclusão da função; a atribuição
foi removida ao final. A [regra de atribuição RBAC](../../deteccoes/regras-analiticas/azure-rbac-role-assignment.md)
detecta a operação de escrita bem-sucedida; a remoção é um evento distinto.
