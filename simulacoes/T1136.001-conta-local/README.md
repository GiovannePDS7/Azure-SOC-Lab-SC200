# T1136.001 — Conta local

O Atomic Test #4 criou uma conta local de teste na VM Windows. O registro aponta
evento 4720 em `SecurityEvent`, código de saída 0 e limpeza executada.

A primeira tentativa falhou por causa da política de senha; os parâmetros do teste
foram ajustados para atendê-la, sem enfraquecer a política. O modo interativo
resolveu a espera por entrada. Consulte o [diário](../../documentacao/attack-journal.md)
e a [regra de criação de conta](../../deteccoes/regras-analiticas/local-account-creation.md).
