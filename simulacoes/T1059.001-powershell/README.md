# T1059.001 — PowerShell

O Atomic Test #17 executou PowerShell no endpoint Windows do laboratório. A fonte
registra código de saída 0 e execução de `powershell.exe` com `-e` no evento 4688,
além de criação de processo no evento 1 do Sysmon.

Consulte o [diário](../../documentacao/attack-journal.md) e a
[regra de PowerShell codificado](../../deteccoes/regras-analiticas/encoded-powershell.md).
Os exemplos são telemetria de teste, não evidência de atividade maliciosa real.
