# T1053.005 — Tarefa agendada

O Atomic Test #2 criou uma tarefa de teste no Windows. Sua existência foi confirmada
localmente e o evento 4688 registrou `schtasks.exe /Create`. O evento 4698 esperado
não foi observado, portanto a validação usou a evidência alternativa. A limpeza foi
executada.

Consulte o [diário](../../documentacao/attack-journal.md) e a
[regra de tarefa agendada](../../deteccoes/regras-analiticas/scheduled-task-creation.md).
