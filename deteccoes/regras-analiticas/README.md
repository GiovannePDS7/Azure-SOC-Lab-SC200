# Regras analíticas

As oito regras abaixo estão descritas no registro oficial do laboratório e incluídas
no [export ARM parametrizado do Sentinel](azure-sentinel-analytics-rules.json). No
export fornecido, todas estão habilitadas com severidade Medium e frequência de
cinco minutos. Consulte cada descrição para ver os períodos de consulta, os
mapeamentos de entidades, o agrupamento e o estado da validação.

| Regra | Origem dos dados | ATT&CK | Detalhes |
| --- | --- | --- | --- |
| Tentativas SSH com usuário inexistente | `Syslog` | T1110 | [Descrição](brute-force-ssh.md) |
| Força bruta RDP (4625) | `SecurityEvent` | T1110 | [Descrição](brute-force-windows.md) |
| Atribuição de função Azure RBAC | `AzureActivity` | T1098 | [Descrição](azure-rbac-role-assignment.md) |
| Atribuição de função privilegiada no Entra ID | `AuditLogs` | T1098 | [Descrição](privileged-role-change.md) |
| Criação de tarefa agendada (`schtasks /Create`) | `SecurityEvent` | T1053 / T1053.005 | [Descrição](scheduled-task-creation.md) |
| Processo PowerShell com comando codificado | `SecurityEvent` | T1059 / T1059.001 | [Descrição](encoded-powershell.md) |
| Criação de conta local (4720) | `SecurityEvent` | T1136 / T1136.001 | [Descrição](local-account-creation.md) |
| Falhas de autenticação no Entra ID (50126) | `SigninLogs` | T1110 | [Descrição](entra-failed-signins.md) |

Com `Trigger threshold = 0` e `GreaterThan`, um alerta é gerado quando a consulta
retorna um resultado; os limiares de quantidade de eventos são definidos na KQL. O
export mapeia entidades somente para SSH, RDP e falhas de autenticação no Entra ID.
O período da consulta RDP e a janela de agrupamento de incidentes diferem dos valores
registrados na seção detalhada do PDF. Antes da implantação, consulte o
[registro sanitizado do laboratório](../../documentacao/lab-build-record.md).
