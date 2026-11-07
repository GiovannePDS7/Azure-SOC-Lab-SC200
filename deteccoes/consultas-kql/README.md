# Consultas KQL

As consultas estão organizadas por origem de dados e caso de uso. Antes de
executá-las, confirme a disponibilidade das tabelas e dos campos no workspace.

## Consultas das regras analíticas exportadas

Estas consultas correspondem às regras do export fornecido para o Sentinel. São
detecções de laboratório, não limiares prontos para produção; valide-as no esquema
do workspace ativo e ajuste-as ao ambiente.

| Consulta | Regra |
| --- | --- |
| [Falhas de autenticação SSH](linux/ssh-authentication-failures.kql) | Força bruta SSH |
| [Falhas de logon RDP](windows/failed-rdp-logons.kql) | Força bruta RDP |
| [Atribuição Azure RBAC](azure/rbac-role-assignment.kql) | Atribuição de função Azure RBAC |
| [Atribuição de função privilegiada no Entra ID](entra-id/privileged-role-assignment.kql) | Atribuição de função no Entra ID |
| [Criação de tarefa agendada](windows/scheduled-task.kql) | `schtasks.exe /Create` |
| [PowerShell codificado](windows/encoded-powershell.kql) | Comando PowerShell codificado |
| [Criação de conta local](windows/local-account-created.kql) | Evento 4720 do Windows |
| [Falhas de autenticação no Entra ID](entra-id/failed-signins.kql) | ResultType 50126 |

O export JSON correspondente está em [regras analíticas](../regras-analiticas/azure-sentinel-analytics-rules.json).
