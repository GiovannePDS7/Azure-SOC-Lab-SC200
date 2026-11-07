# Cobertura MITRE ATT&CK

Esta tabela registra as oito regras analíticas do Sentinel incluídas no arquivo
exportado e as técnicas associadas a elas. Para algumas regras, o export registra a
técnica principal, enquanto a simulação ou a descrição da regra cita uma subtécnica
mais específica. A tabela não comprova cobertura completa do ATT&CK. A seção
detalhada da matriz no registro oficial lista verificações pendentes, mas a lista
final afirma que as capturas de antes e depois foram concluídas; a variação exata de
cobertura não foi transcrita. O responsável confirmou que todas as oito regras foram
testadas e validadas no Azure antes da exclusão do laboratório. Essa validação das
regras não comprova, por si só, a variação da cobertura na matriz ATT&CK.

| Técnica registrada no export | Simulação / comportamento | Detecção | Tabela de origem | Estado registrado |
| --- | --- | --- | --- | --- |
| T1110 | Falhas de autenticação SSH | [Força bruta SSH com usuário inexistente](../deteccoes/regras-analiticas/brute-force-ssh.md) | `Syslog` | Testada e validada no Azure; laboratório excluído |
| T1110 | Falhas de autenticação RDP | [Força bruta RDP](../deteccoes/regras-analiticas/brute-force-windows.md) | `SecurityEvent` | Testada e validada no Azure; incidente observado |
| T1110 | Falhas de autenticação no Entra ID (ResultType 50126) | [Falhas de entrada no Entra ID](../deteccoes/regras-analiticas/entra-failed-signins.md) | `SigninLogs` | Testada e validada no Azure; laboratório excluído |
| T1098 | Atribuição de função Azure RBAC | [Atribuição de função Azure RBAC](../deteccoes/regras-analiticas/azure-rbac-role-assignment.md) | `AzureActivity` | Testada e validada no Azure; laboratório excluído |
| T1098 | Atribuição de função privilegiada no Entra ID | [Alteração de função no Entra ID](../deteccoes/regras-analiticas/privileged-role-change.md) | `AuditLogs` | Testada e validada no Azure; laboratório excluído |
| T1053 (descrição: T1053.005) | Criação de tarefa agendada por `schtasks.exe` | [Criação de tarefa agendada](../deteccoes/regras-analiticas/scheduled-task-creation.md) | `SecurityEvent` | Testada e validada no Azure; laboratório excluído |
| T1059 (descrição: T1059.001) | Criação de processo PowerShell com comando codificado | [PowerShell codificado](../deteccoes/regras-analiticas/encoded-powershell.md) | `SecurityEvent` | Testada e validada no Azure; laboratório excluído |
| T1136 (simulação: T1136.001) | Criação de conta local do Windows | [Criação de conta local](../deteccoes/regras-analiticas/local-account-creation.md) | `SecurityEvent` | Testada e validada no Azure; laboratório excluído |

Para consultar a configuração registrada das regras e as limitações da matriz de
cobertura, veja o [registro sanitizado do laboratório](lab-build-record.md) e o
[export das regras analíticas](../deteccoes/regras-analiticas/azure-sentinel-analytics-rules.json).

## Linha de base registrada antes das regras do laboratório

O documento oficial informa que a matriz ATT&CK do Sentinel foi capturada em
20/10/2026, antes da criação da primeira regra do laboratório. Os valores abaixo
foram lidos visualmente da captura de tela; o documento indica que a maioria das
associações de técnicas ainda precisa de confirmação. As capturas restantes serão
adicionadas posteriormente, conforme disponibilidade.

| Técnica | Valor aproximado exibido na linha de base | Confiança indicada na fonte |
| --- | ---: | --- |
| T1110 Brute Force | 5 | Confirmado no painel aberto |
| T1136 Create Account | 4 | Precisa de confirmação |
| T1098 Account Manipulation | 4 | Precisa de confirmação |
| T1059 Command and Scripting Interpreter | 1 | Precisa de confirmação |
| T1053 Scheduled Task/Job | Nenhum valor visível | Aparentemente sem cobertura; confirmar |
| T1078 Valid Accounts | 18 | Precisa de confirmação |

Se as capturas posteriores forem recuperadas, use os mesmos filtros da matriz ao
compará-las e confira os nomes e tipos das regras associados a cada técnica. Os
números são aproximados e não devem ser apresentados como uma diferença exata após
a criação das regras.
