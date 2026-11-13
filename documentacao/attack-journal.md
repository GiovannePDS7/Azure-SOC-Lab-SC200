# Diário das simulações

Registro resumido dos testes controlados descritos no documento do laboratório. Os
horários abaixo são os registrados em UTC, não horários inferidos. As detecções foram
posteriormente testadas e validadas no Azure, conforme confirmação do responsável.

| Simulação | Período UTC | Resultado registrado |
| --- | --- | --- |
| Falhas RDP | 18/10/2026, janelas iniciadas às 03:20 e 05:50 | Eventos 4625 em `SecurityEvent` |
| Falhas SSH | 18/10/2026, 05:44:11–05:44:29 | Quatro eventos de usuário inexistente e conexão interrompida em `Syslog`; a VM aceitava somente chave |
| Falhas Entra ID | 19/10/2026, 13:34:47–13:48:18 | Falhas `50126` em `SigninLogs` |
| Conta local T1136.001 | 18/10/2026, 06:23:17–06:34:05 | Evento 4720; teste concluído e limpeza executada |
| PowerShell T1059.001 | 19/10/2026, 12:37:30 | Processo no evento 4688 e evento 1 do Sysmon; saída 0 |
| Tarefa agendada T1053.005 | 19/10/2026, 12:53:32–12:57:32 | Criação observada no 4688 e confirmada localmente; limpeza executada |
| Função Entra ID | 19/10/2026, 13:44:47–13:50:03 | Adição e remoção de Directory Readers em `AuditLogs` |
| Azure RBAC | 19/10/2026, 14:19:46–14:27:33 | Atribuição e remoção de Owner no grupo de recursos em `AzureActivity` |

O evento 4698 de criação de tarefa não foi observado; a validação usou o 4688 e a
consulta local da tarefa. Não interprete as contagens do painel como quantidade de
ataques distintos. Detalhes, fontes e limitações estão no
[registro da implantação](lab-build-record.md) e nas [simulações](../simulacoes/README.md).