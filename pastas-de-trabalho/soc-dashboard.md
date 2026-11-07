# Pasta de trabalho do SOC — Visão geral das detecções

O documento oficial do laboratório registra uma pasta de trabalho do Microsoft
Sentinel configurada para um período de 30 dias. Os painéis contam os eventos
retornados; não representam ataques distintos.

## Painéis e observações registrados

| Painel | Origens / métrica | Resultado registrado |
| --- | --- | --- |
| Falhas de autenticação por origem | RDP no Windows (`SecurityEvent` 4625), SSH no Linux (`Syslog`), Entra ID (`SigninLogs`, ResultType 50126) | SSH 18, RDP 12, Entra ID 7 |
| Principais IPs de origem | Mesmas origens de autenticação, agrupadas por IP | 37 eventos em dois IPs de origem (30 e 7); endereços omitidos |
| Eventos por técnica ATT&CK | `SecurityEvent`, `Syslog`, `SigninLogs` | T1110 SSH 18; T1110 RDP 12; T1110 Entra ID 7; conta local T1136.001 3; PowerShell T1059.001 1; tarefa agendada T1053.005 1 |
| Alterações de privilégios por origem | Painel planejado | Indicado como pendente na seção sobre a pasta de trabalho |

## Consulta de falhas de autenticação

O primeiro painel registrado usa esta união para comparar as origens:

```kusto
union
(SecurityEvent
| where EventID == 4625
| where IpAddress !in ("-", "::1", "127.0.0.1")
| project TimeGenerated, Fonte = "Windows/RDP", Host = Computer, IP = IpAddress),
(Syslog
| where Facility in ("auth", "authpriv")
| where ProcessName == "sshd"
| where SyslogMessage has_any ("Invalid user", "Failed password")
| extend IP = extract(@"(\d{1,3}(?:\.\d{1,3}){3})", 1, SyslogMessage)
| project TimeGenerated, Fonte = "Linux/SSH", Host = Computer, IP),
(SigninLogs
| where ResultType == "50126"
| project TimeGenerated, Fonte = "Entra ID", Host = AppDisplayName, IP = IPAddress)
| summarize Falhas = count() by Fonte
| sort by Falhas desc
```

O painel de principais IPs usa os mesmos filtros de origem, projeta o rótulo da
origem e o IP, agrupa os resultados com `count()` por IP e retorna os dez primeiros.
Não copie para este repositório endereços IP públicos sem sanitização.

## Estado e interpretação

A seção detalhada sobre a pasta de trabalho no documento oficial informa que ela
estava em andamento, com o painel de alterações de privilégios e o salvamento final
pendentes. Uma lista de verificação posterior marca o trabalho como concluído, com
base na confirmação do autor. Verifique a versão salva atual antes de considerá-la
finalizada.

As contagens acima são resultados registrados para o período de 30 dias documentado,
não uma visão atualizada. Execute novamente a pasta de trabalho após alterar o
período ou a coleta de dados e apresente separadamente as contagens de eventos e as
contagens de incidentes ou ataques.
