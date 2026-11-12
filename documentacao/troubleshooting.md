# Solução de problemas

Problemas e resoluções registrados durante a implantação e os testes do laboratório.
O ambiente foi removido; para uma recriação, confirme o estado atual antes de aplicar
qualquer ajuste.

| Sintoma | Verificação ou resolução registrada |
| --- | --- |
| `AzureActivity` sem eventos | A política estava não conforme porque faltava a configuração de diagnóstico; a remediação criou `subscriptionToLa` e a ingestão foi verificada após o atraso de coleta. |
| `AuditLogs` sem resultados inicialmente | Uma criação controlada de grupo permitiu verificar o fluxo; `SigninLogs` também foi validada. |
| Evento 4688 sem linha de comando | Foi habilitada a política de inclusão da linha de comando na auditoria de criação de processos. |
| Consulta `Syslog` vazia | O agente AMA e a DCR foram verificados antes de considerar a recriação de recursos. |
| SSH falhou com chave local | O caminho da chave foi colocado entre aspas e suas permissões foram restringidas; a conexão por chave passou a funcionar. |
| Teste de conta local falhou ou aguardou entrada | Foram ajustados os parâmetros para respeitar a política de senha e usado o modo interativo; a política não foi enfraquecida. |
| Evento 4698 ausente | A criação da tarefa foi confirmada pela consulta local e pelo evento 4688 com `schtasks.exe /Create`. |
| Incidente RDP não aparecia na lista | O filtro de pontuação de prioridade foi removido; em seguida, o incidente ficou visível. |

No teste com Atomic Red Team, houve uma exclusão temporária e restrita do Defender
na VM isolada. O registro informa que ela foi removida após os testes; não é uma
recomendação para desabilitar proteção globalmente. Consulte também a
[análise de falsos positivos](../deteccoes/ajustes/false-positive-analysis.md).