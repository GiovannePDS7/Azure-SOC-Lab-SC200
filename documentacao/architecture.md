# Arquitetura do laboratório

O laboratório usava um grupo de recursos e um workspace do Log Analytics dedicados
para delimitar a coleta e a investigação. O Microsoft Sentinel estava habilitado no
workspace. O ambiente foi excluído após o término dos créditos gratuitos do Azure;
este documento descreve a arquitetura histórica, não recursos ativos.

## Inventário de recursos

| Camada | Recurso | Configuração registrada |
| --- | --- | --- |
| Azure | Grupo de recursos | `rg-soclab-fintech` |
| SIEM | Workspace do Log Analytics | `law-soclab`; Microsoft Sentinel habilitado |
| Rede | VNet / subnet | `vnet-soclab` (`10.0.0.0/16`) / `snet-soclab` (`10.0.1.0/24`) |
| Rede | Grupo de segurança de rede | `nsg-soclab`; acessos de entrada RDP e SSH restritos ao endereço público `/32` do operador do laboratório |
| Endpoint Windows | `vm-win-01` | Windows Server 2022; tamanho registrado `Standard_D2nls_v6` (2 vCPU, 4 GiB); AMA, eventos de segurança e Sysmon |
| Endpoint Linux | `vm-lnx-01` | Ubuntu Server 24.04 LTS; AMA e Syslog de autenticação |
| Coleta do Windows | `dcr-win-security-common` | AMA / Windows Security Events, conjunto Common |
| Coleta do Sysmon | `dcr-win-sysmon` | AMA / `Microsoft-Windows-Sysmon/Operational` |
| Coleta do Linux | `dcr-lnx-syslog` | AMA / facilities Syslog `auth` e `authpriv` |

O registro da implantação indica o uso de discos Standard SSD. O Defender for Servers
não estava habilitado quando o documento foi elaborado. Consulte o
[registro sanitizado do laboratório](lab-build-record.md) para ver as fontes e as
inconsistências conhecidas.

## Fluxo de telemetria

| Origem | Conector / coleta | Tabela do workspace | Finalidade |
| --- | --- | --- | --- |
| Atividade da assinatura Azure | Configuração de diagnóstico `subscriptionToLa` | `AzureActivity` | Atividade do plano de controle e Azure RBAC |
| Microsoft Entra ID | Configuração de diagnóstico `AzureSentinel_law-soclab` | `AuditLogs`, `SigninLogs` | Auditoria do diretório e atividade de autenticação |
| Segurança do Windows | `dcr-win-security-common` via AMA | `SecurityEvent` | Logons, criação de processos e eventos de contas |
| Sysmon do Windows | `dcr-win-sysmon` via AMA | `Event` | Telemetria de processos e linhas de comando do Sysmon |
| Autenticação do Ubuntu | `dcr-lnx-syslog` via AMA | `Syslog` | SSH e eventos de autenticação do Linux |

A coleta era separada por origem. Em uma futura recriação, valide as consultas de
detecção em relação às tabelas e aos campos existentes no workspace de destino.

Consulte o [diagrama geral da arquitetura](../diagramas/architecture-overview.png) e
o [fluxo de telemetria](../diagramas/telemetry-flow.png).
