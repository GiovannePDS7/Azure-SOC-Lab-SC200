# Registro sanitizado da implantação do laboratório

Esta página reúne os recursos, os fluxos de coleta, as detecções e os resultados de
validação descritos nos arquivos fornecidos
`Lab_SOC_Azure_SC200_Documentacao.pdf` e `Azure_Sentinel_analytics_rules.json`. O PDF
se apresenta como o registro técnico do laboratório e informa que oito regras
analíticas foram criadas e habilitadas. O usuário confirmou que todas as oito regras
foram testadas e validadas no ambiente Azure. Esta página é um resumo sanitizado, não
uma cópia do PDF ou das capturas de tela.

O JSON exportado está versionado em
[`deteccoes/regras-analiticas/azure-sentinel-analytics-rules.json`](../deteccoes/regras-analiticas/azure-sentinel-analytics-rules.json).
Esse arquivo é um modelo ARM parametrizado que requer o nome de um workspace. Por
decisão do responsável pelo laboratório, os valores do JSON são a referência adotada
neste repositório quando diferem do PDF.

Após o término dos créditos gratuitos, o laboratório foi excluído para evitar
cobranças. Portanto, os recursos e as configurações descritos neste registro são
históricos, não representam um ambiente Azure ativo. Restaram algumas capturas de
tela, que serão adicionadas posteriormente após sanitização.

## Escopo do laboratório e recursos implantados

O ambiente é um laboratório SOC pessoal e isolado para praticar com o Sentinel e se
preparar para a SC-200. O registro oficial descreve telemetria e simulações
controladas, princípio do menor privilégio, remoção de acessos temporários e
controles de custo. O documento proíbe expressamente a publicação de credenciais,
chaves privadas, IPs públicos, IDs de tenant ou assinatura e evidências brutas.

| Recurso | Configuração registrada / finalidade |
| --- | --- |
| Grupo de recursos | `rg-soclab-fintech`; escopo principal do laboratório |
| Workspace do Log Analytics | `law-soclab`; workspace central de telemetria |
| Microsoft Sentinel | Habilitado em `law-soclab` |
| Rede virtual | `vnet-soclab`, espaço de endereços `10.0.0.0/16` |
| Subnet | `snet-soclab`, `10.0.1.0/24` |
| Grupo de segurança de rede | `nsg-soclab`; acessos RDP TCP/3389 e SSH TCP/22 limitados ao endereço público `/32` do operador do laboratório |
| Endpoint Windows | `vm-win-01`, Windows Server 2022, `Standard_D2nls_v6` (2 vCPU, 4 GiB), Standard SSD |
| Endpoint Linux | `vm-lnx-01`, Ubuntu Server 24.04 LTS, Standard SSD |
| DCR do Windows Security | `dcr-win-security-common`, AMA, conjunto de eventos Common |
| DCR do Sysmon | `dcr-win-sysmon`, AMA, XPath personalizado `Microsoft-Windows-Sysmon/Operational` |
| DCR do Syslog Linux | `dcr-lnx-syslog`, AMA, facilities `LOG_AUTH` e `LOG_AUTHPRIV` a partir de `LOG_INFO` |

A VM Windows foi registrada na região East US. O documento oficial não informa o
tamanho da VM Linux, os IDs da assinatura ou do tenant, nem o valor total do
orçamento; esses dados foram intencionalmente omitidos.

## Telemetria e validação

| Origem | Configuração de diagnóstico / DCR | Tabela | Uso registrado |
| --- | --- | --- | --- |
| Assinatura Azure | `subscriptionToLa` | `AzureActivity` | Atividade do plano de controle do Azure e RBAC |
| Microsoft Entra ID | `AzureSentinel_law-soclab` | `AuditLogs`, `SigninLogs` | Auditoria do diretório e eventos de autenticação |
| Segurança do Windows | `dcr-win-security-common` | `SecurityEvent` | Logons, criação de processos e eventos de contas |
| Sysmon do Windows | `dcr-win-sysmon` | `Event` | Eventos de processo e linha de comando do Sysmon |
| Autenticação do Ubuntu | `dcr-lnx-syslog` | `Syslog` | SSH e autenticação no Linux |

O documento registra que foi necessário corrigir uma configuração de diagnóstico
para que os dados de Azure Activity fossem ingeridos. Também informa que a política
de linha de comando do evento Windows 4688 foi habilitada para incluir `CommandLine`
nos eventos de criação de processos. Consultas inicialmente vazias foram
investigadas pela validação do AMA/DCR e pela seleção de um intervalo de tempo
adequado, em vez de recriar recursos sem evidências.

## Regras de detecção no export fornecido

As oito regras do JSON estão `Enabled`, têm severidade `Medium`, são executadas a
cada cinco minutos e criam incidentes. O período da consulta e o comportamento de
agrupamento variam. O limiar `GreaterThan 0` significa que o alerta é disparado
quando a consulta retorna uma linha; limiares de contagem, como `Falhas >= 3`, são
implementados na KQL.

| Regra | Sinal e lógica | Tabela | Valor ATT&CK no export | Período da consulta | Mapeamento de entidades |
| --- | --- | --- | --- | --- | --- |
| Força bruta SSH com usuário inexistente | Pelo menos 3 falhas de autenticação SSH agrupadas por IP de origem e host; reconhece `Invalid user` e `Failed password` | `Syslog` | T1110 | 10 min | IP (`IpOrigem`), Host (`Computer`) |
| Força bruta RDP | Pelo menos 3 falhas remotas 4625 agrupadas por IP de origem e host | `SecurityEvent` | T1110 | 10 min, conforme o JSON adotado | IP (`IpAddress`), Host (`Computer`) |
| Atribuição de função Azure RBAC | Operação `MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE` concluída com sucesso | `AzureActivity` | T1098 | 15 min | Nenhum |
| Atribuição de função privilegiada no Entra ID | Operação `Add member to role` concluída com sucesso em `RoleManagement` | `AuditLogs` | T1098 | 10 min | Nenhum |
| Criação de tarefa agendada | Criação de processo 4688 para `schtasks.exe` com `/Create` | `SecurityEvent` | T1053 (a descrição identifica T1053.005) | 10 min | Nenhum |
| PowerShell com comando codificado | Criação de processo 4688 para PowerShell / PowerShell Core com parâmetro de comando codificado | `SecurityEvent` | T1059 (a descrição identifica T1059.001) | 10 min | Nenhum |
| Criação de conta local | Evento 4720 com conta de destino não vazia | `SecurityEvent` | T1136 (a descrição identifica T1136.001) | 10 min | Nenhum |
| Falhas de autenticação no Entra ID | Pelo menos 5 falhas ResultType 50126 para o mesmo usuário e IP | `SigninLogs` | T1110 | 15 min | Conta (`UserPrincipalName`), IP (`IPAddress`) |

As regras de SSH, RDP e falhas de autenticação no Entra ID agrupam incidentes por
todas as entidades, em uma janela de uma hora, segundo o JSON fornecido. As outras
cinco regras não habilitam o agrupamento de incidentes. O agrupamento de eventos é
`SingleAlert` para SSH e RDP e `AlertPerResult` para as outras seis regras. A
supressão está desabilitada no export.

Os arquivos de regras em [`deteccoes/regras-analiticas/`](../deteccoes/regras-analiticas/README.md)
e as consultas KQL em [`deteccoes/consultas-kql/`](../deteccoes/consultas-kql/README.md) formam o índice
legível e contêm as consultas.

## Resultados da validação e limitações

- O PDF informa que oito de oito regras foram criadas, ativadas e habilitadas na fase
  de engenharia de detecção.
- O responsável pelo laboratório confirmou que todas as oito regras foram testadas e
  validadas no ambiente Azure antes da exclusão dos recursos. A validação foi
  executada no ambiente; as capturas comprobatórias restantes ainda serão
  adicionadas após sanitização.
- A regra RDP foi testada novamente na VM do laboratório. O registro relata que a
  consulta encontrou sete falhas 4625 de um IP contra `vm-win-01` em cerca de
  23 segundos; em seguida, foi gerado um incidente com seis alertas agrupados. As
  entidades IP e Host foram confirmadas.
- Inicialmente, o filtro padrão de pontuação de prioridade ocultava o incidente.
  Depois de removido o filtro, o incidente ficou visível. A severidade registrada
  foi Medium e a categoria, Credential Access.
- O PDF diz que as detecções 2 a 8 usaram telemetria previamente confirmada e não
  foram todas simuladas novamente naquela fase. Essa anotação foi complementada pela
  confirmação posterior do responsável: todas as regras foram testadas e validadas
  no ambiente Azure.
- O JSON fornecido contém mapeamentos de entidades somente para SSH, RDP e falhas de
  autenticação no Entra ID. A confirmação de teste e validação das regras não altera
  os mapeamentos descritos no export.
- O PDF também apresenta informações conflitantes sobre a revisão ATT&CK: a seção da
  matriz lista verificações por técnica como pendentes, enquanto a lista final
  afirma que as capturas de antes e depois foram concluídas. Como os valores
  completos da matriz posterior às regras não foram transcritos aqui, este registro
  não estabelece a variação exata de cobertura. Os testes das regras não substituem
  essa comparação de cobertura. O export usa técnicas principais para T1053, T1059
  e T1136, ainda que as descrições ou simulações indiquem subtécnicas.

## Observações da pasta de trabalho e estado de conclusão

O PDF registra um intervalo de 30 dias e estas contagens de eventos: falhas de
autenticação SSH 18, RDP 12 e Entra ID 7; o painel de técnicas mostrou T1110 SSH 18,
T1110 RDP 12, T1110 Entra ID 7, criação de conta local T1136.001 3, PowerShell
T1059.001 1 e tarefa agendada T1053.005 1. São contagens de eventos retornados, não
de ataques distintos. Um painel de principais origens registrou 37 eventos em dois
IPs de origem (30 e 7); os endereços foram intencionalmente omitidos.

O estado da pasta de trabalho é inconsistente no PDF: a seção correspondente diz
que o trabalho estava em andamento, com um quarto painel e o salvamento final
pendentes, mas a lista da fase apresentada depois marca a pasta de trabalho como
concluída, com base na confirmação do autor. As capturas restantes poderão ajudar a
esclarecer essa divergência quando forem adicionadas.

## Referência adotada para a configuração RDP

Para este repositório, adota-se o JSON fornecido como referência: período de consulta
de 10 minutos e janela de agrupamento de incidentes de uma hora. A seção detalhada
do PDF diverge e registra, respectivamente, 30 minutos e cinco horas; também relata
seis alertas agrupados em um incidente. O usuário confirmou que todas as regras
foram testadas e validadas no Azure. O laboratório foi excluído após o término dos
créditos gratuitos, portanto os valores atuais não podem ser consultados no Sentinel.
O PDF também registra o limiar observado de três falhas, a frequência de cinco
minutos e os mapeamentos de IP e Host.

O limiar de três foi escolhido para se adequar ao baixo volume de eventos do
laboratório. Para um ambiente de produção, a fonte recomenda aumentá-lo (por
exemplo, para dez ou mais) e considerar exclusões de origens conhecidas, como uma
watchlist. A sobreposição dos períodos de consulta causou alertas repetidos no
laboratório; o agrupamento reduziu a duplicação de incidentes, mas não eliminou os
registros repetidos de alerta.

As anotações detalhadas do incidente confirmam a tática Credential Access e as duas
entidades mapeadas, mas registram que T1110 e a descrição ainda não haviam sido
verificados em um alerta individual naquela etapa. O responsável confirmou
posteriormente que todas as regras foram testadas e validadas no Azure; a captura
desse alerta específico ainda não está disponível no repositório.

## Controles de custo e segurança

- Limite diário do Log Analytics: 1 GB.
- Desligamento automático das VMs: 19h (UTC-03); desaloque-as ao final das sessões.
- O orçamento e os alertas de custo foram informados como configurados, mas os
  respectivos valores não constam na fonte.
- O Defender for Servers não estava habilitado na fase registrada.
- Mantenha as evidências sanitizadas. O PDF alerta que as capturas de tela podem
  mostrar um IP público, endereço de e-mail, IDs de tenant ou assinatura e dados da
  barra de endereço do navegador. Não as inclua no repositório sem revisá-las e
  ocultar esses dados.

Para instruções de configuração, consulte [lab-setup.md](lab-setup.md); para detalhes
das regras, consulte [regras analíticas](../deteccoes/regras-analiticas/README.md).
