# Configuração e escopo do laboratório

> **Estado:** execução concluída. O ambiente foi removido após o
> encerramento dos créditos gratuitos do Azure. As etapas abaixo registram a
> configuração histórica para consulta ou eventual recriação.

Este repositório registra um laboratório SOC pessoal e isolado no Microsoft Azure,
voltado à prática com o Microsoft Sentinel e à preparação para a SC-200. A telemetria
e as simulações são controladas; não use dados de clientes nem publique no Git
credenciais, chaves, endereços IP públicos ou IDs de tenant e de assinatura.

## Sequência de configuração registrada

1. Crie `rg-soclab-fintech`, o workspace `law-soclab`, a VNet e a subnet do laboratório,
   além de `nsg-soclab`.
2. Restrinja os acessos de entrada RDP (TCP/3389) e SSH (TCP/22) ao endereço público
   `/32` necessário para o operador. Não use uma origem irrestrita.
3. Habilite o Sentinel, configure os diagnósticos de Azure Activity e Entra ID e
   instale o conteúdo de Azure Activity, Entra ID, Windows Security Events e Syslog.
4. Implante `vm-win-01` (Windows Server 2022) e `vm-lnx-01` (Ubuntu Server 24.04 LTS)
   com o Azure Monitor Agent. Associe as regras de coleta documentadas para Windows
   Security, Sysmon e Syslog do Linux.
5. Antes de testar as detecções, valide a ingestão em `AzureActivity`, `AuditLogs`,
   `SigninLogs`, `SecurityEvent`, `Event` e `Syslog`.
6. Execute somente as simulações controladas descritas em
   [simulações](../simulacoes/README.md) e registre as evidências e a limpeza
   correspondente.

O [registro do laboratório](lab-build-record.md) contém o inventário e o estado
descritos no documento oficial, complementados pela confirmação de que todas as
regras foram testadas e validadas no Azure. O laboratório foi excluído após o fim
dos créditos gratuitos para evitar cobranças; as etapas acima descrevem a
configuração histórica e servem de referência para uma eventual recriação. As
capturas operacionais foram organizadas em [evidências](../evidencias/README.md).
Elas receberam tarjas para ocultar dados pessoais e identificadores não documentados;
nomes de recursos e redes descritos neste repositório foram mantidos. Revise as
imagens manualmente antes de compartilhar ou versionar.

## Controles operacionais

- O limite diário registrado para o Log Analytics é de 1 GB. Os valores do orçamento
  e dos alertas de custo não foram registrados no documento oficial.
- Durante o laboratório, o desligamento automático das VMs foi configurado para
  19h (UTC-03). Em uma futura recriação, desaloque as VMs ao final de cada sessão.
- Prefira discos Standard SSD. O Defender for Servers não estava habilitado na
  configuração registrada.
- Em uma futura recriação, remova as atribuições temporárias de funções e os
  artefatos de teste após cada exercício.
- Sanitize as evidências antes de adicioná-las a
  [evidências](../evidencias/README.md).
