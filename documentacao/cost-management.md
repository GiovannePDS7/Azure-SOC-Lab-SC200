# Gestão de custos

O registro oficial do laboratório confirma o limite diário de 1 GB do Log Analytics,
o desligamento automático das VMs e sua desalocação ao final das sessões. O orçamento
e os alertas foram configurados, mas seus valores não foram registrados. Não trate
estimativas inventadas como dados históricos de custo. O laboratório foi excluído
após o término dos créditos gratuitos para evitar cobranças.

## Controles registrados

- Limite diário do Log Analytics: 1 GB.
- Desligamento automático das VMs: 19h (UTC-03).
- Interrompa e desaloque as VMs ao final de cada sessão do laboratório.
- Foram usados discos Standard SSD.
- O Defender for Servers não estava habilitado na fase registrada.
- O orçamento e os alertas de custo foram informados como configurados; os valores e
  limites de notificação não foram registrados.

Antes de recriar o laboratório, consulte os preços atuais do Azure e o consumo real
da assinatura. Para novas estimativas, registre a região, o período de uso, o SKU,
as premissas e a data. A exclusão dos recursos foi informada pelo responsável; uma
confirmação de eventuais cobranças residuais no Cost Management não está registrada.
Para uma futura desmontagem, siga as instruções de [desmontagem](teardown.md).

Consulte o [registro do laboratório](lab-build-record.md) para ver os recursos e o
escopo do documento de origem.
