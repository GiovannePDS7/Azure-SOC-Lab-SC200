# Regra de falhas de autenticação no Entra ID

- **Regra do Sentinel:** `[Lab] Entra ID - múltiplas falhas de autenticação 50126`
- **Estado no export fornecido:** habilitada, severidade Medium, execução a cada
  cinco minutos e período de consulta de 15 minutos.
- **Origem e lógica:** `SigninLogs`, `ResultType == "50126"`; pelo menos 5 falhas
  agrupadas por `UserPrincipalName` e `IPAddress`.
- **ATT&CK:** Credential Access / T1110.
- **Mapeamento de entidades:** Conta `FullName` a partir de `UserPrincipalName`; IP
  `Address` a partir de `IPAddress`.
- **Agrupamento:** um alerta por resultado da consulta; agrupamento de incidentes
  habilitado para todas as entidades correspondentes, em uma janela de uma hora; a
  supressão está desabilitada.
- **Validação:** o responsável pelo laboratório confirmou que esta regra foi
  testada e validada no Azure antes da exclusão do ambiente. O registro oficial
  descreve telemetria de autenticação previamente confirmada na fase de criação;
  as capturas comprobatórias restantes serão adicionadas após sanitização.
- **Ajuste:** considere os padrões esperados de falhas do provedor de identidade e
  as exclusões de origens aprovadas. Antes de usar em produção, ajuste o limiar à
  atividade normal do tenant.

Consulta: [`failed-signins.kql`](../consultas-kql/entra-id/failed-signins.kql).
