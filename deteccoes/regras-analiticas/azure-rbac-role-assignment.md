# Regra de atribuição de função Azure RBAC

- **Regra do Sentinel:** `[Lab] Azure RBAC - nova atribuição de função`
- **Estado no export fornecido:** habilitada, severidade Medium, execução a cada
  cinco minutos e período de consulta de 15 minutos.
- **Origem e lógica:** operações
  `MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE` concluídas com sucesso em
  `AzureActivity`.
- **ATT&CK:** Persistence / T1098.
- **Mapeamento de entidades:** nenhum no export fornecido.
- **Agrupamento:** um alerta por resultado da consulta; criação de incidentes
  habilitada, agrupamento de incidentes desabilitado e supressão desabilitada.
- **Validação:** o responsável pelo laboratório confirmou que esta regra foi
  testada e validada no Azure antes da exclusão do ambiente. O registro oficial
  informa que a telemetria de Azure RBAC já havia sido confirmada durante a fase de
  criação. As capturas comprobatórias não foram incluídas no repositório.
- **Ajuste:** valide os valores de operação e estado no workspace de destino e
  investigue atribuições temporárias de funções e sua remoção.

Consulta: [`rbac-role-assignment.kql`](../consultas-kql/azure/rbac-role-assignment.kql).
