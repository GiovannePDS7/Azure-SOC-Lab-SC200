# Regra de atribuição de função privilegiada no Microsoft Entra ID

- **Regra do Sentinel:** `[Lab] Entra ID - atribuição de função privilegiada`
- **Estado no export fornecido:** habilitada, severidade Medium, execução a cada
  cinco minutos e período de consulta de 10 minutos.
- **Origem e lógica:** operações `Add member to role` bem-sucedidas na categoria
  `RoleManagement` da tabela `AuditLogs`.
- **ATT&CK:** Persistence / T1098.
- **Mapeamento de entidades:** nenhum no export fornecido.
- **Agrupamento:** um alerta por resultado da consulta; criação de incidentes
  habilitada, agrupamento de incidentes desabilitado e supressão desabilitada.
- **Validação:** o responsável pelo laboratório confirmou que esta regra foi
  testada e validada no Azure antes da exclusão do ambiente. O registro oficial
  relata que a telemetria de alteração de função já havia sido confirmada durante a
  fase de criação. As capturas comprobatórias não foram incluídas no repositório.
- **Ajuste:** confirme os nomes das operações e os resultados na tabela `AuditLogs`
  do tenant e revise as alterações administrativas de função esperadas.

Consulta: [`privileged-role-assignment.kql`](../consultas-kql/entra-id/privileged-role-assignment.kql).
