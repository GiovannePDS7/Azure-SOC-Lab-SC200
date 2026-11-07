# Regra de criação de conta local no Windows

- **Regra do Sentinel:** `[Lab] Windows - criação de conta local 4720`
- **Estado no export fornecido:** habilitada, severidade Medium, execução a cada
  cinco minutos e período de consulta de 10 minutos.
- **Origem e lógica:** evento 4720 da tabela `SecurityEvent`, com `TargetUserName`
  preenchido.
- **ATT&CK:** Persistence / T1136 no export; a simulação e a descrição identificam
  T1136.001.
- **Mapeamento de entidades:** nenhum no export fornecido.
- **Agrupamento:** um alerta por resultado da consulta; criação de incidentes
  habilitada, agrupamento de incidentes desabilitado e supressão desabilitada.
- **Validação:** o responsável pelo laboratório confirmou que esta regra foi
  testada e validada no Azure antes da exclusão do ambiente. O registro oficial
  informa que a telemetria histórica havia sido confirmada durante a fase de
  criação. As capturas comprobatórias não foram incluídas no repositório.
- **Ajuste:** valide as atividades esperadas de provisionamento e administração e
  adicione exclusões aprovadas quando apropriado.

Consulta: [`local-account-created.kql`](../consultas-kql/windows/local-account-created.kql).
