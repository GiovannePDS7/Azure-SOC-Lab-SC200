# Regra de criação de tarefa agendada no Windows

- **Regra do Sentinel:** `[Lab] Windows - criação de tarefa agendada via schtasks`
- **Estado no export fornecido:** habilitada, severidade Medium, execução a cada
  cinco minutos e período de consulta de 10 minutos.
- **Origem e lógica:** evento 4688 da tabela `SecurityEvent`; `NewProcessName`
  termina em `\schtasks.exe` e `CommandLine` contém `/Create`.
- **ATT&CK:** Execution / T1053 no export; a descrição e a simulação identificam
  T1053.005.
- **Mapeamento de entidades:** nenhum no export fornecido.
- **Agrupamento:** um alerta por resultado da consulta; criação de incidentes
  habilitada, agrupamento de incidentes desabilitado e supressão desabilitada.
- **Validação:** o responsável pelo laboratório confirmou que esta regra foi
  testada e validada no Azure antes da exclusão do ambiente. O registro oficial
  descreve a telemetria histórica como confirmada na fase de criação; as capturas
  comprobatórias restantes serão adicionadas após sanitização.
- **Ajuste:** esta regra usa o evento de criação de processo (4688), não o evento
  4698 de tarefa agendada. Segundo o registro oficial, o evento 4698 não foi
  observado no teste anterior do laboratório.

Consulta: [`scheduled-task.kql`](../consultas-kql/windows/scheduled-task.kql).
