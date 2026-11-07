# Regra de PowerShell com comando codificado

- **Regra do Sentinel:** `[Lab] Windows - PowerShell com comando codificado`
- **Estado no export fornecido:** habilitada, severidade Medium, execução a cada
  cinco minutos e período de consulta de 10 minutos.
- **Origem e lógica:** evento 4688 da tabela `SecurityEvent`; detecta
  `powershell.exe` ou `pwsh.exe` com os parâmetros `-e`, `-ec`, `-enc` ou
  `-EncodedCommand`.
- **ATT&CK:** Execution / T1059 no export; a descrição e a simulação identificam
  T1059.001.
- **Mapeamento de entidades:** nenhum no export fornecido.
- **Agrupamento:** um alerta por resultado da consulta; criação de incidentes
  habilitada, agrupamento de incidentes desabilitado e supressão desabilitada.
- **Validação:** o responsável pelo laboratório confirmou que esta regra foi
  testada e validada no Azure antes da exclusão do ambiente. O registro oficial
  descreve a telemetria histórica como confirmada na fase de criação; as capturas
  comprobatórias restantes serão adicionadas após sanitização.
- **Ajuste:** habilite a política de auditoria de linha de comando para incluir
  `CommandLine` no evento 4688. Antes de usar a regra em produção, revise os scripts
  administrativos legítimos.

Consulta: [`encoded-powershell.kql`](../consultas-kql/windows/encoded-powershell.kql).
