# Hipótese de uso suspeito do PowerShell

## Hipótese

O uso de PowerShell com comando codificado pode exigir investigação, mas a
codificação também ocorre em atividades administrativas legítimas.

## Busca e interpretação

Use a [consulta de PowerShell codificado](../../deteccoes/consultas-kql/windows/encoded-powershell.kql)
em eventos 4688 de `SecurityEvent` e, quando disponível, correlacione com eventos de
processo do Sysmon. Defina o período e examine conta, host, processo pai e contexto
da execução antes de classificá-la.

O laboratório gerou esse sinal em uma simulação controlada. A
[simulação](../../simulacoes/T1059.001-powershell/README.md) não comprova uso
malicioso nem uma caçada concluída.
