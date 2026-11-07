# Regra de força bruta RDP no Windows

- **Regra do Sentinel:** `[Lab] Brute force RDP - múltiplas falhas 4625`
- **Estado no export fornecido:** habilitada, severidade Medium e execução a cada
  cinco minutos.
- **Origem e lógica:** evento 4625 da tabela `SecurityEvent`; exclui IPs locais ou
  marcadores; agrupa por `IpAddress` e `Computer`; alerta a partir de 3 falhas.
- **ATT&CK:** Credential Access / T1110.
- **Mapeamento de entidades:** IP `Address` a partir de `IpAddress`; Host `HostName`
  a partir de `Computer`.
- **Teste observado:** o registro oficial relata sete falhas em cerca de 23 segundos,
  de uma origem contra `vm-win-01`; em seguida, foi criado um incidente com seis
  alertas agrupados. As entidades IP e Host foram confirmadas. Inicialmente, o
  filtro padrão de pontuação de prioridade ocultava o incidente.
- **Ajuste:** o limiar 3 foi escolhido para as simulações de baixo volume do
  laboratório. Em um ambiente real, considere um limiar mais alto (a fonte sugere,
  por exemplo, 10 ou mais) e exclusões de origens aprovadas. A janela de consulta
  sobreposta produziu alertas repetidos, embora o agrupamento os tenha reunido em
  um único incidente.

## Configuração de referência

Este repositório adota os valores do JSON fornecido: período de consulta de
10 minutos e janela de agrupamento de incidentes de 1 hora. O registro detalhado do
PDF diverge e informa, respectivamente, 30 minutos e 5 horas. O responsável
confirmou que a regra foi testada e validada no Azure; o laboratório foi excluído
após o término dos créditos gratuitos, portanto os valores descrevem a referência
documentada e não uma configuração atualmente ativa.

Consulta: [`failed-rdp-logons.kql`](../consultas-kql/windows/failed-rdp-logons.kql).
