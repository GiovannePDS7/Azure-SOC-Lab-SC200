# Regra de força bruta SSH com usuário inexistente

- **Regra do Sentinel:** `[Lab] SSH - múltiplas tentativas com usuário inválido`
- **Estado no export fornecido:** habilitada, severidade Medium e execução a cada
  cinco minutos.
- **Origem e lógica:** eventos `Syslog` das facilities `auth` / `authpriv`, processo
  `sshd`, contendo `Invalid user` ou `Failed password`; pelo menos 3 eventos de um
  IP para um host em um período de consulta de 10 minutos.
- **ATT&CK:** Credential Access / T1110.
- **Mapeamento de entidades:** IP `Address` a partir de `IpOrigem`; Host `HostName` a
  partir de `Computer`.
- **Agrupamento de alertas e incidentes:** um alerta por execução da consulta;
  agrupamento de incidentes habilitado para todas as entidades correspondentes, em
  uma janela de uma hora. A supressão está desabilitada.
- **Validação:** o responsável pelo laboratório confirmou que esta regra foi
  testada e validada no Azure antes da exclusão do ambiente. O PDF registra que,
  na fase de criação, as regras 2 a 8 se basearam em telemetria previamente
  confirmada. As capturas comprobatórias restantes serão adicionadas após
  sanitização.
- **Ajuste:** o limiar baixo foi escolhido para os eventos controlados do laboratório.
  Valide os formatos das mensagens Syslog e aumente o limiar ou adicione exclusões
  de origens aprovadas antes de usar a regra em produção.

Consulta: [`ssh-authentication-failures.kql`](../consultas-kql/linux/ssh-authentication-failures.kql).
