# Análise de falsos positivos

## Regra de força bruta RDP

- **Atividade benigna possível:** um usuário legítimo que digite a senha errada
  repetidamente pode atingir o limiar de três falhas de logon usado no laboratório.
- **Evidência e limiar do laboratório:** o registro oficial relata até quatro
  eventos 4625 em uma janela de consulta de 10 minutos; o limiar `Falhas >= 3`
  permitiu que a simulação controlada gerasse um alerta.
- **Ajuste para produção:** considere um limiar mais alto (a fonte sugere, por
  exemplo, dez ou mais falhas) e uma watchlist de escopo restrito para origens
  conhecidas. Antes de excluir qualquer origem, valide o limiar no ambiente.
- **Comportamento de alertas repetidos:** o PDF detalhado registra uma janela de
  consulta de 30 minutos e uma frequência de cinco minutos; a mesma atividade gerou
  seis alertas, agrupados em um incidente. O documento sugere avaliar uma janela
  menor (por exemplo, 10 minutos) ou a supressão, considerando o atraso de ingestão.
- **Configuração de referência:** este repositório adota o export JSON, que define um
  período de consulta RDP de 10 minutos e uma janela de agrupamento de incidentes de
  uma hora. O PDF detalhado informa 30 minutos e cinco horas. O responsável confirmou
  que a regra foi testada e validada no Azure; como o laboratório foi excluído, esses
  valores são históricos. Em uma futura recriação, valide os limiares com a nova
  telemetria antes de ajustá-los.

A fonte oficial não apresenta uma análise equivalente de falsos positivos para as
outras sete regras. Antes de criar exclusões ou alterar seus limiares, registre
atividades benignas e evidências específicas do ambiente.
