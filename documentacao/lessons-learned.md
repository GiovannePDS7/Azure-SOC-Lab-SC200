# Lições aprendidas

Observações extraídas da implantação, das simulações e da validação do laboratório.

- Verificar a coleta antes da detecção evita tratar uma tabela vazia como ausência
  definitiva de atividade. Confira o agente, a DCR, o intervalo e o tempo de ingestão.
- Registrar a ação e o horário em UTC ajuda a correlacionar os testes com os eventos.
  Uma diferença entre sinal esperado e observado deve ser documentada: no teste de
  tarefa agendada, o 4698 não apareceu, mas o 4688 e a consulta local deram suporte
  à validação.
- Limiares do laboratório não são padrões de produção. Três falhas RDP foram úteis
  no baixo volume de testes, mas também podem ocorrer em uso legítimo; ajuste e
  valide com a telemetria do ambiente.
- Janelas de consulta sobrepostas podem produzir alertas repetidos. Agrupá-los pode
  reduzir o número de incidentes, sem eliminar os alertas duplicados.
- SPF, DKIM e DMARC precisam ser interpretados no contexto: autenticação válida de
  um domínio parecido não comprova a identidade do fornecedor. Os dois exercícios
  sintéticos de [phishing](../phishing/README.md) ilustram sinais diferentes.
- Restrinja permissões temporárias, registre sua remoção e mantenha proteções ativas.
  Remova artefatos e exceções criados para testes.
- Limite de ingestão, desligamento e orçamento ajudam a controlar custos, mas não
  substituem a verificação de cobranças residuais após a exclusão.

Consulte [solução de problemas](troubleshooting.md) e
[gestão de custos](cost-management.md) para os detalhes registrados.