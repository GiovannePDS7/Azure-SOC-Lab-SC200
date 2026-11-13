# Hipótese de persistência por tarefa agendada

## Hipótese

Uma tarefa agendada criada fora de uma atividade autorizada pode indicar tentativa
de persistência. A criação de uma tarefa, por si só, também pode ser administrativa.

## Busca e interpretação

Consulte eventos 4688 em `SecurityEvent` com
[a consulta de tarefa agendada](../../deteccoes/consultas-kql/windows/scheduled-task.kql).
Defina o período e examine host, conta, linha de comando e finalidade da tarefa.
Compare com as mudanças autorizadas e os processos relacionados antes de concluir.

No teste controlado, o 4698 não foi observado; a tarefa foi confirmada localmente e
pelo 4688. Isso não prova que eventos 4698 estarão ausentes em outros ambientes.
Consulte a [simulação](../../simulacoes/T1053.005-tarefa-agendada/README.md).
