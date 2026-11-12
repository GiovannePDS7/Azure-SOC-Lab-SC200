# Hipótese de comprometimento de conta

## Hipótese

Uma sequência de falhas de entrada associada à mesma conta e origem pode indicar
tentativa de acesso indevido. Falhas isoladas também podem resultar de erro legítimo.

## Busca e interpretação

Use `SigninLogs` e a [consulta de falhas no Entra ID](../../deteccoes/consultas-kql/entra-id/failed-signins.kql)
como ponto de partida. Em uma investigação, defina o período, examine conta, origem,
horário e aplicação e correlacione os eventos com o contexto autorizado da conta.
Uma falha `50126` não comprova que houve entrada bem-sucedida ou comprometimento.

O laboratório simulou falhas controladas, mas este arquivo não registra uma caçada
ou conclusão sobre comprometimento real.
