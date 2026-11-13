# Falhas de logon RDP

Foram feitas tentativas com senha incorreta contra a VM Windows isolada. O diário
registra janelas iniciadas às 03:20 e 05:50 UTC de 18/10/2026, com eventos 4625 em
`SecurityEvent`.

Um reteste posterior produziu sete falhas e um incidente com seis alertas agrupados,
conforme o [registro da implantação](../../documentacao/lab-build-record.md). A
[regra RDP](../../deteccoes/regras-analiticas/brute-force-windows.md) usa o limiar
de três falhas no laboratório. A fonte não registra uma limpeza específica para as
tentativas; use apenas contas e hosts autorizados em uma eventual recriação.
