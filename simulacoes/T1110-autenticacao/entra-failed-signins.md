# Falhas de autenticação no Entra ID

Uma conta de teste recebeu tentativas controladas com senha inválida. O documento
registra eventos entre 13:34:47 e 13:48:18 UTC de 19/10/2026, com `ResultType`
`50126` na tabela `SigninLogs`.

A [regra de falhas no Entra ID](../../deteccoes/regras-analiticas/entra-failed-signins.md)
agrupa falhas por conta e IP. A confirmação de teste e validação da regra consta no
[registro da implantação](../../documentacao/lab-build-record.md). A fonte não
descreve uma limpeza específica para este teste; não interprete o registro como
evidência de comprometimento de uma conta real.
