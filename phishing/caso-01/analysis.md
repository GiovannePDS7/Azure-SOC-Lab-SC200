# Análise do caso 01

Registre o contexto da mensagem, o método de análise, as descobertas e a conclusão
deste caso sanitizado.

## Gabarito

Amostra sintética de treinamento. Os domínios `.example` e os IPs de documentação
(192.0.2.0/24, 198.51.100.0/24 e 203.0.113.0/24) não resolvem nem apontam para
infraestrutura real.

## Descobertas esperadas
1. **Nome de exibição e domínio:** o nome exibido sugere um banco, mas o domínio do remetente é `bancoexemplo-seguro.example`, um domínio parecido, porém diferente do domínio oficial.
2. **Desalinhamento entre From, Return-Path e Reply-To:** são usados três domínios diferentes (`bancoexemplo-seguro`, `mailer-xyz` e `mail-reply`). O Reply-To direciona as respostas para outro domínio.
3. **Autenticação:** o SPF passa para o domínio controlado pelo atacante (`mailer-xyz.example`), portanto **não está alinhado** ao From. O DKIM está ausente. O DMARC falha (`p=none`), ou seja, a política do domínio não solicita a rejeição da mensagem. É um exemplo de que “SPF pass” não significa que a mensagem seja legítima.
4. **Cadeia Received (leitura de baixo para cima):** o primeiro salto se apresenta como `bancoexemplo.example`, mas o IP corresponde a um VPS (`hosting-barato.example`). O Message-ID também aponta para esse VPS.
5. **X-Mailer PHPMailer 5.2.0:** versão antiga, típica de envio em massa por script.
6. **Horário:** a mensagem foi enviada às 03h12 UTC, fora do horário comercial.
7. **Engenharia social:** urgência (bloqueio em 24 horas), medo (alegação de atividade suspeita) e solicitação de dados (CPF e senha).
8. **Link enganoso:** o texto visível é `https://www.bancoexemplo.com.br/seguranca`, mas o destino real (`href`) é `hxxp://bancoexemplo-seguro[.]example/autenticar?ref=ALVO123`. O link usa HTTP, sem TLS, e contém um identificador da vítima.
9. **Pixel de rastreamento:** `hxxp://track.mailer-xyz[.]example/o.gif?u=ALVO123` permite identificar que a mensagem foi aberta.
10. **Anexo:** usa a extensão dupla `.pdf.html`. Contém um formulário que envia CPF e senha por POST para `hxxp://coleta.bancoexemplo-seguro[.]example/post`. Não abra anexos de amostras reais fora de um ambiente isolado.

## Indicadores (desarmados)
- Domínios: `bancoexemplo-seguro[.]example`, `mailer-xyz[.]example`, `mail-reply[.]example`, `coleta.bancoexemplo-seguro[.]example`, `track.mailer-xyz[.]example`
- IPs: `198.51.100.77` (relay) e `192.0.2.45` (origem)
- E-mail: `atendimento.bancoexemplo@mail-reply[.]example`
- URL: `hxxp://bancoexemplo-seguro[.]example/autenticar?ref=ALVO123`

## Veredito esperado
**Phishing**, com alto grau de confiança.

## MITRE ATT&CK
- T1566.002 Phishing: Spearphishing Link
- T1566.001 Phishing: Spearphishing Attachment

## Resposta SOC sugerida
Bloqueie os domínios e IPs no gateway e no proxy; procure o mesmo remetente ou
assunto nas caixas de e-mail; remova as mensagens; verifique quem clicou no link ou
abriu o anexo; force a redefinição das credenciais de quem interagiu com a mensagem;
e denuncie o domínio parecido para que seja retirado do ar.
