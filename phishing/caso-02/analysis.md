# Análise do caso 02

Registre o contexto da mensagem, o método de análise, as descobertas e a conclusão
deste caso sanitizado.

## Gabarito

Amostra sintética de treinamento. Os domínios `.example` e os IPs de documentação
não resolvem nem apontam para infraestrutura real. O PDF é benigno e contém apenas
texto.

Ao contrário do caso 01, esta mensagem **não contém link nem malware, e SPF, DKIM e
DMARC passam**. Trata-se de fraude de fornecedor (BEC), com alteração dos dados de
pagamento.

## Descobertas esperadas

1. **Domínio parecido (homóglifo):** o remetente usa `logistica-exernplo.example` (as letras “r” e “n” substituem o “m”), enquanto o domínio legítimo é `logistica-exemplo.example`. A mensagem citada no fim do corpo mostra o domínio verdadeiro, permitindo a comparação direta.
2. **A autenticação passa, mas ainda pode ser fraude:** SPF, DKIM e DMARC passam porque o atacante controla o próprio domínio parecido; portanto, os resultados estão alinhados a esse domínio. A autenticação confirma que a mensagem passou pelos mecanismos válidos para esse domínio, mas não garante que ele seja o esperado.
3. **Reply-To direcionado a um serviço de webmail gratuito** (`freemail.example`), diferente do From. As respostas são desviadas do domínio da empresa.
4. **Sequestro simulado de conversa:** o assunto contém `RES:`, e os campos `In-Reply-To` e `References` apontam para uma mensagem original do domínio legítimo (`logistica-exemplo.example`), que nunca passou pelo domínio do atacante. Em um caso real, confirme se a mensagem referenciada existe na caixa do destinatário.
5. **Cadeia Received (leitura de baixo para cima):** o cliente `[10.8.0.6]`, com IP de origem `192.0.2.88`, enviou a mensagem por um provedor de e-mail em nuvem (`198.51.100.140`), sem relação com a infraestrutura do fornecedor. O `X-Mailer: Microsoft Outlook 16.0` é pouco compatível com um envio autenticado por SMTP na nuvem, mas esse é um indício fraco.
6. **Engenharia social:** solicitação de troca de conta bancária e PIX, urgência (“hoje às 17h”), ameaça de multa, instrução para **não ligar** (“telefone em manutenção”) e vencimento próximo (sexta-feira, 23/10). O campo Importance está definido como High.
7. **Anexo:** PDF sem macros nem scripts, contendo os novos dados bancários. O risco está no conteúdo, não no arquivo; detectores de malware podem não identificar esse tipo de fraude.
8. **Horário:** a mensagem foi enviada às 12h41 (UTC-03; 15h41 UTC), durante o horário comercial, para parecer legítima.

## Indicadores (desarmados)

- Domínio parecido: `logistica-exernplo[.]example`
- Domínio legítimo (referência): `logistica-exemplo[.]example`
- Reply-To: `logistica.exemplo.fin@freemail[.]example`
- IPs: `198.51.100.140` (relay) e `192.0.2.88` (origem do cliente)
- PDF `Fatura_4471_2026.pdf`, SHA-256: `d58de574994fc989310b8a87f2680d78c6a5f83ae8ff876b8b0e55cea34a5654`
- EML, SHA-256: `bba5c19f78eeb7e9106ef297fe0832073f79c653a4e78fa200527b00c7114254`
- Dados bancários fictícios e fraudulentos do PDF: agência 0000, conta 00000-0 e PIX 00.000.000/0001-00

## Veredito esperado

**Phishing (fraude de fornecedor / BEC)**, com alto grau de confiança. Em um caso
real, confirme a solicitação ligando para o fornecedor por um telefone já conhecido,
nunca pelo número fornecido na mensagem.

## MITRE ATT&CK (somente com evidências)

- T1656 Impersonation (personificação do fornecedor).
- T1583.001 Acquire Infrastructure: Domains somente se uma consulta WHOIS real confirmar que o domínio foi registrado recentemente; isso não pode ser comprovado apenas pelo e-mail.
- Não há mapeamento de execução porque não existe payload.

## Resposta SOC sugerida

Não faça o pagamento na nova conta. Valide a solicitação por um telefone já
conhecido, avise as equipes financeira e do fornecedor, bloqueie o domínio parecido
e o endereço Reply-To e procure o mesmo domínio nas demais caixas de e-mail. Verifique
se algum pagamento já foi feito; em caso afirmativo, acione o banco para tentar
recuperar o valor (incluindo o Mecanismo Especial de Devolução — MED — no caso de
PIX). Denuncie também o domínio para que seja retirado do ar.

## Comparação com o caso 01

| Aspecto                | Caso 01                                                 | Caso 02                    |
| ---------------------- | ------------------------------------------------------- | -------------------------- |
| Objetivo               | Roubo de credenciais                                    | Desvio de pagamento        |
| Link ou anexo malicioso | Sim (link enganoso e formulário)                        | Não (PDF benigno)          |
| SPF, DKIM e DMARC      | SPF passa sem alinhamento, DKIM ausente e DMARC falha   | Todos passam               |
| Principal indício      | Cabeçalhos e autenticação                               | Domínio parecido e contexto |
