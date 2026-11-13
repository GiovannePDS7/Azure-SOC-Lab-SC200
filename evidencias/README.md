# Evidências

As 99 capturas são cópias selecionadas manualmente da Galeria, revisadas com apoio
de OCR e organizadas por fase. Os arquivos mantidos foram renomeados conforme seu
conteúdo e receberam tarjas pretas opacas sobre dados pessoais e identificadores não
documentados encontrados na revisão.

O laboratório foi concluído e o ambiente Azure foi removido. As capturas são registros
históricos, não evidências de um ambiente ativo.

> [!WARNING]
> A revisão aplicou tarjas a dados pessoais, e-mails, IPs não documentados, IDs de
> assinatura ou tenant e partes da interface do navegador. Nomes de recursos e
> endereços de rede que também constam na documentação foram mantidos. OCR pode deixar
> passar texto pequeno ou pouco legível; confira cada captura antes de compartilhá-la
> ou versioná-la. Não inclua credenciais, tokens, dados de clientes nem informações
> que ainda possam identificar uma conta ou ambiente.

A Galeria original permanece intacta. A revisão alterou somente as cópias em
`evidencias`: além das tarjas, removeu duplicatas confirmadas, telas sem resultados,
erros de execução e capturas sem relação clara com o laboratório.

## Organização

- `fase-0`: rede, NSGs, máquinas virtuais e configuração de acesso.
- `fase-1`: Sentinel, conectores e validação da ingestão de telemetria.
- `fase-2`: simulações controladas e eventos observados.
- `fase-3`: regras analíticas, MITRE ATT&CK, incidentes e pastas de trabalho,
  incluindo o [incidente RDP](fase-3/incidentes/incidente-deteccao-de-falhas-rdp.png)
  e a [investigação SSH](fase-3/incidentes/incidente-investigacao-de-forca-bruta-ssh.png).
- `fase-4`: sem capturas mantidas; a imagem disponível mostrava um incidente, mas não
  comprovava a execução de um playbook.
- `fase-5`: uma captura de configurações do Defender for Cloud; ela não comprova que
  o Defender for Servers estava habilitado.
- `encerramento`: notificações de exclusão de recursos. Elas não confirmam que o grupo
  ficou vazio nem que não houve cobranças residuais.

Pastas sem capturas selecionadas não são mantidas apenas como marcadores vazios.

## Nomes dos arquivos

Os nomes descrevem o recurso, a consulta ou a etapa mostrada, sem incluir a data ou o
horário da captura. Quando há mais de uma imagem sobre o mesmo tema, o nome destaca a
diferença entre as telas, como o estado do conector ou o tipo de evento consultado.

Nesta revisão, os valores de senha legíveis nas capturas do teste de conta local foram
cobertos com tarjas opacas. O histórico Git remoto ainda pode conter as versões
anteriores; a remoção dessas versões exige uma limpeza coordenada do histórico.
