# Scripts de análise

`parse_eml.py` faz triagem estática de arquivos `.eml` sem executar o conteúdo das
mensagens. Use somente amostras autorizadas e revise a saída antes de compartilhá-la.

Para analisar as duas amostras sintéticas a partir da raiz do repositório:

```powershell
python scripts\parse_eml.py phishing\caso-01\evidencias\treino_phishing_banco_exemplo.eml phishing\caso-02\evidencias\treino_phishing_02_fraude_fornecedor.eml
```

O formato padrão é texto; `--format json` ou `--format md` altera a saída e `--out`
grava em arquivo. O script desarma indicadores por padrão; `--raw` desativa essa
proteção e deve ser usado apenas em ambiente isolado. Os resultados são indícios
para análise, não prova independente de comprometimento.

Consulte as análises do [caso 01](../phishing/caso-01/analysis.md) e do
[caso 02](../phishing/caso-02/analysis.md).