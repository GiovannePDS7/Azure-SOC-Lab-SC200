# Microsoft Sentinel

O Microsoft Sentinel foi habilitado no workspace `law-soclab`. O laboratório reuniu
Azure Activity, Microsoft Entra ID, Windows Security Events, Sysmon e Syslog, com
coleta e destinos descritos na [arquitetura](../../documentacao/architecture.md).

O limite diário de ingestão registrado era 1 GB. O período de retenção não foi
confirmado na fonte. As [oito regras exportadas](../../deteccoes/regras-analiticas/README.md)
foram testadas e validadas, conforme confirmação do responsável. Para a divergência
entre o PDF e o JSON sobre a regra RDP, consulte o
[registro da implantação](../../documentacao/lab-build-record.md).
