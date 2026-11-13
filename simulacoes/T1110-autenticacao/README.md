# T1110 — Força bruta

Testes controlados de falhas de autenticação, documentados por origem:

- [RDP no Windows](rdp-failed-logons.md): eventos 4625.
- [SSH no Linux](ssh-invalid-user.md): registros de usuário inexistente.
- [Microsoft Entra ID](entra-failed-signins.md): falhas de entrada `50126`.

Os resultados e horários estão no [diário](../../documentacao/attack-journal.md).
Os limiares usados nas regras atendem ao volume reduzido do laboratório e precisam
ser revistos em outro ambiente.
