# Rede

A rede histórica usava a VNet `vnet-soclab` (`10.0.0.0/16`), a subnet
`snet-soclab` (`10.0.1.0/24`) e o grupo de segurança `nsg-soclab`.

As regras de entrada para RDP (TCP/3389) e SSH (TCP/22) foram limitadas ao endereço
público `/32` do operador. Esse endereço não é reproduzido aqui. Em uma recriação,
restrinja o acesso administrativo e revise as regras para o ambiente atual.
Consulte a [arquitetura](../../documentacao/architecture.md).
