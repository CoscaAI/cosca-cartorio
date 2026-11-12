# Cartório da Cadeia v2

Cartório público do Cosca. Este repositório guarda **apenas âncoras**: hashes e
assinaturas que provam que um determinado estado da memória existiu em um
determinado momento. Nada mais.

## O que este repositório NÃO contém

- **Nenhum conteúdo de memória.** Nem texto, nem ID, nem nome de arquivo, nem
  trecho de bloco. Só o hash do topo (`head`) e o `merkle_root` do checkpoint —
  ambos irreversíveis.
- **Nenhum segredo.** Nenhuma chave privada, passphrase ou token. A `pubkey.txt`
  é a chave **pública** Ed25519; ela é pública por definição.

## Como qualquer pessoa verifica

```sh
go run ./verify -file anchors.jsonl -pub pubkey.txt
```

Saída de sucesso — uma linha, nada mais:

```
anchors=<n> head=<64 hex> upto=<n> verdict=INTEGRO
```

Se qualquer coisa estiver errada (arquivo vazio, `seq` fora de ordem, `prev`
quebrado, assinatura inválida, `head` que não é hex de 64), o programa lista os
problemas em stderr e sai com código 1. **Ele nunca imprime `INTEGRO` parcial.**

`verify/` é uma **segunda implementação** do formato, independente do emissor.
Se ela e o `cadeia anchor` discordarem sobre o mesmo arquivo, isso é um bug.

## Regra absoluta: append-only

> **Este repositório é append-only. Nunca reescreva, nunca rebase, nunca
> force-push.**

O `anchors.jsonl` só cresce, uma linha por âncora. O histórico do git **é** a
testemunha: cada linha publicada fica amarrada ao commit que a publicou. Quem
reescreve o passado aqui é detectável por qualquer pessoa que tenha um clone —
o commit antigo continua existindo no clone dela, com outro hash, e a divergência
aparece na hora. Reescrever não apaga a âncora: denuncia quem tentou.

## Formato

```json
{"v":2,"seq":1,"prev":"<64 hex>","upto":10,"head":"<64 hex>","merkle_root":"<64 hex>","ts":"<RFC3339Nano>","sig":"<base64>"}
```

- `hash da âncora` = BLAKE3 (hex minúsculo) do JSON com `sig` em branco.
- `prev` da linha N = hash da linha N-1; a linha 1 usa 64 zeros.
- `sig` = Ed25519 sobre os **bytes ASCII do hex do hash**, em base64 padrão.

Procedimento de publicação: [CARTORIO.md](CARTORIO.md).
