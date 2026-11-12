# Publicar uma âncora

O `anchors.jsonl` deste repositório é a **cópia pública** do que está no pendrive
testemunha. O pendrive é a via original; este repositório é o espelho. Se os dois
divergirem, o pendrive vale e a divergência é evidência.

## Procedimento (Don)

1. Aponte o emissor para uma cópia local deste repo e acrescente uma âncora:

   ```sh
   cadeia anchor --ledger /caminho/do/ledger \
     --witness /caminho/do/cosca-cartorio \
     --agent cosca-kernel --key /caminho/da/chave.key.json
   ```

   A passphrase vem de `CADEIA_PASSPHRASE` ou do stdin — nunca de argv. O comando
   acrescenta **uma linha** ao `anchors.jsonl` e grava `cosca-kernel/head.json`
   (estado da testemunha, não é âncora).

2. Publique **somente** o log:

   ```sh
   cd /caminho/do/cosca-cartorio
   git add anchors.jsonl
   git commit -m "anchor seq=<N> upto=<M>"
   git push
   ```

## Nunca faça

- **Nunca** `git add .` — o `head.json` da testemunha não é âncora e não se publica.
- **Nunca** editar, reordenar ou apagar linha de `anchors.jsonl`.
- **Nunca** `rebase`, `amend` de commit publicado, ou `push --force`.
- **Nunca** comitar chave privada, `.key.json`, `.k-*` ou `.cosca/`.

A CI roda a verificação em cada push. Se ela falhar, a âncora publicada não está
íntegra: pare e investigue antes de publicar a próxima.
