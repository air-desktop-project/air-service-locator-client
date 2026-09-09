#!/usr/bin/env bash
#
# check-format — le workspace passe-t-il `cargo fmt --check` ?
#
# # POURQUOI CETTE BARRIÈRE EXISTE ICI DÈS LE PREMIER COMMIT
#
# Sur `air-mail-server`, `cargo fmt --check` n'a d'abord vécu que dans la CI. Il
# n'était dans aucune barrière locale, personne ne le lançait, et LA CI EST
# RESTÉE ROUGE SEIZE POUSSÉES DE SUITE — pendant lesquelles clippy, le build et
# les essais n'ont pas tourné une seule fois, puisqu'une étape qui échoue arrête
# celles qui la suivent.
#
# Une faute de forme ne doit pas cacher une faute de fond. C'est pourquoi cette
# étape est la DERNIÈRE de la CI, et pourquoi elle existe aussi en local.
#
# Ce dépôt n'a qu'une portée à formater — pas de crate hors workspace. Le jour où
# il en aura une (un `fuzz/`, par exemple), c'est ICI qu'elle doit s'ajouter.

set -euo pipefail

cd "$(dirname "$0")/.."

echo 'check-format — le workspace, et `fuzz/` qui n'"'"'en fait pas partie'
echo

violations=0

if cargo fmt --all -- --check; then
    echo "workspace : formaté"
else
    echo "ÉCHEC : le workspace n'est pas formaté (\`cargo fmt --all\` le corrige)."
    violations=$((violations + 1))
fi

if (cd fuzz && cargo fmt -- --check); then
    echo "fuzz/     : formaté"
else
    echo "ÉCHEC : \`fuzz/\` n'est pas formaté (\`cd fuzz && cargo fmt\` le corrige)."
    violations=$((violations + 1))
fi

if [ "$violations" -gt 0 ]; then
    echo
    echo "ÉCHEC : $violations portée(s) mal formatée(s)."
    exit 1
fi

echo
echo 'OK : les deux portées passent `cargo fmt --check`.'
