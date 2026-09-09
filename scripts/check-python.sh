#!/usr/bin/env bash
#
# check-python — la liaison Python dit-elle la même chose que l'ABI ?
#
# # CE QUE CETTE BARRIÈRE PROTÈGE, ET QUI N'EST PAS DU CODE PYTHON
#
# `liaisons/python/asl/_abi.py` est une TRANSCRIPTION à la main de
# `crates/asl-client-ffi/include/asl.h` — constantes, dispositions de structures,
# signatures. Rien dans les deux langages ne relie ces deux fichiers : ils
# peuvent diverger sans qu'aucun compilateur ne bronche.
#
# **ET UNE DIVERGENCE NE PLANTE PAS, ELLE MENT.** Une constante décalée fait
# lever `Refuse` là où l'ABI disait `Injoignable` ; un champ déplacé fait lire un
# port dans un champ de protocole. Les essais lisent l'en-tête et comparent.
#
# # POURQUOI LA BIBLIOTHÈQUE EST CONSTRUITE ICI
#
# La liaison charge un objet natif. L'éprouver sans lui n'éprouverait que du
# texte : `ctypes` ne vérifie RIEN tant qu'on n'appelle pas.
#
# # CE QUE CE CONTRÔLE N'EST PAS
#
# **Il ne juge pas le style.** Il n'y a pas de `ruff` ici, ni de `mypy` : les
# imposer ferait de leur présence une condition pour construire ce dépôt, et ils
# ne sont pas dans la bibliothèque standard. Ce qui est vérifié à la place est le
# seul invariant qui coûterait cher : **la liaison n'importe rien hors de la
# bibliothèque standard**, et un essai le prouve en lisant ses propres sources.

set -euo pipefail

cd "$(dirname "$0")/.."

echo 'check-python — la liaison contre l'"'"'ABI qu'"'"'elle transcrit'
echo

if ! command -v python3 >/dev/null 2>&1; then
    echo "ÉCHEC : \`python3\` est absent — RIEN n'a été éprouvé."
    exit 1
fi

version=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
echo "python3 : $version"

# `requires-python = ">=3.11"`, pour les types `X | Y` en annotation et les
# `dataclass(slots=True)`.
if ! python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)'; then
    echo "ÉCHEC : la liaison demande Python 3.11 ou plus."
    exit 1
fi

echo "construction de l'objet natif…"
cargo build --workspace --locked --quiet

objet=""
for candidat in target/debug/libasl_client_ffi.so target/debug/libasl_client_ffi.dylib; do
    if [ -f "$candidat" ]; then
        objet="$(pwd)/$candidat"
        break
    fi
done

if [ -z "$objet" ]; then
    echo "ÉCHEC : l'objet natif est introuvable après construction."
    echo "        Le \`crate-type\` de \`asl-client-ffi\` a-t-il changé ?"
    exit 1
fi
echo "objet   : $objet"
echo

cd liaisons/python
if ! ASL_BIBLIOTHEQUE="$objet" python3 -m unittest discover -s essais -t . ; then
    echo
    echo "ÉCHEC : la liaison Python et l'ABI ne disent pas la même chose."
    exit 1
fi

echo
echo "OK : la liaison Python suit l'ABI, et n'importe que la bibliothèque standard."
