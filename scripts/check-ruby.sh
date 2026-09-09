#!/usr/bin/env bash
#
# check-ruby — la liaison Ruby dit-elle la même chose que l'ABI ?
#
# # CE QUE CETTE BARRIÈRE PROTÈGE, ET QUI N'EST PAS DU CODE RUBY
#
# `liaisons/ruby/lib/asl/abi.rb` est une TRANSCRIPTION à la main de
# `crates/asl-client-ffi/include/asl.h` — constantes, dispositions, signatures.
# Rien dans les deux langages ne relie ces deux fichiers : ils peuvent diverger
# sans qu'aucun compilateur ne bronche.
#
# **ET UNE DIVERGENCE NE PLANTE PAS, ELLE MENT.** Une constante décalée fait lever
# `Refuse` là où l'ABI disait `Injoignable` ; un champ déplacé fait lire un port
# dans un champ de protocole, sans changer aucune taille.
#
# # CE QUE CETTE BARRIÈRE ATTRAPE ET QUE CELLE DE PYTHON N'ATTRAPE PAS
#
# **Le GVL.** Un appel `fiddle` déclaré `need_gvl: true` fige l'interpréteur
# entier pendant qu'un annuaire ne répond pas — vingt secondes de serveur web
# arrêté, sans une ligne d'erreur. L'essai le mesure : un fil témoin doit AVANCER
# pendant un appel bloquant, et il gagne zéro tour quand le GVL est tenu.
#
# # CE QUE CE CONTRÔLE N'EST PAS
#
# **Il ne juge pas le style.** Pas de `rubocop` : l'imposer ferait de sa présence
# une condition pour construire ce dépôt, et il n'est pas dans la distribution.
# Ce qui est vérifié à la place est le seul invariant qui coûterait cher — **la
# liaison ne charge rien hors de la distribution de Ruby**, et un essai le prouve
# en lisant ses propres sources.

set -euo pipefail

cd "$(dirname "$0")/.."

echo 'check-ruby — la liaison contre l'"'"'ABI qu'"'"'elle transcrit'
echo

if ! command -v ruby >/dev/null 2>&1; then
    echo "ÉCHEC : \`ruby\` est absent — RIEN n'a été éprouvé."
    exit 1
fi

echo "ruby : $(ruby -e 'print RUBY_VERSION')"

# `Data.define` demande 3.2, et la gemspec le déclare.
if ! ruby -e 'exit(Gem::Version.new(RUBY_VERSION) >= Gem::Version.new("3.2"))'; then
    echo "ÉCHEC : la liaison demande Ruby 3.2 ou plus (`Data.define`)."
    exit 1
fi

# **`fiddle` EST DANS LA DISTRIBUTION, MAIS IL PEUT AVOIR ÉTÉ RETIRÉ.** Le dire
# vaut mieux que de laisser l'échec ressembler à une faute de notre code.
for besoin in fiddle minitest; do
    if ! ruby -e "require '$besoin'" >/dev/null 2>&1; then
        echo "ÉCHEC : \`$besoin\` est absent de cette installation de Ruby."
        echo "        RIEN n'a été éprouvé."
        exit 1
    fi
done

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
echo "objet : $objet"
echo

cd liaisons/ruby
echecs=0
for essai in essais/test_*.rb; do
    if ! ASL_BIBLIOTHEQUE="$objet" ruby -Ilib -Iessais "$essai"; then
        echecs=$((echecs + 1))
    fi
done

if [ "$echecs" -gt 0 ]; then
    echo
    echo "ÉCHEC : la liaison Ruby et l'ABI ne disent pas la même chose."
    exit 1
fi

echo
echo "OK : la liaison Ruby suit l'ABI, relâche le GVL, et ne charge que la distribution."
