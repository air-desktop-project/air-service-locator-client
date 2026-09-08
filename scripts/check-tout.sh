#!/usr/bin/env bash
#
# check-tout — les barrières de ce dépôt, dans l'ordre, d'un seul geste.
#
# # L'ORDRE N'EST PAS ARBITRAIRE
#
# Ce qui répond vite répond tôt : une erreur de type se lit en une seconde, et
# l'apprendre après trois minutes de lints ne l'apprend pas mieux.
#
# LE FORMATAGE EST EN DERNIER, et c'est une leçon payée ailleurs : sur
# `air-mail-server`, il était en premier, il a échoué, et il est resté rouge
# seize poussées pendant lesquelles RIEN de ce qui juge le code n'a tourné. Une
# faute de forme ne doit pas cacher une faute de fond. Le script échoue toujours
# si le formatage cloche — c'est une barrière, pas un avis — mais tout ce qui
# juge le code a déjà parlé quand il le fait.
#
# # CE QUI MANQUE ENCORE, ET QUI EST DIT PLUTÔT QUE TU
#
# # L'ORDRE, EN DÉTAIL
#
#   1. `check-toolchain` — INSTANTANÉ, et en premier : un verdict rendu par la
#      mauvaise toolchain ne vaut rien.
#   2. `check-compile`   — une erreur de type se lit en une seconde.
#   3. `check-pile`      — le graphe résolu, donc les dépendances transitives.
#   4. `check-abi`       — la surface exportée, lue dans le BINAIRE.
#   5. `check-clippy`
#   6. `cargo test`
#   7. `check-format`    — EN DERNIER (voir ci-dessus).
#
# **`check-abi` EXISTE AVANT LA PREMIÈRE FONCTION EXPORTÉE, et c'est un choix.**
# On aurait pu attendre : comparer une surface vide à un registre vide n'atteste
# de rien. Mais une barrière ajoutée après coup se découvre cassée le jour où
# l'on en a besoin — et surtout, le registre `abi.txt` doit exister AVANT la
# première fonction, sinon celle-ci entrera sans que rien ne l'inscrive.
#
# Le contrôle DIT qu'il n'a rien comparé, plutôt que de rendre un OK muet.
#
# # CE QUI MANQUE ENCORE
#
# `check-abi` ne juge pas les SIGNATURES : changer un `int32_t` en `int64_t` sans
# renommer la fonction casse les cinq liaisons sans qu'il bronche. Le jour où la
# première fonction existera, il faudra soit un en-tête committé en plus, soit la
# discipline de renommer ce qu'on change.

set -euo pipefail

cd "$(dirname "$0")/.."

barrieres=(
    scripts/check-toolchain.sh
    scripts/check-compile.sh
    scripts/check-pile.sh
    scripts/check-abi.sh
    scripts/check-clippy.sh
    scripts/check-format.sh
)

echecs=()

for barriere in "${barrieres[@]}"; do
    echo "═══ $barriere"
    if "$barriere"; then
        echo "─── $barriere : OK"
    else
        echo "─── $barriere : ÉCHEC"
        echecs+=("$barriere")
    fi
    echo
done

echo "═══ cargo test --workspace --locked"
if cargo test --workspace --locked; then
    echo "─── essais : OK"
else
    echo "─── essais : ÉCHEC"
    echecs+=("cargo test")
fi
echo

if [ "${#echecs[@]}" -gt 0 ]; then
    echo "ÉCHEC : ${#echecs[@]} barrière(s) refusent :"
    printf '  %s\n' "${echecs[@]}"
    exit 1
fi

echo "OK : les ${#barrieres[@]} barrières et les essais passent."
echo
echo "Le DCO ne fait PAS partie de ce lot : il juge des messages de commit, donc"
echo "il se lance APRÈS avoir committé — scripts/check-dco.sh."
