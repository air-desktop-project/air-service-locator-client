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
# Trois barrières et les essais. Celle qui MANQUE et qui comptera le plus ici est
# `check-abi.sh` : la surface exposée par `asl-client-ffi` est un engagement
# envers cinq écosystèmes (contrainte C12 du dépôt serveur), et le retrait d'une
# signature casse du code que nous ne voyons pas.
#
# Elle s'ajoutera AVEC la première fonction exportée, jamais avant : comparer un
# en-tête vide à un en-tête vide est une barrière verte qui n'a rien examiné,
# c'est-à-dire un mensonge poli.

set -euo pipefail

cd "$(dirname "$0")/.."

barrieres=(
    scripts/check-compile.sh
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
