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
#   3 bis. `check-sans-c` — le même graphe, et ce que la compilation a produit.
#      Elle compte DAVANTAGE ici qu'au serveur : une crate qui lierait du C
#      serait chargée dans le processus de quelqu'un d'autre.
#   4. `check-abi`       — la surface exportée, lue dans le BINAIRE.
#   5. `check-clippy`
#   6. `cargo test`
#   7. `check-python`    — la liaison Python contre l'ABI qu'elle transcrit.
#   8. `check-ruby`      — la liaison Ruby, idem, plus le GVL.
#   9. `check-format`    — EN DERNIER (voir ci-dessus).
#
# **`check-abi` A ÉTÉ ÉCRIT AVANT LA PREMIÈRE FONCTION EXPORTÉE, et c'était un
# choix.** Une barrière ajoutée après coup se découvre cassée le jour où l'on en
# a besoin — et le registre `abi.txt` devait exister AVANT la première fonction,
# sinon celle-ci serait entrée sans que rien ne l'inscrive. Il compare
# aujourd'hui trois sources : le binaire, le registre, et `include/asl.h`.
#
# # CE QUI MANQUE ENCORE
#
# Ni `check-abi` ni `check-python` ne jugent le TYPE des arguments. Ce qui les
# rattrape en partie : les tailles de structures, vérifiées à la compilation des
# deux côtés, et les constantes, comparées à l'en-tête par un essai dans chaque
# langage. Le reste tient par la discipline de renommer ce qu'on change.
#
# **TROIS LIAISONS SUR CINQ N'EXISTENT PAS**, et il n'y a donc rien à vérifier
# pour C++, Kotlin et Swift. Le jour où l'une entrera, elle aura besoin de sa
# propre barrière — `check-python` et `check-ruby` ne la couvriront pas.

set -euo pipefail

cd "$(dirname "$0")/.."

barrieres=(
    scripts/check-toolchain.sh
    scripts/check-compile.sh
    scripts/check-pile.sh
    scripts/check-sans-c.sh
    scripts/check-abi.sh
    scripts/check-clippy.sh
    scripts/check-python.sh
    scripts/check-ruby.sh
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

echo "═══ scripts/check-fuzz.sh --smoke"
if ./scripts/check-fuzz.sh --smoke; then
    echo "─── scripts/check-fuzz.sh : OK"
else
    echo "─── scripts/check-fuzz.sh : ÉCHEC"
    echecs+=("scripts/check-fuzz.sh")
fi
echo

echo "═══ scripts/check-couverture.sh"
if ./scripts/check-couverture.sh; then
    echo "─── scripts/check-couverture.sh : OK"
else
    echo "─── scripts/check-couverture.sh : ÉCHEC"
    echecs+=("scripts/check-couverture.sh")
fi
echo

if [ "${#echecs[@]}" -gt 0 ]; then
    echo "ÉCHEC : ${#echecs[@]} barrière(s) refusent :"
    printf '  %s\n' "${echecs[@]}"
    exit 1
fi

echo "OK : les ${#barrieres[@]} barrières, le fuzz, la couverture et les essais passent."
echo
echo "Le DCO ne fait PAS partie de ce lot : il juge des messages de commit, donc"
echo "il se lance APRÈS avoir committé — scripts/check-dco.sh."
