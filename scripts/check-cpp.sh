#!/usr/bin/env bash
#
# check-cpp — la liaison C++, et le premier compilateur qui LIT `asl.h`.
#
# # CE QUE CETTE BARRIÈRE ATTRAPE ET QU'AUCUNE AUTRE N'ATTRAPAIT
#
# `check-abi.sh` le disait lui-même : **il ne juge pas le TYPE des arguments.**
# Changer un `int32_t` en `int64_t` dans l'en-tête ET dans le code Rust, sans
# renommer, cassait les cinq liaisons sans que rien ne bronche.
#
# Ce contrôle-ci compile l'en-tête et LIE contre la bibliothèque. Une signature
# qui aurait bougé ne compile pas ; un symbole qui aurait disparu ne lie pas.
# C'est le seul endroit du dépôt où le contrat est jugé par un compilateur.
#
# **ET `asl.h` EST COMPILÉ COMME DU C.** Il se dit un en-tête C depuis qu'il
# existe, et rien ne l'avait jamais vérifié : Python et Ruby ne font que le LIRE,
# avec des expressions régulières.
#
# # POURQUOI PLUSIEURS COMPILATEURS ET PLUSIEURS NORMES
#
# Cette bibliothèque est embarquée par du code dont nous ne choisissons pas la
# chaîne de compilation. Un en-tête qui ne compilerait qu'avec `g++` en C++20 ne
# serait pas une liaison C++, ce serait une liaison vers notre poste de travail.
#
# `-Werror` avec `-Wall -Wextra -Wpedantic` : un en-tête qui AVERTIT chez son
# porteur est un en-tête qu'il finira par mettre en liste noire.
#
# # L'ESSAI QUI DOIT ÉCHOUER
#
# Python et Ruby lèvent des exceptions : un code de retour oublié y est
# impossible. C++ ne lève pas — décision prise pour les bases qui se construisent
# avec `-fno-exceptions` —, et ce qui la rend tenable est `[[nodiscard]]`. Sans
# essai, l'annotation se perdrait au premier remaniement sans que rien ne casse.
#
# Ce script compile donc un fichier qui jette une `Faute`, et **exige qu'il ne
# compile PAS**.
#
# # CE QUE CE CONTRÔLE N'EST PAS
#
# Pas de `clang-tidy`, pas de `cppcheck` : les imposer ferait de leur présence une
# condition pour construire ce dépôt.

set -euo pipefail

cd "$(dirname "$0")/.."

entete_c="crates/asl-client-ffi/include"
entete_cpp="liaisons/cpp/include"
essais="liaisons/cpp/essais"

echo 'check-cpp — la liaison C++, et le contrat lu par un compilateur'
echo

compilateurs=()
for candidat in g++ clang++; do
    if command -v "$candidat" >/dev/null 2>&1; then
        compilateurs+=("$candidat")
    fi
done

if [ "${#compilateurs[@]}" -eq 0 ]; then
    echo "ÉCHEC : ni \`g++\` ni \`clang++\` — RIEN n'a été éprouvé."
    exit 1
fi
echo "compilateurs : ${compilateurs[*]}"

echo "construction de l'objet natif…"
cargo build --workspace --locked --quiet

objet="$(pwd)/target/debug"
if [ ! -f "$objet/libasl_client_ffi.so" ] && [ ! -f "$objet/libasl_client_ffi.dylib" ]; then
    echo "ÉCHEC : l'objet natif est introuvable après construction."
    exit 1
fi

# ── `asl.h` EST-IL DU C ? ───────────────────────────────────────────────────
#
# Il le prétend depuis qu'il existe. Personne ne l'avait vérifié.
if command -v gcc >/dev/null 2>&1 || command -v clang >/dev/null 2>&1; then
    cc_c=$(command -v gcc || command -v clang)
    for norme in c99 c11 c17; do
        if ! echo '#include "asl.h"' \
            | "$cc_c" -x c -std="$norme" -Wall -Wextra -Wpedantic -Werror \
                      -I "$entete_c" -fsyntax-only - 2>&1; then
            echo "ÉCHEC : \`asl.h\` n'est pas du $norme valide."
            exit 1
        fi
    done
    echo "asl.h       : valide en c99, c11 et c17"
else
    echo "ÉCHEC : aucun compilateur C — \`asl.h\` n'a PAS été vérifié comme du C."
    exit 1
fi
echo

drapeaux=(-Wall -Wextra -Wpedantic -Werror -I "$entete_c" -I "$entete_cpp")
travail=$(mktemp -d)
trap 'rm -rf "$travail"' EXIT

echecs=0

for compilateur in "${compilateurs[@]}"; do
    for norme in c++17 c++20 c++23; do
        printf '%-9s %-6s ' "$compilateur" "$norme"

        if ! "$compilateur" -std="$norme" "${drapeaux[@]}" \
             "$essais/essais.cpp" -L "$objet" -lasl_client_ffi \
             -o "$travail/essais" 2>"$travail/erreurs"; then
            echo "ÉCHEC (compilation)"
            sed 's/^/      /' "$travail/erreurs" | head -20
            echecs=$((echecs + 1))
            continue
        fi

        if ! LD_LIBRARY_PATH="$objet" DYLD_LIBRARY_PATH="$objet" "$travail/essais"; then
            echo "      ÉCHEC (exécution)"
            echecs=$((echecs + 1))
            continue
        fi

        # ── LE FICHIER QUI DOIT REFUSER DE COMPILER ─────────────────────────
        if "$compilateur" -std="$norme" "${drapeaux[@]}" -fsyntax-only \
             "$essais/ne_compile_pas/faute_ignoree.cpp" >/dev/null 2>&1; then
            echo "      ÉCHEC : une \`Faute\` jetée compile — \`[[nodiscard]]\` a disparu."
            echecs=$((echecs + 1))
        fi
    done
done

echo
if [ "$echecs" -gt 0 ]; then
    echo "ÉCHEC : $echecs combinaison(s) refusent."
    exit 1
fi

echo "OK : l'en-tête compile en C et en C++, lie contre l'ABI, et \`[[nodiscard]]\` mord."
