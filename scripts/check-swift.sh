#!/usr/bin/env bash
#
# check-swift — la liaison Swift, et ce que le mode Swift 6 refuse.
#
# # CE QU'ELLE N'A PAS À VÉRIFIER, ET POURQUOI
#
# **Swift INCLUT le contrat.** La carte de module pointe
# `crates/asl-client-ffi/include/asl.h` : il n'y a pas de transcription, donc pas
# de conformité à comparer. Python, Ruby et Kotlin doivent recopier l'en-tête et
# vérifier la copie à l'exécution ; ici le compilateur lit la source, et une
# signature qui aurait bougé ne compile pas.
#
# C'est la seconde des cinq à être dans ce cas, avec C++.
#
# # L'ESSAI QUI DOIT ÉCHOUER
#
# `Client` ne conforme pas à `Sendable` : sous le mode Swift 6, le compilateur
# refuse de le PARTAGER entre domaines d'isolement. C'est ce qui remplace le
# verrou que Python, Ruby et Kotlin posent à l'exécution.
#
# Sans essai, ce refus disparaîtrait le jour où quelqu'un ajouterait
# `: @unchecked Sendable` pour faire taire un avertissement — et rien ne
# casserait, sinon en production, une fois.
#
# # POURQUOI IL Y A UN CONTRÔLE DE FORME ICI, ET PAS POUR LES AUTRES LIAISONS
#
# `ruff`, `rubocop`, `ktlint` et `clang-tidy` sont des installations SÉPARÉES :
# les imposer ferait de leur présence une condition pour construire ce dépôt.
# `swift format` est dans la chaîne d'outils, comme `cargo fmt`. Il ne coûte rien
# à personne, donc il est employé.

set -euo pipefail

cd "$(dirname "$0")/.."

echo 'check-swift — la liaison Swift, et ce que le mode Swift 6 refuse'
echo

if ! command -v swiftc >/dev/null 2>&1; then
    echo "ÉCHEC : \`swiftc\` est absent — RIEN n'a été éprouvé."
    exit 1
fi
echo "swift : $(swift --version 2>&1 | head -1)"

echo "construction de l'objet natif…"
cargo build --workspace --locked --quiet

objet="$(pwd)/target/debug"
if [ ! -f "$objet/libasl_client_ffi.so" ] && [ ! -f "$objet/libasl_client_ffi.dylib" ]; then
    echo "ÉCHEC : l'objet natif est introuvable après construction."
    exit 1
fi
echo

travail=$(mktemp -d)
trap 'rm -rf "$travail"' EXIT

module="liaisons/swift/Sources/CAsl"
sources="liaisons/swift/Sources/Asl/Asl.swift"
essais="liaisons/swift/essais"

# **LA BIBLIOTHÈQUE SEULE, D'ABORD.** Si elle ne compilait qu'accompagnée de ses
# essais, un porteur le découvrirait et pas nous. `-warnings-as-errors` : une
# bibliothèque qui avertit chez son porteur est une bibliothèque qu'il finira par
# mettre en liste noire.
if ! swiftc -swift-version 6 -warnings-as-errors -I "$module" -L "$objet" \
     -emit-module -emit-library -module-name Asl "$sources" \
     -emit-module-path "$travail/Asl.swiftmodule" -o "$travail/libAsl.so" \
     2>"$travail/erreurs"; then
    echo "ÉCHEC : la bibliothèque ne compile pas."
    sed 's/^/  /' "$travail/erreurs" | head -25
    exit 1
fi
echo "la bibliothèque compile seule, sans avertissement."

if ! swiftc -swift-version 6 -warnings-as-errors -parse-as-library \
     -I "$travail" -I "$module" -L "$travail" -L "$objet" \
     "$essais/Essais.swift" -lAsl -o "$travail/essais" 2>"$travail/erreurs"; then
    echo "ÉCHEC : les essais ne compilent pas."
    sed 's/^/  /' "$travail/erreurs" | head -25
    exit 1
fi
echo

if ! LD_LIBRARY_PATH="$travail:$objet" DYLD_LIBRARY_PATH="$travail:$objet" \
     "$travail/essais"; then
    echo
    echo "ÉCHEC : les essais refusent."
    exit 1
fi
echo

# ── CE QUI DOIT REFUSER DE COMPILER ─────────────────────────────────────────
for refus in "$essais"/ne_compile_pas/*.swift; do
    if swiftc -swift-version 6 -parse-as-library -I "$travail" -I "$module" \
         -typecheck "$refus" >/dev/null 2>&1; then
        echo "ÉCHEC : $(basename "$refus") compile, et il ne devrait pas."
        echo "        \`Client\` est-il devenu \`Sendable\` ?"
        exit 1
    fi
done
echo "ce qui doit refuser de compiler refuse : $(ls "$essais"/ne_compile_pas/*.swift | wc -l) fichier(s)."

# ── LA FORME, PAR L'OUTIL DE LA CHAÎNE ──────────────────────────────────────
if command -v swift-format >/dev/null 2>&1 || swift format --version >/dev/null 2>&1; then
    if ! swift format lint --recursive liaisons/swift/Sources liaisons/swift/essais; then
        echo "ÉCHEC : \`swift format --in-place --recursive\` le corrige."
        exit 1
    fi
    echo "la forme est celle de \`swift format\`."
else
    echo "ÉCHEC : \`swift format\` est absent de cette chaîne d'outils."
    exit 1
fi

echo
echo "OK : Swift inclut le contrat, refuse de partager un client, et se tient."
