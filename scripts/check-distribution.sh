#!/usr/bin/env bash
#
# check-distribution — les cinq liaisons trouvent-elles l'objet SANS qu'on le leur
# montre du doigt ?
#
# # CE QUE CETTE BARRIÈRE ÉPROUVE, ET QU'AUCUNE AUTRE N'ÉPROUVAIT
#
# `check-python`, `check-ruby`, `check-kotlin`, `check-cpp` et `check-swift`
# posent tous `ASL_BIBLIOTHEQUE` ou passent `-L target/debug`. **Ils éprouvent la
# liaison, jamais son installation.**
#
# Or c'est là que tout se joue pour un porteur : il n'aura ni variable
# d'environnement, ni arbre de sources. Ici, `ASL_BIBLIOTHEQUE` et
# `LD_LIBRARY_PATH` sont RETIRÉS de l'environnement, et rien ne pointe vers
# `target/`. Ce qui marche marche parce que la distribution est juste.
#
# # TROIS CHARGENT, DEUX LIENT
#
# Python, Ruby et Kotlin doivent TROUVER l'objet à côté de leur paquet — et pour
# Kotlin, DANS son JAR, ce qui demande une extraction. C++ et Swift doivent
# pouvoir compiler et lier contre l'archive SEULE, en-têtes compris : c'est la
# preuve que l'archive est autosuffisante.
#
# # CE QU'ELLE NE PEUT PAS ÉPROUVER
#
# **Les autres plates-formes.** macOS et Windows sont construits par
# `.github/workflows/natif.yml`, et cette barrière-ci ne voit que celle sur
# laquelle elle tourne. C'est une limite réelle, et le workflow existe pour
# qu'elle ne soit pas une inconnue.

set -euo pipefail

cd "$(dirname "$0")/.."
depot=$(pwd)

echo 'check-distribution — les liaisons trouvent-elles l'"'"'objet sans qu'"'"'on le montre ?'
echo

travail=$(mktemp -d)
poses=()
nettoyer() {
    rm -rf "$travail"
    # **CE QUI A ÉTÉ POSÉ DANS L'ARBRE EN REPART.** Un objet natif oublié ferait
    # passer les barrières suivantes pour de mauvaises raisons.
    for pose in "${poses[@]:-}"; do
        [ -n "$pose" ] && rm -f "$pose"
    done
    # **CIBLÉ, ET NON `rm -rf` SUR `resources/`.** Ce répertoire n'a rien
    # aujourd'hui, et le jour où il portera autre chose, un nettoyage large
    # l'emporterait sans que personne le voie.
    rm -rf liaisons/kotlin/src/main/resources/natif
    rmdir liaisons/kotlin/src/main/resources 2>/dev/null || true
}
trap nettoyer EXIT

echo "── l'archive ──────────────────────────────────────────────────────────"
if ! ./scripts/construire-natif.sh "$travail/dist" > "$travail/construire" 2>&1; then
    echo "ÉCHEC : la construction de l'archive a échoué."
    tail -20 "$travail/construire"
    exit 1
fi
archive=$(find "$travail/dist" -name 'asl-natif-*.tar.gz' | head -1)
echo "  $(basename "$archive")"

if ! ./scripts/empaqueter-liaisons.sh "$archive" > "$travail/empaqueter" 2>&1; then
    echo "ÉCHEC : l'empaquetage a échoué."
    tail -20 "$travail/empaqueter"
    exit 1
fi
poses=(
    liaisons/python/asl/libasl_client_ffi.so
    liaisons/ruby/lib/libasl_client_ffi.so
)
echo "  posé dans les trois arbres qui chargent"
echo

# L'archive dépliée, pour C++ et Swift.
tar -xzf "$archive" -C "$travail"
depliee=$(find "$travail" -maxdepth 1 -mindepth 1 -type d -name 'asl-natif-*' | head -1)

# **L'ENVIRONNEMENT EST NETTOYÉ.** C'est tout l'objet de cette barrière.
sans() { env -u ASL_BIBLIOTHEQUE -u LD_LIBRARY_PATH -u DYLD_LIBRARY_PATH "$@"; }

echecs=0
echo "── ce qui CHARGE ──────────────────────────────────────────────────────"

# Python : l'objet est à côté du paquet.
if command -v python3 >/dev/null 2>&1; then
    if sortie=$(cd liaisons/python && sans python3 -c \
        'import asl; print("python  ", asl.version())' 2>&1); then
        echo "  $sortie"
    else
        echo "  python   ÉCHEC"
        echo "$sortie" | sed 's/^/    /' | head -8
        echecs=$((echecs + 1))
    fi
else
    echo "ÉCHEC : \`python3\` est absent — la liaison Python n'a PAS été éprouvée."
    exit 1
fi

# Ruby : l'objet est à côté de `lib/`.
if command -v ruby >/dev/null 2>&1; then
    if sortie=$(cd liaisons/ruby && sans ruby -Ilib -e \
        'require "asl"; puts "ruby     #{Asl.version.inspect}"' 2>&1); then
        echo "  $sortie"
    else
        echo "  ruby     ÉCHEC"
        echo "$sortie" | sed 's/^/    /' | head -8
        echecs=$((echecs + 1))
    fi
else
    echo "ÉCHEC : \`ruby\` est absent — la liaison Ruby n'a PAS été éprouvée."
    exit 1
fi

# Kotlin : l'objet est DANS le JAR, et doit en être extrait.
if command -v kotlinc >/dev/null 2>&1 && command -v jar >/dev/null 2>&1; then
    cat > "$travail/Fumee.kt" <<'KOTLIN'
import io.github.airdesktopproject.asl.version

fun main() {
    println("kotlin   " + version())
}
KOTLIN
    if kotlinc -jvm-target 22 -include-runtime \
        liaisons/kotlin/src/main/kotlin/io/github/airdesktopproject/asl/*.kt \
        "$travail/Fumee.kt" -d "$travail/fumee.jar" > "$travail/kt" 2>&1; then
        # **LES RESSOURCES ENTRENT DANS LE JAR ICI.** `kotlinc` ne les connaît
        # pas : c'est le rôle d'un système de construction, et ce script n'en
        # impose aucun.
        (cd liaisons/kotlin/src/main/resources && jar uf "$travail/fumee.jar" natif) \
            >> "$travail/kt" 2>&1
        if sortie=$(sans java --enable-native-access=ALL-UNNAMED \
            -cp "$travail/fumee.jar" FumeeKt 2>&1); then
            echo "  $sortie"
        else
            echo "  kotlin   ÉCHEC — l'objet n'a pas été extrait du JAR"
            echo "$sortie" | sed 's/^/    /' | head -8
            echecs=$((echecs + 1))
        fi
    else
        echo "  kotlin   ÉCHEC (compilation)"
        tail -10 "$travail/kt" | sed 's/^/    /'
        echecs=$((echecs + 1))
    fi
else
    echo "ÉCHEC : \`kotlinc\` ou \`jar\` est absent — Kotlin n'a PAS été éprouvé."
    exit 1
fi

echo
echo "── ce qui LIE ─────────────────────────────────────────────────────────"

# C++ : l'archive doit suffire — en-têtes ET bibliothèque.
if command -v g++ >/dev/null 2>&1; then
    cat > "$travail/fumee.cpp" <<'CPP'
#include <cstdio>
#include "asl.hpp"
int main() {
    const asl::Version v = asl::version();
    std::printf("c++      (%u, %u, %u)\n", v.majeur, v.mineur, v.correctif);
    return 0;
}
CPP
    if g++ -std=c++17 -Wall -Wextra -Werror -I "$depliee/include" \
        "$travail/fumee.cpp" -L "$depliee/lib" -lasl_client_ffi \
        -o "$travail/fumee_cpp" 2>"$travail/cpp"; then
        if sortie=$(LD_LIBRARY_PATH="$depliee/lib" "$travail/fumee_cpp" 2>&1); then
            echo "  $sortie"
        else
            echo "  c++      ÉCHEC (exécution)"
            echecs=$((echecs + 1))
        fi
    else
        echo "  c++      ÉCHEC — l'archive ne suffit pas à compiler"
        sed 's/^/    /' "$travail/cpp" | head -10
        echecs=$((echecs + 1))
    fi
else
    echo "ÉCHEC : \`g++\` est absent — la liaison C++ n'a PAS été éprouvée."
    exit 1
fi

# Swift : la carte de module ENGENDRÉE dans l'archive doit fonctionner.
if command -v swiftc >/dev/null 2>&1; then
    cat > "$travail/fumee.swift" <<'SWIFT'
import Asl

@main
struct Fumee {
    static func main() {
        let v = version()
        print("swift    (\(v.majeur), \(v.mineur), \(v.correctif))")
    }
}
SWIFT
    if swiftc -swift-version 6 -I "$depliee/include" -L "$depliee/lib" \
        -emit-module -emit-library -module-name Asl \
        liaisons/swift/Sources/Asl/Asl.swift \
        -emit-module-path "$travail/Asl.swiftmodule" -o "$travail/libAsl.so" \
        2>"$travail/swift" \
        && swiftc -swift-version 6 -parse-as-library \
            -I "$travail" -I "$depliee/include" -L "$travail" -L "$depliee/lib" \
            "$travail/fumee.swift" -lAsl -o "$travail/fumee_swift" \
            2>>"$travail/swift"; then
        if sortie=$(LD_LIBRARY_PATH="$travail:$depliee/lib" "$travail/fumee_swift" 2>&1); then
            echo "  $sortie"
        else
            echo "  swift    ÉCHEC (exécution)"
            echecs=$((echecs + 1))
        fi
    else
        echo "  swift    ÉCHEC — la carte de module engendrée ne suffit pas"
        sed 's/^/    /' "$travail/swift" | head -10
        echecs=$((echecs + 1))
    fi
else
    echo "ÉCHEC : \`swiftc\` est absent — la liaison Swift n'a PAS été éprouvée."
    exit 1
fi

echo
if [ "$echecs" -gt 0 ]; then
    echo "ÉCHEC : $echecs liaison(s) ne trouvent pas l'objet une fois distribué."
    exit 1
fi

echo "OK : les cinq liaisons marchent sur la seule archive, sans ASL_BIBLIOTHEQUE."
