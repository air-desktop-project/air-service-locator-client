#!/usr/bin/env bash
#
# construire-natif — l'objet natif, empaqueté pour les cinq liaisons.
#
# # LE PROBLÈME QUE CE SCRIPT EXISTE POUR RÉSOUDRE
#
# Les cinq liaisons CHERCHENT `libasl_client_ffi`. Aucune ne l'EMBARQUE : jusqu'ici
# il fallait `cargo build --release` et poser `ASL_BIBLIOTHEQUE` à la main, ce qui
# n'est pas une distribution — c'est une recette pour développeur.
#
# # UNE SEULE ARCHIVE POUR LES CINQ, ET NON CINQ FORMATS
#
# Une roue Python, une gemme, un JAR, une archive C++ et un paquet SwiftPM
# porteraient le MÊME objet et les MÊMES en-têtes. Les construire séparément
# multiplierait par cinq les occasions de publier des versions qui ne
# correspondent pas.
#
# Ce script produit donc UN artefact par plate-forme, et `empaqueter-liaisons.sh`
# le distribue dans les arbres qui en ont besoin.
#
# # AUCUNE DATE DANS LE MANIFESTE, ET C'EST DÉLIBÉRÉ
#
# Une date rendrait deux constructions du même code différentes, donc
# invérifiables l'une par l'autre. Ce qui est inscrit est ce qui INFLUE sur le
# contenu : la version, la cible, le compilateur, et l'empreinte de chaque
# fichier.

set -euo pipefail

cd "$(dirname "$0")/.."

# **`sha256sum` N'EST PAS PARTOUT.** macOS n'a que `shasum`. Le choisir une fois
# ici évite de découvrir l'absence au milieu d'une construction de publication.
#
# C'est une CHAÎNE et non une fonction : elle est passée à `xargs`, qui lance un
# programme et ne connaît pas les fonctions du shell.
if command -v sha256sum >/dev/null 2>&1; then
    outil_empreinte="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
    outil_empreinte="shasum -a 256"
else
    echo "ÉCHEC : ni \`sha256sum\` ni \`shasum\` — le MANIFESTE serait sans empreintes."
    exit 1
fi

version=$(awk -F'"' '/^version = / {print $2; exit}' Cargo.toml)
cible=$(rustc -vV | awk '/^host: / {print $2}')
nom="asl-natif-$version-$cible"
sortie="${1:-distribution}"

echo "construire-natif — l'objet natif pour les cinq liaisons"
echo
echo "version : $version"
echo "cible   : $cible"
echo "sortie  : $sortie/$nom"
echo

# **`--release`, ET NON `--debug`.** Ce qui est distribué n'est pas ce qu'on
# éprouve : les barrières travaillent sur `target/debug`, plus rapide à
# construire ; ce qu'un porteur charge doit être optimisé.
echo "construction…"
cargo build --release --locked --package asl-client-ffi

racine="$sortie/$nom"
rm -rf "$racine"
mkdir -p "$racine/lib" "$racine/include"

# Les deux sorties natives : l'objet partagé pour ce qui charge à l'exécution
# (Python, Ruby, la JVM), la bibliothèque statique pour ce qui lie à la
# construction (C++, et Swift quand on ne veut pas d'objet à installer).
compte=0
for artefact in libasl_client_ffi.so libasl_client_ffi.dylib asl_client_ffi.dll \
                libasl_client_ffi.a asl_client_ffi.lib; do
    if [ -f "target/release/$artefact" ]; then
        cp "target/release/$artefact" "$racine/lib/"
        compte=$((compte + 1))
    fi
done

if [ "$compte" -eq 0 ]; then
    echo "ÉCHEC : aucun artefact natif dans target/release."
    echo "        Le \`crate-type\` de \`asl-client-ffi\` a-t-il changé ?"
    exit 1
fi

# **LES EN-TÊTES VOYAGENT AVEC L'OBJET.** Un consommateur C++ ou Swift qui
# récupérerait la bibliothèque sans son en-tête aurait une version de l'un et une
# version de l'autre — c'est-à-dire la faute que `check-abi` existe pour empêcher,
# déplacée chez lui.
cp crates/asl-client-ffi/include/asl.h "$racine/include/"
cp liaisons/cpp/include/asl.hpp "$racine/include/"
cp LICENSE "$racine/" 2>/dev/null || true

# ── LA CARTE DE MODULE, ENGENDRÉE ET NON RECOPIÉE ───────────────────────────
#
# Celle du dépôt pointe `../../../../crates/asl-client-ffi/include/asl.h` — le
# contrat lui-même, pour que Swift n'en ait pas de copie. Dans une archive, ce
# chemin ne mène nulle part.
#
# Elle est donc ENGENDRÉE ici, et jamais committée : ce qui est dérivé ne peut pas
# diverger de ce dont il dérive.
cat > "$racine/include/module.modulemap" <<'MAP'
// Engendrée par `scripts/construire-natif.sh`. Ne pas modifier.
//
// Celle du dépôt pointe l'en-tête à son emplacement de source ; celle-ci le
// pointe à côté d'elle, tel qu'il voyage dans cette archive.
module CAsl {
    header "asl.h"
    link "asl_client_ffi"
    export *
}
MAP

# ── LE MANIFESTE ────────────────────────────────────────────────────────────
{
    echo "# Ce que cette archive contient, et de quoi elle a été construite."
    echo "#"
    echo "# AUCUNE DATE : une date rendrait deux constructions du même code"
    echo "# différentes, donc invérifiables l'une par l'autre."
    echo
    echo "version = $version"
    echo "cible = $cible"
    echo "rustc = $(rustc --version)"
    echo
    echo "# Empreintes SHA-256, une par fichier."
} > "$racine/MANIFESTE"

(
    cd "$racine"
    find . -type f ! -name MANIFESTE -print0 \
        | LC_ALL=C sort -z \
        | xargs -0 $outil_empreinte \
        | sed 's|  \./|  |' >> MANIFESTE
)

archive="$sortie/$nom.tar.gz"

# **L'ARCHIVE EST REPRODUCTIBLE QUAND `tar` SAIT LA RENDRE TELLE, ET LE DIT
# QUAND IL NE SAIT PAS.**
#
# `--sort=name` et une date fixe font que deux constructions du même code donnent
# le même octet. Ce sont des options GNU : le `tar` de macOS et celui de Windows
# ne les ont pas. Plutôt que d'échouer là-bas — ce qui empêcherait de publier pour
# ces plates-formes — l'archive y est faite sans, et la ligne le nomme. Les
# EMPREINTES du manifeste, elles, restent justes partout : c'est ce qu'on vérifie.
if tar --version 2>/dev/null | grep -q GNU; then
    tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner \
        -czf "$archive" -C "$sortie" "$nom"
    reproductible="oui"
else
    tar -czf "$archive" -C "$sortie" "$nom"
    reproductible="non — \`tar\` n'est pas celui de GNU sur cette plate-forme"
fi

echo
echo "contenu :"
sed 's/^/  /' "$racine/MANIFESTE" | grep -v '^  #' | grep -v '^  $'
echo
echo "archive        : $archive"
echo "empreinte      : $($outil_empreinte "$archive" | awk '{print $1}')"
echo "reproductible  : $reproductible"
echo
echo "OK : un artefact pour les cinq liaisons."
