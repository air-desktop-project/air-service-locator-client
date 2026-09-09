#!/usr/bin/env bash
#
# empaqueter-liaisons — pose l'objet natif là où chaque liaison le cherche.
#
# # CE QUE CE SCRIPT REND POSSIBLE
#
# Sans lui, une liaison ne trouve l'objet natif que si le porteur pose
# `ASL_BIBLIOTHEQUE`. **Ce n'est pas une distribution, c'est une recette pour
# développeur.** Après lui, `import asl` fonctionne.
#
# # TROIS LIAISONS EMBARQUENT, DEUX LIENT
#
# Python, Ruby et Kotlin CHARGENT l'objet à l'exécution : il doit voyager avec
# leur paquet. C++ et Swift LIENT à la construction : ils n'embarquent rien, ils
# consomment l'archive de `construire-natif.sh` — et c'est pourquoi elle porte
# aussi les en-têtes.
#
# # CE QUI EST POSÉ ICI N'EST JAMAIS COMMITTÉ
#
# `.gitignore` couvre ces emplacements. Un objet natif de plusieurs mébioctets
# dans un commit se remarque tard, et ne se retire jamais vraiment d'un
# historique — c'est la même raison que pour les paquets `.deb`.

set -euo pipefail

cd "$(dirname "$0")/.."

archive="${1:-}"

if [ -z "$archive" ]; then
    echo "usage : $0 <archive asl-natif-*.tar.gz>"
    echo
    echo "Construisez-la d'abord :"
    echo "    ./scripts/construire-natif.sh"
    exit 1
fi

if [ ! -f "$archive" ]; then
    echo "ÉCHEC : $archive est introuvable."
    exit 1
fi

echo "empaqueter-liaisons — l'objet natif dans les arbres qui le chargent"
echo
echo "archive : $archive"

travail=$(mktemp -d)
trap 'rm -rf "$travail"' EXIT
tar -xzf "$archive" -C "$travail"

racine=$(find "$travail" -maxdepth 1 -mindepth 1 -type d | head -1)
if [ -z "$racine" ] || [ ! -f "$racine/MANIFESTE" ]; then
    echo "ÉCHEC : $archive ne ressemble pas à une archive d'`asl`."
    exit 1
fi

cible=$(awk -F' = ' '/^cible = / {print $2}' "$racine/MANIFESTE")
echo "cible   : $cible"

# **LES EMPREINTES SONT VÉRIFIÉES AVANT DE POSER QUOI QUE CE SOIT.** Une archive
# abîmée en transit poserait un objet natif que cinq liaisons chargeraient dans
# le processus de quelqu'un d'autre.
if command -v sha256sum >/dev/null 2>&1; then
    verifier() { sha256sum --check --quiet; }
elif command -v shasum >/dev/null 2>&1; then
    verifier() { shasum -a 256 --check --quiet; }
else
    echo "ÉCHEC : ni \`sha256sum\` ni \`shasum\` — les empreintes ne peuvent PAS être vérifiées."
    exit 1
fi

if ! (cd "$racine" && grep -vE '^(#|$)|^(version|cible|rustc) = ' MANIFESTE | verifier); then
    echo "ÉCHEC : les empreintes du MANIFESTE ne correspondent pas."
    exit 1
fi
echo "empreintes : vérifiées"
echo

# La clé de plate-forme telle que la JVM la calcule — voir `Abi.cleDePlateforme`.
# `os.arch` dit `amd64` là où `rustc` dit `x86_64` : la traduction est ici, et
# elle est la seule.
systeme=linux
case "$cible" in
    *apple-darwin) systeme=macos ;;
    *windows*) systeme=windows ;;
esac
machine=${cible%%-*}
case "$machine" in
    x86_64) machine=x86_64 ;;
    aarch64) machine=aarch64 ;;
esac
cle="$systeme-$machine"

partage=$(find "$racine/lib" \( -name 'libasl_client_ffi.so' -o \
    -name 'libasl_client_ffi.dylib' -o -name 'asl_client_ffi.dll' \) | head -1)
if [ -z "$partage" ]; then
    echo "ÉCHEC : l'archive ne porte pas d'objet PARTAGÉ."
    echo "        Python, Ruby et Kotlin ne peuvent pas charger une bibliothèque statique."
    exit 1
fi
nom=$(basename "$partage")

poser() {
    local ou="$1"
    mkdir -p "$ou"
    cp "$partage" "$ou/$nom"
    echo "  $ou/$nom"
}

echo "posé :"
poser liaisons/python/asl
poser liaisons/ruby/lib
poser "liaisons/kotlin/src/main/resources/natif/$cle"

echo
echo "C++ et Swift ne reçoivent rien : ils LIENT contre l'archive, en-têtes"
echo "compris. Voir liaisons/cpp/README.md et liaisons/swift/README.md."
echo
echo "OK : les trois liaisons qui chargent trouveront l'objet sans ASL_BIBLIOTHEQUE."
