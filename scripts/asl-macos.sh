#!/usr/bin/env bash
#
# asl-macos — l'utilitaire `asl` pour macOS, universel (arm64 + x86_64), tel
# que l'application Mac l'embarque dans `Contents/Helpers/asl`.
#
# # CE QUE CE SCRIPT PRODUIT, ET OÙ
#
#   distribution/asl-macos-universel-<version>.tar.gz
#       asl            le binaire universel, NON SIGNÉ ;
#       asl.entitlements les droits que le projet Mac lui donne en signant ;
#       LICENSE        la licence ;
#       MANIFESTE      version, commit, architectures, empreintes SHA-256.
#
# # CE QUE CE DÉPÔT FAIT, ET CE QUE LE PROJET MAC FAIT
#
# C'est ce dépôt qui PRODUIT le binaire — comme le xcframework de
# `construire-mobile.sh` — et le projet Mac qui le REPREND, épinglé par le SHA
# de ce dépôt, le signe (Developer ID, runtime renforcé, identifiant
# `org.airdesktop.servicelocator.asl`) avec les droits de `asl.entitlements`,
# et le pose dans le paquet de l'application. **Ce script ne signe rien** : la
# signature et ses droits sont une identité d'éditeur, qui n'a rien à faire
# dans la CI d'un dépôt public.
#
# Ce qu'il garantit, en revanche, et qu'on ne peut pas ajouter après coup sans
# réécrire le binaire : **l'`Info.plist` intégré** dans `__TEXT,__info_plist`
# (`crates/asl-cli/build.rs`). Sans lui, un `asl` signé en bac à sable meurt
# au démarrage. Le script le vérifie sur les DEUX tranches.
#
# # CE QU'IL FAUT
#
#   • un Mac, avec les outils en ligne de commande de Xcode (`lipo`, `otool`) ;
#   • les deux cibles Rust de la toolchain du dépôt :
#     `rustup target add aarch64-apple-darwin x86_64-apple-darwin`.
#
# Ce n'est PAS une barrière : la cible macOS ne se construit pas sur Linux.
# La CI la lance sur un runner macOS (`.github/workflows/asl-macos.yml`).
#
#   asl-macos.sh                       construit, vérifie, archive
#   asl-macos.sh --sortie <dossier>    l'archive ailleurs que dans distribution/

set -euo pipefail

depot=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$depot"

sortie="distribution"
while [ $# -gt 0 ]; do
    case "$1" in
        --sortie) sortie="${2-}"; shift 2 ;;
        --aide|-h)
            sed -n '3,38p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) echo "asl-macos.sh : option inconnue : $1" >&2; exit 2 ;;
    esac
done

dit() { printf '  %s\n' "$*"; }
titre() { printf '\n── %s %s\n' "$1" "$(printf '─%.0s' $(seq 1 $((70 - ${#1}))))"; }
echec() { echo "asl-macos.sh : $*" >&2; exit 1; }

# **LA VERSION EST CELLE DU WORKSPACE**, lue dans SA section — la lecture de
# `check-version.sh` et de `paquet.sh`.
version=$(sed -n '/^\[workspace\.package\]/,/^\[/{s/^version = "\(.*\)"$/\1/p;}' Cargo.toml | head -1)

titre "contrôles préalables"
[ "$(uname -s)" = Darwin ] || echec "ce script construit pour macOS et ne tourne que sur un Mac"
for outil in lipo otool shasum; do
    command -v "$outil" > /dev/null 2>&1 \
        || echec "\`$outil\` est absent — il vient des outils en ligne de commande de Xcode"
done
[ -n "$version" ] || echec "aucune version lue dans [workspace.package] de Cargo.toml"
dit "lipo, otool et shasum sont là ; version $version"

cibles=(aarch64-apple-darwin x86_64-apple-darwin)

titre "construction"
for cible in "${cibles[@]}"; do
    # `--locked` : le binaire porte ce que le verrou dit, pas ce que le
    # registre propose ce jour-là.
    cargo build --release --locked -p asl-cli --target "$cible"
    dit "$cible construit"
done

titre "binaire universel"
travail="target/asl-macos"
rm -rf "$travail"
mkdir -p "$travail"
universel="$travail/asl"
lipo -create \
    target/aarch64-apple-darwin/release/asl \
    target/x86_64-apple-darwin/release/asl \
    -output "$universel"
architectures=$(lipo -archs "$universel")
dit "lipo -info : $(lipo -info "$universel")"
# **LES DEUX, ET RIEN D'AUTRE.** Un Mac Intel qui reçoit un binaire sans sa
# tranche ne le lance pas, et le dit mal (« bad CPU type »).
for arch in arm64 x86_64; do
    case " $architectures " in
        *" $arch "*) ;;
        *) echec "la tranche $arch manque : $architectures" ;;
    esac
done

titre "Info.plist intégré, sur chaque tranche"
# Chaque tranche a sa propre édition de liens : une tranche sans la section
# serait un Mac sur deux où le bac à sable tue `asl` au démarrage. On isole
# donc chaque tranche, on lit dans ses commandes de chargement (`otool -l`)
# où la section `__TEXT,__info_plist` commence et combien elle pèse, et on en
# extrait les octets eux-mêmes : c'est CE QUE le système lira, et non une
# chaîne qui traînerait ailleurs dans le binaire. (`otool -s` affiche la
# section en mots de quatre octets sur arm64, dans l'ordre de la machine —
# illisible sans le remettre à l'endroit.)
for arch in arm64 x86_64; do
    tranche="$travail/asl-$arch"
    lipo -thin "$arch" "$universel" -output "$tranche"
    read -r decalage taille < <(otool -l "$tranche" | awk '
        $1 == "sectname" { dedans = ($2 == "__info_plist") }
        dedans && $1 == "segname" && $2 != "__TEXT" { dedans = 0 }
        dedans && $1 == "size" { taille = $2 }
        dedans && $1 == "offset" { print $2, taille; exit }')
    [ -n "${decalage:-}" ] && [ -n "${taille:-}" ] \
        || echec "$arch : aucune section __TEXT,__info_plist"
    # `dd` et non `tail | head` : sous `pipefail`, `head` qui ferme le tube
    # avant la fin ferait échouer `tail`. `skip` sur un fichier se positionne,
    # il ne lit pas octet par octet ce qui précède.
    section=$(dd if="$tranche" bs=1 skip="$decalage" count="$((taille))" 2>/dev/null)
    case "$section" in
        *"<string>org.airdesktop.servicelocator.asl</string>"*) ;;
        *) echec "$arch : __TEXT,__info_plist ne porte pas l'identifiant org.airdesktop.servicelocator.asl" ;;
    esac
    case "$section" in
        *"<string>$version</string>"*) ;;
        *) echec "$arch : __TEXT,__info_plist ne porte pas la version $version" ;;
    esac
    dit "$arch : __TEXT,__info_plist, $((taille)) octets — org.airdesktop.servicelocator.asl $version"
    rm -f "$tranche"
done

titre "le binaire démarre"
# Sur la tranche de ce Mac seulement — l'autre ne se lancerait que sous
# Rosetta, qu'un runner n'a pas forcément. Non signé et hors bac à sable : on
# éprouve le binaire, pas les droits.
dit "$("$universel" --version)"
"$universel" --version | grep -q "^asl $version" \
    || echec "\`asl --version\` ne dit pas la version $version"

titre "archive"
nom="asl-macos-universel-$version"
contenu="$travail/$nom"
mkdir -p "$contenu"
cp "$universel" "$contenu/asl"
cp LICENSE "$contenu/LICENSE"
# **LES DROITS ATTENDUS VOYAGENT AVEC LE BINAIRE.** Le projet Mac les reprend
# tels quels ; les écrire ici, à côté de ce qu'ils couvrent, évite qu'un
# oubli (`network.server`) se découvre sur un Mac en « injoignable ».
cat > "$contenu/asl.entitlements" <<'DROITS'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>com.apple.security.app-sandbox</key>
	<true/>
	<key>com.apple.security.network.client</key>
	<true/>
	<key>com.apple.security.network.server</key>
	<true/>
	<key>com.apple.security.application-groups</key>
	<array>
		<string>SB7H9B6TY8.org.airdesktop.servicelocator</string>
	</array>
</dict>
</plist>
DROITS
commit=$(git rev-parse HEAD 2>/dev/null || echo inconnu)
{
    echo "asl $version, macOS universel"
    echo "commit        $commit"
    echo "architectures $architectures"
    echo "identifiant   org.airdesktop.servicelocator.asl (Info.plist intégré)"
    echo "signature     aucune — le projet Mac signe, avec asl.entitlements"
    echo
    (cd "$contenu" && shasum -a 256 asl asl.entitlements LICENSE)
} > "$contenu/MANIFESTE"

mkdir -p "$sortie"
archive="$sortie/$nom.tar.gz"
tar -C "$travail" -czf "$archive" "$nom"
dit "$archive"
sed 's/^/  /' "$contenu/MANIFESTE"
