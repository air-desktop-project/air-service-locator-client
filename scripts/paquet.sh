#!/usr/bin/env bash
#
# Construit le paquet Debian de l'utilitaire `asl`.
#
# **LA CIBLE EST UBUNTU**, comme pour l'annuaire, et c'est elle qui décide du
# format. Debian et Ubuntu partagent `dpkg` et la charte ; ce paquet vaut donc
# pour les deux. Il est calqué sur `scripts/paquet.sh` du dépôt serveur — mêmes
# garde-fous, même structure —, et ce qui en diffère le dit.
#
# ── UN OUTIL D'UTILISATEUR, PAS UN SERVICE ──────────────────────────────────
#
# `asl` se lance à la main, par quelqu'un, pour quelqu'un. Le paquet pose donc
# UN binaire, sa licence, et une unité UTILISATEUR désactivée — rien d'autre :
#
#   — une seule unité systemd, `asl-echo.service`, sous
#     `/usr/lib/systemd/user/` et DÉSACTIVÉE (`protocole.md` §3 quater,
#     décision 93) : l'écho répond au nom de la clé de cette machine, et c'est
#     à celui qui la porte de l'activer (`systemctl --user enable --now
#     asl-echo`). Aucune unité système : `asl announce` tient son annonce au
#     premier plan, et c'est au porteur du daemon de décider qui la lance et
#     quand ;
#   — aucun compte système, et donc aucun `postinst` : il n'y a rien à créer ;
#   — aucun état : l'identité d'une machine vit chez l'utilisateur
#     (`$XDG_CONFIG_HOME/asl`, sinon `~/.config/asl`, ou `--state`), elle est
#     générée PAR `asl enroll`, et un paquet qui la poserait ou l'effacerait
#     déciderait à la place de celui dont elle porte la clé privée.
#
# Pas de script de mainteneur, c'est aussi pas de code qui s'exécute en root
# chez un inconnu sans que personne l'ait relu : la meilleure garde est celle
# dont on n'a pas besoin.
set -euo pipefail

depot=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$depot"

# **LA VERSION EST CELLE DU WORKSPACE**, et la lire dans SA section compte : la
# première ligne `version = ` venue pourrait un jour être celle d'une
# dépendance. C'est la lecture de `check-version.sh`.
version=$(sed -n '/^\[workspace\.package\]/,/^\[/{s/^version = "\(.*\)"$/\1/p;}' Cargo.toml | head -1)
sortie="."
construire=1
architecture=$(dpkg --print-architecture 2>/dev/null || echo amd64)

while [ $# -gt 0 ]; do
    case "$1" in
        --version) version="${2-}"; shift 2 ;;
        --sortie) sortie="${2-}"; shift 2 ;;
        --sans-construire) construire=0; shift ;;
        --aide|-h)
            sed -n '3,30p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) echo "paquet.sh : option inconnue : $1" >&2; exit 2 ;;
    esac
done

dit() { printf '  %s\n' "$*"; }
titre() { printf '\n── %s %s\n' "$1" "$(printf '─%.0s' $(seq 1 $((70 - ${#1}))))"; }

titre "contrôles préalables"
# **ON REFUSE PLUTÔT QUE DE BRICOLER.** Un `.deb` se fabrique aussi à la main
# avec `ar` et `tar` ; le résultat serait subtilement différent de ce que `dpkg`
# attend, et le défaut se découvrirait sur la machine de quelqu'un.
for outil in dpkg-deb dpkg-shlibdeps; do
    if ! command -v "$outil" > /dev/null 2>&1; then
        echo "paquet.sh : \`$outil\` est absent — il vient du paquet \`dpkg-dev\`" >&2
        exit 1
    fi
done
if [ -z "$version" ]; then
    echo "paquet.sh : aucune version lue dans [workspace.package] de Cargo.toml" >&2
    exit 1
fi
dit "dpkg-deb et dpkg-shlibdeps sont là ; version $version"

if [ "$construire" -eq 1 ]; then
    titre "construction"
    # `--locked` : le paquet porte ce que le verrou dit, pas ce que le registre
    # propose ce jour-là.
    cargo build --release -p asl-cli --locked
    dit "binaire construit en release"
fi

if [ ! -x target/release/asl ]; then
    echo "paquet.sh : target/release/asl est absent" >&2
    exit 1
fi

arbre=$(mktemp -d)
trap 'rm -rf "$arbre"' EXIT

titre "arborescence"
# `/usr/bin` et non `/usr/local` : ce dernier appartient à l'administrateur
# (§9.1.2 de la charte Debian), et un paquet n'y a rien à faire.
install -D -m 0755 target/release/asl "$arbre/usr/bin/asl"

install -d -m 0755 "$arbre/usr/share/doc/asl"
install -m 0644 LICENSE "$arbre/usr/share/doc/asl/copyright"
dit "binaire et licence"

# **`/usr/lib/systemd/user`, ET NON `/etc/systemd/user`** : ce dernier est à
# l'administrateur, et une unité qu'on y poserait — ou un lien sous
# `default.target.wants` — l'activerait pour tout le monde. Posée ici, elle
# n'est que proposée ; l'unité est la seule copie, installée telle quelle.
install -D -m 0644 paquet/asl-echo.service \
    "$arbre/usr/lib/systemd/user/asl-echo.service"
dit "unité utilisateur asl-echo.service — posée, pas activée"

titre "dépendances, calculées et non devinées"
# **`dpkg-shlibdeps` LIT LE BINAIRE.** Écrire `libc6 (>= 2.34)` à la main serait
# vrai le jour où on l'écrit, et faux à la première mise à jour de la chaîne de
# compilation — exactement la dérive que ce dépôt passe son temps à traquer.
install -d -m 0755 "$arbre/debian"
printf 'Source: asl\n\nPackage: asl\nArchitecture: any\n' \
    > "$arbre/debian/control"
if ! depends=$(cd "$arbre" && dpkg-shlibdeps -O --ignore-missing-info \
    usr/bin/asl 2>"$arbre/debian/plainte" \
    | sed 's/^shlibs:[A-Za-z]*=//'); then
    echo "paquet.sh : \`dpkg-shlibdeps\` a refusé :" >&2
    sed 's/^/    /' "$arbre/debian/plainte" >&2
    exit 1
fi
rm -rf "$arbre/debian"
if [ -z "$depends" ]; then
    echo "paquet.sh : aucune dépendance calculée — c'est invraisemblable" >&2
    exit 1
fi
dit "$depends"

titre "métadonnées"
install -d -m 0755 "$arbre/DEBIAN"
taille=$(du -sk --exclude=DEBIAN "$arbre" | cut -f1)
cat > "$arbre/DEBIAN/control" <<CONTROL
Package: asl
Version: $version
Section: net
Priority: optional
Architecture: $architecture
Depends: $depends
Installed-Size: $taille
Maintainer: Thierry Delhaise <thierry.delhaise@gmail.com>
Homepage: https://github.com/air-desktop-project/air-service-locator-client
Description: annoncer, resoudre et diagnostiquer un service air-service-locator
 L'utilitaire en ligne de commande d'air-service-locator : enroler une machine
 aupres de son compte, annoncer un service et tenir l'annonce, demander ou
 joindre un service, et diagnostiquer la connexion a l'annuaire.
 .
 Le paquet pose le binaire, et une unite systemd UTILISATEUR asl-echo,
 desactivee : "systemctl --user enable --now asl-echo" l'active pour celui qui
 porte la cle de la machine. L'identite de la machine est generee par
 "asl enroll" et vit chez l'utilisateur (~/.config/asl) : ni l'installation ni
 le retrait du paquet n'y touchent.
CONTROL
dit "control — et aucun script de mainteneur"

titre "assemblage"
# **LA RACINE DU PAQUET EST `/`**, et son mode s'appliquerait à `/`.
# `mktemp -d` crée en 0700, ce qui est juste pour un répertoire jetable et
# catastrophique pour la racine d'un système.
chmod 0755 "$arbre"
mkdir -p "$sortie"
nom="$sortie/asl_${version}_${architecture}.deb"
# `--root-owner-group` : sans lui, les fichiers du paquet appartiendraient au
# compte qui l'a construit, dont le numéro ne veut rien dire ailleurs.
dpkg-deb --root-owner-group --build "$arbre" "$nom" > /dev/null
dit "$nom"

printf '\nOK : %s (%s)\n' "$nom" "$(du -h "$nom" | cut -f1)"
