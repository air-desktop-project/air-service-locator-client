#!/usr/bin/env bash
#
# check-paquet — éprouve le paquet Debian que `scripts/paquet.sh` construit.
#
# ── POURQUOI CE CONTRÔLE EXISTE ─────────────────────────────────────────────
#
# Un paquet s'installe sur la machine de quelqu'un d'autre, avec les privilèges
# du superutilisateur. Celui-ci n'a AUCUN script de mainteneur, et c'est une
# promesse : rien de ce dépôt ne s'exécute en root chez un inconnu. Aucun essai
# Rust ne peut la tenir — c'est ici qu'elle se tient.
#
# Et il en porte deux autres : que ce qu'il pose soit exactement un binaire et
# sa licence, rien sous `/etc`, rien dans le répertoire de quiconque ; et que le
# binaire déballé PARTE, sur l'architecture que le paquet annonce, et connaisse
# les options et les commandes de la SOURCE.
#
# Calqué sur `scripts/check-paquet.sh` du dépôt serveur ; ce qui n'y est pas
# (l'unité, la posture d'attestation, le purge, les doublures du `postinst`)
# n'a pas d'objet ici, puisqu'il n'y a ni service ni script de mainteneur.
set -euo pipefail

racine=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$racine"

fautes=0
rate() { printf '\nÉCHEC : %s\n' "$*" >&2; fautes=$((fautes + 1)); }
titre() { printf '\n── %s %s\n' "$1" "$(printf '─%.0s' $(seq 1 $((70 - ${#1}))))"; }

avant=0
commencer() { avant=$fautes; }
conclure() { [ "$fautes" -eq "$avant" ] && echo "OK — $1"; return 0; }

# **UNE MACHINE SANS `dpkg` NE PEUT PAS ÉPROUVER UN `.deb`**, et le prétendre
# serait pire que de s'abstenir.
if ! command -v dpkg-deb > /dev/null 2>&1 || ! command -v dpkg-shlibdeps > /dev/null 2>&1; then
    cat >&2 <<'ABSENT'

IGNORÉ : `dpkg-deb` ou `dpkg-shlibdeps` est absent de cette machine.

Ce contrôle ne peut pas s'exécuter, et n'a donc RIEN éprouvé. Il tourne en
intégration continue, où `dpkg-dev` est présent — c'est là que son verdict
compte.

ABSENT
    exit 0
fi

essai=$(mktemp -d)
trap 'rm -rf "$essai"' EXIT

version=$(sed -n '/^\[workspace\.package\]/,/^\[/{s/^version = "\(.*\)"$/\1/p;}' Cargo.toml | head -1)
machine=$(dpkg --print-architecture)

echo "check-paquet — ce qu'on installera en root chez quelqu'un d'autre"

titre "1. le paquet se construit"
commencer
# **PAS DE `--sans-construire`.** S'en remettre à `target/release` sans le
# rebâtir, c'est éprouver un paquet qui porte un binaire vieux de plusieurs
# heures. `cargo` est incrémental : quand rien n'a changé, cela ne coûte rien.
if ! ./scripts/paquet.sh --sortie "$essai" > "$essai/construction" 2>&1; then
    rate "la construction échoue :
$(tail -20 "$essai/construction")"
    exit 1
fi
paquet=$(ls "$essai"/asl_*.deb)
[ "$(basename "$paquet")" = "asl_${version}_${machine}.deb" ] \
    || rate "le paquet s'appelle $(basename "$paquet"), et non asl_${version}_${machine}.deb"
conclure "$(basename "$paquet")"

titre "2. dpkg le relit ; dépendances calculées ; CETTE architecture"
commencer
if ! dpkg-deb --info "$paquet" > "$essai/control" 2>&1; then
    rate "\`dpkg-deb --info\` refuse le paquet"
fi
# Une dépendance ÉCRITE À LA MAIN serait vraie le jour où on l'écrit, et fausse
# à la première mise à jour de la chaîne de compilation.
grep -q '^ Depends: .*libc6' "$essai/control" \
    || rate "les dépendances ne portent pas la libc — elles n'ont pas été calculées"
# **LE CHAMP `Architecture` EST CE QUE `dpkg` CONFRONTERA À LA MACHINE QUI
# INSTALLE.** Un paquet `arm64` qui porterait un binaire x86 s'installerait sans
# un mot, et ne partirait pas.
[ "$(dpkg-deb --field "$paquet" Architecture)" = "$machine" ] \
    || rate "le paquet se dit $(dpkg-deb --field "$paquet" Architecture), la machine est $machine"
[ "$(dpkg-deb --field "$paquet" Version)" = "$version" ] \
    || rate "le paquet se dit en $(dpkg-deb --field "$paquet" Version), Cargo.toml en $version"
[ "$(dpkg-deb --field "$paquet" Package)" = "asl" ] \
    || rate "le paquet ne s'appelle pas asl"
conclure "$machine, $version — $(sed -n 's/^ Depends: //p' "$essai/control")"

titre "3. il pose un binaire et sa licence, et RIEN d'autre"
commencer
dpkg-deb --contents "$paquet" > "$essai/contenu"
# **LA LISTE EST FERMÉE.** Un fichier de plus — une unité, une configuration
# sous `/etc`, un état d'exemple — serait une décision prise à la place de
# l'utilisateur, et c'est précisément ce que ce paquet s'interdit.
awk '$1 !~ /^d/ { print $NF }' "$essai/contenu" | sort > "$essai/fichiers"
printf '%s\n' ./usr/bin/asl ./usr/share/doc/asl/copyright > "$essai/attendus"
if ! cmp -s "$essai/attendus" "$essai/fichiers"; then
    rate "le paquet ne pose pas exactement ce qu'on attend :
$(diff "$essai/attendus" "$essai/fichiers" | sed 's/^/    /')"
fi
grep -q ' \./usr/local/' "$essai/contenu" \
    && rate "un fichier sous /usr/local, qui appartient à l'administrateur"
grep -q ' \./etc/' "$essai/contenu" \
    && rate "quelque chose sous /etc — un outil d'utilisateur n'y a rien à faire"
grep -qE ' \./(home|root|var)/' "$essai/contenu" \
    && rate "un état posé par le paquet — l'identité est générée par \`asl enroll\`"
grep -qE '^-rwxr-xr-x root/root .* \./usr/bin/asl$' "$essai/contenu" \
    || rate "/usr/bin/asl n'est pas 0755 root:root"
# **LA RACINE DU PAQUET NE DOIT PAS RESSERRER `/`.** `mktemp -d` crée en 0700 ;
# une racine expédiée dans ce mode rendrait le système inutilisable.
racine_mode=$(awk '$NF == "./" { print $1 }' "$essai/contenu")
[ "$racine_mode" = "drwxr-xr-x" ] \
    || rate "la racine du paquet est en $racine_mode, et non drwxr-xr-x"
conclure "/usr/bin/asl, /usr/share/doc/asl/copyright"

titre "4. la licence du paquet est CELLE du dépôt"
commencer
install -d "$essai/deballe"
dpkg-deb --extract "$paquet" "$essai/deballe"
cmp -s LICENSE "$essai/deballe/usr/share/doc/asl/copyright" \
    || rate "le copyright empaqueté diffère de LICENSE"
conclure "MPL-2.0, un seul texte"

titre "5. AUCUN script de mainteneur"
commencer
# **RIEN NE S'EXÉCUTE EN ROOT À L'INSTALLATION.** Ni compte à créer, ni service
# à recharger, ni état à poser : un `postinst` qui apparaîtrait ici serait du
# code que personne n'a demandé.
install -d "$essai/CONTROLE"
dpkg-deb --control "$paquet" "$essai/CONTROLE"
for script in preinst postinst prerm postrm config triggers; do
    [ -e "$essai/CONTROLE/$script" ] \
        && rate "le paquet porte un \`$script\` — un outil d'utilisateur n'en a pas besoin"
done
conclure "control seul"

titre "6. ce qu'on déballe s'exécute, et connaît la SOURCE"
commencer
# UN PAQUET QUI S'INSTALLE ET DONT LE BINAIRE NE PART PAS n'a rien installé.
# Qu'il parte prouve aussi qu'il est de l'architecture de cette machine.
if ! "$essai/deballe/usr/bin/asl" --version > "$essai/version" 2>&1; then
    rate "\`asl --version\` échoue :
$(cat "$essai/version")"
fi
grep -q "^asl $version " "$essai/version" \
    || rate "\`asl --version\` dit « $(cat "$essai/version") », et non asl $version"
if ! "$essai/deballe/usr/bin/asl" --help > "$essai/aide" 2>&1; then
    rate "\`asl --help\` échoue :
$(cat "$essai/aide")"
fi
# **CE QUI COMPTE N'EST PAS QU'IL SOIT IDENTIQUE À `target/release`** — il l'est
# par construction. Ce qui compte est qu'il corresponde à la SOURCE : un binaire
# vieux de quelques heures s'exécute très bien et ignore les options et les
# commandes ajoutées depuis. On confronte donc les bras de `match` de
# l'analyseur à son aide — sauf ceux d'une option RETIRÉE, que l'aide ne
# montre plus, et c'est voulu.
#
# **L'AIDE SE LIT UNE FOIS** : un `--help | grep -q` par mot est une course au
# `SIGPIPE`, qui rend un faux échec sous charge.
analyseur=crates/asl-cli/src/arguments.rs
for drapeau in $(grep -E '"--[a-z]+"( \| "--[a-z]+")* =>' "$analyseur" \
        | grep -v 'OptionRetiree' | grep -oE '"--[a-z]+"' | tr -d '"'); do
    grep -qF -- "$drapeau" "$essai/aide" \
        || rate "le binaire empaqueté ignore $drapeau, que la source connaît"
done
for verbe in $(grep -oE '^ +"[a-z]+" =>' "$analyseur" | grep -oE '[a-z]+'); do
    grep -qwF -- "$verbe" "$essai/aide" \
        || rate "le binaire empaqueté ignore la commande $verbe, que la source connaît"
done
conclure "$(head -1 "$essai/version") — son aide dit tout ce que la source lit"

if [ "$fautes" -ne 0 ]; then
    printf '\nÉCHEC : %s contrôle(s) du paquet n'"'"'ont pas passé.\n' "$fautes" >&2
    exit 1
fi
printf '\nOK : le paquet pose un binaire qui part et sa licence, rien d'"'"'autre,\n'
printf '     et rien ne s'"'"'exécute en root à son installation.\n'
