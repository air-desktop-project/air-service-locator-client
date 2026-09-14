#!/usr/bin/env bash
#
# check-version — chaque PR change la version, et toutes les crates la partagent.
#
# # LA RÈGLE, ET POURQUOI ELLE EST TENUE PAR UNE BARRIÈRE
#
# « Chaque PR change la version semver (MAJOR.MINOR.PATCH) de l'application,
# dans le commit qui porte le changement ; une PR qui ne change pas la version
# ne se merge pas. » (`CLAUDE.md`)
#
# Une version qui ne bouge pas ne nomme rien : deux bancs qui disent tous deux
# « 0.1.0 » peuvent servir deux protocoles, et l'on en est réduit à s'échanger
# des SHA. La règle vaut pour TOUTE PR, documentation comprise — un lecteur qui
# tient une version doit pouvoir retrouver ce qu'elle décrit, et une règle
# avec des exceptions est une règle qu'on discute à chaque PR.
#
# # CE QUE LE GATE VÉRIFIE
#
#   VIOLATION  la version n'est pas un semver `MAJOR.MINOR.PATCH[-pré]`
#   VIOLATION  une crate interne est déclarée à une autre version (lockstep)
#   VIOLATION  un verrou (`Cargo.lock`, `fuzz/Cargo.lock`) porte une autre
#              version pour une crate interne
#   VIOLATION  la version est celle de la base (la PR n'a pas bumpé)
#   VIOLATION  la version est INFÉRIEURE à celle de la base
#
# Les trois premières se vérifient sans git : elles tiennent sur l'arbre. Les
# deux dernières comparent à une BASE — `origin/main` par défaut, comme
# `check-dco` —, et sont sautées, EN LE DISANT, quand il n'y a rien à comparer :
# sur `main` même, ou dans un dépôt sans base.
#
# # CE QU'IL NE VÉRIFIE PAS
#
# Que le bump soit du BON cran — patch, mineur, majeur. C'est un jugement sur le
# changement, et un script qui le rendrait se tromperait dans les deux sens.
# La revue le porte.
#
# # IL TOURNE AUSSI SUR macOS, ET CELA SE VOIT DANS SA SYNTAXE
#
# Le `sed` des BSD veut un `;` avant `}`, ne connaît ni `\?` ni `\s` ; le
# `bash` livré avec macOS est un 3.2 sans `mapfile` ni tableaux associatifs ;
# et `sort -V` n'y est pas promis. Rien ici n'emploie ces commodités, et la
# comparaison de deux versions se fait à la main, champ par champ.
#
# Usage : scripts/check-version.sh [base]

set -euo pipefail

cd "$(dirname "$0")/.."

echo 'check-version — chaque PR change la version, et toutes les crates la partagent'
echo

violations=0

# ── La version du workspace ──────────────────────────────────────────────────

version_du_manifeste() {
    sed -n '/^\[workspace\.package\]/,/^\[/{s/^version = "\(.*\)"$/\1/p;}' "$1" | head -1
}

# `a` est-elle STRICTEMENT inférieure à `b` ? Semver, sans `sort -V` : les trois
# nombres d'abord ; à nombres égaux, une pré-version passe avant la version
# pleine, et deux pré-versions se comparent en texte.
inferieure() {
    local a="$1" b="$2" na nb pa pb i
    na="${a%%-*}"; nb="${b%%-*}"
    pa=""; pb=""
    [ "$na" != "$a" ] && pa="${a#*-}"
    [ "$nb" != "$b" ] && pb="${b#*-}"
    for i in 1 2 3; do
        local ca cb
        ca=$(printf '%s' "$na" | cut -d. -f"$i")
        cb=$(printf '%s' "$nb" | cut -d. -f"$i")
        [ "$ca" -lt "$cb" ] && return 0
        [ "$ca" -gt "$cb" ] && return 1
    done
    [ -n "$pa" ] && [ -z "$pb" ] && return 0
    [ -z "$pa" ] && [ -n "$pb" ] && return 1
    [ "$pa" \< "$pb" ]
}

version=$(version_du_manifeste Cargo.toml)
if [ -z "$version" ]; then
    echo "VIOLATION  \`[workspace.package] version\` est introuvable dans Cargo.toml"
    exit 1
fi
echo "version           : $version"

if ! [[ "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$ ]]; then
    echo "VIOLATION  « $version » n'est pas un semver MAJOR.MINOR.PATCH[-pré]"
    violations=$((violations + 1))
fi

# ── Le lockstep : les crates du workspace, dans le manifeste et les verrous ──

# **LES CRATES INTERNES SONT LES MEMBRES DU WORKSPACE**, lus dans `members`,
# et non « tout ce qui s'appelle `asl-*` » : le dépôt client tire par `git` des
# crates `asl-*` du serveur, qui portent la version DU SERVEUR, et un contrôle
# par le nom les accuserait à tort.
membres=()
while IFS= read -r membre; do
    membres+=("$membre")
done < <(sed -n '/^members = \[/,/^\]/{s/^[[:space:]]*"\([^"]*\)",\{0,1\}$/\1/p;}' Cargo.toml)
if [ "${#membres[@]}" -eq 0 ]; then
    echo "VIOLATION  \`[workspace] members\` est introuvable dans Cargo.toml"
    exit 1
fi
internes=()
for membre in "${membres[@]}"; do
    nom=$(sed -n 's/^name = "\(.*\)"$/\1/p' "$membre/Cargo.toml" | head -1)
    internes+=("$nom")
    # Chaque membre prend la version du workspace, et n'en déclare pas une à lui.
    if ! grep -q '^version\.workspace = true$' "$membre/Cargo.toml"; then
        echo "VIOLATION  $nom ($membre) ne prend pas \`version.workspace = true\`"
        violations=$((violations + 1))
    fi
done
echo "crates internes   : ${internes[*]}"

# Chaque arête interne de `[workspace.dependencies]` répète la version : c'est
# cette valeur qu'un consommateur externe lit.
for nom in "${internes[@]}"; do
    while IFS= read -r ligne; do
        declaree=$(printf '%s' "$ligne" | sed -n 's/.*version = "\([^"]*\)".*/\1/p')
        if [ -n "$declaree" ] && [ "$declaree" != "$version" ]; then
            echo "VIOLATION  $nom est déclarée en $declaree dans Cargo.toml, et non $version"
            violations=$((violations + 1))
        fi
    done < <(grep -E "^$nom = \{ path = " Cargo.toml || true)
done

# Les verrous : une crate interne figée à une autre version est un verrou qu'on
# a oublié de rafraîchir, et `--locked` le refusera de toute façon — autant le
# dire ici, en nommant la crate.
for verrou in Cargo.lock fuzz/Cargo.lock; do
    [ -f "$verrou" ] || continue
    for nom in "${internes[@]}"; do
        while IFS= read -r figee; do
            echo "VIOLATION  $verrou fige $nom en $figee, et non $version"
            violations=$((violations + 1))
        done < <(awk -v v="$version" -v n="name = \"$nom\"" '
            $0 == n        { interne = 1; next }
            /^name = /     { interne = 0; next }
            interne && /^version = / {
                gsub(/^version = "|"$/, "")
                if ($0 != v) print $0
                interne = 0
            }' "$verrou")
    done
done

# ── Les liaisons, quand le dépôt en porte ────────────────────────────────────
#
# Le dépôt client publie la même bibliothèque à quatre écosystèmes, et chacun
# a sa propre place pour écrire une version. Elles disent toutes celle du
# workspace, sinon un paquet Python ou une gemme porterait un numéro qu'aucun
# commit ne nomme. Le dépôt serveur n'en a pas : ce bloc n'y fait rien.
# Deux listes parallèles plutôt qu'un tableau associatif : le bash 3.2 de
# macOS n'en a pas.
liaisons_fichiers=(
    liaisons/python/pyproject.toml
    liaisons/ruby/asl.gemspec
    liaisons/kotlin/build.gradle.kts
    liaisons/cpp/CMakeLists.txt
)
liaisons_motifs=(
    '^version = "\(.*\)"$'
    '^[[:space:]]*gemme\.version = "\(.*\)"$'
    '^version = "\(.*\)"$'
    '^project(.* VERSION \([0-9.]*\))$'
)
for i in "${!liaisons_fichiers[@]}"; do
    fichier="${liaisons_fichiers[$i]}"
    [ -f "$fichier" ] || continue
    lue=$(sed -n "s/${liaisons_motifs[$i]}/\1/p" "$fichier" | head -1)
    if [ "$lue" != "$version" ]; then
        echo "VIOLATION  $fichier dit « ${lue:-rien} », et non $version"
        violations=$((violations + 1))
    fi
done

# ── La comparaison à la base ─────────────────────────────────────────────────

resoudre_base() {
    if [ $# -ge 1 ] && [ -n "$1" ]; then
        printf '%s\n' "$1"
        return 0
    fi
    for candidat in origin/main main; do
        if git rev-parse --verify --quiet "$candidat" >/dev/null 2>&1; then
            printf '%s\n' "$candidat"
            return 0
        fi
    done
    return 1
}

if ! git rev-parse --verify --quiet HEAD >/dev/null 2>&1; then
    echo "base              : (pas un dépôt git — RIEN n'a été comparé)"
elif ! base=$(resoudre_base "${1-}"); then
    echo "base              : (aucune — RIEN n'a été comparé)"
elif [ "$(git rev-parse "$base")" = "$(git rev-parse HEAD)" ] \
    || git merge-base --is-ancestor HEAD "$base" 2>/dev/null; then
    # Sur la base elle-même, ou derrière elle : il n'y a pas de PR à juger.
    echo "base              : $base — HEAD en fait partie, rien à comparer"
else
    ancienne=$(git show "$base:Cargo.toml" 2>/dev/null | version_du_manifeste /dev/stdin || true)
    echo "base              : $base ($ancienne)"
    if [ -z "$ancienne" ]; then
        echo "SIGNALEMENT la base n'a pas de version lisible — comparaison impossible"
    elif [ "$ancienne" = "$version" ]; then
        echo "VIOLATION  la version n'a pas changé depuis $base : une PR qui ne change"
        echo "           pas la version ne se merge pas (bump dans \`[workspace.package]\`)"
        violations=$((violations + 1))
    elif inferieure "$version" "$ancienne"; then
        echo "VIOLATION  $version est INFÉRIEURE à $ancienne, la version de $base"
        violations=$((violations + 1))
    else
        echo "bump              : $ancienne → $version"
    fi
fi

echo
if [ "$violations" -gt 0 ]; then
    echo "ÉCHEC : $violations violation(s)."
    exit 1
fi
echo "OK : la version $version est un semver, partagée par toutes les crates."
