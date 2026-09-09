#!/usr/bin/env bash
#
# check-fuzz — les cibles existent, se décrivent, se formatent et compilent ;
#              et avec `--smoke`, chacune tourne quelques secondes. (C3)
#
# # POURQUOI CE SCRIPT EXISTE
#
# La crate de fuzz vit HORS DU WORKSPACE (voir `fuzz/Cargo.toml`). La conséquence
# tient en une phrase : **`cargo build --workspace` ne la touche pas.** Une cible
# qui cesse de compiler ne se voit ni au build, ni aux essais, ni au clippy.
#
# Sur `air-mail-server`, c'est arrivé DEUX FOIS, les deux fois en changeant un
# trait que les cibles implémentent — et la première fois, la cible était en
# outre absente de la liste du smoke-test, si bien qu'elle ne compilait plus
# depuis deux commits sans que rien ne le dise.
#
# # CE QU'IL VÉRIFIE
#
#   1. La LISTE ci-dessous coïncide avec les `[[bin]]` de `fuzz/Cargo.toml`.
#      Une cible ajoutée sans être inscrite ici ne serait jamais lancée, et le
#      gate resterait vert en ne l'ayant pas examinée.
#   2. Le TABLEAU de `fuzz/README.md` décrit exactement ces cibles-là. Une cible
#      qu'aucune ligne ne décrit est une cible que personne ne sait lire.
#   3. Les GRAINES sont NOMMÉES POUR CE QU'ELLES ÉPROUVENT. Un fichier dont le
#      nom est quarante caractères hexadécimaux est une trouvaille brute de
#      libFuzzer — son nom est le SHA-1 de son contenu — et sa place est
#      `corpus/`, pas `seeds/`.
#
#      **Cela n'interdit PAS de garder une trouvaille** : une entrée qui a fait
#      tomber une cible mérite d'être conservée pour qu'elle ne repasse jamais.
#      Ce qui est exigé est de la RENOMMER pour ce qu'elle prouve — un SHA-1
#      n'apprend rien à qui lira ce répertoire dans six mois.
#   4. Avec `--smoke`, chacune tourne quelques secondes sur ses graines.
#
# **IL NE VÉRIFIE NI LE FORMATAGE NI LA COMPILATION**, et ce n'est pas un oubli :
# `check-format.sh` et `check-compile.sh` couvrent tous deux les DEUX portées,
# workspace et `fuzz/`. Deux endroits qui disent la même chose finissent par
# diverger, et c'est le second — celui qu'on oublie — qui diverge.
#
# # LA LISTE VIT ICI, ET NON DANS LE WORKFLOW
#
# La CI appelle ce script. On peut donc lancer en local EXACTEMENT ce qu'elle
# lancera — un contrôle qu'on ne peut pas rejouer chez soi est un contrôle qu'on
# découvre après un `push`.
#
# Et les MÊMES DRAPEAUX : le workflow pose `RUSTFLAGS: -D warnings`. Sans cela,
# un `unused import` dans une cible passerait en local et échouerait après la
# poussée — ce serait le même script, et pas la même épreuve.
#
# # LA CIBLE DE COMPILATION EST NOMMÉE, JAMAIS LAISSÉE AU DÉFAUT
#
# `cargo-fuzz` 0.13.1 choisit `x86_64-unknown-linux-gnu` ; 0.13.2 choisit musl,
# dont la libc statique est INCOMPATIBLE avec le sanitizer. Le job passait en
# local et échouait en CI, à la seule faveur d'un écart de version de l'outil.
#
# # PENDANT QU'UNE CAMPAGNE TOURNE, NE PAS TOUCHER AU DÉPÔT
#
# Les binaires instrumentés sont construits, puis exécutés. Éditer un fichier
# entre les deux ne corrompt rien — mais **la campagne ne vaut alors que pour
# l'état construit**, pas pour ce qu'on écrit pendant. Vérifier ce qu'elle a
# réellement éprouvé avant de s'en réclamer dans un message de commit.

set -euo pipefail

# Les mêmes que le workflow, pour que l'épreuve locale soit celle de la CI.
export RUSTFLAGS="${RUSTFLAGS:--D warnings}"

# `cargo-fuzz` 0.13.2 choisit musl par défaut, incompatible avec le sanitizer.
CIBLE_DE_COMPILATION="x86_64-unknown-linux-gnu"

smoke=0
case "${1-}" in
    --smoke) smoke=1 ;;
    "") ;;
    *)
        echo "usage : $(basename "$0") [--smoke]" >&2
        exit 2
        ;;
esac
secondes="${ASL_FUZZ_SECONDES-10}"

racine=$(cd "$(dirname "$0")/.." && pwd)
cd "$racine/fuzz"

# <cible> <répertoire de graines>
CIBLES=$(cat <<'TABLE'
fuzz_asl_client_reprise reprise
TABLE
)

echo 'check-fuzz — les cibles de fuzz (C3)'
echo

violations=0
noms=$(printf '%s\n' "$CIBLES" | awk '{print $1}' | sort)

# ── 1. La liste coïncide avec les `[[bin]]` du manifeste ────────────────────
declares=$(grep -A1 '^\[\[bin\]\]' Cargo.toml | sed -n 's/^name = "\(.*\)"/\1/p' | sort)
if [ "$noms" != "$declares" ]; then
    echo "VIOLATION  la liste de ce script et les [[bin]] de fuzz/Cargo.toml diffèrent :"
    diff <(printf '%s\n' "$noms") <(printf '%s\n' "$declares") | sed 's/^/           /' || true
    violations=$((violations + 1))
fi

# ── 2. Le README décrit exactement ces cibles ───────────────────────────────
while read -r cible _; do
    if ! grep -q "\`$cible\`" README.md; then
        echo "VIOLATION  $cible n'est décrite par aucune ligne de fuzz/README.md"
        violations=$((violations + 1))
    fi
done <<< "$CIBLES"

# ── 3. Les graines sont écrites à la main ───────────────────────────────────
graines=0
while IFS= read -r graine; do
    graines=$((graines + 1))
    nom=$(basename "$graine")
    if printf '%s' "$nom" | grep -qE '^[0-9a-f]{40}$'; then
        echo "VIOLATION  seeds/$nom est une trouvaille de libFuzzer (SHA-1)"
        echo "           sa place est corpus/, pas seeds/"
        violations=$((violations + 1))
    fi
done < <(find seeds -type f)

if [ "$graines" -eq 0 ]; then
    echo "VIOLATION  aucune graine — une campagne repartirait de zéro à chaque fois"
    violations=$((violations + 1))
fi
echo "graines : $graines"

if [ "$violations" -gt 0 ]; then
    echo
    echo "ÉCHEC : $violations violation(s)."
    exit 1
fi

if [ "$smoke" -eq 0 ]; then
    echo
    echo "OK : les cibles existent, sont décrites, et leurs graines sont nommées"
    # UNE APOSTROPHE FRANÇAISE DANS UNE CHAÎNE SHELL EST UN PIÈGE, et c'est la
    # deuxième fois qu'il se referme sur ce dépôt : `check-couverture.sh` avait
    # déjà été coupé en deux au milieu d'une ligne par « rien n'a été mesuré ».
    # La règle qui l'évite : PAS D'APOSTROPHE dans un `echo`, ou une chaîne
    # entre guillemets doubles où l'apostrophe ne signifie rien.
    echo "     pour ce que chacune éprouve. (\`--smoke\` pour les faire tourner)"
    exit 0
fi

# ── 5. Le smoke-test ────────────────────────────────────────────────────────
#
# CE N'EST PAS UNE CAMPAGNE. Quelques secondes par cible depuis un corpus neuf
# n'explorent pas ce que des heures explorent : cela attrape la panique qu'un
# changement vient d'introduire sur un chemin déjà connu, et rien de plus.
if ! command -v cargo-fuzz >/dev/null 2>&1; then
    echo "ÉCHEC : \`cargo-fuzz\` est absent — aucune cible n'a TOURNÉ."
    exit 1
fi

echo
while read -r cible graines_de_la_cible; do
    echo "═══ $cible ($secondes s, graines : seeds/$graines_de_la_cible)"
    # libFuzzer EXIGE que le premier répertoire de corpus existe : il n'y écrit
    # que s'il peut l'ouvrir, et refuse de démarrer sinon. `cargo-fuzz` ne le
    # crée que lorsqu'on ne lui en nomme aucun.
    mkdir -p "corpus/$cible"
    # `< /dev/null` N'EST PAS DU ZÈLE. L'entrée de cette boucle est la table des
    # cibles ; une commande qui lirait l'entrée standard en avalerait le reste,
    # et la boucle s'arrêterait après la première cible — en rendant un OK, parce
    # qu'aucune des suivantes n'aurait échoué. Un gate qui n'examine qu'une cible
    # sur deux et se déclare vert est exactement ce qu'on cherche à éviter.
    if ! cargo fuzz run "$cible" \
        --target "$CIBLE_DE_COMPILATION" \
        "corpus/$cible" "seeds/$graines_de_la_cible" \
        -- -max_total_time="$secondes" < /dev/null; then
        echo "─── $cible : ÉCHEC"
        violations=$((violations + 1))
    else
        echo "─── $cible : OK"
    fi
done <<< "$CIBLES"

echo
if [ "$violations" -gt 0 ]; then
    echo "ÉCHEC : $violations cible(s) ont trouvé quelque chose ou n'ont pas tourné."
    echo "        L'entrée fautive est dans fuzz/artifacts/."
    exit 1
fi

echo "OK : toutes les cibles ont tourné $secondes s sans rien trouver."
echo "     Ce n'est PAS une campagne — voir fuzz/README.md."
