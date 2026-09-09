#!/usr/bin/env bash
#
# check-abi — la surface exportée n'a rien perdu depuis le dernier commit. (C12)
#
# # CE QUE CETTE BARRIÈRE PROTÈGE
#
# `asl-client-ffi` est le passage par lequel entrent CINQ liaisons — Python,
# Ruby, C++, Kotlin, Swift. Elles ne se mettent pas à jour au même rythme, et
# elles vivent dans du code que nous ne voyons pas.
#
# **Un ajout est libre ; c'est le RETRAIT qui casse.** Ajouter une fonction ne
# gêne personne ; en retirer une casse du code chez des gens qu'on ne peut ni
# prévenir ni corriger.
#
# # POURQUOI LES SYMBOLES DU BINAIRE, ET PAS L'EN-TÊTE GÉNÉRÉ
#
# On pourrait comparer un en-tête C produit par `cbindgen`. On compare le
# BINAIRE, et c'est plus fort : un en-tête décrit ce que le code prétend
# exporter, `nm` dit ce qu'il exporte VRAIMENT. Un `#[no_mangle]` oublié, un
# `crate-type` mal formé, une fonction rendue conditionnelle par une feature —
# rien de tout cela ne se voit dans un en-tête, et tout se voit ici.
#
# C'est aussi ce qui évite d'imposer `cbindgen` au graphe de dépendances pour
# rendre un service que `nm` rend déjà.
#
# # TROIS SOURCES, ET ELLES DOIVENT DIRE LA MÊME CHOSE
#
# Le binaire dit ce qui est exporté. `abi.txt` dit ce qu'on s'est engagé à
# exporter. `include/asl.h` dit ce que les cinq liaisons compilent. **Deux
# suffiraient à se contredire sans que personne s'en aperçoive** : un symbole
# exporté qu'aucun en-tête ne déclare n'est atteignable par personne, et une
# déclaration sans symbole derrière est une erreur d'édition de liens chez le
# consommateur, jamais chez nous.
#
# # CE QUE CE CONTRÔLE N'EST TOUJOURS PAS
#
# **Il ne juge pas le TYPE des arguments.** Changer un `int32_t` en `int64_t`
# dans l'en-tête ET dans le code Rust, sans renommer la fonction, casse les cinq
# liaisons sans que ce script bronche. Ce qui l'attrape est ailleurs : les
# tailles des structures sont vérifiées à la compilation (`const _: () =
# assert!`), et les constantes de l'en-tête sont comparées aux constantes Rust
# par un essai. Le type des paramètres, lui, reste tenu par la discipline de
# renommer ce qu'on change.

set -euo pipefail

cd "$(dirname "$0")/.."

registre="crates/asl-client-ffi/abi.txt"
prefixe="asl_"

echo 'check-abi — la surface exportée n'"'"'a rien perdu (C12)'
echo

if ! command -v nm >/dev/null 2>&1; then
    echo "ÉCHEC : \`nm\` est absent — le contrôle ne peut RIEN examiner."
    echo "        (binutils ; ce script suppose un environnement ELF)"
    exit 1
fi

echo "construction de la bibliothèque partagée…"
cargo build --workspace --locked --quiet

objet=$(find target/debug -maxdepth 1 -name 'libasl_client_ffi.so' | head -1)
if [ -z "$objet" ]; then
    echo "ÉCHEC : \`libasl_client_ffi.so\` est introuvable après construction."
    echo "        Le \`crate-type\` de la crate a-t-il changé ?"
    exit 1
fi

# `-D` : symboles dynamiques. `--defined-only` : ce que CETTE bibliothèque
# fournit, et non ce qu'elle réclame à d'autres.
actuel=$(nm -D --defined-only "$objet" 2>/dev/null \
    | awk '{print $3}' \
    | grep -E "^${prefixe}" \
    | sort -u || true)

if [ ! -f "$registre" ]; then
    echo "ÉCHEC : $registre est absent."
    echo "        Ce fichier EST le contrat. Sans lui, rien ne peut être comparé."
    exit 1
fi

# Les commentaires du registre commencent par `#`.
attendu=$(grep -vE '^\s*(#|$)' "$registre" | sort -u || true)

nb_actuel=$(printf '%s\n' "$actuel" | grep -c . || true)
nb_attendu=$(printf '%s\n' "$attendu" | grep -c . || true)

# Les fonctions déclarées dans l'en-tête : ce que les cinq liaisons compilent.
entete="crates/asl-client-ffi/include/asl.h"
if [ ! -f "$entete" ]; then
    echo "ÉCHEC : $entete est absent."
    echo "        L'en-tête EST le contrat, au même titre que le registre."
    exit 1
fi
declares=$(grep -oE "\\b${prefixe}[a-z0-9_]+\\s*\\(" "$entete" \
    | sed -E "s/[[:space:]]*\\(\$//" \
    | sort -u || true)
nb_declares=$(printf '%s\n' "$declares" | grep -c . || true)

echo "exportés par le binaire : $nb_actuel"
echo "inscrits au registre    : $nb_attendu"
echo "déclarés dans l'en-tête : $nb_declares"
echo

# UN REGISTRE VIDE COMPARÉ À UNE SURFACE VIDE N'ATTESTE DE RIEN, ET ON LE DIT.
if [ "$nb_actuel" -eq 0 ] && [ "$nb_attendu" -eq 0 ]; then
    echo "Aucune fonction exportée — RIEN n'a été comparé."
    echo "(vrai tant que \`asl-client-ffi\` est vide ; ce ne le restera pas)"
    exit 0
fi

retires=$(comm -13 <(printf '%s\n' "$actuel") <(printf '%s\n' "$attendu") | grep -v '^$' || true)
ajoutes=$(comm -23 <(printf '%s\n' "$actuel") <(printf '%s\n' "$attendu") | grep -v '^$' || true)

violations=0

if [ -n "$retires" ]; then
    echo "RETRAIT — RUPTURE MAJEURE. Ces symboles étaient au registre et ont disparu :"
    printf '  %s\n' $retires
    echo
    echo "  Chacun casse du code chez des gens qu'on ne peut ni prévenir ni corriger,"
    echo "  dans cinq écosystèmes qui ne se mettent pas à jour au même rythme."
    echo "  Si le retrait est VOULU, il appartient à une version majeure, et le"
    echo "  registre se met à jour dans le MÊME commit, avec la raison en message."
    violations=$((violations + 1))
fi

if [ -n "$ajoutes" ]; then
    echo "AJOUT — libre, mais à consigner. Ces symboles ne sont pas au registre :"
    printf '  %s\n' $ajoutes
    echo
    echo "  Ajouter une fonction est une décision LIBRE ; ce qui est exigé est de"
    echo "  l'inscrire. Un registre en retard ne protège plus rien : c'est lui qui"
    echo "  dira, dans six mois, ce qui existait."
    echo "  Ajoutez-les à $registre."
    violations=$((violations + 1))
fi

# ── L'EN-TÊTE, TROISIÈME VOIX ───────────────────────────────────────────────
sans_entete=$(comm -23 <(printf '%s\n' "$attendu") <(printf '%s\n' "$declares") | grep -v '^$' || true)
sans_registre=$(comm -13 <(printf '%s\n' "$attendu") <(printf '%s\n' "$declares") | grep -v '^$' || true)

if [ -n "$sans_entete" ]; then
    echo "INATTEIGNABLE — au registre, mais absents de l'en-tête :"
    printf '  %s\n' $sans_entete
    echo
    echo "  Un symbole qu'aucun en-tête ne déclare n'est atteignable par personne."
    echo "  Déclarez-les dans $entete."
    violations=$((violations + 1))
fi

if [ -n "$sans_registre" ]; then
    echo "PROMESSE SANS SYMBOLE — déclarés dans l'en-tête, absents du registre :"
    printf '  %s\n' $sans_registre
    echo
    echo "  Une déclaration sans symbole derrière est une erreur d'édition de liens"
    echo "  chez le consommateur, jamais chez nous — c'est-à-dire au pire endroit."
    violations=$((violations + 1))
fi

if [ "$violations" -gt 0 ]; then
    echo "ÉCHEC : le binaire, le registre et l'en-tête ne disent pas la même chose."
    exit 1
fi

echo "OK : $nb_actuel symbole(s) exporté(s), tous au registre et tous déclarés."
