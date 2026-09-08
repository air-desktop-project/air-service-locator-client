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
# # CE QUE CE CONTRÔLE N'EST PAS
#
# **Il ne juge pas les SIGNATURES.** Changer un `int32_t` en `int64_t` sans
# renommer la fonction casse les cinq liaisons sans que ce script bronche. C'est
# une limite réelle, et le jour où la première fonction existera il faudra soit
# un en-tête committé en plus, soit la discipline de renommer ce qu'on change.

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

echo "exportés par le binaire : $nb_actuel"
echo "inscrits au registre    : $nb_attendu"
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

if [ "$violations" -gt 0 ]; then
    echo "ÉCHEC : la surface exportée et le registre divergent."
    exit 1
fi

echo "OK : $nb_actuel symbole(s) exporté(s), tous au registre."
