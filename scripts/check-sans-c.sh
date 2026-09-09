#!/usr/bin/env bash
#
# check-sans-c — rien de ce dépôt ne compile ni ne lie du C. (C4)
#
# # POURQUOI CETTE BARRIÈRE, ET POURQUOI MAINTENANT
#
# Elle n'avait rien à examiner tant que le graphe ne contenait que nos crates.
# **`ed25519-dalek` y est entrée** par `asl-cle`, avec ses dépendances
# transitives — c'est le moment où la règle cesse d'être une intention.
#
# **ELLE COMPTE DAVANTAGE ICI QUE DANS LE DÉPÔT SERVEUR.** Là-bas, une crate qui
# lierait du C s'exécuterait sur nos machines ; ici, elle serait chargée dans le
# processus de quelqu'un d'autre.
#
# La règle est STRUCTURELLE pour `asl-client` : cette bibliothèque est chargée
# dans des processus qui ne sont pas les nôtres — un interpréteur Python, une
# JVM. Une crate qui lierait sa propre libcrypto entrerait en conflit avec celle
# du processus hôte, et ce genre de panne se diagnostique en jours.
#
# # TROIS CONTRÔLES, ET LE TROISIÈME EST LE SEUL QUI REGARDE LA RÉALITÉ
#
#   1. Aucune crate `*-sys` dans le graphe résolu. Par convention, ce suffixe
#      désigne une liaison vers une bibliothèque système.
#   2. Ni `cc`, ni `bindgen`, ni `pkg-config`. Leur présence signifie qu'un
#      script de construction compile ou cherche du C.
#   3. **Aucun objet compilé dans la sortie d'un script de construction.** Les
#      deux premiers lisent des NOMS ; celui-ci regarde ce que la compilation a
#      réellement fait. Une crate qui compilerait du C sans porter `-sys` dans
#      son nom n'est attrapée que par lui.
#
# **LE TROISIÈME NE CHERCHE QUE DANS `target/*/build/*/out/`, ET C'EST ESSENTIEL.**
# Une première version balayait tout `target/` : elle a trouvé des centaines de
# `.o` sous `target/debug/incremental/` et déclaré une violation. Ce sont les
# objets de la compilation incrémentale de RUSTC, pas ceux d'un compilateur C.
#
# Un contrôle qui accuse le compilateur du langage qu'il protège est pire
# qu'absent : on apprend à ignorer son verdict.
#
# # `libc` EST ADMISE, ET IL FAUT DIRE POURQUOI
#
# Elle ne contient pas une ligne de C : ce sont des DÉCLARATIONS de l'ABI de la
# libc du système, que tout programme Rust utilise déjà par sa bibliothèque
# standard. Elle n'embarque aucune implémentation, et ne peut donc entrer en
# conflit avec rien.
#
# Elle arrive ici par `cpufeatures`, que `sha2` emploie pour choisir son chemin
# selon le processeur.

set -euo pipefail

cd "$(dirname "$0")/.."

# Ce qui est admis malgré un nom ou une nature qui pourraient inquiéter.
ADMISES=(libc)

echo 'check-sans-c — rien ne compile ni ne lie du C (C4)'
echo

if ! metadata=$(cargo metadata --format-version 1 --locked 2>/dev/null); then
    echo "ÉCHEC : \`cargo metadata\` n'a pas répondu."
    exit 1
fi

paquets=$(printf '%s' "$metadata" | python3 -c '
import json, sys
donnees = json.load(sys.stdin)
for nom in sorted({paquet["name"] for paquet in donnees["packages"]}):
    print(nom)
')

nombre=$(printf '%s\n' "$paquets" | grep -c . || true)
tierces=$(printf '%s\n' "$paquets" | grep -vE '^asl-' || true)
nombre_tierces=$(printf '%s\n' "$tierces" | grep -c . || true)
echo "paquets dans le graphe : $nombre"
echo "dont tierces           : $nombre_tierces"
echo

violations=0

# ── 1 et 2 : les noms ────────────────────────────────────────────────────────
for paquet in $paquets; do
    admise=0
    for exception in "${ADMISES[@]}"; do
        [ "$paquet" = "$exception" ] && admise=1
    done
    [ "$admise" -eq 1 ] && continue

    case "$paquet" in
        *-sys)
            echo "VIOLATION  $paquet — une crate \`-sys\` lie une bibliothèque système"
            violations=$((violations + 1))
            ;;
        cc | bindgen | pkg-config | cmake)
            echo "VIOLATION  $paquet — sa présence signifie qu'un script compile du C"
            violations=$((violations + 1))
            ;;
        *) ;;
    esac
done

# ── 3 : ce que la compilation a RÉELLEMENT produit ───────────────────────────
#
# APRÈS une construction, et pas avant : un `target/` vide ne dirait rien.
echo "construction, puis inspection des artefacts…"
cargo build --workspace --locked --quiet

# `cc` dépose ses objets et ses archives dans le `OUT_DIR` du script de
# construction, et nulle part ailleurs. C'est donc là, et seulement là, qu'on
# regarde.
objets=$(find target -path '*/build/*/out/*' \( -name '*.o' -o -name '*.a' \) -type f 2>/dev/null | head -20 || true)
if [ -n "$objets" ]; then
    echo "VIOLATION  des objets compilés par un script de construction :"
    printf '%s\n' "$objets" | sed 's/^/           /'
    violations=$((violations + 1))
else
    echo "aucun objet dans la sortie d'un script de construction"
fi

echo
if [ "$nombre_tierces" -eq 0 ]; then
    echo "Aucune crate tierce dans le graphe — RIEN n'a été examiné."
    exit 0
fi

if [ "$violations" -gt 0 ]; then
    echo "ÉCHEC : $violations violation(s) de C4."
    exit 1
fi

echo "OK : $nombre_tierces crates tierces, aucune ne compile ni ne lie du C."
