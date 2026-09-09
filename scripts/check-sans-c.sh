#!/usr/bin/env bash
#
# check-sans-c — aucune crate tierce ne compile ni ne lie du C. (C4)
#
# # CE SCRIPT EST UNE COPIE DE CELUI DU DÉPÔT SERVEUR, ET ELLE AVAIT DIVERGÉ
#
# La copie d'ici lisait le graphe RÉSOLU, alors que celle de là-bas avait été
# corrigée pour lire le graphe CONSTRUIT. **Elle a donc crié au loup** dès que la
# pile QUIC est entrée : `cc`, tiré par un `ring` que rien n'active, et
# `windows-sys`, conditionné à une plateforme qui n'est pas la nôtre.
#
# `check-pile.sh` dit la règle en tête : « Toute correction faite là-bas doit
# être reportée ici. » C'est ce report-ci.
#
# # POURQUOI CETTE BARRIÈRE, ET POURQUOI MAINTENANT
#
# Elle n'avait rien à examiner tant que le graphe ne contenait que nos crates.
# `ed25519-dalek` y est entrée d'abord, puis **la pile QUIC et HTTP/3** — c'est
# le moment où la règle cesse d'être une intention.
#
# **ELLE COMPTE DAVANTAGE ICI QUE DANS LE DÉPÔT SERVEUR.** Là-bas, une crate qui
# lierait du C s'exécuterait sur nos machines. Ici, la règle est STRUCTURELLE :
# cette bibliothèque est chargée dans des processus qui ne sont pas les nôtres —
# un interpréteur Python, une JVM. Une crate qui lierait sa propre libcrypto
# entrerait en conflit avec celle du processus hôte, et ce genre de panne se
# diagnostique en jours.
#
# # IL LIT LE GRAPHE CONSTRUIT, PAS LE GRAPHE RÉSOLU — ET C'EST TOUTE LA QUESTION
#
# `cargo metadata` rend le RÉSOLU : tout ce que cargo a dû considérer pour
# choisir des versions. Cela inclut les dépendances OPTIONNELLES dont la
# fonctionnalité n'est pas activée, celles réservées à une autre plateforme, et
# les dépendances de développement.
#
# **Rien de tout cela n'est compilé, et rien de tout cela n'est livré.**
#
# La greffe de la pile QUIC l'a rendu manifeste. `rustls` déclare `ring` en
# dépendance optionnelle — nous ne l'activons pas, puisque le fournisseur retenu
# est `rustls-rustcrypto`, en Rust pur. Mais `ring` reste dans le résolu, et il
# amène `cc` avec lui. Une version antérieure de ce script aurait alors annoncé
# « VIOLATION cc », sur une crate que le compilateur ne touche jamais. Elle
# aurait aussi dénoncé `windows-sys`, conditionné à une plateforme qui n'est pas
# la nôtre.
#
# Mesure faite le 2026-09-09 sur la sonde de greffe : **111 paquets résolus, dont
# deux faux positifs ; 90 unités réellement construites, et aucun suspect.**
#
# On lit donc `cargo build --unit-graph`, qui rend exactement ce que cargo
# COMPILERA : les fonctionnalités actives, la plateforme hôte, et rien d'autre.
# C'est une option `-Z`, donc nightly — et la toolchain de ce dépôt en est une,
# épinglée sur celle d'Air.
#
# # TROIS CONTRÔLES, ET LE TROISIÈME EST LE SEUL QUI REGARDE LA RÉALITÉ
#
#   1. Aucune crate `*-sys` parmi les unités construites. Par convention, ce
#      suffixe désigne une liaison vers une bibliothèque système.
#   2. Ni `cc`, ni `bindgen`, ni `pkg-config`, ni `cmake` parmi elles. Leur
#      présence signifierait qu'un script de construction compile du C.
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

# Le RÉSOLU, pour le seul plaisir de montrer l ecart. Il ne sert a aucun verdict.
if ! metadata=$(cargo metadata --format-version 1 --locked 2>/dev/null); then
    echo "ÉCHEC : \`cargo metadata\` n'a pas répondu."
    exit 1
fi
nombre_resolu=$(printf '%s' "$metadata" | python3 -c '
import json, sys
donnees = json.load(sys.stdin)
print(len({paquet["name"] for paquet in donnees["packages"]}))
')

# Le CONSTRUIT. C est lui qui decide.
if ! unites=$(cargo build --workspace --locked --unit-graph -Z unstable-options 2>/dev/null); then
    echo "ÉCHEC : \`cargo build --unit-graph\` n'a pas répondu."
    echo "        Cette option est une option \`-Z\` : elle EXIGE la toolchain nightly"
    echo "        épinglée par \`rust-toolchain.toml\`."
    exit 1
fi

paquets=$(printf '%s' "$unites" | python3 -c '
import json, sys
donnees = json.load(sys.stdin)
noms = set()
for unite in donnees["units"]:
    identifiant = unite["pkg_id"]
    apres_diese = identifiant.split("#")[-1]
    if "@" in apres_diese:
        noms.add(apres_diese.split("@")[0])
    else:
        # Un identifiant sans version apres le diese : le nom est le dernier
        # segment du chemin, avant un eventuel parametre de requete.
        noms.add(identifiant.split("#")[0].rstrip("/").split("/")[-1].split("?")[0])
for nom in sorted(noms):
    print(nom)
')

nombre=$(printf '%s\n' "$paquets" | grep -c . || true)
tierces=$(printf '%s\n' "$paquets" | grep -vE '^asl-' || true)
nombre_tierces=$(printf '%s\n' "$tierces" | grep -c . || true)
echo "paquets RÉSOLUS        : $nombre_resolu"
echo "unités CONSTRUITES     : $nombre  ← c'est sur elles que porte le verdict"
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
