#!/usr/bin/env bash
#
# check-couverture — 100 % sur les étages 1 et 2, et rien de moins. (C2)
#
# # POURQUOI 100 %, ET POURQUOI SEULEMENT LÀ
#
# Une machine à états se pilote pas à pas depuis un essai : on lui donne des
# octets et l'heure, on regarde ce qu'elle rend. Il n'y a aucune raison qu'une
# branche reste inatteinte, et une branche inatteinte est presque toujours une
# branche que personne n'a lue.
#
# Une boucle asynchrone, elle, ne se pilote pas — on l'attend. Y atteindre 100 %
# exigerait de simuler des pannes du noyau, ce qui mesure la simulation.
# L'étage 3 est donc hors mesure, non par indulgence mais par honnêteté.
#
# # UN 100 % SUR DU VIDE N'ATTESTE DE RIEN, ET CE SCRIPT LE DIT
#
# Une crate sans code a zéro région couverte sur zéro : arithmétiquement
# parfaite, et vide de sens. Ce script COMPTE ces crates à part et les nomme,
# au lieu de les laisser gonfler un pourcentage.
#
# **AUCUNE NE L'EST PLUS DEPUIS QUE LES CINQ CRATES DES ÉTAGES 1 ET 2 SONT
# ÉCRITES**, et ce compteur reste : il redeviendra utile à la sixième.
#
# # CE QU'IL NE MESURE PAS
#
# La couverture dit qu'une ligne a été exécutée, jamais qu'elle a été éprouvée.
# Un essai qui appelle sans rien vérifier rend 100 % et ne prouve rien. C'est la
# limite de tout gate de couverture, et elle vaut d'être écrite ici pour qu'on
# ne prenne pas ce vert pour une garantie de correction.

set -euo pipefail

cd "$(dirname "$0")/.."

# **`asl-client` SEULE.** `asl-client-ffi` est une façade — elle n'a aucune
# logique à elle, et l'y soumettre reviendrait à mesurer la couverture d'un
# passe-plat. `asl-cli` est un binaire : ses chemins d'erreur dépendent de ce que
# l'utilisateur a tapé, et les atteindre tous demanderait de simuler un terminal.
#
# **CE SCRIPT EST UNE COPIE DE CELUI DU DÉPÔT SERVEUR.** Deux copies finissent
# par diverger — c'est le prix de la séparation, et il est assumé ici comme pour
# `check-pile` et `check-toolchain`.
sous_mesure=(asl-client)

echo 'check-couverture — 100 % sur la logique du client (C2)'
echo

if ! command -v cargo-llvm-cov >/dev/null 2>&1; then
    echo "ÉCHEC : \`cargo-llvm-cov\` est absent — RIEN n'a été mesuré."
    echo "        cargo install cargo-llvm-cov, ou taiki-e/install-action en CI."
    exit 1
fi

rapport=$(cargo llvm-cov --workspace --locked --json --summary-only 2>/dev/null) || {
    echo "ÉCHEC : la mesure de couverture n'a pas abouti."
    exit 1
}

# LE SCRIPT PYTHON EST PASSÉ PAR UNE SUBSTITUTION DE COMMANDE, ET NON ENTRE
# APOSTROPHES. Sa prose est en français : « rien n'a été mesuré » contient une
# apostrophe, qui refermait la chaîne du shell et coupait le script en deux au
# milieu d'une ligne. Un heredoc entre apostrophes n'a pas ce défaut.
printf '%s' "$rapport" | SOUS_MESURE="${sous_mesure[*]}" python3 -c "$(cat <<'PYTHON'
import json, os, sys

sous_mesure = os.environ["SOUS_MESURE"].split()
rapport = json.load(sys.stdin)

mesurees = {}
for fichier in rapport["data"][0]["files"]:
    chemin = fichier["filename"]
    if "/crates/" not in chemin:
        continue
    crate = chemin.split("/crates/", 1)[1].split("/", 1)[0]
    if crate not in sous_mesure:
        continue
    regions = fichier["summary"]["regions"]
    total, couvertes = mesurees.get(crate, (0, 0))
    mesurees[crate] = (total + regions["count"], couvertes + regions["covered"])

vides, incompletes, completes = [], [], []
for crate in sous_mesure:
    total, couvertes = mesurees.get(crate, (0, 0))
    if total == 0:
        vides.append(crate)
    elif couvertes == total:
        completes.append((crate, total))
    else:
        incompletes.append((crate, total, couvertes))

for crate, total in completes:
    print(f"  {crate:<14} {total:>5} régions, toutes couvertes")
for crate, total, couvertes in incompletes:
    manquantes = total - couvertes
    taux = 100.0 * couvertes / total
    print(f"  {crate:<14} {total:>5} régions, {manquantes} NON couverte(s) — {taux:.2f} %")
for crate in vides:
    print(f"  {crate:<14}     0 régions — VIDE, rien mesuré")

print()
print(f"crates à 100 %  : {len(completes)}")
print(f"crates vides    : {len(vides)}")
print(f"crates en défaut: {len(incompletes)}")
print()

if incompletes:
    print("ÉCHEC : C2 exige 100 % aux étages 1 et 2.")
    print("        `cargo llvm-cov --package <crate> --text` montre les lignes.")
    sys.exit(1)

if not completes:
    print("Aucune crate sous mesure ne porte de code — RIEN n'a été mesuré.")
    sys.exit(0)

print("OK : tout ce qui porte de la logique dans le client est couvert à 100 %.")
PYTHON
)"
