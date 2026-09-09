#!/usr/bin/env bash
#
# check-kotlin — la liaison Kotlin dit-elle la même chose que l'ABI ?
#
# # POURQUOI CETTE BARRIÈRE RESSEMBLE À CELLE DE PYTHON ET NON À CELLE DE C++
#
# **La JVM ne peut pas INCLURE un en-tête C.** C++ obtient la conformité
# gratuitement — il compile le contrat. Kotlin, comme Python et Ruby, doit le
# RECOPIER : constantes, dispositions, décalages. Rien dans les deux langages ne
# relie la copie à l'original.
#
# **ET UNE DIVERGENCE NE PLANTE PAS, ELLE MENT.** Une constante décalée fait lever
# `Refuse` là où l'ABI disait `Injoignable` ; un champ déplacé fait lire un port
# dans un champ de protocole, sans changer aucune taille.
#
# # CE QU'ELLE ATTRAPE QUE LES AUTRES N'ATTRAPENT PAS
#
# **Les décalages.** Python emploie `ctypes.Structure`, Ruby `pack` : les deux
# calculent les positions à partir d'une liste ordonnée. L'API FFM, elle, les
# NOMME — et l'essai compare chaque décalage à la position qu'il devrait occuper
# d'après l'ordre des champs de l'en-tête.
#
# # CE QUE CE CONTRÔLE N'EST PAS
#
# Pas de `ktlint`, pas de `detekt` : les imposer ferait de leur présence une
# condition pour construire ce dépôt. Ce qui est vérifié à la place est le seul
# invariant qui coûterait cher — **la liaison n'importe rien hors du JDK et de la
# bibliothèque standard de Kotlin** —, et un essai le prouve en lisant ses propres
# sources.

set -euo pipefail

cd "$(dirname "$0")/.."

echo 'check-kotlin — la liaison contre l'"'"'ABI qu'"'"'elle transcrit'
echo

for besoin in kotlinc java; do
    if ! command -v "$besoin" >/dev/null 2>&1; then
        echo "ÉCHEC : \`$besoin\` est absent — RIEN n'a été éprouvé."
        exit 1
    fi
done

# **L'API FFM EST STABLE DEPUIS LE JDK 22**, et c'est ce que cette liaison exige.
# Le dire ici évite un échec de compilation obscur trente lignes plus bas.
version_jdk=$(java -XshowSettings:properties -version 2>&1 \
    | awk -F'= ' '/java.specification.version/ {print $2}' | tr -d ' ')
echo "jdk     : $version_jdk"
if [ "${version_jdk%%.*}" -lt 22 ]; then
    echo "ÉCHEC : la liaison demande un JDK 22 ou plus (\`java.lang.foreign\`)."
    exit 1
fi
echo "kotlinc : $(kotlinc -version 2>&1 | head -1)"

echo "construction de l'objet natif…"
cargo build --workspace --locked --quiet

objet=""
for candidat in target/debug/libasl_client_ffi.so target/debug/libasl_client_ffi.dylib; do
    if [ -f "$candidat" ]; then
        objet="$(pwd)/$candidat"
        break
    fi
done

if [ -z "$objet" ]; then
    echo "ÉCHEC : l'objet natif est introuvable après construction."
    exit 1
fi
echo "objet   : $objet"
echo

travail=$(mktemp -d)
trap 'rm -rf "$travail"' EXIT

sources=(liaisons/kotlin/src/main/kotlin/io/github/airdesktopproject/asl/*.kt)

# **LA BIBLIOTHÈQUE SEULE, D'ABORD.** Si elle ne compilait qu'accompagnée de ses
# essais, un porteur le découvrirait et pas nous.
if ! kotlinc -jvm-target 22 -Werror "${sources[@]}" -d "$travail/lib" 2>"$travail/erreurs"; then
    echo "ÉCHEC : la bibliothèque seule ne compile pas."
    sed 's/^/  /' "$travail/erreurs" | head -20
    exit 1
fi
echo "la bibliothèque compile seule, sans avertissement."

if ! kotlinc -jvm-target 22 -Werror -include-runtime \
     "${sources[@]}" liaisons/kotlin/essais/Essais.kt -d "$travail/essais.jar" \
     2>"$travail/erreurs"; then
    echo "ÉCHEC : les essais ne compilent pas."
    sed 's/^/  /' "$travail/erreurs" | head -20
    exit 1
fi
echo

# `--enable-native-access` : sans lui la JVM avertit aujourd'hui et REFUSERA
# demain. Un porteur doit le poser ; l'omettre ici cacherait ce qu'il doit savoir.
if ! ASL_BIBLIOTHEQUE="$objet" java --enable-native-access=ALL-UNNAMED \
     -cp "$travail/essais.jar" io.github.airdesktopproject.asl.essais.EssaisKt; then
    echo
    echo "ÉCHEC : la liaison Kotlin et l'ABI ne disent pas la même chose."
    exit 1
fi

echo
echo "OK : la liaison Kotlin suit l'ABI, et n'importe que le JDK et Kotlin."
