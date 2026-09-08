#!/usr/bin/env bash
#
# check-toolchain — une seule toolchain, celle d'Air, datée. (C16)
#
# # LA CONTRAINTE EST FACILE À VIOLER DE BONNE FOI
#
# Ce dépôt n'a besoin de rien de ce que nightly apporte. Quelqu'un remarquera
# qu'il pourrait revenir sur stable, et il aura raison LOCALEMENT. Il aura tort
# globalement : la pile QUIC migrera dans `air`, et il y aura une version
# `linux-air` de ces composants, qui exige `-Z build-std`. Deux pins, ce sont
# deux LLVM, et les profils de couverture que l'un écrit, l'autre ne sait pas les
# relire — la panne qu'Air a payée le 2026-08-15.
#
# # TROIS CONTRÔLES, ET LE TROISIÈME NE TOURNE QUE CHEZ NOUS
#
#   1. `rust-toolchain.toml` déclare bien la version attendue.
#   2. La toolchain ACTIVE est celle-là — un pin que rustup n'honore pas ne pin
#      rien, et cela arrive quand un `RUSTUP_TOOLCHAIN` traîne dans un
#      environnement.
#   3. Le dépôt `air` déclare la MÊME. Il n'existe pas sur un runner de CI : le
#      contrôle est alors sauté, et il le DIT au lieu de rendre un vert muet.
#
# CE SCRIPT EST UNE COPIE DE CELUI DU DÉPÔT SERVEUR. Deux copies finissent par
# diverger — mais une divergence sur CE contrôle-ci se voit tout de suite, car
# les deux dépôts se compilent avec la même toolchain et l'un des deux échouerait.
#
# La valeur attendue est écrite ici EN DUR, et c'est ce qui rend (1) utile en CI
# où `air` est absent. Elle doit être changée en même temps que les deux fichiers,
# jamais après — et le contrôle (3) est ce qui l'apprend à qui l'oublierait.

set -euo pipefail

cd "$(dirname "$0")/.."

attendu="nightly-2026-07-11"
toolchain_air="$HOME/Code/air/rust-toolchain.toml"

echo "check-toolchain — une seule toolchain, celle d'Air (C16)"
echo "attendu : $attendu"
echo

lire_canal() {
    grep -E '^\s*channel\s*=' "$1" | head -1 | sed 's/.*=\s*"\(.*\)".*/\1/'
}

violations=0

# ── 1. Ce que ce dépôt déclare ───────────────────────────────────────────────
if [ ! -f rust-toolchain.toml ]; then
    echo "VIOLATION  rust-toolchain.toml est absent — rien n'est épinglé."
    violations=$((violations + 1))
else
    notre=$(lire_canal rust-toolchain.toml)
    if [ "$notre" = "$attendu" ]; then
        echo "rust-toolchain.toml : $notre"
    else
        echo "VIOLATION  rust-toolchain.toml déclare « $notre », attendu « $attendu »"
        violations=$((violations + 1))
    fi
fi

# ── 2. Ce que rustup emploie RÉELLEMENT ──────────────────────────────────────
if actif=$(rustup show active-toolchain 2>/dev/null | head -1 | cut -d' ' -f1); then
    if printf '%s' "$actif" | grep -q "^$attendu"; then
        echo "toolchain active    : $actif"
    else
        echo "VIOLATION  la toolchain ACTIVE est « $actif », pas « $attendu »"
        echo "           (un \`RUSTUP_TOOLCHAIN\` dans l'environnement ?)"
        violations=$((violations + 1))
    fi
else
    echo "SIGNALEMENT rustup n'a pas répondu — la toolchain active n'a pas été vérifiée."
fi

# ── 3. Ce qu'Air déclare, quand Air est là ───────────────────────────────────
if [ -f "$toolchain_air" ]; then
    canal_air=$(lire_canal "$toolchain_air")
    if [ "$canal_air" = "$attendu" ]; then
        echo "air                 : $canal_air"
    else
        echo "VIOLATION  Air déclare « $canal_air », ce dépôt attend « $attendu »"
        echo "           Alignez-vous sur AIR, jamais l'inverse, et corrigez la"
        echo "           valeur \`attendu\` de ce script en même temps."
        violations=$((violations + 1))
    fi
else
    echo "air                 : absent ($toolchain_air) — NON VÉRIFIÉ"
    echo "                      (normal sur un runner de CI ; la dérive avec Air"
    echo "                       ne se voit alors qu'en local)"
fi

echo
if [ "$violations" -gt 0 ]; then
    echo "ÉCHEC : $violations violation(s) de C16."
    exit 1
fi
echo "OK : la toolchain est celle d'Air."
