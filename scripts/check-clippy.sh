#!/usr/bin/env bash
#
# check-clippy — les lints du produit, avant la CI et non après elle.
#
# LA MÊME COMMANDE QUE LA CI, `--locked` compris. Une barrière locale plus
# indulgente que la CI ne fait que déplacer l'attente ; une plus sévère ferait
# refuser des tranches que la CI accepterait. On copie donc, et ce commentaire
# est là pour qu'un changement dans `ci.yml` se répercute ici.
#
#     ci.yml, étape « check-clippy » :
#         cargo clippy --workspace --all-targets --locked -- -D warnings
#
# POURQUOI `check-compile` NE SUFFIT PAS : les règles `deny` du `[lints]` du
# workspace — `arithmetic_side_effects`, `cast_possible_truncation` — sont des
# lints CLIPPY. `cargo check` ne les voit pas, et ne peut pas les voir.

set -euo pipefail

cd "$(dirname "$0")/.."

echo 'check-clippy — les lints du workspace, comme la CI les passe'
echo

if cargo clippy --workspace --all-targets --locked -- -D warnings; then
    echo
    echo 'OK : `cargo clippy --workspace --all-targets` ne dit rien.'
else
    echo
    echo 'ÉCHEC : clippy refuse. La CI dira la même chose, plusieurs minutes plus tard.'
    exit 1
fi
