#!/usr/bin/env bash
#
# check-compile — tout ce dépôt compile-t-il, essais compris ?
#
# `--all-targets` et non un simple `cargo check` : un essai qui ne compile plus
# est un essai qui ne tourne plus, et `cargo check` seul ne l'apprend jamais.
#
# `--locked` : le `Cargo.lock` est committé. Une barrière qui le laisserait
# bouger en silence ne vérifierait plus le build qu'elle prétend vérifier.
#
# CE SCRIPT COUVRE AUJOURD'HUI EXACTEMENT LE WORKSPACE, et c'est tout ce qu'il y
# a. Sur `air-mail-server`, son intérêt vient de ce qu'il atteint `fuzz/`, une
# crate hors workspace que ni clippy ni les essais ne compilent — et deux
# tranches y avaient perdu une campagne pour une signature de trait non
# répercutée. Ici, rien de tel n'existe encore : le jour où une crate sortira du
# workspace, elle s'ajoute ICI.

set -euo pipefail

cd "$(dirname "$0")/.."

echo 'check-compile — le workspace, essais compris'
echo

if cargo check --workspace --all-targets --locked; then
    echo
    echo 'OK : tout compile.'
else
    echo
    echo 'ÉCHEC : le dépôt ne compile pas.'
    exit 1
fi
