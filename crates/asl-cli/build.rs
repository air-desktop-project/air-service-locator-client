//! Embarque le commit git dans le binaire, pour `asl --version`.
//!
//! # POURQUOI LE COMMIT, ALORS QUE LA VERSION SUFFIT À NOMMER UNE LIVRAISON
//!
//! La version change à chaque PR (règle dans `CLAUDE.md`), donc elle nomme bien
//! ce qui est livré. Mais un banc se met à jour depuis un paquet construit sur
//! une machine de travail, parfois depuis une branche : c'est le commit qui dit
//! CE QUI a été construit, et « le client est à 4726464 » est la phrase qu'on
//! échange entre dépôts.
//!
//! # CE QU'IL FAIT, ET CE QU'IL NE FAIT PAS
//!
//! Il demande à `git` le commit court et si l'arbre est propre, et rend
//! `ASL_COMMIT` au binaire — vide si `git` manque ou si ce n'est pas un dépôt
//! (une archive de sources, par exemple). **Il ne compile rien, ne lit rien
//! d'autre, et n'échoue jamais** : un commit inconnu se dit, il n'empêche pas
//! de construire.
//!
//! Un arbre modifié porte un `+` derrière le commit : un binaire construit sur
//! un arbre sale n'est pas ce commit, et le dire évite de croire un banc à jour.

use std::process::Command;

/// Lance `git` avec ces arguments depuis le dépôt, et rend sa sortie nettoyée.
fn git(arguments: &[&str]) -> Option<String> {
    let sortie = Command::new("git")
        .arg("-C")
        .arg(env!("CARGO_MANIFEST_DIR"))
        .args(arguments)
        .output()
        .ok()?;
    if !sortie.status.success() {
        return None;
    }
    Some(String::from_utf8(sortie.stdout).ok()?.trim().to_owned())
}

fn main() {
    // Se relancer quand le sommet bouge — un commit, une bascule de branche —
    // et non à chaque construction.
    for chemin in [
        "../../.git/HEAD",
        "../../.git/refs/heads",
        "../../.git/packed-refs",
    ] {
        println!("cargo:rerun-if-changed={chemin}");
    }

    let commit = match git(&["rev-parse", "--short=7", "HEAD"]) {
        Some(commit) => {
            let sale = git(&["status", "--porcelain", "--untracked-files=no"])
                .is_some_and(|etat| !etat.is_empty());
            if sale { format!("{commit}+") } else { commit }
        }
        None => String::new(),
    };
    println!("cargo:rustc-env=ASL_COMMIT={commit}");
}
