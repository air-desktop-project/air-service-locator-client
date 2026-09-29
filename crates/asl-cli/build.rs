//! Embarque le commit git dans le binaire, pour `asl --version` — et, sur
//! macOS, un `Info.plist` dans le binaire lui-même.
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
//!
//! # SUR MACOS, UN `Info.plist` DANS `__TEXT,__info_plist`
//!
//! Sur macOS, `asl` est livré dans l'application Mac
//! (`Air Service Locator.app/Contents/Helpers/asl`), **en bac à sable** (Mac
//! App Store). Un exécutable nu n'a pas de paquet autour de lui pour dire qui
//! il est ; or le bac à sable en a besoin pour lui attribuer son conteneur
//! (`~/Library/Containers/org.airdesktop.servicelocator.asl`). **Sans cet
//! `Info.plist`, un `asl` signé avec le droit `app-sandbox` meurt au démarrage**
//! (SIGILL dans `sandbox.cold`, essai réel sur macOS 15.7.9) ; avec lui, il
//! démarre, lit le conteneur de groupe et joint les racines.
//!
//! La section est écrite par l'éditeur de liens (`-sectcreate`), depuis un
//! fichier généré ici dans `OUT_DIR` à partir de la version du crate : la
//! version affichée par le Finder et celle d'`asl --version` ne peuvent pas
//! diverger. **Hors macOS, rien** — ni fichier, ni argument d'édition de liens.
//! La cible se lit dans `CARGO_CFG_TARGET_OS` et non par `cfg!` : un script de
//! construction est compilé pour l'HÔTE, et c'est la CIBLE qui décide.

use std::path::Path;
use std::process::Command;

/// L'identifiant de paquet d'`asl` : celui que la signature du projet Mac
/// porte, et celui qui nomme son conteneur de bac à sable.
const IDENTIFIANT: &str = "org.airdesktop.servicelocator.asl";

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

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        integrer_l_info_plist();
    }
}

/// Écrit l'`Info.plist` d'`asl` dans `OUT_DIR` et demande à l'éditeur de liens
/// de le poser dans `__TEXT,__info_plist` — pour le binaire `asl` seulement,
/// pas pour les essais ni pour une autre cible.
///
/// # POURQUOI `CFBundleVersion` = LA VERSION DU CRATE
///
/// `CFBundleShortVersionString` est la version montrée aux gens,
/// `CFBundleVersion` celle que le système compare. Ce dépôt n'a qu'un numéro,
/// qui change à chaque PR et ne recule jamais (`check-version.sh`) : il fait
/// l'un et l'autre, et aucun second compteur n'est à tenir.
fn integrer_l_info_plist() {
    let version = env!("CARGO_PKG_VERSION");
    let contenu = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleIdentifier</key>
	<string>{IDENTIFIANT}</string>
	<key>CFBundleName</key>
	<string>asl</string>
	<key>CFBundleShortVersionString</key>
	<string>{version}</string>
	<key>CFBundleVersion</key>
	<string>{version}</string>
	<key>CFBundleInfoDictionaryVersion</key>
	<string>6.0</string>
</dict>
</plist>
"#
    );
    // `OUT_DIR` est toujours posé par Cargo pour un script de construction ;
    // son absence serait un Cargo cassé, pas un cas à traiter.
    let dossier = std::env::var("OUT_DIR").expect("Cargo pose OUT_DIR");
    let chemin = Path::new(&dossier).join("Info.plist");
    std::fs::write(&chemin, contenu).expect("OUT_DIR est inscriptible");
    // `-sectcreate` prend ses arguments séparés par des virgules : un chemin
    // qui en porterait une serait coupé en deux, et l'édition de liens
    // échouerait sur un message obscur. On le dit ici plutôt.
    let chemin = chemin.display().to_string();
    assert!(
        !chemin.contains(','),
        "le chemin de l'Info.plist ne doit pas contenir de virgule : {chemin}"
    );
    println!("cargo:rustc-link-arg-bin=asl=-Wl,-sectcreate,__TEXT,__info_plist,{chemin}");
}
