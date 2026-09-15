//! Le binaire tel qu'un script le voit.
//!
//! # POURQUOI CES ESSAIS LANCENT LE VRAI PROCESSUS
//!
//! Ce qu'ils éprouvent n'est pas une fonction : c'est un **contrat**. Les codes
//! de sortie de `asl` sont documentés comme une interface, et une interface qui
//! n'est vérifiée nulle part dérive au premier remaniement — sans que rien ne
//! casse à la compilation, puisqu'un `ExitCode` est un nombre.
//!
//! Un script qui distingue « l'annuaire a dit non » de « personne n'a répondu »
//! le fait sur ce nombre, et sur rien d'autre.

use std::path::Path;
use std::process::{Command, Output};

use asl_id::{Genre, Identifiant};

/// Lance `asl`, dans un environnement propre.
///
/// **L'ENVIRONNEMENT EST VIDÉ DE CE QUI COMPTE.** `ASL_DIRECTORY`, `ASL_ROOTS`
/// et `ASL_STATE` posés sur la machine de qui lance les essais changeraient leur
/// résultat — et c'est exactement le genre d'essai qui passe chez son auteur.
fn asl(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_asl"))
        .args(arguments)
        .env_remove("ASL_DIRECTORY")
        .env_remove("ASL_ROOTS")
        .env_remove("ASL_STATE")
        .env("ASL_TIMEOUT", "2")
        .output()
        .expect("le binaire `asl` se lance")
}

/// Le code de sortie, ou `None` si un signal a emporté le processus.
fn code(sortie: &Output) -> Option<i32> {
    sortie.status.code()
}

fn texte(octets: &[u8]) -> String {
    String::from_utf8_lossy(octets).into_owned()
}

/// Un répertoire d'essai, effacé à la fin.
struct Bac(std::path::PathBuf);

impl Bac {
    fn neuf(nom: &str) -> Self {
        let ou = std::env::temp_dir().join(format!("asl-essai-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&ou);
        std::fs::create_dir_all(&ou).expect("un répertoire d'essai");
        Self(ou)
    }

    fn chemin(&self) -> &Path {
        &self.0
    }
}

impl Drop for Bac {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Écrit une identité, avec le mode demandé.
fn poser_une_identite(dossier: &Path, mode: u32) -> Identifiant {
    use std::os::unix::fs::PermissionsExt as _;
    let machine = Identifiant::depuis_entropie(Genre::Machine, [0x11; 16]);
    let ou = dossier.join("identite");
    std::fs::write(
        &ou,
        format!(
            "machine = {}\ngraine = {}\n",
            machine.texte().as_str(),
            "5a".repeat(32)
        ),
    )
    .expect("l'identité s'écrit");
    std::fs::set_permissions(&ou, std::fs::Permissions::from_mode(mode)).expect("le mode se pose");
    machine
}

// ── L'aide ──────────────────────────────────────────────────────────────────

#[test]
fn l_aide_repond_quand_rien_n_est_configure() {
    // C'est la commande qu'on tape justement parce qu'on ne sait pas quoi
    // configurer : elle ne doit exiger ni annuaire, ni racine, ni identité.
    for forme in [["help"], ["--help"]] {
        let sortie = asl(&forme);
        assert_eq!(code(&sortie), Some(0), "{forme:?}");
        let dit = texte(&sortie.stdout);
        for verbe in ["enroll", "announce", "where ", "diagnose"] {
            assert!(dit.contains(verbe), "l'aide doit citer `{verbe}` : {dit}");
        }
        assert!(
            dit.contains("EXIT CODES"),
            "les codes sont une interface, l'aide doit les dire"
        );
    }
}

// ── Ce qui a été tapé : code 1 ──────────────────────────────────────────────

#[test]
fn ce_qui_ne_se_lit_pas_rend_un_et_le_dit_sur_stderr() {
    for ligne in [
        vec![],
        vec!["announcer"],
        vec!["--verbose", "diagnose"],
        vec!["announce", "depot"],
        vec!["announce", "depot", "sctp:1"],
        vec!["where", "pas-un-identifiant", "depot"],
        vec!["diagnose", "et", "puis"],
        vec!["--directory"],
    ] {
        let sortie = asl(&ligne);
        assert_eq!(
            code(&sortie),
            Some(1),
            "{ligne:?} : {}",
            texte(&sortie.stderr)
        );
        assert!(
            !sortie.stderr.is_empty(),
            "{ligne:?} : un refus muet n'apprend rien"
        );
    }
}

// ── La configuration : code 2 ───────────────────────────────────────────────

#[test]
fn une_configuration_qui_manque_rend_deux_et_dit_quoi_poser() {
    let bac = Bac::neuf("config");
    let etat = bac.chemin().to_string_lossy().into_owned();

    // **Aucun annuaire donné : ce sont les racines qu'on joint**, sous leur
    // alias — et ce n'est donc plus une faute de configuration. Ce que
    // l'essai peut tenir sans réseau, c'est que l'alias est bien celui que
    // la commande vise : il apparaît dans ce qu'elle dit, résolu ou non.
    let sortie = asl(&["--state", &etat, "diagnose"]);
    assert_ne!(code(&sortie), Some(1), "{}", texte(&sortie.stderr));
    let dit = texte(&sortie.stdout) + &texte(&sortie.stderr);
    assert!(dit.contains("asl-root.air-desktop.org"), "{dit}");

    // Un annuaire, mais aucune racine donnée : **celle d'air-desktop-project
    // est épinglée**, et c'est elle qui vaut — pas le magasin du système. Un
    // annuaire qui n'est pas signé par elle est donc refusé, et ce n'est pas
    // une faute de configuration non plus.
    let sortie = asl(&[
        "--state",
        &etat,
        "--directory",
        "127.0.0.1:6630",
        "diagnose",
    ]);
    assert_ne!(code(&sortie), Some(2), "{}", texte(&sortie.stderr));

    // Un fichier de racines qui n'existe pas.
    let sortie = asl(&[
        "--state",
        &etat,
        "--directory",
        "127.0.0.1:6630",
        "--roots",
        "/n-existe-pas/ca.pem",
        "diagnose",
    ]);
    assert_eq!(code(&sortie), Some(2));
    assert!(texte(&sortie.stderr).contains("/n-existe-pas/ca.pem"));
}

#[test]
fn un_nom_qui_ne_se_resout_pas_rend_deux_et_non_quatre() {
    // **CE N'EST PAS UNE PANNE DE RÉSEAU** : rien n'a été essayé. Le rendre en
    // `4` enverrait chercher un câble là où il y a une faute de frappe.
    let bac = Bac::neuf("dns");
    let racines = bac.chemin().join("ca.pem");
    std::fs::write(&racines, b"pas un PEM").expect("le fichier s'écrit");

    let sortie = asl(&[
        "--state",
        &bac.chemin().to_string_lossy(),
        "--directory",
        "annuaire.invalid:6630",
        "--roots",
        &racines.to_string_lossy(),
        "diagnose",
    ]);
    assert_eq!(code(&sortie), Some(2), "{}", texte(&sortie.stderr));
    assert!(texte(&sortie.stderr).contains("annuaire.invalid"));
}

/// `ASL_DIRECTORY` se lit avec la même grammaire que `--directory`, et c'est
/// précisément là qu'un renommage de commande s'est cassé une fois : la
/// variable était relue à travers l'analyseur avec un mot de commande qui
/// n'existait plus. Une adresse posée par la variable doit donc arriver au
/// même endroit que l'option — ici, jusqu'au refus du PEM, code 2, sans
/// jamais dire qu'une commande n'existe pas.
#[test]
fn asl_directory_se_lit_comme_l_option() {
    let bac = Bac::neuf("env");
    let racines = bac.chemin().join("ca.pem");
    std::fs::write(&racines, b"pas un PEM").expect("le fichier s'écrit");

    let sortie = Command::new(env!("CARGO_BIN_EXE_asl"))
        .args([
            "--state",
            &bac.chemin().to_string_lossy(),
            "--roots",
            &racines.to_string_lossy(),
            "diagnose",
        ])
        .env_remove("ASL_STATE")
        .env("ASL_DIRECTORY", "annuaire.invalid:6630, [::1]:6630")
        .env("ASL_TIMEOUT", "2")
        .output()
        .expect("le binaire `asl` se lance");
    let dit = texte(&sortie.stderr);
    assert!(
        !dit.contains("n'existe pas"),
        "la variable doit passer l'analyseur : {dit}"
    );
    assert_eq!(code(&sortie), Some(2), "{dit}");
    assert!(dit.contains("annuaire.invalid"), "{dit}");
}

#[test]
fn une_cle_lisible_par_d_autres_est_refusee_et_la_correction_est_donnee() {
    // **UNE CLÉ LISIBLE PAR LE GROUPE N'EST PLUS UNE CLÉ.** Un avertissement
    // dans un journal ne serait pas lu ; un refus, si.
    let bac = Bac::neuf("mode");
    poser_une_identite(bac.chemin(), 0o644);

    let sortie = asl(&[
        "--state",
        &bac.chemin().to_string_lossy(),
        "announce",
        "depot",
        "tcp:8080",
    ]);
    assert_eq!(code(&sortie), Some(2), "{}", texte(&sortie.stderr));
    let dit = texte(&sortie.stderr);
    assert!(
        dit.contains("0644"),
        "le mode fautif doit être nommé : {dit}"
    );
    assert!(dit.contains("chmod 600"), "et la correction donnée : {dit}");
}

#[test]
fn une_machine_non_enrolee_l_apprend_avant_toute_connexion() {
    // **AVANT**, et non après vingt secondes passées à joindre un annuaire qui
    // l'aurait de toute façon renvoyée.
    let bac = Bac::neuf("pas-enrolee");
    let depart = std::time::Instant::now();
    let sortie = asl(&[
        "--state",
        &bac.chemin().to_string_lossy(),
        "--directory",
        "127.0.0.1:1",
        "where",
        Identifiant::depuis_entropie(Genre::Machine, [3; 16])
            .texte()
            .as_str(),
        "depot",
    ]);
    assert_eq!(code(&sortie), Some(2), "{}", texte(&sortie.stderr));
    assert!(
        depart.elapsed() < std::time::Duration::from_secs(2),
        "elle a essayé de se connecter avant de lire son identité"
    );
    let dit = texte(&sortie.stderr);
    assert!(dit.contains("asl enroll"), "et l'on dit quoi faire : {dit}");
}

// ── Personne n'a répondu : code 4 ───────────────────────────────────────────

#[test]
fn un_annuaire_qui_ne_repond_pas_rend_quatre() {
    // La distinction qui compte : `4` est un réseau, `3` serait un droit.
    let bac = Bac::neuf("injoignable");
    let racines = bac.chemin().join("ca.pem");
    // **UNE RACINE QUE `rustls` SAIT LIRE**, sans quoi l'on obtiendrait `2` et
    // l'essai prouverait le contraire de ce qu'il cherche.
    let atelier = ams_quic_client::atelier("asl-cli");
    let (autorite, _cert, _cle) =
        ams_quic_client::materiel(atelier.chemin()).expect("`openssl` est requis pour cet essai");
    std::fs::write(&racines, &autorite).expect("la racine s'écrit");

    let sortie = asl(&[
        "--state",
        &bac.chemin().to_string_lossy(),
        "--directory",
        "127.0.0.1:1",
        "--roots",
        &racines.to_string_lossy(),
        "diagnose",
    ]);
    assert_eq!(code(&sortie), Some(4), "{}", texte(&sortie.stderr));
    assert!(
        texte(&sortie.stderr).contains("2 secondes"),
        "la borne est celle qu'on a posée"
    );
}
