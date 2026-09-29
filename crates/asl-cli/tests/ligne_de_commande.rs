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

/// Un annuaire où rien n'écoute, avec l'identité qu'on y attendrait : la
/// forme que `--directory` exige depuis la décision 58, étape 5.
const MUET: &str = "127.0.0.1:1=n-0PWT8HZD80QMSPPDZ5CQXXYHQC";

/// Lance `asl`, dans un environnement propre.
///
/// **L'ENVIRONNEMENT EST VIDÉ DE CE QUI COMPTE.** `ASL_DIRECTORY`, `ASL_ROOTS`
/// (qui n'est plus lue, mais qu'on signale) et `ASL_STATE` posés sur la machine de qui lance les essais changeraient leur
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
    poser_une_identite_avec_compte(dossier, mode, None)
}

/// Écrit une identité qui sait, ou non, pour quel compte elle agit.
fn poser_une_identite_avec_compte(
    dossier: &Path,
    mode: u32,
    compte: Option<Identifiant>,
) -> Identifiant {
    use std::os::unix::fs::PermissionsExt as _;
    let machine = Identifiant::depuis_entropie(Genre::Machine, [0x11; 16]);
    let ou = dossier.join("identite");
    let ligne_compte = compte.map_or(String::new(), |compte| {
        format!("compte = {}\n", compte.texte().as_str())
    });
    std::fs::write(
        &ou,
        format!(
            "machine = {}\ngraine = {}\n{ligne_compte}",
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
        for verbe in [
            "enroll",
            "announce",
            "where ",
            "machines [u-…]",
            "enrolled [u-…]",
            "replication",
            "echo ",
            "ping <m-…|name|alias>",
            "domains",
            "domain <d-…|alias> [--where]",
            "identity",
            "diagnose",
        ] {
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
        vec!["machines", "pas-un-utilisateur"],
        vec!["enrolled", "pas-un-utilisateur"],
        vec!["enrolled", "u-5884A5EE7THEKHBQ3BT0VPGJKN", "encore"],
        vec!["replication", "n-0PWT8HZDQ7V4XK2M9RJ3TB6ANE"],
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

// ── Sans rien dire : les racines embarquées ─────────────────────────────────

#[test]
fn sans_annuaire_donne_ce_sont_les_racines_embarquees() {
    let bac = Bac::neuf("config");
    let etat = bac.chemin().to_string_lossy().into_owned();

    // **Aucun annuaire donné : ce sont les racines EMBARQUÉES qu'on joint**,
    // par leurs adresses et leurs identités — et ce n'est donc pas une faute
    // de configuration. Ce que l'essai tient sans réseau : les deux identités
    // sont celles que la commande vise, et AUCUN NOM n'est résolu (C20) — le
    // vieil alias n'apparaît plus.
    let sortie = asl(&["--state", &etat, "diagnose"]);
    assert_ne!(code(&sortie), Some(1), "{}", texte(&sortie.stderr));
    let dit = texte(&sortie.stdout) + &texte(&sortie.stderr);
    assert!(dit.contains("n-0PWT8HZD80QMSPPDZ5CQXXYHQC"), "{dit}");
    assert!(dit.contains("n-3K3P6H252W8K9370QG1YYTWBWB"), "{dit}");
    assert!(dit.contains("2001:41d0:20a:900::1dd4"), "{dit}");
    assert!(!dit.contains("asl-root.air-desktop.org"), "{dit}");
}

// ── La forme d'hier : retirée, et dite comme telle ──────────────────────────

#[test]
fn la_forme_d_hier_se_refuse_et_dit_quoi_ecrire() {
    // **DÉCISION 58, ÉTAPE 5** : un annuaire se croit par sa clé. Un
    // `hôte:port` sans identité, ou `--roots`, se refusent à la lecture de
    // la ligne — code 1, rien n'a été essayé — et le refus dit la forme qui
    // les remplace.
    let bac = Bac::neuf("forme-d-hier");
    let etat = bac.chemin().to_string_lossy().into_owned();

    let sortie = asl(&[
        "--state",
        &etat,
        "--directory",
        "127.0.0.1:6630",
        "diagnose",
    ]);
    assert_eq!(code(&sortie), Some(1), "{}", texte(&sortie.stderr));
    assert!(
        texte(&sortie.stderr).contains("127.0.0.1:6630=n-…"),
        "{}",
        texte(&sortie.stderr)
    );

    let sortie = asl(&["--state", &etat, "--roots", "/etc/asl/ca.pem", "diagnose"]);
    assert_eq!(code(&sortie), Some(1), "{}", texte(&sortie.stderr));
    let dit = texte(&sortie.stderr);
    assert!(dit.contains("`--roots` n'existe plus"), "{dit}");
    assert!(dit.contains("--directory <hôte:port>=<n-…>"), "{dit}");
}

/// `ASL_ROOTS` n'est plus lue, et on le dit — sans échouer : une unité
/// systemd qui la pose encore ne doit pas faire tomber un daemon qui joint
/// très bien les racines par leur identité.
#[test]
fn asl_roots_est_signalee_et_non_fatale() {
    let bac = Bac::neuf("asl-roots");
    let sortie = Command::new(env!("CARGO_BIN_EXE_asl"))
        .args([
            "--state",
            &bac.chemin().to_string_lossy(),
            "--directory",
            MUET,
            "diagnose",
        ])
        .env_remove("ASL_STATE")
        .env_remove("ASL_DIRECTORY")
        .env("ASL_ROOTS", "/etc/asl/ca.pem")
        .env("ASL_TIMEOUT", "2")
        .output()
        .expect("le binaire `asl` se lance");
    let dit = texte(&sortie.stderr);
    assert_eq!(
        code(&sortie),
        Some(4),
        "personne ne répond, c'est tout : {dit}"
    );
    assert!(dit.contains("`ASL_ROOTS` est ignorée"), "{dit}");
}

// ── La configuration : code 2 ───────────────────────────────────────────────

#[test]
fn un_nom_qui_ne_se_resout_pas_rend_deux_et_non_quatre() {
    // **CE N'EST PAS UNE PANNE DE RÉSEAU** : rien n'a été essayé. Le rendre en
    // `4` enverrait chercher un câble là où il y a une faute de frappe.
    let bac = Bac::neuf("dns");

    let sortie = asl(&[
        "--state",
        &bac.chemin().to_string_lossy(),
        "--directory",
        "annuaire.invalid:6630=n-0PWT8HZD80QMSPPDZ5CQXXYHQC",
        "diagnose",
    ]);
    assert_eq!(code(&sortie), Some(2), "{}", texte(&sortie.stderr));
    assert!(texte(&sortie.stderr).contains("annuaire.invalid"));
}

/// `ASL_DIRECTORY` se lit avec la même grammaire que `--directory`, et c'est
/// précisément là qu'un renommage de commande s'est cassé une fois : la
/// variable était relue à travers l'analyseur avec un mot de commande qui
/// n'existait plus. Une adresse posée par la variable doit donc arriver au
/// même endroit que l'option — ici, jusqu'au nom qui ne se résout pas, code
/// 2, sans jamais dire qu'une commande n'existe pas.
#[test]
fn asl_directory_se_lit_comme_l_option() {
    let bac = Bac::neuf("env");

    let sortie = Command::new(env!("CARGO_BIN_EXE_asl"))
        .args(["--state", &bac.chemin().to_string_lossy(), "diagnose"])
        .env_remove("ASL_STATE")
        .env_remove("ASL_ROOTS")
        .env(
            "ASL_DIRECTORY",
            "annuaire.invalid:6630=n-0PWT8HZD80QMSPPDZ5CQXXYHQC, \
             [::1]:6630=n-0PWT8HZD80QMSPPDZ5CQXXYHQC",
        )
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
        MUET,
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

// ── `asl enrolled`, `asl machines` : les deux formes ────────────────────────

#[test]
fn enrolled_refuse_un_compte_etranger_avant_toute_connexion() {
    // **LES APPAREILS D'UN COMPTE NE SE VOIENT QUE DEPUIS CE COMPTE** (C13) :
    // `asl enrolled u-…` avec un compte qui n'est pas celui de cette machine
    // est refusé par `asl` lui-même — code 1, ce qui a été demandé ne se
    // demande pas —, sans rien joindre : l'annuaire visé ne répond pas, et
    // l'essai tient en moins de deux secondes.
    let bac = Bac::neuf("enrolled-etranger");
    let notre = Identifiant::depuis_entropie(Genre::Utilisateur, [0x51; 16]);
    let autre = Identifiant::depuis_entropie(Genre::Utilisateur, [0x52; 16]);
    poser_une_identite_avec_compte(bac.chemin(), 0o600, Some(notre));

    let depart = std::time::Instant::now();
    let sortie = asl(&[
        "--state",
        &bac.chemin().to_string_lossy(),
        "--directory",
        MUET,
        "enrolled",
        autre.texte().as_str(),
    ]);
    assert_eq!(code(&sortie), Some(1), "{}", texte(&sortie.stderr));
    assert!(
        depart.elapsed() < std::time::Duration::from_secs(2),
        "elle a essayé de se connecter avant de refuser"
    );
    let dit = texte(&sortie.stderr);
    assert!(
        dit.contains("ne se voient que depuis ce compte"),
        "la raison est dite : {dit}"
    );
    assert!(
        dit.contains(notre.texte().as_str()),
        "et le nôtre nommé : {dit}"
    );
    assert!(
        dit.contains(autre.texte().as_str()),
        "et l'autre aussi : {dit}"
    );
}

#[test]
fn enrolled_et_machines_avec_le_compte_de_la_machine_ou_sans_vont_a_l_annuaire() {
    // Le compte de la machine, ou aucun : les deux formes passent l'analyse et
    // la lecture de l'identité, puis vont joindre l'annuaire — qui, ici, ne
    // répond pas : `4`, personne n'a répondu, et non `1` ni `2`.
    let bac = Bac::neuf("enrolled-formes");
    let notre = Identifiant::depuis_entropie(Genre::Utilisateur, [0x51; 16]);
    poser_une_identite_avec_compte(bac.chemin(), 0o600, Some(notre));
    let etat = bac.chemin().to_string_lossy().into_owned();
    let notre = notre.texte();

    for ligne in [
        vec!["enrolled"],
        vec!["enrolled", notre.as_str()],
        vec!["machines"],
        vec!["machines", notre.as_str()],
        // Même voie, même identité, même issue quand personne ne répond.
        vec!["replication"],
    ] {
        let mut arguments = vec!["--state", etat.as_str(), "--directory", MUET];
        arguments.extend_from_slice(&ligne);
        let sortie = asl(&arguments);
        assert_eq!(
            code(&sortie),
            Some(4),
            "{ligne:?} : {}",
            texte(&sortie.stderr)
        );
    }
}

#[test]
fn enrolled_sans_compte_connu_ne_refuse_pas_hors_ligne() {
    // Un fichier d'identité d'avant 0.3.0 ne porte pas le compte : le refus
    // ne peut pas se décider hors ligne, et c'est `GET /v1/moi` qui tranchera
    // — donc on joint, et ici personne ne répond : `4`.
    let bac = Bac::neuf("enrolled-sans-compte");
    poser_une_identite(bac.chemin(), 0o600);
    let autre = Identifiant::depuis_entropie(Genre::Utilisateur, [0x52; 16]);

    let sortie = asl(&[
        "--state",
        &bac.chemin().to_string_lossy(),
        "--directory",
        MUET,
        "enrolled",
        autre.texte().as_str(),
    ]);
    assert_eq!(code(&sortie), Some(4), "{}", texte(&sortie.stderr));
}

#[test]
fn identity_dit_d_ou_vient_l_identite() {
    // `--state` est pris tel quel : l'identité s'y lit, la provenance est
    // dite, et rien n'est à signaler sur la sortie d'erreur — ni repli, ni
    // conflit, quoi que porte la maison de qui lance l'essai.
    let bac = Bac::neuf("identity-origine");
    let machine = poser_une_identite(bac.chemin(), 0o600);
    let sortie = asl(&["--state", &bac.chemin().to_string_lossy(), "identity"]);
    assert_eq!(code(&sortie), Some(0), "{}", texte(&sortie.stderr));
    let dit = texte(&sortie.stdout);
    assert!(dit.contains(machine.texte().as_str()), "{dit}");
    assert!(dit.contains("lue depuis --state"), "{dit}");
    assert_eq!(texte(&sortie.stderr), "");
}

// ── Personne n'a répondu : code 4 ───────────────────────────────────────────

#[test]
fn un_annuaire_qui_ne_repond_pas_rend_quatre() {
    // La distinction qui compte : `4` est un réseau, `3` serait un droit.
    let bac = Bac::neuf("injoignable");

    let sortie = asl(&[
        "--state",
        &bac.chemin().to_string_lossy(),
        "--directory",
        MUET,
        "diagnose",
    ]);
    assert_eq!(code(&sortie), Some(4), "{}", texte(&sortie.stderr));
    assert!(
        texte(&sortie.stderr).contains("2 secondes"),
        "la borne est celle qu'on a posée"
    );
}

// ── `asl where n-… asl-directory` et le cache des racines (0.21.0) ──────────

#[test]
fn un_annuaire_ne_se_resout_que_par_asl_directory_et_le_refus_le_dit() {
    // Refusé à la lecture de la ligne — code 1, rien n'a été essayé.
    let sortie = asl(&["where", "n-7MSV5RPCXBZH25PQM4ZPE5X87P", "depot"]);
    assert_eq!(code(&sortie), Some(1), "{}", texte(&sortie.stderr));
    let dit = texte(&sortie.stderr);
    assert!(dit.contains("asl where <n-…> asl-directory"), "{dit}");
}

#[test]
fn le_diagnostic_dit_d_ou_vient_chaque_locateur_et_ignore_un_cache_corrompu() {
    let bac = Bac::neuf("cache-racines");
    let etat = bac.chemin().to_string_lossy().into_owned();
    // Un locateur appris pour nitrogen, sur un autre port : il passe en tête
    // des IPv6, et se dit « appris » ; les embarqués suivent en secours.
    std::fs::write(
        bac.chemin().join("racines"),
        format!(
            "appris_a = {}\nracine = n-0PWT8HZD80QMSPPDZ5CQXXYHQC [2001:db8::1]:7000\n",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        ),
    )
    .expect("poser le cache");
    let sortie = asl(&["--state", &etat, "diagnose"]);
    let dit = texte(&sortie.stdout);
    let premiere = dit
        .lines()
        .find(|ligne| ligne.trim_start().starts_with("1."))
        .expect("une première ligne d'ordre");
    assert!(premiere.contains("[2001:db8::1]:7000"), "{dit}");
    assert!(premiere.contains("(IPv6, appris)"), "{dit}");
    assert!(dit.contains("(IPv6, embarqué)"), "{dit}");
    assert!(dit.contains("appris il y a 0 h"), "{dit}");

    // **CORROMPU : IGNORÉ, DIT, JAMAIS UNE PANNE DE CONFIGURATION** — les
    // racines embarquées seules, dans leur ordre d'usine.
    std::fs::write(bac.chemin().join("racines"), "ceci n'est pas un cache\n")
        .expect("corrompre le cache");
    let sortie = asl(&["--state", &etat, "diagnose"]);
    assert_ne!(code(&sortie), Some(2), "{}", texte(&sortie.stderr));
    let dit = texte(&sortie.stdout);
    assert!(dit.contains("ILLISIBLE, ignoré"), "{dit}");
    assert!(!dit.contains("appris)"), "{dit}");
    assert!(dit.contains("2001:41d0:20a:900::1dd4"), "{dit}");
}

// ── `asl domains`, `asl domain` (serveur 0.39.0) ─────────────────────────────

#[test]
fn domain_sans_domaine_ou_avec_une_option_inconnue_est_une_faute_d_usage() {
    // Code 1, et rien n'est joint : l'annuaire visé ne répond pas.
    for ligne in [
        &["domain"][..],
        &["domain", "--where"][..],
        &["domain", "Maison", "--verbose"][..],
        &["domain", "Maison", "Grenier"][..],
        &["domains", "Maison"][..],
    ] {
        let mut complete = vec!["--directory", MUET];
        complete.extend_from_slice(ligne);
        let sortie = asl(&complete);
        assert_eq!(
            code(&sortie),
            Some(1),
            "{ligne:?} : {}",
            texte(&sortie.stderr)
        );
    }
}

#[test]
fn domains_et_domain_lisent_l_identite_avant_toute_connexion() {
    // Sur la voie machine : sans identité, code 2, tout de suite.
    let bac = Bac::neuf("domaines-sans-identite");
    for ligne in [&["domains"][..], &["domain", "Maison", "--where"][..]] {
        let depart = std::time::Instant::now();
        let mut complete = vec![
            "--state",
            bac.chemin().to_str().expect("un chemin UTF-8"),
            "--directory",
            MUET,
        ];
        complete.extend_from_slice(ligne);
        let sortie = asl(&complete);
        assert_eq!(
            code(&sortie),
            Some(2),
            "{ligne:?} : {}",
            texte(&sortie.stderr)
        );
        assert!(
            depart.elapsed() < std::time::Duration::from_secs(2),
            "{ligne:?}"
        );
    }
}
