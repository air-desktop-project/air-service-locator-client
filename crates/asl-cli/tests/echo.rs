//! **`asl echo` ET `asl ping`, DE BOUT EN BOUT** : deux processus `asl`, deux
//! identités de machine, un annuaire de banc en face — et des sondes que
//! l'essai forge lui-même.
//!
//! # CE QUI EST VRAI ICI, ET CE QUI EST FEINT
//!
//! Vrais : les deux binaires, leurs sockets, la poignée de main, le tri de la
//! socket partagée, les datagrammes, **le jeton** — signé par la clé
//! d'identité du banc, lié aux deux clés — et chaque signature. Feint :
//! l'annuaire ne vérifie ni preuve ni droit ; c'est l'essai qui dit qui a le
//! droit ([`banc::AnnuaireDEcho`]).
//!
//! # LE VERDICT MESURÉ SUR UDP
//!
//! Depuis le serveur 0.43.0, l'annuaire pousse `joignable` sur le point UDP
//! de l'écho quand sa signature a tenu — un verdict qu'un `asl-proto` de
//! 0.42.0 refusait. [`l_echo_dit_le_verdict_joignable_que_l_annuaire_pousse`]
//! le fait pousser par le banc, et vérifie que l'écho le lit et le dit.

#[path = "../../asl-client-tokio/tests/banc/mod.rs"]
mod banc;

use std::io::Read as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use asl_cle::CleSecrete;
use asl_echo::{
    DefiEcho, Jeton, REPONSE_OCTETS, REQUETE_OCTETS, Reponse, SondeAnnuaire, SondeJeton,
};
use asl_id::{Genre, Identifiant};
use banc::{AnnuaireDEcho, EtatDEcho, cle_de_banc, lever_a_plusieurs_qui_pousse, materiel};
use tokio::net::UdpSocket;

/// Les deux machines de l'essai : l'écho, et celle qui sonde.
const GRAINE_ECHO: u8 = 0x33;
const GRAINE_SONDEUR: u8 = 0x44;

fn machine_echo() -> Identifiant {
    Identifiant::depuis_entropie(Genre::Machine, [0x70; 16])
}

fn machine_sondeur() -> Identifiant {
    Identifiant::depuis_entropie(Genre::Machine, [0x80; 16])
}

fn cle(graine: u8) -> CleSecrete {
    CleSecrete::depuis_entropie([graine; 32])
}

/// Un répertoire d'état, effacé à la fin.
struct Bac(PathBuf);

impl Bac {
    fn neuf(nom: &str) -> Self {
        let ou = std::env::temp_dir().join(format!("asl-echo-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&ou);
        std::fs::create_dir_all(&ou).expect("un répertoire d'essai");
        Self(ou)
    }
}

impl Drop for Bac {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Écrit l'identité d'une machine, en `0600`.
fn identite(bac: &Bac, machine: Identifiant, graine: u8) {
    use std::os::unix::fs::PermissionsExt as _;
    let ou = bac.0.join("identite");
    std::fs::write(
        &ou,
        format!(
            "machine = {}\ngraine = {}\n",
            machine.texte().as_str(),
            format!("{graine:02x}").repeat(32)
        ),
    )
    .expect("l'identité s'écrit");
    std::fs::set_permissions(&ou, std::fs::Permissions::from_mode(0o600)).expect("le mode");
}

/// `asl`, dans un environnement propre, contre ce banc.
fn asl(annuaire: &str, etat: &Path, arguments: &[&str]) -> Command {
    let mut commande = Command::new(env!("CARGO_BIN_EXE_asl"));
    commande
        .arg("--directory")
        .arg(annuaire)
        .arg("--state")
        .arg(etat)
        .args(arguments)
        .env_remove("ASL_DIRECTORY")
        .env_remove("ASL_ROOTS")
        .env_remove("ASL_STATE")
        .env("ASL_TIMEOUT", "10");
    commande
}

/// Le décor : un banc, un écho qui tourne, deux identités.
struct Decor {
    annuaire: String,
    identite_du_banc: Identifiant,
    cle_du_banc: CleSecrete,
    etat: Arc<Mutex<EtatDEcho>>,
    echo: Child,
    port: u16,
    sondeur: Bac,
    _bac_echo: Bac,
    tache: tokio::task::JoinHandle<()>,
    pousser: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
}

impl Decor {
    /// Lève le banc, lance `asl echo`, et attend son annonce.
    async fn lever(nom: &str, sans_droit: Vec<Identifiant>) -> Self {
        let (identite_du_banc, cert, pkcs8) = materiel(nom);
        let etat: Arc<Mutex<EtatDEcho>> = Arc::default();
        let service = AnnuaireDEcho {
            cle: Arc::new(cle_de_banc(nom)),
            echo: (machine_echo(), cle(GRAINE_ECHO).publique()),
            sondeur: (machine_sondeur(), cle(GRAINE_SONDEUR).publique()),
            compte: Identifiant::depuis_entropie(Genre::Utilisateur, [0x55; 16]),
            sans_droit,
            etat: Arc::clone(&etat),
        };
        let (adresse, tache, pousser) = lever_a_plusieurs_qui_pousse(cert, pkcs8, service).await;
        let annuaire = format!("{adresse}={}", identite_du_banc.texte().as_str());

        let bac_echo = Bac::neuf(&format!("{nom}-echo"));
        identite(&bac_echo, machine_echo(), GRAINE_ECHO);
        let sondeur = Bac::neuf(&format!("{nom}-sondeur"));
        identite(&sondeur, machine_sondeur(), GRAINE_SONDEUR);

        let echo = asl(&annuaire, &bac_echo.0, &["echo"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("asl echo se lance");
        let mut port = None;
        for _ in 0..200 {
            port = etat.lock().unwrap().port;
            if port.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let port = port.expect("asl echo s'annonce en moins de dix secondes");
        Self {
            annuaire,
            identite_du_banc,
            cle_du_banc: cle_de_banc(nom),
            etat,
            echo,
            port,
            sondeur,
            _bac_echo: bac_echo,
            tache,
            pousser,
        }
    }

    /// `asl ping`, depuis l'autre machine — hors de l'ordonnanceur, qui doit
    /// continuer de servir le banc pendant ce temps.
    async fn ping(&self, cible: &str) -> Output {
        let mut commande = asl(&self.annuaire, &self.sondeur.0, &["ping", cible]);
        tokio::task::spawn_blocking(move || commande.output().expect("asl ping se lance"))
            .await
            .expect("la tâche aboutit")
    }

    fn ecoute(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], self.port))
    }

    /// Arrête l'écho par `SIGTERM`, comme systemd le fera, et rend ce qu'il
    /// a dit.
    fn arreter(mut self) -> (Option<i32>, String) {
        let _ = Command::new("kill")
            .arg("-TERM")
            .arg(self.echo.id().to_string())
            .status();
        let statut = self.echo.wait().expect("il s'arrête");
        let mut dit = String::new();
        if let Some(mut sortie) = self.echo.stdout.take() {
            let _ = sortie.read_to_string(&mut dit);
        }
        self.tache.abort();
        (statut.code(), dit)
    }
}

impl Drop for Decor {
    fn drop(&mut self) {
        let _ = self.echo.kill();
        let _ = self.echo.wait();
    }
}

fn texte(octets: &[u8]) -> String {
    String::from_utf8_lossy(octets).into_owned()
}

/// Envoie un datagramme à l'écho, et rend ce qui revient dans la seconde.
async fn sonder(vers: SocketAddr, datagramme: &[u8]) -> Option<Vec<u8>> {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("une socket");
    socket.send_to(datagramme, vers).await.expect("envoyé");
    let mut recu = [0_u8; 1_500];
    match tokio::time::timeout(Duration::from_millis(1_500), socket.recv_from(&mut recu)).await {
        Ok(Ok((lus, _))) => Some(recu.get(..lus).unwrap_or_default().to_vec()),
        _ => None,
    }
}

fn maintenant_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

// ── Les essais ──────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn asl_ping_prouve_l_echo_par_son_nom_et_par_son_identifiant() {
    let decor = Decor::lever("echo-ping", Vec::new()).await;

    for cible in ["grenier", machine_echo().texte().as_str()] {
        let sortie = decor.ping(cible).await;
        let dit = texte(&sortie.stdout);
        assert_eq!(
            sortie.status.code(),
            Some(0),
            "{cible} : {dit}\n{}",
            texte(&sortie.stderr)
        );
        assert!(dit.contains("joignable d'ici"), "{dit}");
        assert!(dit.contains("preuve vérifiée"), "{dit}");
        // **D'OÙ LA SONDE EST PARTIE, ET COMMENT L'ÉCHO L'A VUE** — signé.
        assert!(
            dit.contains(&format!(
                "sonde partie de {} (carbon)",
                machine_sondeur().texte().as_str()
            )),
            "{dit}"
        );
        assert!(dit.contains("vue par l'écho comme 127.0.0.1:"), "{dit}");
        assert!(
            dit.contains(&format!("127.0.0.1:{}", decor.port)),
            "le candidat est le port de l'écho : {dit}"
        );
        assert!(
            dit.contains(&format!(
                "grenier ({}) : joignable d'ici",
                machine_echo().texte().as_str()
            )),
            "{dit}"
        );
        assert!(
            dit.contains(&format!(
                "selon la racine {}",
                decor.identite_du_banc.texte().as_str()
            )),
            "{dit}"
        );
    }
    assert_eq!(decor.etat.lock().unwrap().jetons, 2, "un jeton par ping");

    // **L'ÉCHO LE DIT, SOBREMENT, ET S'ARRÊTE PROPREMENT SUR SIGTERM.**
    let (code, dit) = decor.arreter();
    assert_eq!(code, Some(0), "{dit}");
    assert!(dit.contains("preuve rendue"), "{dit}");
    assert!(
        dit.contains(machine_sondeur().texte().as_str()),
        "le sondeur est nommé : {dit}"
    );
    assert!(dit.contains("écho retiré"), "{dit}");
}

#[tokio::test(flavor = "multi_thread")]
async fn sans_droit_ou_sans_machine_c_est_introuvable() {
    let decor = Decor::lever("echo-sans-droit", vec![machine_echo()]).await;

    let sortie = decor.ping(machine_echo().texte().as_str()).await;
    assert_eq!(sortie.status.code(), Some(3), "{}", texte(&sortie.stdout));
    assert!(
        texte(&sortie.stderr).contains("introuvable"),
        "{}",
        texte(&sortie.stderr)
    );
    assert_eq!(decor.etat.lock().unwrap().jetons, 0, "aucun jeton délivré");

    // Un nom que ce compte ne voit pas : dit tel, code 3.
    let sortie = decor.ping("atelier").await;
    assert_eq!(sortie.status.code(), Some(3));
    assert!(texte(&sortie.stderr).contains("« atelier »"));
    let _ = decor.arreter();
}

#[tokio::test(flavor = "multi_thread")]
async fn l_echo_repond_a_l_annuaire_du_bail_et_se_tait_devant_le_reste() {
    let decor = Decor::lever("echo-silence", Vec::new()).await;
    let vers = decor.ecoute();
    let n = |marque| DefiEcho::depuis_octets([marque; 16]);

    // **LA SONDE DE L'ANNUAIRE QUI TIENT LE BAIL** : signée de sa clé
    // d'identité, vérifiée hors ligne — et la preuve est pour lui.
    let sonde = SondeAnnuaire::signer(
        n(1),
        decor.identite_du_banc,
        machine_echo(),
        maintenant_ms(),
        &decor.cle_du_banc,
    )
    .unwrap()
    .octets();
    let reponse = sonder(vers, &sonde)
        .await
        .expect("l'annuaire du bail est cru");
    // **AUCUNE AMPLIFICATION** : 132 octets pour 384.
    assert_eq!(reponse.len(), REPONSE_OCTETS);
    assert!(reponse.len() < sonde.len());
    let lue = Reponse::lire(&reponse).expect("elle se lit");
    assert_eq!(
        lue.verifier(
            &n(1),
            machine_echo(),
            decor.identite_du_banc,
            &cle(GRAINE_ECHO).publique()
        ),
        Ok(())
    );
    // Rejouée : le silence.
    assert_eq!(
        sonder(vers, &sonde).await,
        None,
        "un défi ne sert qu'une fois"
    );

    // **UN ANNUAIRE INCONNU** : le silence.
    let intrus = cle(0x99);
    let intrus_id = asl_cle::identifiant_de_racine(&intrus.publique());
    let inconnue = SondeAnnuaire::signer(n(2), intrus_id, machine_echo(), maintenant_ms(), &intrus)
        .unwrap()
        .octets();
    assert_eq!(sonder(vers, &inconnue).await, None);

    // **UN JETON QUI N'EST PAS D'UNE RACINE** : le silence.
    let faux = Jeton::emettre(
        &intrus,
        machine_echo(),
        cle(GRAINE_ECHO).publique(),
        machine_sondeur(),
        cle(GRAINE_SONDEUR).publique(),
        maintenant_ms(),
    )
    .unwrap();
    let signee = SondeJeton::signer(n(3), faux, &cle(GRAINE_SONDEUR)).octets();
    assert_eq!(sonder(vers, &signee).await, None);

    // **UN VRAI JETON, PRÉSENTÉ PAR UN TIERS** — il n'est pas porteur.
    let vrai = Jeton::emettre(
        &decor.cle_du_banc,
        machine_echo(),
        cle(GRAINE_ECHO).publique(),
        machine_sondeur(),
        cle(GRAINE_SONDEUR).publique(),
        maintenant_ms(),
    )
    .unwrap();
    let volee = SondeJeton::signer(n(4), vrai, &cle(0x77)).octets();
    assert_eq!(sonder(vers, &volee).await, None);
    // Le même, par qui il nomme : la preuve.
    let juste = SondeJeton::signer(n(5), vrai, &cle(GRAINE_SONDEUR)).octets();
    assert_eq!(
        sonder(vers, &juste).await.map(|octets| octets.len()),
        Some(REPONSE_OCTETS)
    );

    // **CE QUI N'A PAS LA LONGUEUR D'UNE SONDE** : le silence, sans rien
    // vérifier — ni un en-tête d'écho tronqué, ni un datagramme plus gros.
    assert_eq!(sonder(vers, &[0x0A, 0x01, 0, 0]).await, None);
    let mut gros = sonde.to_vec();
    gros.resize(REQUETE_OCTETS * 3, 0);
    assert_eq!(sonder(vers, &gros).await, None);

    let (code, dit) = decor.arreter();
    assert_eq!(code, Some(0), "{dit}");
}

#[tokio::test(flavor = "multi_thread")]
async fn personne_ne_repond_d_ici_et_le_code_le_dit() {
    // L'écho est arrêté : l'annuaire se souvient encore de son port, mais
    // rien n'écoute plus. Le ping doit dire « pas de réponse d'ici », code 1.
    let decor = Decor::lever("echo-muet", Vec::new()).await;
    let annuaire = decor.annuaire.clone();
    let sondeur = Bac::neuf("echo-muet-sondeur-bis");
    identite(&sondeur, machine_sondeur(), GRAINE_SONDEUR);
    let port = decor.port;
    let etat = Arc::clone(&decor.etat);
    // On garde le banc vivant ; seul l'écho s'arrête.
    let mut echo = decor;
    let _ = echo.echo.kill();
    let _ = echo.echo.wait();
    etat.lock().unwrap().port = Some(port);

    let mut commande = asl(&annuaire, &sondeur.0, &["ping", "grenier"]);
    let sortie = tokio::task::spawn_blocking(move || commande.output().unwrap())
        .await
        .unwrap();
    let dit = texte(&sortie.stdout);
    assert_eq!(
        sortie.status.code(),
        Some(1),
        "{dit}\n{}",
        texte(&sortie.stderr)
    );
    assert!(dit.contains("pas de réponse (3 envois, 3 s)"), "{dit}");
    assert!(texte(&sortie.stderr).contains("pas de réponse d'ici"));
    echo.tache.abort();
}

/// Un faux écho, tenu par l'essai, à qui l'annuaire renvoie les sondeurs :
/// il répond à chaque sonde par ce que `repondre` en fait.
async fn faux_echo(
    repondre: fn(&[u8], SocketAddr) -> Vec<u8>,
) -> (u16, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("une socket");
    let port = socket.local_addr().unwrap().port();
    let tache = tokio::spawn(async move {
        let mut recu = [0_u8; 1_500];
        while let Ok((lus, source)) = socket.recv_from(&mut recu).await {
            let reponse = repondre(recu.get(..lus).unwrap_or_default(), source);
            let _ = socket.send_to(&reponse, source).await;
        }
    });
    (port, tache)
}

/// `asl ping grenier`, l'annuaire renvoyant vers ce port.
async fn ping_vers(nom: &str, port: u16) -> Output {
    let decor = Decor::lever(nom, Vec::new()).await;
    decor.etat.lock().unwrap().port = Some(port);
    let sortie = decor.ping("grenier").await;
    let _ = decor.arreter();
    sortie
}

#[tokio::test(flavor = "multi_thread")]
async fn quelqu_un_d_autre_repond_a_cette_adresse() {
    // **UNE RÉPONSE BIEN FORMÉE, À NOTRE DÉFI, SIGNÉE D'UNE AUTRE CLÉ** :
    // l'adresse a été reprise. C'est ce qu'un trois-temps TCP n'aurait pas vu.
    let (port, tache) = faux_echo(|sonde, source| {
        let defi =
            SondeJeton::lire(sonde).map_or(DefiEcho::depuis_octets([0; 16]), |lue| lue.defi());
        Reponse::signer(
            defi,
            machine_echo(),
            asl_echo::Adresse::depuis_source(source),
            machine_sondeur(),
            &cle(0x77),
        )
        .unwrap()
        .octets()
        .to_vec()
    })
    .await;
    let sortie = ping_vers("echo-autre-cle", port).await;
    let dit = texte(&sortie.stdout);
    assert_eq!(
        sortie.status.code(),
        Some(2),
        "{dit}\n{}",
        texte(&sortie.stderr)
    );
    assert!(dit.contains("QUELQU'UN D'AUTRE RÉPOND"), "{dit}");
    assert!(texte(&sortie.stderr).contains("quelqu'un d'autre répond"));
    tache.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn une_reponse_illisible_se_dit_telle() {
    let (port, tache) = faux_echo(|_, _| vec![0x0A, 0x81, 0xFF]).await;
    let sortie = ping_vers("echo-illisible", port).await;
    let dit = texte(&sortie.stdout);
    assert_eq!(
        sortie.status.code(),
        Some(2),
        "{dit}\n{}",
        texte(&sortie.stderr)
    );
    assert!(dit.contains("réponse illisible"), "{dit}");
    tache.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn l_echo_dit_le_verdict_joignable_que_l_annuaire_pousse() {
    let decor = Decor::lever("echo-joignable", Vec::new()).await;
    // Le port est dans la plage de l'écho.
    assert!((6631..=6639).contains(&decor.port), "{}", decor.port);
    // **CE QUE L'ANNUAIRE 0.43.0 POUSSE** quand la preuve a tenu : `joignable`
    // sur le point UDP, avec le candidat qui a répondu.
    let port = decor.port;
    let poussee = format!(
        r#"{{"vu_depuis":{{"adresse":"127.0.0.1","port":{port}}},"derriere_nat":"non","joignabilite":[{{"protocole":"udp","port":{port},"verdict":"joignable","candidat":"127.0.0.1:{port}","origine":"reflexif","a":1789217731000}}]}}"#
    );
    let mut tampons = asl_proto::cadrage::TamponsReponse::nouveaux();
    asl_proto::Poussee::decoder(poussee.as_bytes(), &mut tampons)
        .expect("l'asl-proto épinglé lit un verdict mesuré sur UDP");
    decor
        .pousser
        .send(poussee.into_bytes())
        .expect("le banc écoute");
    // Le temps que la poussée traverse, et qu'une boucle d'entretien la lise.
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    let (code, dit) = decor.arreter();
    assert_eq!(code, Some(0), "{dit}");
    assert!(
        dit.lines().any(
            |ligne| ligne.starts_with(&format!("verdict        udp:{port}"))
                && ligne.contains("joignable      constaté à 1789217731000")
        ),
        "l'écho dit le verdict poussé : {dit}"
    );
    assert!(!dit.contains("ILLISIBLE"), "{dit}");
}
