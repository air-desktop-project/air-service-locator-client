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
//! # LA PASSERELLE, CONTRE UNE FAUSSE BOX
//!
//! **Aucun essai ne parle à une vraie box** : [`asl`] coupe UPnP
//! (`ASL_ECHO_UPNP=0`) pour tous, et les essais de la passerelle lèvent un
//! faux IGD sur la boucle locale — un répondeur SSDP en unicast
//! (`ASL_ECHO_SSDP`) et un serveur HTTP qui sert une description et répond
//! en SOAP ([`FauxIgd`]). Aucun `M-SEARCH` ne part sur le réseau de la
//! machine qui fait tourner les essais.
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

/// `asl`, dans un environnement propre, contre ce banc — **UPnP coupé** :
/// aucun essai ne parle à la box du réseau qui le fait tourner.
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
        .env_remove("ASL_ECHO_SSDP")
        .env("ASL_ECHO_UPNP", "0")
        .env("ASL_TIMEOUT", "10");
    commande
}

/// Lance `asl echo` — avec ces arguments et cet environnement en plus.
fn lancer_l_echo(
    annuaire: &str,
    etat: &Path,
    arguments: &[&str],
    environnement: &[(&str, &str)],
) -> Child {
    let mut commande = asl(annuaire, etat, arguments);
    for (nom, valeur) in environnement {
        commande.env(nom, valeur);
    }
    commande
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("asl echo se lance")
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
    bac_echo: Bac,
    tache: tokio::task::JoinHandle<()>,
    pousser: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
}

impl Decor {
    /// Lève le banc, lance `asl echo`, et attend son annonce.
    async fn lever(nom: &str, sans_droit: Vec<Identifiant>) -> Self {
        Self::lever_avec(nom, sans_droit, None, &["echo"], &[]).await
    }

    /// La même chose, avec la version que le banc dit, et les arguments et
    /// l'environnement de l'écho.
    async fn lever_avec(
        nom: &str,
        sans_droit: Vec<Identifiant>,
        version: Option<&'static str>,
        arguments: &[&str],
        environnement: &[(&str, &str)],
    ) -> Self {
        let (identite_du_banc, cert, pkcs8) = materiel(nom);
        let etat: Arc<Mutex<EtatDEcho>> = Arc::default();
        let service = AnnuaireDEcho {
            cle: Arc::new(cle_de_banc(nom)),
            echo: (machine_echo(), cle(GRAINE_ECHO).publique()),
            sondeur: (machine_sondeur(), cle(GRAINE_SONDEUR).publique()),
            compte: Identifiant::depuis_entropie(Genre::Utilisateur, [0x55; 16]),
            sans_droit,
            etat: Arc::clone(&etat),
            version,
        };
        let (adresse, tache, pousser) = lever_a_plusieurs_qui_pousse(cert, pkcs8, service).await;
        let annuaire = format!("{adresse}={}", identite_du_banc.texte().as_str());

        let bac_echo = Bac::neuf(&format!("{nom}-echo"));
        identite(&bac_echo, machine_echo(), GRAINE_ECHO);
        let sondeur = Bac::neuf(&format!("{nom}-sondeur"));
        identite(&sondeur, machine_sondeur(), GRAINE_SONDEUR);

        let echo = lancer_l_echo(&annuaire, &bac_echo.0, arguments, environnement);
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
            bac_echo,
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

// ── La passerelle, contre un faux IGD ───────────────────────────────────────

/// Ce que la fausse box fait des demandes.
#[derive(Debug, Clone, Default)]
struct ReglageIgd {
    /// Ce que `GetExternalIPAddress` rend.
    externe: &'static str,
    /// La box n'accepte que le bail permanent (`725` sinon).
    permanent_seulement: bool,
    /// Tant de `718 ConflictInMappingEntry` avant d'accepter.
    conflits: u32,
    /// Le délai avant de répondre au `M-SEARCH` : une vraie box le tire au
    /// hasard jusqu'à `MX` secondes.
    retard_ssdp: Duration,
}

/// Une fausse box sur la boucle locale : un répondeur SSDP en unicast, et un
/// serveur HTTP qui sert une description IGD v1 et répond aux actions SOAP.
/// Elle retient chaque action, et son corps.
struct FauxIgd {
    /// Où envoyer le `M-SEARCH` (`ASL_ECHO_SSDP`).
    ssdp: SocketAddr,
    /// Les `M-SEARCH` reçus.
    recherches: Arc<Mutex<u32>>,
    /// Les actions SOAP reçues, dans l'ordre : nom, corps.
    actions: Arc<Mutex<Vec<(String, String)>>>,
    taches: Vec<tokio::task::JoinHandle<()>>,
}

/// La description que sert la fausse box : IGD v1, `WANIPConnection:1`.
const DESCRIPTION_IGD: &str = "<?xml version=\"1.0\"?>\n<root xmlns=\"urn:schemas-upnp-org:device-1-0\">\
    <device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>\
    <deviceList><device><deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>\
    <deviceList><device><deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>\
    <serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>\
    <serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId><controlURL>/ctl/IPConn</controlURL>\
    </service></serviceList></device></deviceList></device></deviceList></device></root>";

/// La valeur d'un élément dans un corps SOAP.
fn valeur(corps: &str, nom: &str) -> Option<String> {
    let (_, apres) = corps.split_once(&format!("<{nom}>"))?;
    let (dedans, _) = apres.split_once(&format!("</{nom}>"))?;
    Some(dedans.to_owned())
}

impl FauxIgd {
    async fn lever(reglage: ReglageIgd) -> Self {
        let http = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("un port HTTP");
        let port_http = http.local_addr().unwrap().port();
        let udp = UdpSocket::bind("127.0.0.1:0").await.expect("un port SSDP");
        let ssdp = udp.local_addr().unwrap();
        let recherches: Arc<Mutex<u32>> = Arc::default();
        let actions: Arc<Mutex<Vec<(String, String)>>> = Arc::default();

        let compte = Arc::clone(&recherches);
        let retard = reglage.retard_ssdp;
        let udp = Arc::new(udp);
        let repondeur = tokio::spawn(async move {
            let mut tampon = [0_u8; 2_048];
            while let Ok((lus, source)) = udp.recv_from(&mut tampon).await {
                let recu =
                    String::from_utf8_lossy(tampon.get(..lus).unwrap_or_default()).into_owned();
                if !recu.starts_with("M-SEARCH * HTTP/1.1\r\n") {
                    continue;
                }
                {
                    let mut vus = compte.lock().unwrap();
                    *vus = vus.saturating_add(1);
                }
                let cible = recu
                    .lines()
                    .find_map(|ligne| ligne.strip_prefix("ST: "))
                    .unwrap_or_default()
                    .to_owned();
                let reponse = format!(
                    "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nST: {cible}\r\n\
                     USN: uuid:faux::{cible}\r\nEXT:\r\nLOCATION: http://127.0.0.1:{port_http}/rootDesc.xml\r\n\r\n"
                );
                let udp = Arc::clone(&udp);
                tokio::spawn(async move {
                    tokio::time::sleep(retard).await;
                    let _ = udp.send_to(reponse.as_bytes(), source).await;
                });
            }
        });

        let journal = Arc::clone(&actions);
        let reglage = Arc::new(Mutex::new(reglage));
        let serveur = tokio::spawn(async move {
            while let Ok((flux, _)) = http.accept().await {
                let journal = Arc::clone(&journal);
                let reglage = Arc::clone(&reglage);
                tokio::spawn(servir(flux, journal, reglage));
            }
        });
        Self {
            ssdp,
            recherches,
            actions,
            taches: vec![repondeur, serveur],
        }
    }

    fn actions(&self) -> Vec<(String, String)> {
        self.actions.lock().unwrap().clone()
    }

    /// Les ports externes des actions `nom`, dans l'ordre.
    fn ports(&self, nom: &str) -> Vec<(u16, String)> {
        self.actions()
            .iter()
            .filter(|(action, _)| action == nom)
            .map(|(_, corps)| {
                (
                    valeur(corps, "NewExternalPort")
                        .and_then(|port| port.parse().ok())
                        .unwrap_or(0),
                    valeur(corps, "NewLeaseDuration").unwrap_or_default(),
                )
            })
            .collect()
    }
}

impl Drop for FauxIgd {
    fn drop(&mut self) {
        for tache in &self.taches {
            tache.abort();
        }
    }
}

/// **LA MÊME BOX, VUE EN IPv6** : un répondeur SSDP sur `[::1]` qui répond
/// tout de suite, et sert — sur `[::1]` aussi — la description de la box.
/// Jointe en IPv6, elle ne peut rien donner pour la redirection IPv4 : c'est
/// ce que la Livebox a fait à 0.24.1. `repond: false` : un IPv6 muet.
struct VoisinV6 {
    ssdp: SocketAddr,
    recherches: Arc<Mutex<u32>>,
    taches: Vec<tokio::task::JoinHandle<()>>,
}

impl VoisinV6 {
    async fn lever(repond: bool) -> Self {
        let http = tokio::net::TcpListener::bind("[::1]:0")
            .await
            .expect("un port HTTP en IPv6");
        let port_http = http.local_addr().unwrap().port();
        let udp = UdpSocket::bind("[::1]:0")
            .await
            .expect("un port SSDP en IPv6");
        let ssdp = udp.local_addr().unwrap();
        let recherches: Arc<Mutex<u32>> = Arc::default();
        let compte = Arc::clone(&recherches);
        let repondeur = tokio::spawn(async move {
            let mut tampon = [0_u8; 2_048];
            while let Ok((lus, source)) = udp.recv_from(&mut tampon).await {
                let recu =
                    String::from_utf8_lossy(tampon.get(..lus).unwrap_or_default()).into_owned();
                if !recu.starts_with("M-SEARCH * HTTP/1.1\r\n") {
                    continue;
                }
                {
                    let mut vus = compte.lock().unwrap();
                    *vus = vus.saturating_add(1);
                }
                if !repond {
                    continue;
                }
                let cible = recu
                    .lines()
                    .find_map(|ligne| ligne.strip_prefix("ST: "))
                    .unwrap_or_default()
                    .to_owned();
                let reponse = format!(
                    "HTTP/1.1 200 OK\r\nST: {cible}\r\nUSN: uuid:voisin::{cible}\r\n\
                     LOCATION: http://[::1]:{port_http}/rootDesc.xml\r\n\r\n"
                );
                let _ = udp.send_to(reponse.as_bytes(), source).await;
            }
        });
        let serveur = tokio::spawn(async move {
            while let Ok((mut flux, _)) = http.accept().await {
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
                    let mut morceau = [0_u8; 4_096];
                    let _ = flux.read(&mut morceau).await;
                    let ecrit = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: {}\r\n\
                         Connection: close\r\n\r\n{DESCRIPTION_IGD}",
                        DESCRIPTION_IGD.len()
                    );
                    let _ = flux.write_all(ecrit.as_bytes()).await;
                    let _ = flux.shutdown().await;
                });
            }
        });
        Self {
            ssdp,
            recherches,
            taches: vec![repondeur, serveur],
        }
    }
}

impl Drop for VoisinV6 {
    fn drop(&mut self) {
        for tache in &self.taches {
            tache.abort();
        }
    }
}

/// Sert une connexion HTTP de la fausse box : une requête, une réponse.
async fn servir(
    mut flux: tokio::net::TcpStream,
    journal: Arc<Mutex<Vec<(String, String)>>>,
    reglage: Arc<Mutex<ReglageIgd>>,
) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let mut lus = Vec::new();
    let mut morceau = [0_u8; 4_096];
    let (tete, mut corps) = loop {
        let Ok(combien) = flux.read(&mut morceau).await else {
            return;
        };
        if combien == 0 {
            return;
        }
        lus.extend_from_slice(morceau.get(..combien).unwrap_or_default());
        let texte = String::from_utf8_lossy(&lus).into_owned();
        if let Some((tete, corps)) = texte.split_once("\r\n\r\n") {
            break (tete.to_owned(), corps.to_owned());
        }
    };
    let longueur: usize = tete
        .lines()
        .find_map(|ligne| ligne.strip_prefix("Content-Length: "))
        .and_then(|longueur| longueur.trim().parse().ok())
        .unwrap_or(0);
    while corps.len() < longueur {
        let Ok(combien) = flux.read(&mut morceau).await else {
            return;
        };
        if combien == 0 {
            break;
        }
        corps.push_str(&String::from_utf8_lossy(
            morceau.get(..combien).unwrap_or_default(),
        ));
    }
    let (statut, reponse) = if tete.starts_with("GET /rootDesc.xml ") {
        ("200 OK", DESCRIPTION_IGD.to_owned())
    } else if tete.starts_with("POST /ctl/IPConn ") {
        let action = tete
            .lines()
            .find_map(|ligne| ligne.strip_prefix("SOAPAction: "))
            .and_then(|valeur| valeur.trim_matches('"').split_once('#'))
            .map(|(_, action)| action.to_owned())
            .unwrap_or_default();
        journal
            .lock()
            .unwrap()
            .push((action.clone(), corps.clone()));
        let faute = |code: u16, description: &str| {
            (
                "500 Internal Server Error",
                format!(
                    "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body>\
                     <s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail>\
                     <UPnPError xmlns=\"urn:schemas-upnp-org:control-1-0\"><errorCode>{code}</errorCode>\
                     <errorDescription>{description}</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>"
                ),
            )
        };
        let reussi = |valeurs: &str| {
            (
                "200 OK",
                format!(
                    "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body>\
                     <u:{action}Response xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">{valeurs}\
                     </u:{action}Response></s:Body></s:Envelope>"
                ),
            )
        };
        let mut reglage = reglage.lock().unwrap();
        match action.as_str() {
            "AddPortMapping" => {
                let bail = valeur(&corps, "NewLeaseDuration").unwrap_or_default();
                if reglage.permanent_seulement && bail != "0" {
                    faute(725, "OnlyPermanentLeasesSupported")
                } else if reglage.conflits > 0 {
                    reglage.conflits = reglage.conflits.saturating_sub(1);
                    faute(718, "ConflictInMappingEntry")
                } else {
                    reussi("")
                }
            }
            "GetExternalIPAddress" => reussi(&format!(
                "<NewExternalIPAddress>{}</NewExternalIPAddress>",
                reglage.externe
            )),
            "DeletePortMapping" => reussi(""),
            _ => faute(401, "Invalid Action"),
        }
    } else {
        ("404 Not Found", String::new())
    };
    let ecrit = format!(
        "HTTP/1.1 {statut}\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reponse}",
        reponse.len()
    );
    let _ = flux.write_all(ecrit.as_bytes()).await;
    let _ = flux.shutdown().await;
}

/// Attend qu'une condition tienne — dix secondes au plus.
async fn attendre(quoi: &str, condition: impl Fn() -> bool) {
    for _ in 0..200 {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("{quoi} : pas en dix secondes");
}

/// L'environnement d'un écho qui parle à la fausse box, et à elle seule.
fn vers_la_fausse_box(igd: &FauxIgd) -> String {
    igd.ssdp.to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn la_box_redirige_le_port_de_l_echo_et_l_annuaire_l_apprend() {
    let igd = FauxIgd::lever(ReglageIgd {
        externe: "127.0.0.1",
        ..ReglageIgd::default()
    })
    .await;
    let ssdp = vers_la_fausse_box(&igd);
    let decor = Decor::lever_avec(
        "echo-upnp",
        Vec::new(),
        Some("0.44.0"),
        &["echo"],
        &[("ASL_ECHO_UPNP", "1"), ("ASL_ECHO_SSDP", &ssdp)],
    )
    .await;
    let port = decor.port;
    let etat = Arc::clone(&decor.etat);
    attendre("l'annonce avec passerelle", || {
        etat.lock()
            .unwrap()
            .annonces
            .iter()
            .any(|annonce| annonce.contains("\"passerelle\""))
    })
    .await;
    let annonces = decor.etat.lock().unwrap().annonces.clone();
    // **DEUX FOIS** : sans le champ d'abord, pour apprendre `vu_depuis` ;
    // avec, une fois la box interrogée — le port seul, jamais l'adresse.
    assert!(!annonces[0].contains("passerelle"), "{annonces:?}");
    assert!(
        annonces.last().unwrap().ends_with(&format!(
            r#","passerelle":{{"port":{port},"via":"upnp"}}}}"#
        )),
        "{annonces:?}"
    );
    // **LE PORT DE L'ÉCHO, ET LUI SEUL** : UDP, le même port externe d'abord,
    // une heure de bail, pour l'adresse d'où l'on a parlé à la box.
    assert!(*igd.recherches.lock().unwrap() >= 1);
    let ajouts: Vec<(String, String)> = igd
        .actions()
        .into_iter()
        .filter(|(action, _)| action == "AddPortMapping")
        .collect();
    assert_eq!(ajouts.len(), 1, "{ajouts:?}");
    let corps = &ajouts[0].1;
    for (nom, attendu) in [
        ("NewProtocol", "UDP".to_owned()),
        ("NewExternalPort", port.to_string()),
        ("NewInternalPort", port.to_string()),
        ("NewInternalClient", "127.0.0.1".to_owned()),
        ("NewLeaseDuration", "3600".to_owned()),
        ("NewPortMappingDescription", "asl-echo".to_owned()),
    ] {
        assert_eq!(
            valeur(corps, nom).as_deref(),
            Some(attendu.as_str()),
            "{nom} : {corps}"
        );
    }
    let memoire = decor.bac_echo.0.join(format!("upnp-{port}"));
    assert!(memoire.exists(), "ce qui est ouvert est retenu");

    // **À L'ARRÊT, LA BOX EST RENDUE PROPRE** — avant le bail.
    let actions_avant = igd.actions().len();
    let (code, dit) = decor.arreter();
    assert_eq!(code, Some(0), "{dit}");
    assert!(
        dit.contains(&format!(
            "redirection UPnP : udp {port} → box 127.0.0.1:{port}, bail 1 h"
        )),
        "{dit}"
    );
    assert!(
        dit.contains(&format!(
            "réannoncée avec la passerelle : port externe {port} (upnp)"
        )),
        "{dit}"
    );
    assert!(
        dit.contains(&format!("redirection retirée : udp {port}")),
        "{dit}"
    );
    let retraits = igd.ports("DeletePortMapping");
    assert_eq!(
        retraits.iter().map(|(p, _)| *p).collect::<Vec<_>>(),
        vec![port]
    );
    assert!(igd.actions().len() > actions_avant);
    assert!(!memoire.exists(), "rien d'ouvert, rien de retenu");
    // Aucune autre action que celles de la redirection du port de l'écho.
    for (action, _) in igd.actions() {
        assert!(
            [
                "AddPortMapping",
                "GetExternalIPAddress",
                "DeletePortMapping"
            ]
            .contains(&action.as_str()),
            "{action}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn un_annuaire_d_avant_0_44_n_entend_pas_parler_de_la_passerelle() {
    let igd = FauxIgd::lever(ReglageIgd {
        externe: "127.0.0.1",
        ..ReglageIgd::default()
    })
    .await;
    let ssdp = vers_la_fausse_box(&igd);
    let decor = Decor::lever_avec(
        "echo-upnp-ancien",
        Vec::new(),
        Some("0.43.0"),
        &["echo"],
        &[("ASL_ECHO_UPNP", "1"), ("ASL_ECHO_SSDP", &ssdp)],
    )
    .await;
    let actions = Arc::clone(&igd.actions);
    attendre("la redirection", || {
        actions
            .lock()
            .unwrap()
            .iter()
            .any(|(action, _)| action == "GetExternalIPAddress")
    })
    .await;
    tokio::time::sleep(Duration::from_millis(1_000)).await;
    let annonces = decor.etat.lock().unwrap().annonces.clone();
    assert!(
        annonces
            .iter()
            .all(|annonce| !annonce.contains("passerelle")),
        "un annuaire d'avant refuserait l'annonce entière : {annonces:?}"
    );
    let (code, dit) = decor.arreter();
    assert_eq!(code, Some(0), "{dit}");
    assert!(
        dit.contains("l'annuaire (0.43.0) ne connaît pas encore le champ `passerelle` (0.44.0)"),
        "{dit}"
    );
    assert!(
        dit.contains("redirection UPnP : udp"),
        "la box, elle, a redirigé : {dit}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn le_permanent_seulement_si_la_box_l_exige_et_un_conflit_fait_tirer_un_port() {
    let igd = FauxIgd::lever(ReglageIgd {
        externe: "127.0.0.1",
        permanent_seulement: true,
        conflits: 1,
        ..ReglageIgd::default()
    })
    .await;
    let ssdp = vers_la_fausse_box(&igd);
    let decor = Decor::lever_avec(
        "echo-upnp-permanent",
        Vec::new(),
        Some("0.44.0"),
        &["echo"],
        &[("ASL_ECHO_UPNP", "1"), ("ASL_ECHO_SSDP", &ssdp)],
    )
    .await;
    let port = decor.port;
    let etat = Arc::clone(&decor.etat);
    attendre("l'annonce avec passerelle", || {
        etat.lock()
            .unwrap()
            .annonces
            .iter()
            .any(|annonce| annonce.contains("\"passerelle\""))
    })
    .await;
    // Une heure d'abord (725), le permanent ensuite ; sur le même port
    // (718), puis un port tiré — permanent aussi.
    let ajouts = igd.ports("AddPortMapping");
    assert_eq!(ajouts.len(), 3, "{ajouts:?}");
    assert_eq!(ajouts[0], (port, "3600".to_owned()));
    assert_eq!(ajouts[1], (port, "0".to_owned()));
    let tire = ajouts[2].0;
    assert_eq!(ajouts[2].1, "0");
    assert!(tire >= 1_024, "{tire}");
    let annonce = decor.etat.lock().unwrap().annonces.last().cloned().unwrap();
    assert!(
        annonce.contains(&format!(r#""passerelle":{{"port":{tire},"via":"upnp"}}"#)),
        "le port accordé, pas celui de l'écho : {annonce}"
    );
    let (code, dit) = decor.arreter();
    assert_eq!(code, Some(0), "{dit}");
    assert!(
        dit.contains("permanente (la box n'accepte que cela) — retirée à l'arrêt"),
        "{dit}"
    );
    assert_eq!(
        igd.ports("DeletePortMapping")
            .iter()
            .map(|(p, _)| *p)
            .collect::<Vec<_>>(),
        vec![tire],
        "la permanente est retirée à l'arrêt"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn apres_un_arret_brutal_la_redirection_est_retiree_au_demarrage_suivant() {
    let igd = FauxIgd::lever(ReglageIgd {
        externe: "127.0.0.1",
        ..ReglageIgd::default()
    })
    .await;
    let ssdp = vers_la_fausse_box(&igd);
    let environnement = [("ASL_ECHO_UPNP", "1"), ("ASL_ECHO_SSDP", ssdp.as_str())];
    let mut decor = Decor::lever_avec(
        "echo-upnp-brutal",
        Vec::new(),
        Some("0.44.0"),
        &["echo"],
        &environnement,
    )
    .await;
    let premier = decor.port;
    let memoire = decor.bac_echo.0.join(format!("upnp-{premier}"));
    let fichier = memoire.clone();
    attendre("la mémoire de la redirection", move || fichier.exists()).await;

    // **SIGKILL** : rien n'est retiré, la mémoire reste.
    decor.echo.kill().expect("tué");
    let _ = decor.echo.wait();
    assert!(memoire.exists(), "un arrêt brutal laisse la mémoire");
    let avant = igd.actions().len();

    decor.echo = lancer_l_echo(
        &decor.annuaire,
        &decor.bac_echo.0,
        &["echo"],
        &environnement,
    );
    let actions = Arc::clone(&igd.actions);
    attendre("le retrait de ce qui était resté", || {
        actions
            .lock()
            .unwrap()
            .iter()
            .skip(avant)
            .any(|(action, corps)| {
                action == "DeletePortMapping"
                    && valeur(corps, "NewExternalPort") == Some(premier.to_string())
            })
    })
    .await;
    attendre("la nouvelle redirection", || {
        actions
            .lock()
            .unwrap()
            .iter()
            .skip(avant)
            .any(|(action, _)| action == "AddPortMapping")
    })
    .await;
    // **LE RETRAIT AVANT TOUTE OUVERTURE.**
    let apres: Vec<String> = igd
        .actions()
        .into_iter()
        .skip(avant)
        .map(|(action, _)| action)
        .collect();
    assert_eq!(apres[0], "DeletePortMapping", "{apres:?}");
    let (code, dit) = decor.arreter();
    assert_eq!(code, Some(0), "{dit}");
    assert!(
        dit.contains(&format!(
            "retiré ce qu'un arrêt brutal avait laissé : la redirection udp {premier} (127.0.0.1)"
        )),
        "{dit}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn un_double_nat_se_dit_et_ne_s_annonce_pas() {
    let igd = FauxIgd::lever(ReglageIgd {
        externe: "100.64.12.34",
        ..ReglageIgd::default()
    })
    .await;
    let ssdp = vers_la_fausse_box(&igd);
    let decor = Decor::lever_avec(
        "echo-upnp-double-nat",
        Vec::new(),
        Some("0.44.0"),
        &["echo"],
        &[("ASL_ECHO_UPNP", "1"), ("ASL_ECHO_SSDP", &ssdp)],
    )
    .await;
    let actions = Arc::clone(&igd.actions);
    attendre("l'adresse externe", || {
        actions
            .lock()
            .unwrap()
            .iter()
            .any(|(action, _)| action == "GetExternalIPAddress")
    })
    .await;
    tokio::time::sleep(Duration::from_millis(1_000)).await;
    let annonces = decor.etat.lock().unwrap().annonces.clone();
    assert!(
        annonces
            .iter()
            .all(|annonce| !annonce.contains("passerelle")),
        "{annonces:?}"
    );
    let (code, dit) = decor.arreter();
    assert_eq!(code, Some(0), "{dit}");
    assert!(
        dit.contains("double NAT : la box n'est pas la dernière (son adresse externe 100.64.12.34 est privée)"),
        "{dit}"
    );
    // La redirection reste posée tant que l'écho tourne (E19), et part avec lui.
    assert_eq!(igd.ports("DeletePortMapping").len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn no_upnp_ne_parle_pas_a_la_box() {
    let igd = FauxIgd::lever(ReglageIgd::default()).await;
    let ssdp = vers_la_fausse_box(&igd);
    let decor = Decor::lever_avec(
        "echo-no-upnp",
        Vec::new(),
        Some("0.44.0"),
        &["echo", "--no-upnp"],
        &[("ASL_ECHO_UPNP", "1"), ("ASL_ECHO_SSDP", &ssdp)],
    )
    .await;
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    let (code, dit) = decor.arreter();
    assert_eq!(code, Some(0), "{dit}");
    assert!(
        dit.contains("UPnP coupé : la box n'est pas interrogée"),
        "{dit}"
    );
    assert_eq!(*igd.recherches.lock().unwrap(), 0, "aucun M-SEARCH");
    assert!(igd.actions().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn asl_echo_upnp_se_lit_strictement() {
    let bac = Bac::neuf("echo-upnp-valeur");
    identite(&bac, machine_echo(), GRAINE_ECHO);
    let sortie = asl("[::1]:9=n-0PWT8HZD80QMSPPDZ5CQXXYHQC", &bac.0, &["echo"])
        .env("ASL_ECHO_UPNP", "oui")
        .output()
        .expect("asl se lance");
    assert_eq!(sortie.status.code(), Some(2));
    assert!(
        texte(&sortie.stderr).contains("ASL_ECHO_UPNP vaut 0"),
        "{}",
        texte(&sortie.stderr)
    );
}

/// **NON-RÉGRESSION DE 0.24.1** — vue en vrai derrière une Livebox : la box
/// répond tout de suite en IPv6 (sa description, jointe en IPv6, ne donne pas
/// de redirection IPv4) et en IPv4 plus tard. L'écoute commune s'arrêtait
/// 300 ms après la première réponse : l'IPv4 n'était jamais entendue, et
/// l'écho disait « pas de passerelle UPnP ». Chaque famille a désormais son
/// délai : la redirection IPv4 est obtenue.
#[tokio::test(flavor = "multi_thread")]
async fn une_reponse_ipv6_precoce_ne_coupe_pas_l_ecoute_ipv4() {
    let igd = FauxIgd::lever(ReglageIgd {
        externe: "127.0.0.1",
        retard_ssdp: Duration::from_millis(1_200),
        ..ReglageIgd::default()
    })
    .await;
    let voisin = VoisinV6::lever(true).await;
    passerelle_ipv4_malgre_l_ipv6(&igd, &voisin, "echo-upnp-v6-precoce").await;
}

/// L'IPv6 muet — une box qui n'écoute pas `ff02::c` — ne retarde ni
/// n'empêche l'IPv4.
#[tokio::test(flavor = "multi_thread")]
async fn un_ipv6_muet_ne_retarde_pas_l_ipv4() {
    let igd = FauxIgd::lever(ReglageIgd {
        externe: "127.0.0.1",
        retard_ssdp: Duration::from_millis(1_200),
        ..ReglageIgd::default()
    })
    .await;
    let voisin = VoisinV6::lever(false).await;
    passerelle_ipv4_malgre_l_ipv6(&igd, &voisin, "echo-upnp-v6-muet").await;
}

/// L'écho, qui cherche la box par les deux familles à la fois
/// (`ASL_ECHO_SSDP` : l'IPv4 de `igd`, l'IPv6 de `voisin`), obtient et
/// annonce la redirection IPv4 — et le mode bavard dit chaque famille.
async fn passerelle_ipv4_malgre_l_ipv6(igd: &FauxIgd, voisin: &VoisinV6, nom: &str) {
    let ssdp = format!("{},{}", igd.ssdp, voisin.ssdp);
    let decor = Decor::lever_avec(
        nom,
        Vec::new(),
        Some("0.44.0"),
        &["echo", "--verbose"],
        &[("ASL_ECHO_UPNP", "1"), ("ASL_ECHO_SSDP", &ssdp)],
    )
    .await;
    let port = decor.port;
    let etat = Arc::clone(&decor.etat);
    attendre("l'annonce avec passerelle", || {
        etat.lock()
            .unwrap()
            .annonces
            .iter()
            .any(|annonce| annonce.contains("\"passerelle\""))
    })
    .await;
    assert!(
        *voisin.recherches.lock().unwrap() >= 1,
        "l'IPv6 a été interrogée"
    );
    let (code, dit) = decor.arreter();
    assert_eq!(code, Some(0), "{dit}");
    for attendu in [
        format!("SSDP IPv4 : M-SEARCH vers {}", igd.ssdp),
        format!("SSDP IPv6 : M-SEARCH vers {}", voisin.ssdp),
        "SSDP IPv4 : 2 réponse(s) reçue(s), 1 passerelle(s) retenue(s)".to_owned(),
        format!("redirection UPnP : udp {port} → box 127.0.0.1:{port}, bail 1 h"),
    ] {
        assert!(dit.contains(&attendu), "« {attendu} » manque : {dit}");
    }
    assert!(!dit.contains("pas de passerelle UPnP"), "{dit}");
}
