//! `asl echo` — l'écho de cette machine (`protocole.md` §3 quater, décisions
//! 89 à 93).
//!
//! # CE QU'IL FAIT
//!
//! Il lie **une** socket UDP à un port que le noyau tire, annonce `asl-echo`
//! avec un seul point `udp:<port>`, et **tient le bail sur cette même
//! socket** (décision 90 ; E2) : derrière un NAT, le mapping que le bail ouvre
//! et que son keepalive tient est celui de la socket où l'écho écoute. Puis il
//! répond aux sondes autorisées — celle de l'annuaire qui tient son bail ou
//! d'une racine, celle d'`asl ping` munie d'un jeton — et se tait devant tout
//! le reste. Comme `asl announce`, il ne rend pas la main : la connexion EST
//! le bail.
//!
//! # CE QU'IL NE DÉCIDE PAS ICI
//!
//! Qui croire, le débit, l'anti-rejeu, la signature : `asl_client::echo`, sans
//! une entrée-sortie, éprouvé à part. Le tri de la socket au premier octet :
//! `asl-client-tokio`. Ce fichier-ci ne fait qu'obéir et dire.
//!
//! # PAS ENCORE D'UPnP, ET PAS D'OPTION QUI FERAIT SEMBLANT
//!
//! La passerelle (décisions 94 à 97) est la PR suivante. `--no-upnp` n'existe
//! donc pas encore : **une option acceptée et sans effet est pire qu'une option
//! refusée** — qui l'écrirait croirait avoir demandé quelque chose. Le point
//! d'accroche est [`apres_l_annonce`] : c'est là que la box sera interrogée,
//! une fois `vu_depuis` connu, et que l'annonce sera refaite avec
//! `passerelle`.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use asl_client::Identite;
use asl_client::echo::{NOM_SERVICE, Repondeur, Silence};
use asl_client_tokio::{Connexion, Faute as FauteReseau, Reglages, joindre_sur};
use asl_echo::RefusSonde;
use asl_id::Genre;
use asl_proto::{NomService, PointEcoute, Port, Protocole};
use tokio::net::UdpSocket;

use crate::arguments::Invocation;
use crate::commandes::{patience, refus_de_l_annuaire, reglages, reglages_du_renvoi};
use crate::{Issue, Sortie, etat, rendu};

/// Combien de temps la boucle dort entre deux réveils, au plus : une sonde
/// réveille la boucle dès qu'elle arrive, et ceci ne borne que le temps qu'un
/// arrêt met à être vu.
const ENTRETIEN_MS: u64 = 500;

/// Ce qu'on attend avant de recommencer après une panne à la preuve ou à
/// l'annonce : sans cela, un annuaire qui accepte la connexion puis échoue
/// serait rejoint en boucle serrée.
const REPRISE: std::time::Duration = std::time::Duration::from_secs(1);

/// Une ligne de bilan par minute, au plus — le débit dépassé, les sondes
/// refusées, une horloge qui dérive (`protocole.md` §3 quater : « une ligne
/// de journal par minute au plus »).
const BILAN_MS: u64 = 60_000;

/// L'heure murale, en millisecondes : c'est elle que les sondes et les jetons
/// datent.
fn maintenant_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |ecoule| {
            u64::try_from(ecoule.as_millis()).unwrap_or(u64::MAX)
        })
}

/// L'écho de cette machine. Ne rend la main que sur un arrêt demandé, ou sur
/// une faute de configuration.
pub async fn echo(invocation: &Invocation, identite: &Identite) -> Sortie {
    refuser_root()?;
    let reglages = reglages(invocation)?;
    let socket = lier().await?;
    let port = socket
        .local_addr()
        .map_err(|quoi| Issue::Configuration(format!("la socket ne dit pas son port : {quoi}")))?
        .port();
    let points = [PointEcoute::nouveau(
        Protocole::Udp,
        Port::depuis_u16(port)
            .map_err(|_| Issue::Configuration("le noyau a rendu le port zéro".to_owned()))?,
    )];
    let nom = NomService::analyser(NOM_SERVICE)
        .map_err(|quoi| Issue::Configuration(format!("`{NOM_SERVICE}` : {quoi:?}")))?;
    let graine = etat::hasard::<8>()
        .map(u64::from_le_bytes)
        .map_err(|quoi| Issue::Configuration(quoi.to_string()))?;
    let mut repondeur = Repondeur::nouveau(identite, graine);
    let arret = ecouter_l_arret();
    let mut journal = Journal::default();

    println!(
        "écho           {} — udp {port}, tiré par le noyau",
        identite.machine().texte().as_str()
    );
    println!("               il ne répond qu'aux sondes signées ; aux autres, le silence.");

    // L'annuaire local vers lequel une racine nous a renvoyés, s'il y en a un
    // — la même règle qu'`asl announce` : un seul saut, et l'on revient aux
    // racines quand il se tait.
    let mut local: Option<Reglages> = None;
    loop {
        if arret.load(Ordering::Acquire) {
            println!("écho arrêté.");
            return Ok(());
        }
        let (courants, racine) = match &local {
            Some(chez_lui) => (chez_lui, false),
            None => (&reglages, true),
        };
        let mut connexion = match joindre(courants, &socket, racine, &arret).await {
            Ok(connexion) => connexion,
            Err(Joindre::Arret) => {
                println!("écho arrêté.");
                return Ok(());
            }
            Err(Joindre::Configuration(quoi)) => return Err(quoi),
            Err(Joindre::LocalMuet) => {
                println!("l'annuaire local ne répond pas — retour aux racines.");
                local = None;
                continue;
            }
        };

        // **QUI TIENT LE BAIL, SOUS QUELLE CLÉ** : celle que la poignée de
        // main a jugée. C'est le seul annuaire hors du binaire que l'écho
        // croira, et il ne délivre de jeton que s'il est une racine de cette
        // invocation — jamais un annuaire local joint par un renvoi.
        let distante = connexion.distante().ok();
        let annuaire = distante.and_then(|ou| {
            courants
                .annuaires()
                .iter()
                .find(|quoi| quoi.adresse == ou)
                .map(|quoi| quoi.identite)
        });
        if let (Some(annuaire), Some(cle)) = (annuaire, connexion.cle_distante()) {
            repondeur.tenir_le_bail(annuaire, cle, racine);
        }

        let locales = adresses_locales(courants, &socket).await;
        let annonce = identite
            .annoncer(nom, &points, &locales)
            .map_err(|quoi| Issue::Configuration(format!("l'annonce est refusée : {quoi:?}")))?;
        match connexion.authentifier(identite).await {
            Ok(()) => {}
            // **UN REFUS DE LA CLÉ S'ARRÊTE ICI** : réessayer ne la rendrait
            // pas meilleure, et un écho qui boucle contre l'annuaire qui vient
            // de le refuser serait pire qu'un écho arrêté.
            Err(quoi @ FauteReseau::Statut(_)) => {
                let _ = connexion.fermer().await;
                return Err(refus_de_l_annuaire(quoi));
            }
            // Une panne n'est pas un refus : on recommence, après un temps.
            Err(quoi) => {
                println!("bail perdu à la preuve ({quoi}) — on recommence.");
                repondeur.lacher_le_bail();
                tokio::time::sleep(REPRISE).await;
                continue;
            }
        }
        let corps = match connexion.annoncer(&annonce).await {
            Ok(corps) => corps,
            Err(FauteReseau::Renvoye(corps)) if local.is_none() => {
                let _ = connexion.fermer().await;
                local = Some(reglages_du_renvoi(&corps).await?);
                continue;
            }
            // **UN SEUL SAUT** : un annuaire local qui renvoie à son tour est
            // une faute de configuration du domaine, pas une direction — la
            // même règle que l'attache et qu'`asl announce`.
            Err(FauteReseau::Renvoye(_)) => {
                let _ = connexion.fermer().await;
                return Err(Issue::Configuration(
                    "l'annuaire local renvoie à son tour ailleurs : un renvoi ne se suit qu'une fois"
                        .to_owned(),
                ));
            }
            Err(FauteReseau::Statut(code)) => {
                let _ = connexion.fermer().await;
                return Err(Issue::Refuse(code));
            }
            Err(quoi) => {
                println!("bail perdu à l'annonce ({quoi}) — on recommence.");
                repondeur.lacher_le_bail();
                tokio::time::sleep(REPRISE).await;
                continue;
            }
        };
        if let Ok(bail) = asl_client_tokio::cadence_du_bail(&corps) {
            connexion.maintenir(bail);
        }
        dire_le_bail(annuaire, distante, &corps);
        apres_l_annonce(&mut connexion, &corps);
        let _ = connexion.ecouter_les_poussees().await;

        tenir(
            &mut connexion,
            identite,
            &mut repondeur,
            &mut journal,
            &arret,
        )
        .await;
        repondeur.lacher_le_bail();

        if arret.load(Ordering::Acquire) {
            let _ = connexion.fermer().await;
            println!("écho retiré : le bail est fermé, l'annonce avec lui.");
            return Ok(());
        }
        println!("bail perdu — on recommence, et l'on réannonce sur le même port.");
    }
}

/// Ce que [`joindre`] rend quand elle ne rend pas de connexion.
enum Joindre {
    /// Une faute de configuration : réessayer n'y changerait rien.
    Configuration(Issue),
    /// L'annuaire local ne répond pas dans le temps d'une personne.
    LocalMuet,
    /// On a demandé l'arrêt pendant qu'on cherchait.
    Arret,
}

/// Joint un annuaire sur la socket de l'écho.
///
/// **AUX RACINES, SANS BORNE** : l'écho est un daemon, et un annuaire
/// injoignable doit le faire attendre, pas tomber (`protocole.md` §1.4).
/// **Chez un annuaire local, la patience d'`asl announce`** : au-delà, on
/// retourne aux racines, qui diront peut-être que le domaine a changé
/// d'hébergeur.
///
/// **L'ARRÊT SE REGARDE PENDANT QU'ON CHERCHE** : Ctrl-C ne tue plus le
/// processus une fois qu'on l'écoute, et une tournée sans fin l'ignorerait.
/// La recherche n'est pas abandonnée entre deux regards — son recul continue
/// là où il en était.
async fn joindre(
    reglages: &Reglages,
    socket: &Arc<UdpSocket>,
    racine: bool,
    arret: &AtomicBool,
) -> Result<Connexion, Joindre> {
    let alea = || etat::hasard::<16>().unwrap_or([0; 16]);
    let mut recherche = Box::pin(joindre_sur(reglages, socket, &alea));
    let echeance = (!racine).then(|| {
        let depuis = std::time::Instant::now();
        depuis
            .checked_add(std::time::Duration::from_secs(patience()))
            .unwrap_or(depuis)
    });
    loop {
        let regard = tokio::time::Duration::from_millis(ENTRETIEN_MS);
        if let Ok(jointe) = tokio::time::timeout(regard, &mut recherche).await {
            return jointe
                .map_err(|quoi| Joindre::Configuration(Issue::Configuration(quoi.to_string())));
        }
        if arret.load(Ordering::Acquire) {
            return Err(Joindre::Arret);
        }
        if echeance.is_some_and(|fin| std::time::Instant::now() >= fin) {
            return Err(Joindre::LocalMuet);
        }
    }
}

/// Tient le bail, et répond. Rend quand la connexion tombe, ou qu'on demande
/// l'arrêt.
async fn tenir(
    connexion: &mut Connexion,
    identite: &Identite,
    repondeur: &mut Repondeur,
    journal: &mut Journal,
    arret: &AtomicBool,
) {
    while connexion.vivante() && !arret.load(Ordering::Acquire) {
        if connexion.entretenir(ENTRETIEN_MS).await.is_err() {
            break;
        }
        for (datagramme, source) in connexion.echos() {
            let maintenant = maintenant_ms();
            match repondeur.recevoir(identite, &datagramme, source, maintenant) {
                Ok(repondue) => {
                    // **LA RÉPONSE PART D'OÙ LA SONDE EST ARRIVÉE** : la
                    // socket du bail, le port annoncé.
                    let envoi = connexion.envoyer_a(&repondue.reponse, source).await;
                    journal.repondu(repondue.sondeur, source, envoi.is_ok());
                }
                Err(silence) => journal.silence(silence),
            }
        }
        journal.bilan(maintenant_ms());
        if let Ok(poussees) = connexion.poussees()
            && let Some(derniere) = poussees.last()
        {
            journal.poussee(derniere);
        }
    }
}

/// Ce que l'écho dit de ce qu'il fait — **sobrement** : une ligne par preuve
/// rendue, un bilan par minute au plus pour ce qu'il a tu, une ligne quand le
/// verdict de l'annuaire change.
#[derive(Debug, Default)]
struct Journal {
    /// Depuis le dernier bilan : refusées, au-delà du débit, illisibles.
    refusees: u64,
    debit: u64,
    illisibles: u64,
    rejeux: u64,
    /// Une sonde d'annuaire authentique, hors de la fenêtre : l'horloge dérive.
    horloge: u64,
    /// Quand le dernier bilan a été dit.
    dernier_bilan: u64,
    /// Le dernier verdict poussé, tel qu'on l'a dit.
    verdict: Option<String>,
}

impl Journal {
    fn repondu(&self, sondeur: asl_id::Identifiant, source: SocketAddr, parti: bool) {
        let qui = if sondeur.genre() == Genre::Annuaire {
            "annuaire"
        } else {
            "jeton   "
        };
        let issue = if parti {
            "preuve rendue"
        } else {
            "preuve signée, NON ENVOYÉE (la socket a refusé)"
        };
        println!(
            "sonde          {qui} {} depuis {} — {issue}",
            sondeur.texte().as_str(),
            vue(source)
        );
    }

    const fn silence(&mut self, silence: Silence) {
        match silence {
            Silence::DebitSource | Silence::DebitTotal => self.debit = self.debit.saturating_add(1),
            Silence::Illisible(_) => self.illisibles = self.illisibles.saturating_add(1),
            Silence::Rejeu => self.rejeux = self.rejeux.saturating_add(1),
            Silence::Refusee(RefusSonde::HorsFenetre) => {
                self.horloge = self.horloge.saturating_add(1);
            }
            Silence::Refusee(_) => self.refusees = self.refusees.saturating_add(1),
        }
    }

    /// Le bilan de la minute écoulée, s'il y a quelque chose à dire.
    fn bilan(&mut self, maintenant: u64) {
        if maintenant.saturating_sub(self.dernier_bilan) < BILAN_MS {
            return;
        }
        if self.horloge > 0 {
            println!(
                "HORLOGE        {} sonde(s) d'annuaire authentique(s) datée(s) à plus de deux\n\
                 \x20              minutes de l'heure de cette machine : son horloge dérive, et l'écho\n\
                 \x20              ne répondra à aucune sonde tant qu'elle dérivera. Réglez NTP.",
                self.horloge
            );
        }
        let tues = self
            .refusees
            .saturating_add(self.debit)
            .saturating_add(self.illisibles)
            .saturating_add(self.rejeux);
        if tues > 0 {
            println!(
                "silence        dans la minute : {} non autorisée(s), {} au-delà du débit, \
                 {} illisible(s), {} rejouée(s)",
                self.refusees, self.debit, self.illisibles, self.rejeux
            );
        }
        *self = Self {
            dernier_bilan: maintenant,
            verdict: self.verdict.take(),
            ..Self::default()
        };
    }

    /// Le verdict que l'annuaire pousse sur le point de l'écho, quand il
    /// change.
    fn poussee(&mut self, octets: &[u8]) {
        let dit = match rendu::poussee(octets) {
            Ok(dit) => dit,
            Err(quoi) => format!("ILLISIBLE — {quoi}"),
        };
        if self.verdict.as_deref() != Some(dit.as_str()) {
            println!("verdict        {dit}");
            self.verdict = Some(dit);
        }
    }
}

/// Une source, telle qu'on la lit : une IPv4 enfouie redevient une IPv4.
fn vue(source: SocketAddr) -> String {
    SocketAddr::new(source.ip().to_canonical(), source.port()).to_string()
}

/// Dit qui tient le bail, et sous quelle adresse l'annuaire nous voit.
fn dire_le_bail(annuaire: Option<asl_id::Identifiant>, distante: Option<SocketAddr>, corps: &[u8]) {
    let qui = annuaire.map_or_else(|| "?".to_owned(), |id| id.texte().as_str().to_owned());
    let ou = distante.map_or_else(|| "?".to_owned(), vue);
    let mut tampons = asl_proto::cadrage::TamponsReponse::nouveaux();
    match asl_proto::Reponse::decoder(corps, &mut tampons) {
        Ok(lue) => {
            let vu = SocketAddr::new(lue.vu_depuis.adresse, lue.vu_depuis.port.valeur());
            println!(
                "bail           tenu par {qui} ({ou}) — {} annoncé, vu depuis {}",
                lue.service.texte().as_str(),
                vue(vu)
            );
            for entree in lue.joignabilite {
                println!("verdict        {}", rendu::verdict(entree));
            }
        }
        Err(quoi) => {
            println!("bail           tenu par {qui} ({ou}) — réponse illisible ({quoi:?})")
        }
    }
}

/// **LE POINT D'ACCROCHE DE LA PASSERELLE** (décisions 94 à 97, PR suivante).
///
/// C'est ici, l'annonce faite et `vu_depuis` connu, que l'écho interrogera la
/// box — SSDP sur le lien local, `AddAnyPortMapping` du seul port de l'écho,
/// `GetExternalIPAddress` comparée à `vu_depuis` — et réannoncera avec
/// `passerelle` sur la même connexion, si l'annuaire en connaît le champ.
/// Aujourd'hui, il n'y a rien à faire : la socket du bail seule.
const fn apres_l_annonce(_connexion: &mut Connexion, _reponse: &[u8]) {}

/// Lie la socket de l'écho : **`[::]:0`, à double pile**, et `0.0.0.0:0` si
/// la machine n'a pas d'IPv6 (`protocole.md` §3 quater, « IPv6 d'abord »).
///
/// La double pile est ce que Linux et macOS donnent par défaut à une socket
/// liée sur `[::]` (`IPV6_V6ONLY` à zéro) ; la poser explicitement demanderait
/// un appel que la bibliothèque standard n'expose pas.
async fn lier() -> Result<Arc<UdpSocket>, Issue> {
    let socket = match UdpSocket::bind("[::]:0").await {
        Ok(socket) => socket,
        Err(_) => UdpSocket::bind("0.0.0.0:0").await.map_err(|quoi| {
            Issue::Configuration(format!("aucune socket UDP ne se lie : {quoi}"))
        })?,
    };
    Ok(Arc::new(socket))
}

/// Les adresses de cette machine à annoncer : **une par famille**, celle par
/// laquelle elle sort vers l'annuaire de cette famille — IPv6 d'abord, puis
/// IPv4.
///
/// # POURQUOI PAS TOUTES
///
/// La spécification les voudrait toutes, jusqu'à `ADRESSES_MAX`. Les
/// énumérer demande `getifaddrs`, c'est-à-dire du C (C4). Ce que le noyau dit
/// sans C, c'est l'adresse qu'il choisirait pour joindre une destination : on
/// le lui demande, sans rien envoyer, pour une destination de chaque famille —
/// les annuaires qu'on joint. Une machine à plusieurs adresses globales n'en
/// annonce donc qu'une par famille, **celle qui sort** : c'est aussi celle
/// qu'un sondeur du même réseau a le plus de chances de joindre.
async fn adresses_locales(reglages: &Reglages, socket: &UdpSocket) -> Vec<IpAddr> {
    let double_pile = socket.local_addr().is_ok_and(|ici| ici.is_ipv6());
    let mut trouvees: Vec<IpAddr> = Vec::new();
    for six in [true, false] {
        if six && !double_pile {
            continue;
        }
        let Some(cible) = reglages
            .annuaires()
            .iter()
            .map(|annuaire| annuaire.adresse)
            .find(|adresse| adresse.is_ipv6() == six)
        else {
            continue;
        };
        let lien = if six { "[::]:0" } else { "0.0.0.0:0" };
        let Ok(sonde) = UdpSocket::bind(lien).await else {
            continue;
        };
        if sonde.connect(cible).await.is_err() {
            continue;
        }
        if let Ok(ici) = sonde.local_addr()
            && !ici.ip().is_unspecified()
            && !trouvees.contains(&ici.ip())
        {
            trouvees.push(ici.ip());
        }
    }
    trouvees
}

/// **L'ÉCHO NE TOURNE PAS EN ROOT** (C8) : l'identité vit chez
/// l'utilisateur qui la détient, et c'est sous son compte qu'il répond.
///
/// L'`euid` se lit sans `libc` : le propriétaire de `/proc/self` sous Linux,
/// celui d'un fichier qu'on vient de créer ailleurs. Si rien ne le dit, on ne
/// refuse pas — on ne sait pas.
fn refuser_root() -> Result<(), Issue> {
    if euid() == Some(0) {
        return Err(Issue::Configuration(
            "asl echo refuse de tourner en root : l'identité de cette machine vit chez\n\
             l'utilisateur qui la détient, et c'est sous son compte que l'écho répond\n\
             (systemctl --user, pas le gestionnaire du système)."
                .to_owned(),
        ));
    }
    Ok(())
}

/// L'`euid` de ce processus, lu sans `unsafe`.
fn euid() -> Option<u32> {
    use std::os::unix::fs::MetadataExt as _;
    if let Ok(meta) = std::fs::metadata("/proc/self") {
        return Some(meta.uid());
    }
    let temoin = std::env::temp_dir().join(format!(
        "asl-echo-euid-{}-{}",
        std::process::id(),
        maintenant_ms()
    ));
    let fichier = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temoin)
        .ok()?;
    let uid = fichier.metadata().ok().map(|meta| meta.uid());
    drop(fichier);
    let _ = std::fs::remove_file(&temoin);
    uid
}

/// Un drapeau que Ctrl-C **ou `SIGTERM`** lève — ce que systemd et launchd
/// envoient pour arrêter l'unité : le bail se ferme alors proprement, et
/// l'annuaire ne donne pas une adresse morte une minute durant.
fn ecouter_l_arret() -> Arc<AtomicBool> {
    let arret = crate::commandes::ecouter_ctrl_c();
    let sien = Arc::clone(&arret);
    tokio::spawn(async move {
        if let Ok(mut terme) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            && terme.recv().await.is_some()
        {
            sien.store(true, Ordering::Release);
        }
    });
    arret
}
