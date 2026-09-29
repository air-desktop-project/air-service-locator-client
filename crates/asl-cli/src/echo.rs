//! `asl echo` — l'écho de cette machine (`protocole.md` §3 quater, décisions
//! 89 à 93).
//!
//! # CE QU'IL FAIT
//!
//! Il lie **une** socket UDP à un port tiré au hasard dans
//! [`PREMIER_PORT`]–[`DERNIER_PORT`], annonce `asl-echo`
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
//! # LA PASSERELLE (décisions 94 à 97)
//!
//! **Active par défaut** (décision 95 ; E15) : une tâche à côté
//! ([`crate::passerelle`]) demande à la box la redirection du port de l'écho,
//! et de lui seul. L'annonce est faite deux fois (§3 quater, « Comment
//! l'annuaire l'apprend ») : **sans** `passerelle` d'abord, pour apprendre
//! `vu_depuis` ; **avec** (`Annonce::avec_passerelle`, `asl-proto` 0.44.0),
//! sur la même connexion, une fois la box interrogée —
//! et seulement vers un annuaire qui connaît le champ (`GET /v1/version`,
//! 0.44.0 ou plus), faute de quoi il refuserait l'annonce entière.
//! `--no-upnp`, ou `ASL_ECHO_UPNP=0` dans l'environnement d'une unité, la
//! coupe.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use asl_client::Identite;
use asl_client::echo::{NOM_SERVICE, Repondeur, Silence};
use asl_client_tokio::{Connexion, Faute as FauteReseau, Reglages, joindre_sur};
use asl_echo::RefusSonde;
use asl_id::Genre;
use asl_proto::{NomService, Passerelle, PointEcoute, Port, Protocole, ViaPasserelle};
use tokio::net::UdpSocket;

use crate::arguments::Invocation;
use crate::commandes::{patience, refus_de_l_annuaire, reglages, reglages_du_renvoi};
use crate::passerelle::{self, Passerelle as TacheDePasserelle};
use crate::{Issue, Sortie, etat, rendu};

/// Ce que la ligne de commande et l'environnement disent de la passerelle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OptionsEcho {
    /// `--no-upnp` n'a pas été donné.
    pub upnp: bool,
    /// `--verbose` : dire aussi ce que la passerelle tait d'habitude.
    pub bavard: bool,
}

/// Lit `ASL_ECHO_UPNP` — `0` coupe la passerelle, `1` la laisse ; toute
/// autre valeur est refusée plutôt que devinée — et `ASL_ECHO_SSDP`.
///
/// # Erreurs
///
/// [`Issue::Configuration`] sur une valeur qui ne se lit pas.
fn reglage_de_la_passerelle(options: OptionsEcho) -> Result<Option<passerelle::Reglage>, Issue> {
    let par_l_environnement = match std::env::var("ASL_ECHO_UPNP").as_deref() {
        Err(_) | Ok("1") => true,
        Ok("0") => false,
        Ok(autre) => {
            return Err(Issue::Configuration(format!(
                "ASL_ECHO_UPNP vaut 0 (couper UPnP) ou 1, et non « {autre} »"
            )));
        }
    };
    if !options.upnp || !par_l_environnement {
        return Ok(None);
    }
    let ssdp = match std::env::var("ASL_ECHO_SSDP") {
        Ok(texte) => Some(passerelle::adresses_ssdp(&texte).map_err(Issue::Configuration)?),
        Err(_) => None,
    };
    Ok(Some(passerelle::Reglage {
        bavard: options.bavard,
        ssdp,
    }))
}

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
pub async fn echo(
    invocation: &Invocation,
    identite: &Identite,
    dossier: &Path,
    options: OptionsEcho,
) -> Sortie {
    refuser_root()?;
    let reglage_upnp = reglage_de_la_passerelle(options)?;
    let reglages = reglages(invocation)?;
    let tirage = etat::hasard::<8>()
        .map(u64::from_le_bytes)
        .map_err(|quoi| Issue::Configuration(quoi.to_string()))?;
    let socket = Arc::new(lier_dans(&ordre_de_la_plage(tirage)).await?);
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

    println!(
        "écho           {} — udp {port}, tiré dans {PREMIER_PORT}–{DERNIER_PORT}",
        identite.machine().texte().as_str()
    );
    println!("               il ne répond qu'aux sondes signées ; aux autres, le silence.");

    // **LA PASSERELLE, À CÔTÉ** : elle ne bloque jamais une réponse. Elle
    // retire d'abord ce qu'un arrêt brutal a laissé sur la box.
    let mut passerelle = match reglage_upnp {
        Some(reglage) => Some(TacheDePasserelle::lancer(port, dossier.to_owned(), reglage)),
        None => {
            println!("passerelle     UPnP coupé : la box n'est pas interrogée");
            None
        }
    };
    let sortie = tenir_l_echo(
        &reglages,
        identite,
        &socket,
        &points,
        nom,
        &mut repondeur,
        &mut passerelle,
    )
    .await;
    // Ce qui n'a pas déjà été retiré avant la fermeture du bail — une
    // faute, un arrêt pendant qu'on cherchait l'annuaire — l'est ici.
    if let Some(passerelle) = passerelle.take() {
        passerelle.arreter().await;
    }
    sortie
}

/// La boucle de l'écho : joindre, annoncer, tenir, recommencer.
async fn tenir_l_echo(
    reglages: &Reglages,
    identite: &Identite,
    socket: &Arc<UdpSocket>,
    points: &[PointEcoute; 1],
    nom: NomService<'_>,
    repondeur: &mut Repondeur,
    passerelle: &mut Option<TacheDePasserelle>,
) -> Sortie {
    let arret = ecouter_l_arret();
    let mut journal = Journal::default();

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
            None => (reglages, true),
        };
        let mut connexion = match joindre(courants, socket, racine, &arret).await {
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

        let locales = adresses_locales(courants, socket).await;
        let annonce = identite
            .annoncer(nom, points, &locales)
            .map_err(|quoi| Issue::Configuration(format!("l'annonce est refusée : {quoi:?}")))
            .and_then(|annonce| {
                // L'encodage est une validation : une annonce qui ne tient
                // pas dans un message est une faute rendue ici, pas une panne
                // qu'on recommencerait sans fin.
                asl_client_tokio::encoder(&annonce)
                    .map(|_| annonce)
                    .map_err(|quoi| {
                        Issue::Configuration(format!("l'annonce ne s'encode pas : {quoi}"))
                    })
            })?;
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
        let mut annonce_tenue = AnnonceTenue {
            sans: annonce,
            annoncee: None,
            accepte: false,
        };
        apres_l_annonce(
            &mut connexion,
            &corps,
            &locales,
            passerelle,
            &mut annonce_tenue,
        )
        .await;
        let _ = connexion.ecouter_les_poussees().await;

        tenir(
            &mut connexion,
            identite,
            repondeur,
            &mut journal,
            &arret,
            passerelle,
            &mut annonce_tenue,
        )
        .await;
        repondeur.lacher_le_bail();

        if arret.load(Ordering::Acquire) {
            // **LA BOX D'ABORD, LE BAIL ENSUITE** (§3 quater, « La durée ») :
            // la redirection est retirée avant que l'annonce tombe.
            if let Some(passerelle) = passerelle.take() {
                passerelle.arreter().await;
            }
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
    passerelle: &mut Option<TacheDePasserelle>,
    annonce: &mut AnnonceTenue<'_>,
) {
    while connexion.vivante() && !arret.load(Ordering::Acquire) {
        if connexion.entretenir(ENTRETIEN_MS).await.is_err() {
            break;
        }
        if let Some(accord) = passerelle.as_mut().and_then(TacheDePasserelle::accord) {
            reannoncer(connexion, annonce, accord).await;
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

/// L'annonce de l'écho sur UNE connexion : l'annonce sans `passerelle`, ce
/// qu'on y a annoncé depuis, et si l'annuaire connaît le champ.
#[derive(Debug)]
struct AnnonceTenue<'a> {
    /// L'annonce, sans `passerelle`.
    sans: asl_proto::Annonce<'a>,
    /// Le port de `passerelle` que cette connexion a annoncé, s'il y en a un.
    annoncee: Option<u16>,
    /// L'annuaire de cette connexion connaît `passerelle` (0.44.0 ou plus).
    accepte: bool,
}

/// **CE QUI SUIT LA PREMIÈRE ANNONCE** (décision 97 ; E21) : lire la
/// version de l'annuaire — il faut 0.44.0 pour `passerelle` —, puis dire à la
/// passerelle d'où l'annuaire nous voit. Elle répondra par un accord, que
/// [`tenir`] réannonce sur cette même connexion.
async fn apres_l_annonce(
    connexion: &mut Connexion,
    reponse: &[u8],
    locales: &[IpAddr],
    passerelle: &Option<TacheDePasserelle>,
    annonce: &mut AnnonceTenue<'_>,
) {
    let Some(passerelle) = passerelle else {
        return;
    };
    let mut tampons = asl_proto::cadrage::TamponsReponse::nouveaux();
    let Ok(lue) = asl_proto::Reponse::decoder(reponse, &mut tampons) else {
        return;
    };
    let vu = lue.vu_depuis.adresse;
    let version = match connexion.version().await {
        Ok(corps) => rendu::version_seule(&corps).ok(),
        Err(_) => None,
    };
    annonce.accepte = version
        .as_deref()
        .is_some_and(passerelle::connait_la_passerelle);
    if !annonce.accepte {
        let (a, b, c) = passerelle::VERSION_PASSERELLE;
        println!(
            "passerelle     l'annuaire ({}) ne connaît pas encore le champ `passerelle` ({a}.{b}.{c}) :\n\
             \x20              ce que la box accordera ne lui sera pas annoncé",
            version.as_deref().unwrap_or("version inconnue")
        );
    }
    passerelle.vu(vu, locales.to_vec());
}

/// Réannonce sur la connexion tenue, avec ou sans `passerelle`, selon
/// l'accord de la box — et seulement vers un annuaire qui connaît le champ.
///
/// **LE CHAMP EST ÉCRIT PAR `asl-proto`** (`Annonce::avec_passerelle`,
/// serveur 0.44.0) : la même grammaire que celle que l'annuaire lit, et qui
/// refuse le champ sur toute autre annonce que `asl-echo`.
async fn reannoncer(
    connexion: &mut Connexion,
    annonce: &mut AnnonceTenue<'_>,
    accord: Option<u16>,
) {
    if accord == annonce.annoncee || !annonce.accepte {
        return;
    }
    let corps = match accord {
        Some(port) => {
            let passerelle = Port::depuis_u16(port).map(|port| Passerelle {
                port,
                via: ViaPasserelle::Upnp,
            });
            match passerelle.and_then(|passerelle| annonce.sans.avec_passerelle(passerelle)) {
                Ok(avec) => avec,
                Err(quoi) => {
                    println!(
                        "annonce        la passerelle ne s'écrit pas ({quoi}) : l'annonce reste sans"
                    );
                    return;
                }
            }
        }
        None => annonce.sans,
    };
    match connexion.annoncer(&corps).await {
        Ok(_) => {
            annonce.annoncee = accord;
            match accord {
                Some(port) => println!(
                    "annonce        réannoncée avec la passerelle : port externe {port} (upnp)"
                ),
                None => println!("annonce        réannoncée sans passerelle"),
            }
        }
        // Un refus du champ : on n'insiste pas sur cette connexion.
        Err(FauteReseau::Statut(code)) => {
            annonce.accepte = false;
            println!(
                "annonce        l'annuaire refuse la passerelle ({code}) : l'annonce reste sans"
            );
        }
        // Une panne : la connexion le dira, et l'on recommencera.
        Err(_) => {}
    }
}

/// Le premier port de la plage de l'écho.
///
/// # UNE PLAGE, ET NON UN PORT ÉPHÉMÈRE (décision du 2026-09-29)
///
/// La spécification disait « un port aléatoire » ; l'essai réel a montré que
/// c'est le pare-feu de la machine (nft, ufw en politique `drop`) qui
/// décidait alors, et qu'aucun exploitant ne peut ouvrir d'avance un port
/// qu'il ne connaît pas. **Neuf ports, 6631 à 6639**, juste au-dessus de
/// celui de l'annuaire : l'exploitant les ouvre une fois —
/// `udp dport 6631-6639 accept` (nft), `ufw allow proto udp from any to any
/// port 6631:6639` —, et l'écho en prend un **au hasard**, le suivant dans
/// son ordre tiré si celui-là est pris. Il reste sans port fixe (décision
/// 89) : neuf échos peuvent tourner sur une même machine, et qui balaie ne
/// sait pas lequel des neuf répondrait — ni qu'il ne répond qu'aux sondes
/// signées.
pub const PREMIER_PORT: u16 = 6631;

/// Le dernier port de la plage de l'écho — voir [`PREMIER_PORT`].
pub const DERNIER_PORT: u16 = 6639;

/// Le nombre de ports de la plage.
const PORTS: usize = 9;

const _: () = assert!(
    DERNIER_PORT - PREMIER_PORT + 1 == 9,
    "PORTS doit compter la plage"
);

/// Les ports de la plage, **dans un ordre tiré de `graine`** : un mélange de
/// Fisher-Yates, sur un générateur `xorshift` que la graine amorce. L'ordre
/// n'a rien de secret — ce qui protège l'écho, ce sont les signatures ; il
/// étale seulement les échos d'une machine sur la plage.
fn ordre_de_la_plage(graine: u64) -> [u16; PORTS] {
    let mut ports = [0_u16; PORTS];
    for (place, port) in ports.iter_mut().zip(PREMIER_PORT..=DERNIER_PORT) {
        *place = port;
    }
    // Une graine nulle figerait `xorshift` à zéro.
    let mut etat = graine | 1;
    for haut in (1..PORTS).rev() {
        etat ^= etat << 13;
        etat ^= etat >> 7;
        etat ^= etat << 17;
        let borne = u64::try_from(haut).unwrap_or(0).saturating_add(1);
        let tire = usize::try_from(etat.checked_rem(borne).unwrap_or(0)).unwrap_or(0);
        ports.swap(haut, tire);
    }
    ports
}

/// Lie la socket de l'écho au premier de ces ports qui soit libre :
/// **`[::]:<port>`, à double pile**, et `0.0.0.0:<port>` si la machine n'a
/// pas d'IPv6 (`protocole.md` §3 quater, « IPv6 d'abord »).
///
/// Un port pris — par un autre écho, par n'importe qui — fait passer au
/// suivant ; une autre faute du noyau aussi, dite à la fin si aucun ne se
/// lie. La double pile est ce que Linux et macOS donnent par défaut à une
/// socket liée sur `[::]` (`IPV6_V6ONLY` à zéro) ; la poser explicitement
/// demanderait un appel que la bibliothèque standard n'expose pas.
///
/// # Erreurs
///
/// [`Issue::Configuration`] — « aucun port libre » — quand toute la plage
/// est occupée : c'est la machine qu'il faut regarder, pas le réseau.
async fn lier_dans(ports: &[u16]) -> Result<UdpSocket, Issue> {
    let mut derniere: Option<std::io::Error> = None;
    for port in ports {
        match UdpSocket::bind(("::", *port)).await {
            Ok(socket) => return Ok(socket),
            Err(quoi) if quoi.kind() == std::io::ErrorKind::AddrInUse => {
                derniere = Some(quoi);
                continue;
            }
            // Pas d'IPv6 sur cette machine : l'IPv4 seule, sur le même port.
            Err(_) => {}
        }
        match UdpSocket::bind(("0.0.0.0", *port)).await {
            Ok(socket) => return Ok(socket),
            Err(quoi) => derniere = Some(quoi),
        }
    }
    let premier = ports.iter().min().copied().unwrap_or(PREMIER_PORT);
    let dernier = ports.iter().max().copied().unwrap_or(DERNIER_PORT);
    Err(Issue::Configuration(format!(
        "aucun port libre dans {premier}–{dernier} : chacun est déjà pris sur cette\n\
         machine{} — un autre écho, ou un autre service. `ss -ulpn` dit lequel.",
        derniere.map_or_else(String::new, |quoi| format!(" (dernier refus : {quoi})"))
    )))
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

#[cfg(test)]
mod tests {
    use super::{DERNIER_PORT, PREMIER_PORT, lier_dans, ordre_de_la_plage};
    use crate::Issue;
    use tokio::net::UdpSocket;

    #[test]
    fn l_ordre_est_un_melange_de_toute_la_plage() {
        let mut vus = std::collections::BTreeSet::new();
        for graine in 0..64_u64 {
            let ordre = ordre_de_la_plage(graine.wrapping_mul(0x9E37_79B9_7F4A_7C15));
            let mut trie = ordre;
            trie.sort_unstable();
            assert_eq!(
                trie.to_vec(),
                (PREMIER_PORT..=DERNIER_PORT).collect::<Vec<_>>(),
                "chaque port une fois"
            );
            vus.insert(ordre[0]);
        }
        assert!(
            vus.len() > 4,
            "le premier port varie avec la graine : {vus:?}"
        );
    }

    /// Deux ports que le noyau vient de donner : le premier reste tenu, le
    /// second est rendu.
    async fn un_pris_un_libre() -> (UdpSocket, u16, u16) {
        let tenu = UdpSocket::bind("[::]:0").await.expect("une socket");
        let pris = tenu.local_addr().unwrap().port();
        let libre = UdpSocket::bind("[::]:0")
            .await
            .expect("une socket")
            .local_addr()
            .unwrap()
            .port();
        (tenu, pris, libre)
    }

    #[tokio::test]
    async fn un_port_pris_fait_passer_au_suivant() {
        let (_tenu, pris, libre) = un_pris_un_libre().await;
        let socket = lier_dans(&[pris, libre])
            .await
            .expect("le suivant est libre");
        assert_eq!(socket.local_addr().unwrap().port(), libre);
    }

    #[tokio::test]
    async fn une_plage_pleine_est_une_faute_de_configuration_dite_clairement() {
        let (_tenu, pris, _) = un_pris_un_libre().await;
        match lier_dans(&[pris]).await {
            Err(Issue::Configuration(quoi)) => {
                assert!(
                    quoi.contains(&format!("aucun port libre dans {pris}–{pris}")),
                    "{quoi}"
                );
            }
            autre => panic!("une faute de configuration : {autre:?}"),
        }
        // Sur la vraie plage, le message nomme la vraie plage.
        let tenus: Vec<_> = {
            let mut tenus = Vec::new();
            for port in PREMIER_PORT..=DERNIER_PORT {
                if let Ok(socket) = UdpSocket::bind(("::", port)).await {
                    tenus.push(socket);
                }
            }
            tenus
        };
        if tenus.len() == 9 {
            match lier_dans(&ordre_de_la_plage(7)).await {
                Err(Issue::Configuration(quoi)) => {
                    assert!(quoi.contains("aucun port libre dans 6631–6639"), "{quoi}");
                }
                autre => panic!("une faute de configuration : {autre:?}"),
            }
        }
    }
}
