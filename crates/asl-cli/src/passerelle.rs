//! La passerelle de l'écho : demander à la box de rediriger son port
//! (`protocole.md` §3 quater, « La passerelle », décisions 94 à 97).
//!
//! # CE QU'ELLE FAIT
//!
//! Une tâche à côté de l'écho, qui ne bloque jamais ses réponses :
//!
//! 1. **au démarrage**, elle retire ce qu'un arrêt brutal a laissé sur la box
//!    — la mémoire `upnp-<port>` du répertoire d'état, quand son écho ne tient
//!    plus son port ;
//! 2. **elle cherche la box** — SSDP sur le lien local, IPv4 et IPv6 —, lit
//!    sa description, et lui demande **la redirection UDP du port de l'écho,
//!    et de lui seul** : `AddAnyPortMapping` (IGD v2) ou `AddPortMapping`
//!    (IGD v1 ; le même port externe que le port interne d'abord, puis
//!    [`TIRAGES`] ports externes tirés au hasard sur `718
//!    ConflictInMappingEntry` — **hors de la plage de l'écho**, où un voisin
//!    de la même box tient peut-être le sien), bail d'une heure, permanent
//!    seulement si la box l'exige ;
//!    puis `GetExternalIPAddress`, et le trou IPv6 (`AddPinhole`) si la box
//!    le propose et le permet ;
//! 3. **elle recommence** toutes les trente minutes — le bail d'une heure est
//!    renouvelé à mi-course, une box redémarrée est retrouvée — et quand
//!    l'adresse de la machine change (décision 95 ; E23) ;
//! 4. **à l'arrêt**, elle retire tout, avant que l'écho ferme son bail.
//!
//! # CE QU'ELLE DIT À L'ÉCHO
//!
//! Deux faits, un [`Accord`] par tour ([`Passerelle::accord`]).
//!
//! **Le port à annoncer dans `passerelle`, ou rien.** Le port seul, jamais
//! l'adresse : l'annuaire emploie celle qu'il a observée (décision 97 ; E21).
//! Il n'y en a donc un que si la redirection vaut pour CETTE adresse :
//!
//! - bail en IPv4 : l'adresse externe de la box **égale** à `vu_depuis` —
//!   sinon il y a un second NAT au-dessus, la redirection ne suffira pas, et
//!   on le dit sans rien annoncer (E19) ;
//! - bail en IPv6 : le trou ouvert pour l'adresse même que l'annuaire voit
//!   (le port est alors celui de l'écho).
//!
//! **La famille où le bail doit se tenir** ([`Voeu`], décision 106). Derrière
//! une box qui refuse le trou IPv6 mais redirige en IPv4 — la Livebox,
//! vue en vrai sur trois machines —, un bail IPv6 ne peut rien annoncer :
//! l'annuaire voit l'IPv6, que la box ferme. La passerelle le dit, et l'écho
//! rouvre son bail en IPv4 pour que `vu_depuis` soit l'adresse externe de la
//! box. Puis, bail IPv4 tenu, elle dit quand revenir : un trou obtenu, la
//! redirection perdue, ou `vu_depuis` qui n'est pas l'adresse de la box — un
//! double NAT qu'elle retient, pour ne pas rebasculer vers la même adresse.
//! **Elle ne sait pas si le bail IPv4 a été choisi ou subi** (une machine
//! sans IPv6) : c'est l'écho qui ne revient que d'une bascule qu'il a faite.
//!
//! # CE QU'ELLE NE FAIT PAS
//!
//! Elle n'ouvre **jamais** un autre port que celui de l'écho — `asl-upnp` ne
//! sait pas en demander d'autre sorte —, ne suit **aucun nom** (C20), n'appelle
//! **aucun tiers** (C19), et n'active pas UPnP sur une box qui l'a coupé :
//! sans passerelle, l'écho continue avec la socket du bail seule.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use asl_upnp::description::{self, WAN_IP_2};
use asl_upnp::http::{self, Lu};
use asl_upnp::memoire::{self, Ouverture};
use asl_upnp::soap::{self, BAIL_S, code};
use asl_upnp::ssdp;
use asl_upnp::url::{self, Url};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot};

use crate::etat;

/// Tous les combien la box est recherchée et le bail renouvelé : trente
/// minutes, la moitié du bail (décision 95 ; E18, E23).
pub const CADENCE: Duration = Duration::from_secs(30 * 60);

/// Combien de temps on écoute les réponses SSDP, au plus : `MX` plus une
/// demi-seconde.
const ECOUTE_SSDP: Duration = Duration::from_millis(2_500);

/// Une fois une passerelle entendue, combien on attend encore les autres
/// réponses (une box répond souvent en IPv4 et en IPv6, IGD v1 et v2).
const APRES_LA_PREMIERE: Duration = Duration::from_millis(300);

/// Le délai d'un échange HTTP avec la box : une box du réseau local répond en
/// quelques millisecondes ; au-delà de cinq secondes, elle ne répondra pas.
const DELAI_HTTP: Duration = Duration::from_secs(5);

/// Combien l'arrêt attend la box, au plus — bien en deçà des 90 s que
/// systemd laisse à une unité pour s'arrêter.
const ARRET_MAX: Duration = Duration::from_secs(20);

/// Les descriptions examinées, au plus, par recherche.
const DESCRIPTIONS_MAX: usize = 4;

/// Les ports tirés au hasard après un conflit (IGD v1), au plus.
const TIRAGES: u8 = 3;

/// Le premier port qu'on tire au hasard après un conflit : en dessous, les
/// ports sont ceux des services connus.
const PREMIER_PORT_TIRE: u16 = 1_024;

/// Combien de ports la plage de l'écho occupe (6631–6639) : un port externe
/// tiré les saute, pour ne pas prendre — ni redemander — celui de l'écho d'un
/// voisin de la même box (essai réel, 2026-09-30).
const PORTS_DE_L_ECHO: u16 = crate::echo::DERNIER_PORT - crate::echo::PREMIER_PORT + 1;

/// Le préfixe du fichier qui retient ce que l'écho a ouvert.
const MEMOIRE: &str = "upnp-";

/// Comment la passerelle est réglée.
#[derive(Debug, Clone, Default)]
pub struct Reglage {
    /// Dire aussi ce qui n'a pas marché et qu'on tait d'habitude (le trou
    /// IPv6 absent, une réponse SSDP écartée).
    pub bavard: bool,
    /// Où envoyer le `M-SEARCH` : les groupes SSDP (par défaut), ou ces
    /// adresses littérales — une passerelle interrogée directement
    /// (`ASL_ECHO_SSDP`).
    pub ssdp: Option<Vec<SocketAddr>>,
}

/// Ce que la passerelle conclut d'un tour, pour l'écho.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Accord {
    /// Le port à annoncer dans `passerelle`, ou rien.
    pub port: Option<u16>,
    /// Où le bail doit se tenir.
    pub voeu: Voeu,
}

/// **La famille où le bail de l'écho doit se tenir** (décision 106).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Voeu {
    /// Rien à changer.
    Rester,
    /// **Passer en IPv4** : bail en IPv6, aucun trou obtenu — refusé, ou pas
    /// de `WANIPv6FirewallControl` —, et la box redirige vers l'écho le port
    /// externe `port` de son adresse externe `externe`, publique.
    Ipv4 {
        /// L'adresse externe que la box dit — celle que l'annuaire devra voir.
        externe: Ipv4Addr,
        /// Le port externe redirigé.
        port: u16,
    },
    /// **Revenir en IPv6**, bail tenu en IPv4, pour cette raison.
    Ipv6(Retour),
}

/// Pourquoi un bail IPv4 doit revenir en IPv6 — les trois cas de la
/// décision 106, et eux seuls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retour {
    /// La box ouvre désormais un trou IPv6.
    TrouObtenu,
    /// La redirection est perdue : refusée au renouvellement, plus de box, ou
    /// une box qui ne dit plus son adresse externe.
    RedirectionPerdue,
    /// L'annuaire nous voit depuis `vu`, et non depuis l'adresse externe de
    /// la box, `boite` : un second NAT au-dessus d'elle.
    DoubleNat {
        /// L'adresse externe que la box dit.
        boite: Ipv4Addr,
        /// L'adresse d'où l'annuaire nous voit.
        vu: Ipv4Addr,
    },
}

impl std::fmt::Display for Retour {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TrouObtenu => f.write_str("la box ouvre maintenant un trou IPv6"),
            Self::RedirectionPerdue => f.write_str("la redirection IPv4 est perdue"),
            Self::DoubleNat { boite, vu } => write!(
                f,
                "double NAT : la box dit {boite}, l'annuaire nous voit depuis {vu}"
            ),
        }
    }
}

/// Ce qu'un tour sait, pour conclure — sans la box ni le réseau : [`decider`]
/// en est une fonction, éprouvée à part.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Faits {
    /// Le port de l'écho.
    port: u16,
    /// D'où l'annuaire nous voit.
    vu: Option<IpAddr>,
    /// La redirection tenue : son port externe, et l'adresse externe que la
    /// box a dite.
    redirection: Option<(u16, Option<Ipv4Addr>)>,
    /// Le trou tenu : l'adresse pour laquelle il est ouvert.
    trou: Option<Ipv6Addr>,
    /// La box dit son pare-feu IPv6 inactif : tout entre en IPv6.
    pare_feu_inactif: bool,
    /// L'adresse externe pour laquelle un double NAT a été constaté.
    double_nat: Option<Ipv4Addr>,
}

/// **CE QU'UN TOUR CONCLUT** — le port à annoncer, et la famille du bail
/// (décisions 97 et 106).
///
/// - **Bail en IPv4** : le port redirigé s'annonce si l'adresse externe de la
///   box est `vu_depuis`. Le bail y reste tant que cela tient ; un trou
///   obtenu, une redirection perdue ou une adresse externe qui n'est pas
///   `vu_depuis` le renvoient en IPv6 — l'écho n'obéit que s'il avait
///   basculé.
/// - **Bail en IPv6** : le port de l'écho s'annonce si le trou est ouvert
///   pour `vu_depuis`. Sans trou, un pare-feu IPv6 actif, une redirection
///   vers une adresse externe publique qu'aucun double NAT n'a démentie : le
///   bail doit passer en IPv4. **Une adresse externe privée ou partagée**
///   (`100.64.0.0/10`) **est un double NAT déjà visible** : on ne bascule
///   pas.
fn decider(faits: &Faits) -> Accord {
    match faits.vu.map(|vu| vu.to_canonical()) {
        Some(IpAddr::V4(vu)) => {
            let port = faits
                .redirection
                .filter(|(_, externe)| *externe == Some(vu))
                .map(|(port, _)| port);
            let voeu = if faits.trou.is_some() {
                Voeu::Ipv6(Retour::TrouObtenu)
            } else {
                match faits.redirection {
                    None | Some((_, None)) => Voeu::Ipv6(Retour::RedirectionPerdue),
                    Some((_, Some(boite))) if boite != vu => {
                        Voeu::Ipv6(Retour::DoubleNat { boite, vu })
                    }
                    Some(_) => Voeu::Rester,
                }
            };
            Accord { port, voeu }
        }
        Some(IpAddr::V6(vu)) => {
            let port = faits
                .trou
                .filter(|client| *client == vu)
                .map(|_| faits.port);
            let voeu = match faits.redirection {
                Some((port, Some(externe)))
                    if faits.trou.is_none()
                        && !faits.pare_feu_inactif
                        && !url::externe_privee(externe)
                        && faits.double_nat != Some(externe) =>
                {
                    Voeu::Ipv4 { externe, port }
                }
                _ => Voeu::Rester,
            };
            Accord { port, voeu }
        }
        None => Accord {
            port: None,
            voeu: Voeu::Rester,
        },
    }
}

/// Ce que le pare-feu IPv6 de la box a répondu.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Trouage {
    /// Le trou est ouvert (ou renouvelé).
    Ouvert(Trou),
    /// Le pare-feu est inactif (`FirewallEnabled = 0`) : rien à ouvrir, tout
    /// entre.
    Inactif,
    /// Les trous ne sont pas permis (`InboundPinholeAllowed = 0`).
    NonPermis,
}

/// Ce qu'on demande à la tâche.
enum Ordre {
    /// L'annuaire nous voit depuis `vu` ; nos adresses sont `locales`.
    Vu { vu: IpAddr, locales: Vec<IpAddr> },
    /// Tout retirer, puis le dire.
    Arreter(oneshot::Sender<()>),
}

/// La passerelle d'un écho : la tâche, et ses deux voies.
#[derive(Debug)]
pub struct Passerelle {
    ordres: mpsc::UnboundedSender<Ordre>,
    accords: mpsc::UnboundedReceiver<Accord>,
}

impl std::fmt::Debug for Ordre {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Vu { vu, .. } => write!(f, "Vu({vu})"),
            Self::Arreter(_) => f.write_str("Arreter"),
        }
    }
}

impl Passerelle {
    /// Lance la tâche de la passerelle pour l'écho du port `port`, qui retient
    /// ce qu'il ouvre dans `dossier`.
    #[must_use]
    pub fn lancer(port: u16, dossier: PathBuf, reglage: Reglage) -> Self {
        let (ordres, recus) = mpsc::unbounded_channel();
        let (accorder, accords) = mpsc::unbounded_channel();
        let tache = Tache {
            port,
            dossier,
            reglage,
            boite: None,
            redirection: None,
            trou: None,
            pare_feu_inactif: false,
            double_nat: None,
            vu: None,
            locales: Vec::new(),
            constats: Vec::new(),
            accorder,
        };
        tokio::spawn(tache.mener(recus));
        Self { ordres, accords }
    }

    /// L'annuaire vient de dire d'où il nous voit : la tâche compare,
    /// cherche la box si l'adresse a changé, et répond par un accord.
    pub fn vu(&self, vu: IpAddr, locales: Vec<IpAddr>) {
        let _ = self.ordres.send(Ordre::Vu { vu, locales });
    }

    /// Le dernier accord arrivé depuis l'appel précédent, ou `None` — rien
    /// de neuf.
    pub fn accord(&mut self) -> Option<Accord> {
        let mut dernier = None;
        while let Ok(accord) = self.accords.try_recv() {
            dernier = Some(accord);
        }
        dernier
    }

    /// Retire tout de la box, et rend quand c'est fait — ou quand la tâche
    /// n'est plus là, ou après [`ARRET_MAX`] : une box qui ne répond plus ne
    /// retient pas l'arrêt de l'écho, et le bail d'une heure fera tomber ce
    /// qui reste.
    pub async fn arreter(self) {
        let (fait, attendre) = oneshot::channel();
        if self.ordres.send(Ordre::Arreter(fait)).is_ok()
            && tokio::time::timeout(ARRET_MAX, attendre).await.is_err()
        {
            dire("la box ne répond pas à temps : ce qui reste tombera avec son bail");
        }
    }
}

/// La box trouvée : où lui parler, et d'où.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Boite {
    /// Le service de redirection, son type, et notre adresse IPv4 vue par la
    /// box (`NewInternalClient`).
    redirection: Option<(Url, &'static str, Ipv4Addr)>,
    /// Le service du pare-feu IPv6.
    pare_feu: Option<Url>,
    /// L'adresse de la box, pour le journal.
    hote: IpAddr,
}

/// Une redirection accordée.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Redirection {
    controle: Url,
    service: &'static str,
    client: Ipv4Addr,
    externe: u16,
    permanente: bool,
    adresse_externe: Option<Ipv4Addr>,
}

/// Un trou IPv6 accordé.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Trou {
    controle: Url,
    client: Ipv6Addr,
    identifiant: u16,
}

/// Pourquoi une demande à la box n'a pas abouti.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Echec {
    /// Pas de réponse, ou pas de connexion.
    Injoignable(String),
    /// Une réponse qui ne se lit pas.
    Illisible(String),
    /// Une faute UPnP : son code, et ce qu'elle dit.
    Refus(u16, String),
    /// La connexion s'est fermée sans un octet ([`http::FauteHttp::Vide`]).
    Muette,
}

impl std::fmt::Display for Echec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Injoignable(quoi) => write!(f, "injoignable ({quoi})"),
            Self::Illisible(quoi) => write!(f, "réponse illisible ({quoi})"),
            Self::Refus(code, description) if description.is_empty() => write!(f, "refus {code}"),
            Self::Refus(code, description) => write!(f, "refus {code} {description}"),
            Self::Muette => f.write_str("la box n'a rien répondu (connexion fermée sans contenu)"),
        }
    }
}

/// La tâche.
struct Tache {
    port: u16,
    dossier: PathBuf,
    reglage: Reglage,
    boite: Option<Boite>,
    redirection: Option<Redirection>,
    trou: Option<Trou>,
    /// Le pare-feu IPv6 de la box se dit inactif : le bail n'a pas à quitter
    /// l'IPv6 (décision 106).
    pare_feu_inactif: bool,
    /// **L'adresse externe pour laquelle un double NAT a été constaté** — un
    /// bail IPv4 vu d'ailleurs que d'elle. Tant que la box dit cette
    /// adresse-là, on ne rebascule pas : ce serait rebasculer toutes les
    /// trente minutes pour constater la même chose (décision 106).
    double_nat: Option<Ipv4Addr>,
    vu: Option<IpAddr>,
    locales: Vec<IpAddr>,
    /// Ce que le dernier tour a conclu, tel qu'on l'a dit : un tour qui
    /// conclut la même chose ne le redit pas.
    constats: Vec<String>,
    accorder: mpsc::UnboundedSender<Accord>,
}

/// Une ligne du journal de la passerelle.
fn dire(texte: &str) {
    println!("passerelle     {texte}");
}

impl Tache {
    /// Ce que dit le mode bavard, et lui seul.
    fn bavarder(&self, texte: &str) {
        if self.reglage.bavard {
            dire(texte);
        }
    }

    async fn mener(mut self, mut ordres: mpsc::UnboundedReceiver<Ordre>) {
        self.nettoyer().await;
        // La première recherche attend la première annonce : sans
        // `vu_depuis`, on ne saurait pas quoi conclure.
        let mut prochain: Option<Instant> = None;
        loop {
            let ordre = match prochain {
                Some(quand) => {
                    let attente = quand.saturating_duration_since(Instant::now());
                    match tokio::time::timeout(attente, ordres.recv()).await {
                        Ok(ordre) => ordre,
                        Err(_) => {
                            self.tour().await;
                            prochain = Instant::now().checked_add(CADENCE);
                            continue;
                        }
                    }
                }
                None => ordres.recv().await,
            };
            match ordre {
                Some(Ordre::Vu { vu, locales }) => {
                    let change = self.vu != Some(vu) || self.locales != locales;
                    self.vu = Some(vu);
                    self.locales = locales;
                    if change || prochain.is_none() {
                        self.tour().await;
                        prochain = Instant::now().checked_add(CADENCE);
                    } else {
                        // Rien de neuf : le même accord, pour la connexion
                        // qui vient de s'ouvrir.
                        let accord = self.conclure();
                        let _ = self.accorder.send(accord);
                    }
                }
                Some(Ordre::Arreter(fait)) => {
                    self.retirer_tout().await;
                    let _ = fait.send(());
                    return;
                }
                // L'écho est parti sans rien dire : on retire quand même.
                None => {
                    self.retirer_tout().await;
                    return;
                }
            }
        }
    }

    /// Un tour : chercher la box, demander ou renouveler, conclure.
    async fn tour(&mut self) {
        let (trouvee, recues) = self.chercher().await;
        let entendue = trouvee.is_some();
        // **UNE BOX QUI N'A PAS RÉPONDU AU `M-SEARCH` N'EST PAS PARTIE** : un
        // datagramme se perd. On renouvelle là où l'on a déjà parlé ; si elle
        // ne répond plus là non plus, elle est partie.
        let boite = trouvee.or_else(|| self.boite.clone());
        self.oublier_ce_qui_est_ailleurs(boite.as_ref()).await;
        let mut constats = Vec::new();
        if let Some(boite) = &boite {
            self.tour_de_redirection(boite, &mut constats).await;
            self.tour_de_trou(boite, &mut constats).await;
        }
        let tient = self.redirection.is_some() || self.trou.is_some();
        self.boite = boite.filter(|_| entendue || tient);
        self.retenir();
        if self.boite.is_none() {
            constats = vec![sans_passerelle(
                cfg!(target_os = "macos"),
                recues,
                std::env::current_exe().ok().as_deref(),
            )];
        }
        let accord = self.conclure();
        if let Some(conclusion) = self.conclusion(&accord) {
            constats.push(conclusion);
        }
        let _ = self.accorder.send(accord);
        self.constater(constats);
    }

    /// Dit ce qu'un tour a conclu, s'il conclut autre chose que le
    /// précédent.
    fn constater(&mut self, constats: Vec<String>) {
        if constats != self.constats {
            for constat in &constats {
                dire(constat);
            }
            self.constats = constats;
        }
    }

    /// Retire ce qu'on tient sur une box qui n'est plus la nôtre, ou pour une
    /// adresse qui n'est plus la nôtre.
    async fn oublier_ce_qui_est_ailleurs(&mut self, boite: Option<&Boite>) {
        let garder_redirection = matches!(
            (&self.redirection, boite.and_then(|b| b.redirection.as_ref())),
            (Some(tenue), Some((controle, _, client))) if tenue.controle == *controle && tenue.client == *client
        );
        if !garder_redirection && let Some(tenue) = self.redirection.take() {
            let _ = demander(
                &tenue.controle,
                tenue.service,
                &soap::retirer(tenue.externe),
            )
            .await;
        }
        let client = self.client_ipv6();
        let garder_trou = matches!(
            (&self.trou, boite.and_then(|b| b.pare_feu.as_ref())),
            (Some(tenu), Some(controle)) if tenu.controle == *controle && Some(tenu.client) == client
        );
        if !garder_trou && let Some(tenu) = self.trou.take() {
            let _ = demander(
                &tenu.controle,
                description::PARE_FEU_6,
                &soap::retirer_le_trou(tenu.identifiant),
            )
            .await;
        }
        self.retenir();
    }

    /// La redirection IPv4 : la demander ou la renouveler, puis lire
    /// l'adresse externe.
    async fn tour_de_redirection(&mut self, boite: &Boite, constats: &mut Vec<String>) {
        let Some((controle, service, client)) = &boite.redirection else {
            if boite.pare_feu.is_some() {
                self.bavarder("la box ne propose pas de redirection IPv4 (ni WANIPConnection, ni WANPPPConnection)");
            }
            return;
        };
        let avant = self.redirection.clone();
        match self.rediriger(controle, service, *client, constats).await {
            Ok(mut obtenue) => {
                if let Some(avant) = &avant
                    && avant.externe != obtenue.externe
                {
                    let _ = demander(controle, service, &soap::retirer(avant.externe)).await;
                }
                obtenue.adresse_externe =
                    match demander(controle, service, &soap::adresse_externe()).await {
                        Ok(retour) => retour.valeur("NewExternalIPAddress").and_then(soap::ipv4),
                        Err(quoi) => {
                            self.bavarder(&format!("GetExternalIPAddress : {quoi}"));
                            None
                        }
                    };
                let externe = obtenue
                    .adresse_externe
                    .map_or_else(|| "?".to_owned(), |adresse| adresse.to_string());
                let bail = if obtenue.permanente {
                    "permanente (la box n'accepte que cela) — retirée à l'arrêt"
                } else {
                    "bail 1 h"
                };
                constats.push(format!(
                    "redirection UPnP : udp {} → box {externe}:{}, {bail}",
                    self.port, obtenue.externe
                ));
                if avant.as_ref().is_some_and(|avant| {
                    avant.externe == obtenue.externe && avant.controle == obtenue.controle
                }) {
                    self.bavarder(&format!("redirection renouvelée : udp {}", obtenue.externe));
                }
                self.redirection = Some(obtenue);
            }
            Err(quoi) => {
                self.redirection = None;
                constats.push(format!(
                    "la box {} refuse la redirection d'udp {} : {quoi}",
                    boite.hote, self.port
                ));
            }
        }
    }

    /// Demande la redirection UDP du port de l'écho.
    ///
    /// # LE PORT EXTERNE N'EST PAS LE PORT INTERNE (essai réel, 2026-09-30)
    ///
    /// On demande d'abord le port de l'écho comme port externe — c'est le
    /// plus lisible, et une box qui l'accorde donne les deux fois le même
    /// nombre. Mais **derrière une même box, un autre écho le tient
    /// peut-être** : speedy a tiré 6637 alors qu'oxygen avait déjà fait
    /// rediriger 6637, et la Livebox a refusé par `718
    /// ConflictInMappingEntry`. Neuf ports pour toutes les machines d'une
    /// maison : ce n'est pas un cas de bord. **On garde alors le port interne
    /// et l'on demande un AUTRE port externe** ([`TIRAGES`] essais), puisque
    /// c'est le port externe qui part dans `passerelle` et que l'annuaire
    /// sonde `adresse externe:port externe`.
    ///
    /// **Même quand la box se dit IGD v2** : `AddAnyPortMapping` devrait
    /// choisir elle-même un port libre plutôt que refuser, et certaines
    /// refusent quand même — un `718` sur cette action fait donc passer à la
    /// voie de la v1, avec un port tiré, au lieu de renoncer.
    async fn rediriger(
        &self,
        controle: &Url,
        service: &'static str,
        client: Ipv4Addr,
        constats: &mut Vec<String>,
    ) -> Result<Redirection, Echec> {
        // On redemande le port qu'on tient déjà — c'est ainsi qu'on
        // renouvelle —, sinon le port de l'écho lui-même.
        let voulu = self
            .redirection
            .as_ref()
            .filter(|tenue| tenue.controle == *controle && tenue.client == client)
            .map_or(self.port, |tenue| tenue.externe);
        let accordee = |externe: u16, permanente: bool| Redirection {
            controle: controle.clone(),
            service,
            client,
            externe,
            permanente,
            adresse_externe: None,
        };
        let mut externe = voulu;
        let mut tirages = 0_u8;
        if service == WAN_IP_2 {
            let action = soap::ajouter_n_importe_lequel(externe, self.port, client, BAIL_S);
            match demander(controle, service, &action).await {
                Ok(retour) => {
                    let reserve = retour
                        .valeur("NewReservedPort")
                        .and_then(soap::port)
                        .unwrap_or(externe);
                    return Ok(accordee(reserve, false));
                }
                // Une box qui se dit v2 sans savoir `AddAnyPortMapping` :
                // la voie de la v1, sur le même port externe.
                Err(Echec::Refus(code::ACTION_INCONNUE, _)) => {}
                // **UNE BOX v2 QUI REFUSE QUAND MÊME** : elle aurait dû
                // choisir un port libre ; on en tire un, et l'on continue par
                // `AddPortMapping`.
                Err(Echec::Refus(code::CONFLIT, _)) => {
                    let neuf = port_tire();
                    constats.push(ligne_de_conflit(externe, neuf, self.port));
                    externe = neuf;
                    tirages = 1;
                }
                Err(autre) => return Err(autre),
            }
        }
        let mut bail = BAIL_S;
        loop {
            let action = soap::ajouter(externe, self.port, client, bail);
            match demander(controle, service, &action).await {
                Ok(_) => return Ok(accordee(externe, bail == 0)),
                // **LE PERMANENT SEULEMENT SI LA BOX L'EXIGE** (E18) — et
                // c'est alors à nous de le retirer.
                Err(Echec::Refus(code::PERMANENT_SEULEMENT, _)) if bail != 0 => bail = 0,
                // **UN PORT EXTERNE DÉJÀ PRIS SE REMPLACE** : le port interne
                // ne change pas, lui — la box redirige vers l'écho.
                Err(Echec::Refus(code::CONFLIT, _)) if tirages < TIRAGES => {
                    tirages = tirages.saturating_add(1);
                    let neuf = port_tire();
                    constats.push(ligne_de_conflit(externe, neuf, self.port));
                    externe = neuf;
                }
                // **TOUT CE QU'ON A ESSAYÉ EST PRIS** : on renonce, et l'on
                // dit combien de ports ont été essayés — sans cela, un `718`
                // seul laisse croire que rien n'a été retenté.
                Err(Echec::Refus(code::CONFLIT, texte)) => {
                    constats.push(format!(
                        "la box refuse tout port externe : udp {voulu} et {tirages} port(s) \
                         tiré(s) sont déjà pris (718) — pas de redirection cette fois"
                    ));
                    return Err(Echec::Refus(code::CONFLIT, texte));
                }
                Err(autre) => return Err(autre),
            }
        }
    }

    /// Le trou IPv6, si la box le propose et le permet — **en silence
    /// sinon**, hors du mode bavard (décision 97 ; E20).
    async fn tour_de_trou(&mut self, boite: &Boite, constats: &mut Vec<String>) {
        self.pare_feu_inactif = false;
        let Some(controle) = &boite.pare_feu else {
            self.bavarder("la box ne propose pas de trou IPv6 (WANIPv6FirewallControl)");
            self.trou = None;
            return;
        };
        let Some(client) = self.client_ipv6() else {
            self.bavarder("pas d'adresse IPv6 globale : pas de trou à demander");
            self.trou = None;
            return;
        };
        match self.trouer(controle, client).await {
            Ok(Trouage::Ouvert(trou)) => {
                constats.push(format!(
                    "trou IPv6 UPnP : udp {} vers [{client}], bail 1 h",
                    self.port
                ));
                self.trou = Some(trou);
            }
            Ok(Trouage::Inactif) => {
                self.pare_feu_inactif = true;
                self.trou = None;
            }
            Ok(Trouage::NonPermis) => self.trou = None,
            Err(quoi) => {
                self.bavarder(&format!("la box refuse le trou IPv6 : {quoi}"));
                self.trou = None;
            }
        }
    }

    /// Demande (ou renouvelle) le trou IPv6.
    async fn trouer(&self, controle: &Url, client: Ipv6Addr) -> Result<Trouage, Echec> {
        let service = description::PARE_FEU_6;
        let etat = demander(controle, service, &soap::etat_du_pare_feu()).await?;
        if etat.valeur("FirewallEnabled").and_then(soap::booleen) == Some(false) {
            self.bavarder("le pare-feu IPv6 de la box est inactif : rien à ouvrir");
            return Ok(Trouage::Inactif);
        }
        if etat.valeur("InboundPinholeAllowed").and_then(soap::booleen) == Some(false) {
            self.bavarder("la box n'autorise pas les trous IPv6 (InboundPinholeAllowed = 0)");
            return Ok(Trouage::NonPermis);
        }
        if let Some(tenu) = &self.trou
            && tenu.controle == *controle
            && tenu.client == client
        {
            let renouveler = soap::renouveler_le_trou(tenu.identifiant, BAIL_S);
            if demander(controle, service, &renouveler).await.is_ok() {
                return Ok(Trouage::Ouvert(tenu.clone()));
            }
            // Expiré, ou perdu par une box redémarrée : on le redemande.
        }
        let retour = demander(
            controle,
            service,
            &soap::ajouter_un_trou(client, self.port, BAIL_S),
        )
        .await?;
        let identifiant = retour
            .valeur("UniqueID")
            .and_then(|texte| texte.parse::<u16>().ok())
            .ok_or_else(|| Echec::Illisible("pas d'UniqueID".to_owned()))?;
        Ok(Trouage::Ouvert(Trou {
            controle: controle.clone(),
            client,
            identifiant,
        }))
    }

    /// L'adresse IPv6 pour laquelle on demande le trou : **celle que
    /// l'annuaire voit**, quand c'est l'une des nôtres (pas de NAT en IPv6),
    /// sinon la première adresse globale de la machine.
    fn client_ipv6(&self) -> Option<Ipv6Addr> {
        let globale = |adresse: &IpAddr| match adresse.to_canonical() {
            IpAddr::V6(v6)
                if !url::locale(IpAddr::V6(v6)) && !v6.is_unspecified() && !v6.is_multicast() =>
            {
                Some(v6)
            }
            _ => None,
        };
        self.vu
            .filter(|vu| self.locales.contains(vu))
            .as_ref()
            .and_then(globale)
            .or_else(|| self.locales.iter().find_map(globale))
    }

    /// Ce que ce tour conclut ([`decider`]) — et, bail IPv4 vu d'ailleurs que
    /// de l'adresse externe de la box, **le double NAT retenu**.
    fn conclure(&mut self) -> Accord {
        if let (Some(IpAddr::V4(vu)), Some(boite)) = (
            self.vu.map(|vu| vu.to_canonical()),
            self.redirection
                .as_ref()
                .and_then(|tenue| tenue.adresse_externe),
        ) && boite != vu
        {
            self.double_nat = Some(boite);
        }
        decider(&Faits {
            port: self.port,
            vu: self.vu,
            redirection: self
                .redirection
                .as_ref()
                .map(|tenue| (tenue.externe, tenue.adresse_externe)),
            trou: self.trou.as_ref().map(|tenu| tenu.client),
            pare_feu_inactif: self.pare_feu_inactif,
            double_nat: self.double_nat,
        })
    }

    /// Ce qu'on dit de l'accord : pourquoi une redirection obtenue n'est pas
    /// annoncée. **Rien quand le bail doit passer en IPv4** : c'est l'écho
    /// qui le dit, en basculant — ou qui dit pourquoi il ne le peut pas.
    fn conclusion(&self, accord: &Accord) -> Option<String> {
        if accord.port.is_some() || matches!(accord.voeu, Voeu::Ipv4 { .. }) {
            return None;
        }
        let tenue = self.redirection.as_ref()?;
        let vu = self.vu?.to_canonical();
        match (tenue.adresse_externe, vu) {
            (Some(externe), _) if url::externe_privee(externe) => Some(format!(
                "double NAT : la box n'est pas la dernière (son adresse externe {externe} est \
                 privée) — la redirection ne suffira pas, elle n'est pas annoncée"
            )),
            (Some(externe), IpAddr::V4(vu)) => Some(format!(
                "double NAT : la box dit {externe}, l'annuaire nous voit depuis {vu} — la \
                 redirection ne suffira pas, elle n'est pas annoncée"
            )),
            (None, IpAddr::V4(_)) => Some(
                "la box ne dit pas son adresse externe : la redirection n'est pas annoncée"
                    .to_owned(),
            ),
            (Some(externe), IpAddr::V6(_)) if self.double_nat == Some(externe) => Some(format!(
                "double NAT déjà constaté derrière la box ({externe}) : le bail reste en IPv6, \
                 la redirection n'est pas annoncée"
            )),
            (_, IpAddr::V6(_)) if self.pare_feu_inactif => Some(
                "le pare-feu IPv6 de la box est inactif : le bail reste en IPv6, où tout entre ; \
                 la redirection IPv4 n'est pas annoncée"
                    .to_owned(),
            ),
            (None, IpAddr::V6(_)) => Some(
                "la box ne dit pas son adresse externe : le bail reste en IPv6, la redirection \
                 n'est pas annoncée"
                    .to_owned(),
            ),
            (Some(_), IpAddr::V6(_)) => Some(
                "le bail part en IPv6 : la redirection IPv4 n'est pas annoncée (l'annuaire ne \
                 sonde que l'adresse qu'il a vue)"
                    .to_owned(),
            ),
        }
    }

    /// Retire tout, au propre : l'arrêt de l'écho.
    async fn retirer_tout(&mut self) {
        if let Some(tenue) = self.redirection.take() {
            match demander(
                &tenue.controle,
                tenue.service,
                &soap::retirer(tenue.externe),
            )
            .await
            {
                Ok(_) => dire(&format!("redirection retirée : udp {}", tenue.externe)),
                Err(quoi) => dire(&format!(
                    "redirection NON retirée (udp {}) : {quoi}{}",
                    tenue.externe,
                    if tenue.permanente {
                        " — elle est permanente : le prochain démarrage réessaiera"
                    } else {
                        " — son bail d'une heure la fera tomber"
                    }
                )),
            }
        }
        if let Some(tenu) = self.trou.take() {
            match demander(
                &tenu.controle,
                description::PARE_FEU_6,
                &soap::retirer_le_trou(tenu.identifiant),
            )
            .await
            {
                Ok(_) => dire("trou IPv6 retiré"),
                Err(quoi) => dire(&format!("trou IPv6 NON retiré : {quoi}")),
            }
        }
        self.retenir();
    }

    /// Le fichier qui retient ce que cet écho tient.
    fn memoire(&self) -> PathBuf {
        memoire_du_port(&self.dossier, self.port)
    }

    /// Écrit ce qu'on tient — ou retire le fichier quand on ne tient rien.
    fn retenir(&self) {
        let mut ouvertures = Vec::new();
        if let Some(tenue) = &self.redirection {
            ouvertures.push(Ouverture::Redirection {
                controle: tenue.controle.clone(),
                service: tenue.service.to_owned(),
                port: tenue.externe,
            });
        }
        if let Some(tenu) = &self.trou {
            ouvertures.push(Ouverture::Trou {
                controle: tenu.controle.clone(),
                service: description::PARE_FEU_6.to_owned(),
                identifiant: tenu.identifiant,
            });
        }
        let fichier = self.memoire();
        if ouvertures.is_empty() {
            let _ = std::fs::remove_file(&fichier);
            return;
        }
        if let Err(quoi) = ecrire_en_prive(&fichier, memoire::ecrire(&ouvertures).as_bytes()) {
            dire(&format!(
                "{} NON écrit ({quoi}) : un arrêt brutal laisserait la redirection jusqu'à la fin de son bail",
                fichier.display()
            ));
        }
    }

    /// **CE QU'UN ARRÊT BRUTAL A LAISSÉ** (E18) : chaque mémoire
    /// `upnp-<port>` dont l'écho ne tient plus son port — on le sait en le
    /// liant nous-mêmes un instant — est relue, et ce qu'elle nomme retiré de
    /// la box, avant d'ouvrir quoi que ce soit.
    async fn nettoyer(&self) {
        let Ok(entrees) = std::fs::read_dir(&self.dossier) else {
            return;
        };
        let mut laissees = BTreeSet::new();
        for entree in entrees.flatten() {
            let nom = entree.file_name();
            let Some(port) = nom
                .to_str()
                .and_then(|nom| nom.strip_prefix(MEMOIRE))
                .and_then(|port| port.parse::<u16>().ok())
            else {
                continue;
            };
            // Le nôtre : nous tenons son port, c'est donc un reste. Un autre :
            // un reste si personne ne tient plus son port.
            if port == self.port || port_libre(port) {
                laissees.insert(port);
            }
        }
        for port in laissees {
            let fichier = memoire_du_port(&self.dossier, port);
            let ouvertures = std::fs::read(&fichier)
                .ok()
                .filter(|octets| octets.len() <= memoire::MEMOIRE_MAX)
                .and_then(|octets| memoire::lire(&octets).ok());
            let Some(ouvertures) = ouvertures else {
                dire(&format!("{} illisible : écarté", fichier.display()));
                let _ = std::fs::remove_file(&fichier);
                continue;
            };
            for ouverture in ouvertures {
                let (controle, service, action, quoi) = match &ouverture {
                    Ouverture::Redirection {
                        controle,
                        service,
                        port,
                    } => (
                        controle,
                        service,
                        soap::retirer(*port),
                        format!("la redirection udp {port}"),
                    ),
                    Ouverture::Trou {
                        controle,
                        service,
                        identifiant,
                    } => (
                        controle,
                        service,
                        soap::retirer_le_trou(*identifiant),
                        format!("le trou IPv6 {identifiant}"),
                    ),
                };
                match demander(controle, service, &action).await {
                    Ok(_) => dire(&format!(
                        "retiré ce qu'un arrêt brutal avait laissé : {quoi} ({})",
                        controle.hote
                    )),
                    Err(echec) => self.bavarder(&format!(
                        "{quoi}, laissée par un arrêt brutal, ne se retire pas : {echec}"
                    )),
                }
            }
            let _ = std::fs::remove_file(&fichier);
        }
    }

    /// Cherche la box : SSDP, puis la description de chaque passerelle
    /// entendue, jusqu'à en avoir une qui redirige.
    async fn chercher(&self) -> (Option<Boite>, usize) {
        let destinations = match &self.reglage.ssdp {
            Some(adresses) => adresses.clone(),
            None => groupes(&interfaces_du_lien(
                std::fs::read_to_string("/proc/net/if_inet6")
                    .ok()
                    .as_deref(),
            )),
        };
        let (entendues, recues) = self.ecouter_ssdp(&destinations).await;
        let mut boite: Option<Boite> = None;
        for location in entendues.iter().take(DESCRIPTIONS_MAX) {
            let (choix, locale) = match examiner(location).await {
                Ok(examinee) => examinee,
                Err(quoi) => {
                    self.bavarder(&format!("description {location} : {quoi}"));
                    continue;
                }
            };
            // **CE QU'UNE DESCRIPTION N'APPORTE PAS SE DIT** : c'est ce qui
            // manquait pour lire l'essai réel de 0.24.1.
            match (&choix.connexion, locale.to_canonical(), &choix.pare_feu) {
                (None, _, None) => self.bavarder(&format!(
                    "description {location} : ni redirection, ni pare-feu IPv6"
                )),
                (Some(_), IpAddr::V6(_), None) => self.bavarder(&format!(
                    "description {location} : redirection décrite, mais jointe en IPv6 — \
                     elle se demande depuis l'IPv4"
                )),
                _ => {}
            }
            let trouvee = boite.get_or_insert(Boite {
                redirection: None,
                pare_feu: None,
                hote: location.hote,
            });
            if trouvee.redirection.is_none()
                && let (Some((controle, genre)), IpAddr::V4(client)) =
                    (choix.connexion, locale.to_canonical())
            {
                trouvee.redirection = Some((controle, genre, client));
                trouvee.hote = location.hote;
            }
            // **LE TROU S'OUVRE DE PRÉFÉRENCE PAR IPv6** : une box peut
            // exiger que la demande vienne de l'adresse qu'on ouvre.
            if let Some(pare_feu) = choix.pare_feu
                && (trouvee.pare_feu.is_none() || location.hote.is_ipv6())
            {
                trouvee.pare_feu = Some(pare_feu);
            }
        }
        (
            boite.filter(|trouvee| trouvee.redirection.is_some() || trouvee.pare_feu.is_some()),
            recues,
        )
    }

    /// Envoie le `M-SEARCH` et écoute : rend les `LOCATION` admises, une par
    /// passerelle — **celles d'IPv4 d'abord**.
    ///
    /// # DEUX FAMILLES, INDÉPENDANTES ET EN PARALLÈLE
    ///
    /// Chacune a sa socket, ses envois, son écoute et **son propre délai** :
    /// l'échec, le silence ou la réponse de l'une ne retarde ni n'abrège
    /// l'autre. C'est la leçon de 0.24.1, vue en vrai derrière une Livebox :
    /// les deux familles partageaient une écoute, et la PREMIÈRE réponse
    /// entendue la raccourcissait à [`APRES_LA_PREMIERE`]. Une réponse IPv6
    /// arrivée tôt — dont la description, jointe en IPv6, ne peut rien donner
    /// pour la redirection IPv4 (`NewInternalClient` est l'adresse IPv4 d'où
    /// l'on parle à la box) — coupait l'écoute avant que la réponse IPv4 ne
    /// vienne : la box tire son délai au hasard jusqu'à `MX` secondes. En
    /// 0.24.0, le `M-SEARCH` IPv6 ne partait pas sous macOS, et le défaut ne
    /// se voyait pas.
    async fn ecouter_ssdp(&self, destinations: &[SocketAddr]) -> (Vec<Url>, usize) {
        let (quatre, six) = les_deux(
            self.ecouter_une_famille(destinations, false),
            self.ecouter_une_famille(destinations, true),
        )
        .await;
        let (quatre, recues_4) = quatre;
        let (six, recues_6) = six;
        // Une box peut se décrire à la même adresse dans ses deux réponses.
        let mut entendues: Vec<Url> = Vec::new();
        for location in quatre.into_iter().chain(six) {
            if !entendues.contains(&location) {
                entendues.push(location);
            }
        }
        (entendues, recues_4.saturating_add(recues_6))
    }

    /// Le `M-SEARCH` d'une famille, et son écoute — voir [`Self::ecouter_ssdp`].
    async fn ecouter_une_famille(
        &self,
        destinations: &[SocketAddr],
        six: bool,
    ) -> (Vec<Url>, usize) {
        let famille = if six { "IPv6" } else { "IPv4" };
        let visees: Vec<&SocketAddr> = destinations
            .iter()
            .filter(|destination| destination.is_ipv6() == six)
            .collect();
        if visees.is_empty() {
            if six && self.reglage.ssdp.is_none() {
                self.bavarder("SSDP IPv6 : aucune interface à lien local, rien n'est envoyé");
            }
            return (Vec::new(), 0);
        }
        let lien = if six { "[::]:0" } else { "0.0.0.0:0" };
        let socket = match UdpSocket::bind(lien).await {
            Ok(socket) => socket,
            Err(quoi) => {
                self.bavarder(&format!("SSDP {famille} : pas de socket {lien} ({quoi})"));
                return (Vec::new(), 0);
            }
        };
        // **UN SAUT** (§3 quater) : la box est sur le lien.
        if !six {
            let _ = socket.set_multicast_ttl_v4(1);
        }
        // Le groupe IPv6 part sur des interfaces peut-être essayées à
        // l'aveugle ([`interfaces_du_lien`]) : leurs refus sont attendus, et
        // l'on ne dit que le bilan. Toute autre destination dit le sien.
        let mut sur: Vec<u32> = Vec::new();
        let mut refus: Option<(SocketAddr, std::io::Error)> = None;
        let mut parties: Vec<SocketAddr> = Vec::new();
        for destination in visees {
            let hote = hote_ssdp(*destination);
            for cible in ssdp::CIBLES {
                match envoyer(&socket, &ssdp::recherche(cible, &hote), *destination).await {
                    Ok(_) => match destination {
                        SocketAddr::V6(v6) if vers_le_groupe_v6(destination) => {
                            if !sur.contains(&v6.scope_id()) {
                                sur.push(v6.scope_id());
                            }
                        }
                        _ => {
                            if !parties.contains(destination) {
                                parties.push(*destination);
                            }
                        }
                    },
                    Err(quoi) if vers_le_groupe_v6(destination) => {
                        refus = Some((*destination, quoi));
                        // L'interface refuse `:2` ; elle refusera `:1`.
                        break;
                    }
                    Err(quoi) => {
                        self.bavarder(&format!("SSDP {famille} vers {destination} : {quoi}"));
                        break;
                    }
                }
            }
        }
        if !parties.is_empty() {
            self.bavarder(&format!(
                "SSDP {famille} : M-SEARCH vers {}",
                parties
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if let Some(bilan) = bilan_du_groupe_v6(&sur, refus.as_ref()) {
            self.bavarder(&bilan);
        }
        if parties.is_empty() && sur.is_empty() {
            return (Vec::new(), 0);
        }
        // Nos liens IPv6, pour admettre une box qui répond de son lien local
        // et se décrit à son adresse globale (`ssdp::passerelle`).
        let table = if six {
            std::fs::read_to_string("/proc/net/if_inet6").ok()
        } else {
            None
        };
        let (entendues, recues) = self.ecouter(&socket, famille, table.as_deref()).await;
        self.bavarder(&format!(
            "SSDP {famille} : {recues} réponse(s) reçue(s), {} passerelle(s) retenue(s)",
            entendues.len()
        ));
        (entendues, recues)
    }

    /// Écoute une socket de recherche jusqu'à [`ECOUTE_SSDP`] — ou
    /// [`APRES_LA_PREMIERE`] après sa première passerelle : rend les
    /// `LOCATION` admises, et le nombre de datagrammes reçus.
    async fn ecouter(
        &self,
        socket: &UdpSocket,
        famille: &str,
        table: Option<&str>,
    ) -> (Vec<Url>, usize) {
        let mut entendues: Vec<Url> = Vec::new();
        let mut recues = 0_usize;
        let debut = Instant::now();
        let mut fin = debut.checked_add(ECOUTE_SSDP).unwrap_or(debut);
        let mut tampon = vec![0_u8; ssdp::REPONSE_MAX];
        loop {
            let reste = fin.saturating_duration_since(Instant::now());
            if reste.is_zero() {
                break;
            }
            let (lus, source) =
                match tokio::time::timeout(reste, socket.recv_from(&mut tampon)).await {
                    Err(_) => break,
                    Ok(Ok(recu)) => recu,
                    // Une socket UDP non connectée n'a guère d'erreur à rendre ;
                    // si elle en rend une, elle la rendrait encore.
                    Ok(Err(quoi)) => {
                        self.bavarder(&format!("SSDP {famille} : écoute interrompue ({quoi})"));
                        break;
                    }
                };
            recues = recues.saturating_add(1);
            let recu = tampon.get(..lus).unwrap_or_default();
            let liens = match source {
                SocketAddr::V6(v6) => liens_du_lien(table, v6.scope_id(), &self.locales),
                SocketAddr::V4(_) => Vec::new(),
            };
            match ssdp::passerelle(recu, source.ip(), &liens) {
                Ok((mut location, admission)) => {
                    if let ssdp::Admission::SurLeLien {
                        lien: (notre, longueur),
                        meme_identifiant,
                    } = admission
                    {
                        self.bavarder(&format!(
                            "SSDP de {source} : LOCATION {location} admise — sur notre lien \
                             ({notre}/{longueur}){}",
                            if meme_identifiant {
                                ", même identifiant d'interface que la source"
                            } else {
                                ", autre identifiant d'interface que la source"
                            }
                        ));
                    }
                    // Un lien local se joint par l'interface d'où il a
                    // répondu ; une adresse globale, par la route.
                    if let (SocketAddr::V6(source), IpAddr::V6(hote)) = (source, location.hote)
                        && hote.is_unicast_link_local()
                        && location.portee == 0
                    {
                        location.portee = source.scope_id();
                    }
                    if !entendues.contains(&location) {
                        if entendues.is_empty() {
                            fin = Instant::now()
                                .checked_add(APRES_LA_PREMIERE)
                                .unwrap_or(fin)
                                .min(fin);
                        }
                        entendues.push(location);
                    }
                }
                Err(quoi) => self.bavarder(&format!("SSDP de {source} écartée : {quoi:?}")),
            }
        }
        (entendues, recues)
    }
}

/// Ce qu'on dit quand aucune passerelle n'est trouvée — et, **sous macOS,
/// quand aucune réponse SSDP n'est même arrivée**, pourquoi c'est peut-être
/// la machine et non le réseau.
///
/// # LE PARE-FEU APPLICATIF DE macOS
///
/// Vu sur le Mac de l'essai réel (journal `com.apple.alf` : « Designated
/// requirement not obtained for flow, dropping flow ») : la réponse à un
/// `M-SEARCH` vient de l'adresse **unicast** de la box, alors que la requête
/// est partie vers un **groupe** ; pour le pare-feu, c'est une connexion
/// entrante, et il la jette sans rien dire pour un binaire qu'il ne sait pas
/// identifier — un `asl` non signé. L'envoi réussit, l'écoute reste vide. Le
/// même binaire signé, ou autorisé, reçoit. L'`asl` livré dans l'app Mac est
/// signé.
fn sans_passerelle(macos: bool, recues: usize, binaire: Option<&Path>) -> String {
    let base = "pas de passerelle UPnP : joignable depuis l'annuaire, peut-être pas d'ailleurs";
    if !macos || recues > 0 {
        return base.to_owned();
    }
    let chemin = binaire.map_or_else(|| "<chemin d'asl>".to_owned(), |b| b.display().to_string());
    format!(
        "{base}\n\
         passerelle     aucune réponse SSDP reçue : sous macOS, le pare-feu applicatif peut jeter\n\
         passerelle     les réponses d'un binaire `asl` qu'il ne connaît pas (non signé, selon ce\n\
         passerelle     qu'il sait déjà de lui). Signez-le, ou autorisez-le :\n\
         passerelle       sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add {chemin}\n\
         passerelle       sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp {chemin}"
    )
}

/// **NOS PRÉFIXES IPv6 SUR L'INTERFACE `index`**, pour admettre une box qui
/// répond de son lien local et se décrit à son adresse globale
/// (`ssdp::passerelle`, [`ssdp::Admission::SurLeLien`]).
///
/// - **Linux** : `/proc/net/if_inet6` dit, pour chaque adresse, l'index de
///   son interface et la longueur de son préfixe — on prend celles de
///   l'interface qui a reçu la réponse, hors lien local et boucle ;
/// - **partout, et seul sous macOS** (pas de `/proc`, et `getifaddrs` est du
///   C) : nos adresses IPv6 globales connues — celles que l'annonce porte,
///   par lesquelles on sort vers l'annuaire —, en `/64`, la longueur d'un lien
///   IPv6 (RFC 4291 §2.5.1). Une box du même réseau local est dans ce `/64` ;
///   si la machine a plusieurs réseaux, celui qu'on ne voit pas n'admet
///   qu'une `LOCATION` égale à sa source, comme avant.
fn liens_du_lien(table: Option<&str>, index: u32, locales: &[IpAddr]) -> Vec<(Ipv6Addr, u8)> {
    let admissible = |adresse: &Ipv6Addr| {
        !adresse.is_unicast_link_local()
            && !adresse.is_loopback()
            && !adresse.is_unspecified()
            && !adresse.is_multicast()
            && adresse.to_ipv4_mapped().is_none()
    };
    let mut liens: Vec<(Ipv6Addr, u8)> = Vec::new();
    for ligne in table.unwrap_or_default().lines() {
        let mut champs = ligne.split_whitespace();
        let (Some(hexa), Some(numero), Some(longueur)) =
            (champs.next(), champs.next(), champs.next())
        else {
            continue;
        };
        let adresse = u128::from_str_radix(hexa, 16)
            .ok()
            .filter(|_| hexa.len() == 32);
        let numero = u32::from_str_radix(numero, 16).ok();
        let longueur = u8::from_str_radix(longueur, 16).ok();
        if let (Some(adresse), Some(numero), Some(longueur)) = (adresse, numero, longueur)
            && numero == index
            && admissible(&Ipv6Addr::from(adresse))
        {
            liens.push((Ipv6Addr::from(adresse), longueur));
        }
    }
    for adresse in locales {
        if let IpAddr::V6(v6) = adresse
            && admissible(v6)
            && !liens.iter().any(|(notre, _)| notre == v6)
        {
            liens.push((*v6, 64));
        }
    }
    liens
}

/// **LES DEUX À LA FOIS** : attend deux futurs menés ensemble, dans la même
/// tâche — ce que `tokio::join!` ferait, sans la fonctionnalité `macros` de
/// tokio que le binaire ne tire pas.
async fn les_deux<A: Future, B: Future>(a: A, b: B) -> (A::Output, B::Output) {
    use std::task::Poll;
    let mut a = std::pin::pin!(a);
    let mut b = std::pin::pin!(b);
    let mut fait_a: Option<A::Output> = None;
    let mut fait_b: Option<B::Output> = None;
    std::future::poll_fn(|contexte| {
        if fait_a.is_none()
            && let Poll::Ready(sortie) = a.as_mut().poll(contexte)
        {
            fait_a = Some(sortie);
        }
        if fait_b.is_none()
            && let Poll::Ready(sortie) = b.as_mut().poll(contexte)
        {
            fait_b = Some(sortie);
        }
        match (fait_a.take(), fait_b.take()) {
            (Some(sortie_a), Some(sortie_b)) => Poll::Ready((sortie_a, sortie_b)),
            (reste_a, reste_b) => {
                fait_a = reste_a;
                fait_b = reste_b;
                Poll::Pending
            }
        }
    })
    .await
}

/// Le fichier de mémoire d'un écho de ce port.
fn memoire_du_port(dossier: &Path, port: u16) -> PathBuf {
    dossier.join(format!("{MEMOIRE}{port}"))
}

/// Ce port est-il libre ? On le lie un instant, et on le rend.
fn port_libre(port: u16) -> bool {
    std::net::UdpSocket::bind(("::", port)).is_ok()
        || std::net::UdpSocket::bind(("0.0.0.0", port)).is_ok()
}

/// Un port tiré au hasard, de 1024 à 65535.
fn port_tire() -> u16 {
    let tirage = etat::hasard::<2>().map_or(0, u16::from_le_bytes);
    let etendue = u16::MAX
        .saturating_sub(PREMIER_PORT_TIRE)
        .saturating_sub(PORTS_DE_L_ECHO);
    let rang = PREMIER_PORT_TIRE.saturating_add(tirage.checked_rem(etendue).unwrap_or(0));
    // La plage de l'écho est sautée, et non retirée après coup : chaque port
    // rendu a la même chance, et aucun n'est celui d'un voisin.
    if rang >= crate::echo::PREMIER_PORT {
        rang.saturating_add(PORTS_DE_L_ECHO)
    } else {
        rang
    }
}

/// Ce qu'on dit quand un port externe est déjà pris, et qu'on en tire un
/// autre — **toujours**, et pas seulement en mode bavard : c'est ce qui
/// explique qu'un port externe ne soit pas le port de l'écho.
fn ligne_de_conflit(pris: u16, neuf: u16, interne: u16) -> String {
    format!(
        "la box a déjà une redirection pour udp {pris} (un autre appareil) — nouveau port \
         externe demandé : udp {neuf} → udp {interne}"
    )
}

/// Écrit un fichier en `0600`, par un renommage : on ne lit jamais une
/// mémoire à moitié écrite.
fn ecrire_en_prive(fichier: &Path, octets: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let provisoire = fichier.with_extension("nouveau");
    let mut sortie = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&provisoire)?;
    sortie.write_all(octets)?;
    sortie.sync_all()?;
    drop(sortie);
    std::fs::rename(&provisoire, fichier)
}

/// L'en-tête `HOST` d'un `M-SEARCH` vers `destination`.
fn hote_ssdp(destination: SocketAddr) -> String {
    match destination {
        SocketAddr::V4(v4) if *v4.ip() == ssdp::GROUPE_V4 => "239.255.255.250:1900".to_owned(),
        SocketAddr::V6(v6) if *v6.ip() == ssdp::GROUPE_V6 => "[FF02::C]:1900".to_owned(),
        SocketAddr::V4(v4) => v4.to_string(),
        SocketAddr::V6(v6) => format!("[{}]:{}", v6.ip(), v6.port()),
    }
}

/// Les index d'interface essayés, au plus, quand le système ne dit pas les
/// siennes (macOS : pas de `/proc`) — voir [`interfaces_du_lien`].
const INDEX_MAX: u32 = 32;

/// Les groupes SSDP : IPv4, et IPv6 **une fois par interface** —
/// `[ff02::c%<index>]:1900`.
fn groupes(interfaces: &[u32]) -> Vec<SocketAddr> {
    let v4 = SocketAddr::new(IpAddr::V4(ssdp::GROUPE_V4), ssdp::PORT);
    core::iter::once(v4)
        .chain(
            interfaces.iter().map(|index| {
                SocketAddr::V6(SocketAddrV6::new(ssdp::GROUPE_V6, ssdp::PORT, 0, *index))
            }),
        )
        .collect()
}

/// Envoie un datagramme — **et, vers un groupe IPv6 nommé par sa portée,
/// sur l'interface de cette portée** : `IPV6_MULTICAST_IF` d'abord, puis
/// l'envoi. Linux se contente de la portée dans l'adresse ; macOS non (voir
/// [`interfaces_du_lien`]). Les envois d'une socket se suivent dans la même
/// tâche : l'option posée est celle de l'envoi qui suit.
async fn envoyer(
    socket: &UdpSocket,
    octets: &[u8],
    destination: SocketAddr,
) -> std::io::Result<usize> {
    if let SocketAddr::V6(v6) = destination
        && v6.ip().is_multicast()
        && v6.scope_id() != 0
    {
        socket2::SockRef::from(socket).set_multicast_if_v6(v6.scope_id())?;
    }
    socket.send_to(octets, destination).await
}

/// Le `M-SEARCH` vers `destination` part-il vers le groupe IPv6, sur une
/// interface qu'on essaie peut-être à l'aveugle ?
fn vers_le_groupe_v6(destination: &SocketAddr) -> bool {
    matches!(destination, SocketAddr::V6(v6) if *v6.ip() == ssdp::GROUPE_V6)
}

/// Ce que le mode bavard dit de l'envoi au groupe IPv6 : les interfaces qui
/// l'ont pris, ou — aucune — le dernier refus. Rien si l'on n'y a rien
/// envoyé (IPv4 seule, ou `ASL_ECHO_SSDP`).
fn bilan_du_groupe_v6(sur: &[u32], refus: Option<&(SocketAddr, std::io::Error)>) -> Option<String> {
    match (sur, refus) {
        ([], None) => None,
        ([], Some((destination, quoi))) => Some(format!(
            "SSDP IPv6 : aucune interface ne prend le M-SEARCH (dernier refus, vers {destination} : {quoi})"
        )),
        (index, _) => Some(format!(
            "SSDP IPv6 : M-SEARCH sur l'interface {}",
            index
                .iter()
                .map(|index| format!("%{index}"))
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

/// **LES INTERFACES OÙ CHERCHER LA BOX EN IPv6, SANS C.**
///
/// `ff02::c` est un groupe **de lien local** : il n'existe que sur une
/// interface, et un envoi sans elle — portée zéro — est un envoi que le noyau
/// doit deviner. macOS ne devine pas : `No route to host` (os error 65), vu
/// derrière une Livebox le 2026-09-29. Linux devine, par sa table de routage
/// (`ff00::/8` sur chaque interface), et prend celle qu'elle trouve la
/// première : juste sur une machine à une interface, n'importe laquelle sur
/// une machine qui en a plusieurs — un pont de conteneurs, un tunnel, le
/// Wi-Fi à côté de l'Ethernet. Le code d'avant 0.24.1 nommait l'interface
/// de notre adresse IPv6 sous Linux, et aucune ailleurs. **On nomme donc
/// l'interface, de deux façons** ([`envoyer`]) : l'index dans l'adresse de
/// destination (`sin6_scope_id`), qui suffit à Linux, et `IPV6_MULTICAST_IF`
/// sur la socket, que macOS exige — posé par `socket2`, que tokio tire déjà,
/// sans une ligne de C ni d'`unsafe` ici.
///
/// Reste à connaître les index. `getifaddrs` et `if_nametoindex` sont du C
/// (C4), qu'aucune crate du graphe n'enveloppe, et les appeler d'ici
/// demanderait `unsafe`. Alors :
///
/// - **Linux** les dit dans `/proc/net/if_inet6` : une ligne par adresse,
///   l'adresse en hexadécimal puis l'index de son interface. On garde les
///   interfaces qui portent une adresse **de lien local** (`fe80::/10`) — sans
///   elle, pas de multicast de lien — et le M-SEARCH part sur chacune ;
/// - **ailleurs** (macOS, ou un `/proc` qu'on ne lit pas), **les index 1 à
///   [`INDEX_MAX`], tous** : un index sans interface, ou une interface sans
///   IPv6, refuse l'option ou l'envoi sur-le-champ (`EINVAL`, `ENXIO`,
///   `EADDRNOTAVAIL`, `ENETUNREACH`), et ce refus est attendu, donc tu. Les index se donnent
///   à partir de 1, dans l'ordre où les interfaces apparaissent, et macOS
///   redonne le même à une interface qui revient (`utun`, un pont de VM) : une
///   machine de bureau reste loin de trente-deux. C'est soixante-quatre appels
///   système toutes les trente minutes.
///
/// **Pourquoi pas seulement l'interface de la route par défaut** : il faudrait
/// lire la table de routage — `/proc/net/ipv6_route` sous Linux, et sous
/// macOS une socket de routage (`PF_ROUTE`) ou `route -n get`, c'est-à-dire du
/// C ou un programme tiers dont on lirait la sortie. Et la box n'est pas
/// toujours derrière la route par défaut (un VPN la prend). Envoyer partout
/// ne coûte rien : **ce qui répond n'est cru qu'à ses conditions**
/// ([`ssdp::passerelle`] : une `LOCATION` égale à la source, et locale), et
/// la réponse revient avec l'index de l'interface qui l'a entendue.
fn interfaces_du_lien(table: Option<&str>) -> Vec<u32> {
    let Some(table) = table else {
        return (1..=INDEX_MAX).collect();
    };
    let mut index: Vec<u32> = Vec::new();
    for ligne in table.lines() {
        let mut champs = ligne.split_whitespace();
        let (Some(adresse), Some(numero)) = (champs.next(), champs.next()) else {
            continue;
        };
        // `fe80::/10` : les dix premiers bits, `fe8`, `fe9`, `fea` ou `feb`.
        let de_lien =
            adresse.len() == 32 && matches!(adresse.get(..3), Some("fe8" | "fe9" | "fea" | "feb"));
        if let (true, Ok(numero)) = (de_lien, u32::from_str_radix(numero, 16))
            && numero != 0
            && !index.contains(&numero)
        {
            index.push(numero);
        }
    }
    index
}

/// Lit la description d'une passerelle : ce qu'on en emploiera, et notre
/// adresse vue d'elle.
async fn examiner(location: &Url) -> Result<(description::Choix, IpAddr), Echec> {
    let (reponse, locale) = echanger(location, &http::get(location)).await?;
    if reponse.statut != 200 {
        return Err(Echec::Illisible(format!("statut {}", reponse.statut)));
    }
    let lue =
        description::lire(&reponse.corps).map_err(|quoi| Echec::Illisible(quoi.to_string()))?;
    Ok((description::choisir(&lue, location), locale.ip()))
}

/// Une action SOAP, et sa réponse — une faute UPnP devient [`Echec::Refus`].
async fn demander(
    controle: &Url,
    service: &str,
    action: &soap::Action,
) -> Result<soap::Retour, Echec> {
    let requete = http::soap(controle, service, action.nom, &action.enveloppe(service));
    let (reponse, _) = echanger(controle, &requete).await?;
    match soap::lire(&reponse.corps, action.nom) {
        Ok(soap::Retour::Refus { code, description }) => Err(Echec::Refus(code, description)),
        Ok(retour) if reponse.statut == 200 => Ok(retour),
        Ok(_) => Err(Echec::Illisible(format!("statut {}", reponse.statut))),
        Err(quoi) => Err(Echec::Illisible(format!(
            "{quoi:?} (statut {})",
            reponse.statut
        ))),
    }
}

/// Un échange HTTP avec la box, borné dans le temps et en taille : rend la
/// réponse, et l'adresse locale d'où l'on a parlé.
async fn echanger(url: &Url, requete: &[u8]) -> Result<(http::Reponse, SocketAddr), Echec> {
    let echange = async {
        let mut flux = TcpStream::connect(url.socket())
            .await
            .map_err(|quoi| Echec::Injoignable(quoi.to_string()))?;
        let locale = flux
            .local_addr()
            .map_err(|quoi| Echec::Injoignable(quoi.to_string()))?;
        flux.write_all(requete)
            .await
            .map_err(|quoi| Echec::Injoignable(quoi.to_string()))?;
        let mut lus = Vec::new();
        let mut morceau = [0_u8; 4_096];
        loop {
            let combien = flux
                .read(&mut morceau)
                .await
                .map_err(|quoi| Echec::Injoignable(quoi.to_string()))?;
            lus.extend_from_slice(morceau.get(..combien).unwrap_or_default());
            match http::lire(&lus, combien == 0) {
                Ok(Lu::Complet(reponse)) => return Ok((reponse, locale)),
                Ok(Lu::Incomplet) => {}
                Err(http::FauteHttp::Vide) => return Err(Echec::Muette),
                Err(quoi) => return Err(Echec::Illisible(format!("{quoi:?}"))),
            }
        }
    };
    tokio::time::timeout(DELAI_HTTP, echange)
        .await
        .unwrap_or_else(|_| {
            Err(Echec::Injoignable(format!(
                "aucune réponse de {} en 5 s",
                url.hote_http()
            )))
        })
}

/// La version d'annuaire qui connaît `passerelle` (serveur 0.44.0, décision
/// 97) : **un annuaire plus ancien refuse l'annonce entière** — son décodeur
/// refuse tout champ inconnu.
pub const VERSION_PASSERELLE: (u64, u64, u64) = (0, 44, 0);

/// La version d'annuaire qui connaît `passerelle.externe` (serveur 0.45.0,
/// décision 107) : un membre d'annuaire local plus ancien refuserait
/// l'annonce entière.
pub const VERSION_EXTERNE: (u64, u64, u64) = (0, 45, 0);

/// Cette version d'annuaire accepte-t-elle `passerelle` ? Une version qui ne
/// se lit pas ne l'accepte pas : dans le doute, on n'envoie rien.
#[must_use]
pub fn connait_la_passerelle(version: &str) -> bool {
    au_moins(version, VERSION_PASSERELLE)
}

/// Cette version d'annuaire accepte-t-elle `passerelle.externe` ? La même
/// prudence.
#[must_use]
pub fn connait_l_externe(version: &str) -> bool {
    au_moins(version, VERSION_EXTERNE)
}

/// La version, lue strictement (`M.m.p`, des chiffres seulement), est-elle
/// au moins `voulue` ?
fn au_moins(version: &str, voulue: (u64, u64, u64)) -> bool {
    let mut morceaux = version.trim().split('.').map(|morceau| {
        morceau
            .bytes()
            .all(|octet| octet.is_ascii_digit())
            .then(|| morceau.parse::<u64>().ok())
            .flatten()
    });
    match (
        morceaux.next(),
        morceaux.next(),
        morceaux.next(),
        morceaux.next(),
    ) {
        (Some(Some(majeure)), Some(Some(mineure)), Some(Some(corrective)), None) => {
            (majeure, mineure, corrective) >= voulue
        }
        _ => false,
    }
}

/// `ASL_ECHO_SSDP` : des adresses littérales `ip:port`, séparées de virgules.
///
/// # Erreurs
///
/// Le texte qui ne se lit pas.
pub fn adresses_ssdp(texte: &str) -> Result<Vec<SocketAddr>, String> {
    texte
        .split(',')
        .map(str::trim)
        .filter(|morceau| !morceau.is_empty())
        .map(|morceau| {
            morceau
                .parse::<SocketAddr>()
                .map_err(|_| format!("ASL_ECHO_SSDP : « {morceau} » n'est pas une adresse ip:port"))
        })
        .collect::<Result<Vec<_>, _>>()
        .and_then(|adresses| {
            if adresses.is_empty() {
                Err("ASL_ECHO_SSDP est vide".to_owned())
            } else {
                Ok(adresses)
            }
        })
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, SocketAddr, SocketAddrV6};

    use asl_upnp::ssdp;
    use tokio::net::UdpSocket;

    use super::{
        Accord, Boite, Echec, Faits, INDEX_MAX, Reglage, Retour, TIRAGES, Tache, Voeu,
        adresses_ssdp, bilan_du_groupe_v6, connait_l_externe, connait_la_passerelle, decider,
        echanger, envoyer, groupes, hote_ssdp, http, interfaces_du_lien, les_deux, liens_du_lien,
        port_tire, sans_passerelle, vers_le_groupe_v6,
    };

    /// `/proc/net/if_inet6` d'une machine à Ethernet, Wi-Fi et pont de
    /// conteneurs : la boucle n'a que `::1`, le pont une ULA et son lien
    /// local, une interface a l'IPv6 sans lien local.
    const IF_INET6: &str = "\
fe800000000000003e0754fffe4a1f79 02 40 20 80   enp2s0
00000000000000000000000000000001 01 80 10 80       lo
2a01cb190d272f003e0754fffe4a1f79 02 40 00 00   enp2s0
fd3fcb218a9700010000000000000103 02 40 00 80   enp2s0
fe80000000000000a8bbccfffedd0011 03 40 20 80   wlp3s0
fe80000000000000004200fffe000001 0c 40 20 80  docker0
fd000000000000000000000000000007 0d 40 00 80   wg0
febf0000000000000000000000000001 0e 40 20 80   bord
fec00000000000000000000000000001 0f 40 20 80   hors
ligne illisible
fe80000000000000a8bbccfffedd0011 zz 40 20 80   casse
fe80000000000000a8bbccfffedd0011 00 40 20 80   nul
fe80 02 40 20 80   court
";

    #[test]
    fn seul_un_annuaire_0_44_0_ou_plus_recoit_la_passerelle() {
        for oui in ["0.44.0", "0.44.1", "0.45.0", "1.0.0", " 0.44.0 "] {
            assert!(connait_la_passerelle(oui), "{oui}");
        }
        for non in [
            "0.43.9", "0.43.0", "0.2.0", "", "0.44", "0.44.0.1", "0.44.x", "0.+44.0", "v0.44.0",
        ] {
            assert!(!connait_la_passerelle(non), "{non}");
        }
    }

    #[test]
    fn seul_un_annuaire_0_45_0_ou_plus_recoit_l_adresse_externe() {
        for oui in ["0.45.0", "0.45.1", "0.46.0", "1.0.0"] {
            assert!(connait_l_externe(oui), "{oui}");
        }
        for non in ["0.44.2", "0.44.0", "", "0.45", "v0.45.0"] {
            assert!(!connait_l_externe(non), "{non}");
        }
    }

    #[test]
    fn asl_echo_ssdp_se_lit_strictement() {
        assert_eq!(
            adresses_ssdp("127.0.0.1:1900, [::1]:1901").unwrap(),
            vec![
                "127.0.0.1:1900".parse().unwrap(),
                "[::1]:1901".parse().unwrap()
            ]
        );
        assert!(adresses_ssdp("").is_err());
        assert!(adresses_ssdp("box:1900").is_err());
    }

    #[test]
    fn le_host_d_un_m_search_suit_la_destination() {
        assert_eq!(
            hote_ssdp("239.255.255.250:1900".parse().unwrap()),
            "239.255.255.250:1900"
        );
        assert_eq!(
            hote_ssdp("[ff02::c%3]:1900".parse().unwrap()),
            "[FF02::C]:1900"
        );
        assert_eq!(
            hote_ssdp("192.168.1.1:1900".parse().unwrap()),
            "192.168.1.1:1900"
        );
        assert_eq!(
            hote_ssdp("[fe80::1]:1900".parse().unwrap()),
            "[fe80::1]:1900"
        );
    }

    #[test]
    fn sous_linux_le_m_search_part_sur_chaque_interface_de_lien_local() {
        // enp2s0 une fois (trois adresses), wlp3s0, docker0, et `febf::`
        // (encore `fe80::/10`) ; ni lo, ni wg0 (sans lien local), ni `fec0::`,
        // ni ce qui ne se lit pas.
        assert_eq!(interfaces_du_lien(Some(IF_INET6)), vec![2, 3, 0x0c, 0x0e]);
        // Un `/proc` lu, sans IPv6 : rien à essayer.
        assert_eq!(interfaces_du_lien(Some("")), Vec::<u32>::new());
    }

    #[test]
    fn sans_proc_on_essaie_les_index_un_a_trente_deux() {
        let essayes = interfaces_du_lien(None);
        assert_eq!(essayes.len(), 32);
        assert_eq!(essayes.first(), Some(&1));
        assert_eq!(essayes.last(), Some(&INDEX_MAX));
    }

    #[test]
    fn chaque_interface_a_son_groupe_ipv6_et_l_ipv4_part_une_fois() {
        let destinations = groupes(&[2, 3, 12]);
        assert_eq!(
            destinations,
            vec![
                "239.255.255.250:1900".parse::<SocketAddr>().unwrap(),
                "[ff02::c%2]:1900".parse().unwrap(),
                "[ff02::c%3]:1900".parse().unwrap(),
                "[ff02::c%12]:1900".parse().unwrap(),
            ]
        );
        // La portée est dans l'adresse elle-même : c'est elle qui nomme
        // l'interface de sortie, et `envoyer` la pose en `IPV6_MULTICAST_IF`.
        let portees: Vec<u32> = destinations
            .iter()
            .filter_map(|destination| match destination {
                SocketAddr::V6(v6) => Some(v6.scope_id()),
                SocketAddr::V4(_) => None,
            })
            .collect();
        assert_eq!(portees, vec![2, 3, 12]);
        for destination in &destinations {
            assert_eq!(vers_le_groupe_v6(destination), destination.is_ipv6());
        }
        // Le `HOST` ne porte pas l'index : c'est le groupe, pour la box.
        assert_eq!(hote_ssdp(destinations[3]), "[FF02::C]:1900");
        // Sans interface IPv6, l'IPv4 seule.
        assert_eq!(
            groupes(&[]),
            vec![SocketAddr::new(IpAddr::V4(ssdp::GROUPE_V4), ssdp::PORT)]
        );
    }

    #[test]
    fn une_passerelle_nommee_n_est_pas_le_groupe() {
        for ailleurs in ["[fe80::1%2]:1900", "[::1]:1900", "192.168.1.1:1900"] {
            assert!(!vers_le_groupe_v6(&ailleurs.parse().unwrap()), "{ailleurs}");
        }
        let groupe = SocketAddr::V6(SocketAddrV6::new(ssdp::GROUPE_V6, 1_901, 0, 0));
        assert!(vers_le_groupe_v6(&groupe));
    }

    #[test]
    fn le_bilan_du_groupe_ipv6_tait_les_refus_attendus() {
        assert_eq!(bilan_du_groupe_v6(&[], None), None);
        let refus = (
            "[ff02::c%32]:1900".parse::<SocketAddr>().unwrap(),
            std::io::Error::from(std::io::ErrorKind::HostUnreachable),
        );
        // Une interface au moins a pris : on ne dit qu'elle.
        assert_eq!(
            bilan_du_groupe_v6(&[4, 7], Some(&refus)).unwrap(),
            "SSDP IPv6 : M-SEARCH sur l'interface %4, %7"
        );
        assert_eq!(
            bilan_du_groupe_v6(&[2], None).unwrap(),
            "SSDP IPv6 : M-SEARCH sur l'interface %2"
        );
        // Aucune : le dernier refus, et vers où.
        let aucune = bilan_du_groupe_v6(&[], Some(&refus)).unwrap();
        assert!(
            aucune.starts_with(
                "SSDP IPv6 : aucune interface ne prend le M-SEARCH (dernier refus, vers [ff02::c%32]:1900 : "
            ),
            "{aucune}"
        );
    }

    /// **SUR LE VRAI NOYAU** — l'essai qui compte sous macOS, où l'IPv4
    /// trouvait la box et l'IPv6 rendait `No route to host` : **là où un
    /// envoi multicast IPv4 part, un envoi de lien local IPv6 part aussi**,
    /// par [`envoyer`], sur au moins une des interfaces que
    /// [`interfaces_du_lien`] rend. Sous macOS, `lo0` (index 1, `fe80::1`,
    /// multicast) est toujours là ; sous Linux, toute interface qui a un lien
    /// local.
    ///
    /// **Si l'IPv4 elle-même ne part pas, l'essai ne juge rien** : c'est le
    /// système qui refuse tout multicast à ce processus — sous macOS 15, la
    /// confidentialité du réseau local, qui répond `No route to host` à un
    /// programme que ni le Terminal ni l'utilisateur n'ont lancé (un runner
    /// de CI). Il le dit, et s'arrête.
    ///
    /// Pour ne rien demander à personne, rien ne va aux groupes SSDP : l'IPv4
    /// va à `239.255.255.114`, l'IPv6 à `ff02::114` (RFC 4727, expériences),
    /// port 9 (`discard`), qu'aucune box n'écoute.
    #[tokio::test]
    async fn un_envoi_de_lien_local_nomme_par_son_index_part() {
        let table = std::fs::read_to_string("/proc/net/if_inet6").ok();
        let interfaces = interfaces_du_lien(table.as_deref());
        if interfaces.is_empty() {
            // Un Linux sans IPv6 : rien à éprouver ici.
            return;
        }
        let quatre = UdpSocket::bind("0.0.0.0:0").await.expect("une socket IPv4");
        quatre.set_multicast_ttl_v4(1).expect("un saut");
        if let Err(quoi) = quatre.send_to(b"asl", "239.255.255.114:9").await {
            eprintln!(
                "le multicast IPv4 ne part pas ({quoi}) : le système le refuse à ce processus, rien à juger"
            );
            return;
        }
        let socket = UdpSocket::bind("[::]:0").await.expect("une socket IPv6");
        let experience = "ff02::114".parse().unwrap();
        let mut prises = Vec::new();
        let mut refus = Vec::new();
        for index in &interfaces {
            let destination = SocketAddr::V6(SocketAddrV6::new(experience, 9, 0, *index));
            match envoyer(&socket, b"asl", destination).await {
                Ok(_) => prises.push(*index),
                Err(quoi) => refus.push((*index, quoi.to_string())),
            }
        }
        assert!(
            !prises.is_empty(),
            "aucune interface ne prend l'envoi : {refus:?}"
        );
    }

    /// Les deux futurs avancent ensemble : le plus lent ne retarde pas le
    /// plus rapide, et le tout dure le plus long des deux, pas la somme.
    #[tokio::test]
    async fn les_deux_menent_ensemble() {
        let debut = std::time::Instant::now();
        let (lent, vif) = les_deux(
            async {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                "lent"
            },
            async {
                tokio::time::sleep(std::time::Duration::from_millis(150)).await;
                7
            },
        )
        .await;
        assert_eq!((lent, vif), ("lent", 7));
        assert!(debut.elapsed() < std::time::Duration::from_millis(340));
    }

    #[test]
    fn nos_liens_sont_ceux_de_l_interface_qui_a_recu_et_nos_adresses_connues() {
        // enp2s0 (index 2) : sa globale (/64) et son ULA ; ni son lien local,
        // ni la boucle, ni wlp3s0 (index 3).
        let table = format!(
            "{IF_INET6}2a01cb190d272f00aaaaaaaaaaaaaaaa 03 40 00 00   wlp3s0\n\
             2a01cb190d272f000000000000000099 02 38 00 00   enp2s0\n\
             zz 02 40 00 00   casse\n"
        );
        let ip = |texte: &str| texte.parse::<std::net::Ipv6Addr>().unwrap();
        assert_eq!(
            liens_du_lien(Some(&table), 2, &[]),
            vec![
                (ip("2a01:cb19:d27:2f00:3e07:54ff:fe4a:1f79"), 64),
                (ip("fd3f:cb21:8a97:1::103"), 64),
                (ip("2a01:cb19:d27:2f00::99"), 56),
            ]
        );
        // Sans `/proc` (macOS) : nos adresses globales connues, en /64 ; ni
        // l'IPv4, ni le lien local, ni la boucle, ni une IPv4 enfouie, ni un
        // doublon.
        let locales: Vec<IpAddr> = [
            "192.168.1.20",
            "2a01:cb19:d27:2f00:1c2b:3a4d:5e6f:7081",
            "fe80::1",
            "::1",
            "::ffff:192.168.1.20",
            "::",
            "ff02::1",
        ]
        .iter()
        .map(|texte| texte.parse().unwrap())
        .collect();
        assert_eq!(
            liens_du_lien(None, 12, &locales),
            vec![(ip("2a01:cb19:d27:2f00:1c2b:3a4d:5e6f:7081"), 64)]
        );
        let deja = [IpAddr::V6(ip("2a01:cb19:d27:2f00:3e07:54ff:fe4a:1f79"))];
        assert_eq!(liens_du_lien(Some(&table), 2, &deja).len(), 3);
    }

    #[test]
    fn sous_macos_sans_reponse_on_dit_le_pare_feu() {
        let base = "pas de passerelle UPnP : joignable depuis l'annuaire, peut-être pas d'ailleurs";
        let binaire = std::path::Path::new("/opt/asl/bin/asl");
        // Ailleurs que sous macOS, ou avec une réponse reçue : la phrase seule.
        assert_eq!(sans_passerelle(false, 0, Some(binaire)), base);
        assert_eq!(sans_passerelle(true, 2, Some(binaire)), base);
        let dit = sans_passerelle(true, 0, Some(binaire));
        assert!(dit.starts_with(base), "{dit}");
        assert!(dit.contains("pare-feu applicatif"), "{dit}");
        assert!(
            dit.contains("socketfilterfw --add /opt/asl/bin/asl")
                && dit.contains("socketfilterfw --unblockapp /opt/asl/bin/asl"),
            "{dit}"
        );
        assert!(sans_passerelle(true, 0, None).contains("--add <chemin d'asl>"));
    }

    /// **LA BOX QUI ACCEPTE ET SE TAIT** — la Livebox, pour sa description
    /// en IPv6 : la connexion s'ouvre, et se ferme sans un octet. On le dit
    /// tel quel ; une réponse partielle, elle, reste « tronquée ».
    #[tokio::test]
    async fn une_box_qui_ferme_sans_rien_dire_n_a_rien_repondu() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let muette = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bavarde = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = |ecoute: &tokio::net::TcpListener| {
            asl_upnp::url::lire(&format!(
                "http://{}/gatedesc.xml",
                ecoute.local_addr().unwrap()
            ))
            .unwrap()
        };
        let (vers_muette, vers_bavarde) = (url(&muette), url(&bavarde));
        tokio::spawn(async move {
            // Elle lit la requête — sans quoi le noyau répondrait par un
            // `RST` — puis ferme proprement, sans rien écrire : `curl` dit
            // « Empty reply from server ».
            while let Ok((mut flux, _)) = muette.accept().await {
                let mut requete = [0_u8; 1_024];
                let _ = flux.read(&mut requete).await;
                let _ = flux.shutdown().await;
            }
        });
        tokio::spawn(async move {
            while let Ok((mut flux, _)) = bavarde.accept().await {
                let mut requete = [0_u8; 1_024];
                let _ = flux.read(&mut requete).await;
                let _ = flux
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 9")
                    .await;
                let _ = flux.shutdown().await;
            }
        });
        let rien = echanger(&vers_muette, &http::get(&vers_muette))
            .await
            .unwrap_err();
        assert_eq!(rien, Echec::Muette);
        assert_eq!(
            rien.to_string(),
            "la box n'a rien répondu (connexion fermée sans contenu)"
        );
        let coupee = echanger(&vers_bavarde, &http::get(&vers_bavarde))
            .await
            .unwrap_err();
        assert_eq!(coupee, Echec::Illisible("Tronquee".to_owned()));
        assert_eq!(coupee.to_string(), "réponse illisible (Tronquee)");
    }

    #[test]
    fn un_port_tire_evite_les_ports_connus_et_la_plage_de_l_echo() {
        for _ in 0..1_024 {
            let port = port_tire();
            assert!(port >= 1_024, "{port}");
            // La plage de l'écho est sautée : le port externe d'un voisin de
            // la même box ne se reprend pas (essai réel, 2026-09-30).
            assert!(
                !(crate::echo::PREMIER_PORT..=crate::echo::DERNIER_PORT).contains(&port),
                "{port} est dans la plage de l'écho"
            );
        }
    }

    // ── Le bail en IPv4 (décision 106) ──────────────────────────────────────

    const PORT: u16 = 6634;

    fn v4(texte: &str) -> std::net::Ipv4Addr {
        texte.parse().unwrap()
    }

    fn v6(texte: &str) -> std::net::Ipv6Addr {
        texte.parse().unwrap()
    }

    /// Les faits d'un bail en IPv6 derrière une box qui redirige vers
    /// `203.0.113.7`, sans trou.
    fn livebox() -> Faits {
        Faits {
            port: PORT,
            vu: Some(IpAddr::V6(v6("2001:db8::7"))),
            redirection: Some((PORT, Some(v4("203.0.113.7")))),
            trou: None,
            pare_feu_inactif: false,
            double_nat: None,
        }
    }

    #[test]
    fn sans_trou_une_redirection_publique_fait_passer_le_bail_en_ipv4() {
        assert_eq!(
            decider(&livebox()),
            Accord {
                port: None,
                voeu: Voeu::Ipv4 {
                    externe: v4("203.0.113.7"),
                    port: PORT
                }
            }
        );
        // Le port externe accordé, pas forcément celui de l'écho.
        let autre = Faits {
            redirection: Some((51_377, Some(v4("203.0.113.7")))),
            ..livebox()
        };
        assert_eq!(
            decider(&autre).voeu,
            Voeu::Ipv4 {
                externe: v4("203.0.113.7"),
                port: 51_377
            }
        );
        // Une IPv4 enfouie reste une IPv6 : c'est la famille du bail qui compte.
        assert_eq!(
            decider(&Faits {
                vu: Some(IpAddr::V6(v6("::ffff:203.0.113.7"))),
                ..livebox()
            }),
            Accord {
                port: Some(PORT),
                voeu: Voeu::Rester
            },
            "vue en IPv4, l'adresse de la box annonce la redirection"
        );
    }

    #[test]
    fn en_ipv6_on_reste_quand_rien_ne_justifie_la_bascule() {
        let rester = |faits: Faits| decider(&faits).voeu;
        // Un trou ouvert pour l'adresse vue : on l'annonce, et l'on reste.
        let troue = Faits {
            trou: Some(v6("2001:db8::7")),
            ..livebox()
        };
        assert_eq!(
            decider(&troue),
            Accord {
                port: Some(PORT),
                voeu: Voeu::Rester
            }
        );
        // Un trou ouvert pour une autre de nos adresses : rien à annoncer,
        // mais la box perce — pas de bascule.
        assert_eq!(
            decider(&Faits {
                trou: Some(v6("2001:db8::8")),
                ..livebox()
            }),
            Accord {
                port: None,
                voeu: Voeu::Rester
            }
        );
        // Le pare-feu IPv6 inactif : tout entre en IPv6.
        assert_eq!(
            rester(Faits {
                pare_feu_inactif: true,
                ..livebox()
            }),
            Voeu::Rester
        );
        // Pas de redirection, ou une box qui ne dit pas son adresse externe.
        assert_eq!(
            rester(Faits {
                redirection: None,
                ..livebox()
            }),
            Voeu::Rester
        );
        assert_eq!(
            rester(Faits {
                redirection: Some((PORT, None)),
                ..livebox()
            }),
            Voeu::Rester
        );
        // Une adresse externe privée ou partagée : un double NAT visible.
        for privee in ["100.64.12.34", "192.168.1.1", "10.0.0.1", "169.254.1.1"] {
            assert_eq!(
                rester(Faits {
                    redirection: Some((PORT, Some(v4(privee)))),
                    ..livebox()
                }),
                Voeu::Rester,
                "{privee}"
            );
        }
        // Un double NAT déjà constaté pour cette adresse-là : on ne rebascule
        // pas ; pour une autre, si.
        assert_eq!(
            rester(Faits {
                double_nat: Some(v4("203.0.113.7")),
                ..livebox()
            }),
            Voeu::Rester
        );
        assert!(matches!(
            rester(Faits {
                double_nat: Some(v4("203.0.113.99")),
                ..livebox()
            }),
            Voeu::Ipv4 { .. }
        ));
        // Rien de vu : rien à conclure.
        assert_eq!(
            decider(&Faits {
                vu: None,
                ..livebox()
            }),
            Accord {
                port: None,
                voeu: Voeu::Rester
            }
        );
    }

    #[test]
    fn en_ipv4_on_reste_tant_que_la_redirection_tient_et_on_revient_sur_les_trois_cas() {
        let en_ipv4 = Faits {
            vu: Some(IpAddr::V4(v4("203.0.113.7"))),
            ..livebox()
        };
        // **L'HYSTÉRÉSIS** : la redirection tient, `vu_depuis` est l'adresse de
        // la box — on annonce le port redirigé, et l'on reste.
        assert_eq!(
            decider(&en_ipv4),
            Accord {
                port: Some(PORT),
                voeu: Voeu::Rester
            }
        );
        // Un trou devient possible.
        assert_eq!(
            decider(&Faits {
                trou: Some(v6("2001:db8::7")),
                ..en_ipv4
            })
            .voeu,
            Voeu::Ipv6(Retour::TrouObtenu)
        );
        // La redirection est perdue — ou la box ne dit plus son adresse.
        for perdue in [None, Some((PORT, None))] {
            assert_eq!(
                decider(&Faits {
                    redirection: perdue,
                    ..en_ipv4
                }),
                Accord {
                    port: None,
                    voeu: Voeu::Ipv6(Retour::RedirectionPerdue)
                }
            );
        }
        // Le double NAT se révèle.
        assert_eq!(
            decider(&Faits {
                vu: Some(IpAddr::V4(v4("198.51.100.9"))),
                ..en_ipv4
            }),
            Accord {
                port: None,
                voeu: Voeu::Ipv6(Retour::DoubleNat {
                    boite: v4("203.0.113.7"),
                    vu: v4("198.51.100.9")
                })
            }
        );
    }

    #[test]
    fn un_retour_se_dit() {
        assert_eq!(
            Retour::TrouObtenu.to_string(),
            "la box ouvre maintenant un trou IPv6"
        );
        assert_eq!(
            Retour::RedirectionPerdue.to_string(),
            "la redirection IPv4 est perdue"
        );
        assert_eq!(
            Retour::DoubleNat {
                boite: v4("203.0.113.7"),
                vu: v4("198.51.100.9")
            }
            .to_string(),
            "double NAT : la box dit 203.0.113.7, l'annuaire nous voit depuis 198.51.100.9"
        );
    }

    /// Ce que la fausse box de [`box_qui_refuse_le_trou`] fait.
    #[derive(Debug, Default)]
    struct Comportement {
        /// `FirewallEnabled`.
        pare_feu_inactif: bool,
        /// `AddPinhole` accordé plutôt que refusé (`606`).
        trou_accorde: bool,
        /// `AddPortMapping` refusé (`606`).
        redirection_refusee: bool,
        /// Les ports externes que la box dit déjà pris : `AddPortMapping`
        /// les refuse par `718`, comme la Livebox l'a fait pour le port que
        /// l'écho d'une autre machine tenait (essai réel, 2026-09-30).
        ports_pris: Vec<u16>,
        /// Tout port externe est refusé par `718` : on épuise les essais.
        conflit_toujours: bool,
        /// `AddAnyPortMapping` refusé — par `718` s'il est vrai, par `401`
        /// (action inconnue) sinon : les deux existent en vrai.
        any_en_conflit: Option<bool>,
        /// Les actions reçues, avec le port externe demandé quand il y en a
        /// un : `AddPortMapping 51234`.
        actions: Vec<String>,
    }

    /// **UNE FAUSSE BOX COMME LA LIVEBOX** : `WANIPConnection:1` redirige et
    /// dit `203.0.113.7` ; `WANIPv6FirewallControl:1` dit son pare-feu actif,
    /// les trous permis — puis refuse `AddPinhole` par `606`, comme en vrai.
    /// Rend l'URL de contrôle de chacun des deux services.
    async fn box_qui_refuse_le_trou(
        comportement: std::sync::Arc<std::sync::Mutex<Comportement>>,
    ) -> (asl_upnp::url::Url, asl_upnp::url::Url) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let ecoute = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ici = ecoute.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut flux, _)) = ecoute.accept().await {
                let comportement = std::sync::Arc::clone(&comportement);
                tokio::spawn(async move {
                    let mut lus = Vec::new();
                    let mut morceau = [0_u8; 4_096];
                    let (tete, corps_recu) = loop {
                        let Ok(combien) = flux.read(&mut morceau).await else {
                            return;
                        };
                        if combien == 0 {
                            return;
                        }
                        lus.extend_from_slice(&morceau[..combien]);
                        let texte = String::from_utf8_lossy(&lus).into_owned();
                        if let Some((tete, corps)) = texte.split_once("\r\n\r\n") {
                            let longueur: usize = tete
                                .lines()
                                .find_map(|ligne| {
                                    ligne
                                        .to_ascii_lowercase()
                                        .strip_prefix("content-length: ")
                                        .map(str::to_owned)
                                })
                                .and_then(|longueur| longueur.trim().parse().ok())
                                .unwrap_or(0);
                            if corps.len() >= longueur {
                                break (tete.to_owned(), corps.to_owned());
                            }
                        }
                    };
                    let action = tete
                        .lines()
                        .find_map(|ligne| {
                            let (nom, valeur) = ligne.split_once(':')?;
                            nom.eq_ignore_ascii_case("soapaction")
                                .then(|| valeur.trim().to_owned())
                        })
                        .and_then(|valeur| {
                            valeur
                                .trim_matches('"')
                                .split_once('#')
                                .map(|(_, action)| action.to_owned())
                        })
                        .unwrap_or_default();
                    let service = if tete.starts_with("POST /ctl/Pare-feu ") {
                        super::description::PARE_FEU_6
                    } else {
                        super::description::WAN_IP_1
                    };
                    // Le port externe demandé, tel que le corps SOAP le
                    // porte — ce qui permet à la fausse box de dire qu'il est
                    // déjà pris.
                    let demande = corps_recu
                        .split_once("<NewExternalPort>")
                        .and_then(|(_, reste)| reste.split_once("</NewExternalPort>"))
                        .and_then(|(nombre, _)| nombre.trim().parse::<u16>().ok());
                    let (statut, corps) = {
                        let mut etat = comportement.lock().unwrap();
                        etat.actions.push(match demande {
                            Some(port) => format!("{action} {port}"),
                            None => action.clone(),
                        });
                        let reussi = |valeurs: &str| {
                            format!(
                                "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body>\
                             <u:{action}Response xmlns:u=\"{service}\">{valeurs}</u:{action}Response></s:Body></s:Envelope>"
                            )
                        };
                        let refuse = |code: u16, quoi: &str| {
                            format!(
                                "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body>\
                                 <s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail>\
                                 <UPnPError xmlns=\"urn:schemas-upnp-org:control-1-0\"><errorCode>{code}</errorCode>\
                                 <errorDescription>{quoi}</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>"
                            )
                        };
                        let refus = refuse(606, "Action not authorized");
                        let conflit = refuse(718, "ConflictInMappingEntry");
                        let pris = etat.conflit_toujours
                            || demande.is_some_and(|port| etat.ports_pris.contains(&port));
                        let (statut, corps) = match action.as_str() {
                            "GetFirewallStatus" => (
                                "200 OK",
                                reussi(&format!(
                                    "<FirewallEnabled>{}</FirewallEnabled><InboundPinholeAllowed>1</InboundPinholeAllowed>",
                                    u8::from(!etat.pare_feu_inactif)
                                )),
                            ),
                            "AddPinhole" if etat.trou_accorde => {
                                ("200 OK", reussi("<UniqueID>7</UniqueID>"))
                            }
                            "UpdatePinhole" if etat.trou_accorde => ("200 OK", reussi("")),
                            // **UN PORT EXTERNE DÉJÀ PRIS** : `718`, comme la
                            // Livebox pour le port d'un autre écho.
                            "AddPortMapping" | "AddAnyPortMapping" if pris => {
                                ("500 Internal Server Error", conflit)
                            }
                            "AddAnyPortMapping" => match etat.any_en_conflit {
                                Some(true) => ("500 Internal Server Error", conflit),
                                Some(false) => {
                                    ("500 Internal Server Error", refuse(401, "Invalid Action"))
                                }
                                None => (
                                    "200 OK",
                                    reussi(&format!(
                                        "<NewReservedPort>{}</NewReservedPort>",
                                        demande.unwrap_or(0)
                                    )),
                                ),
                            },
                            "AddPortMapping" if !etat.redirection_refusee => ("200 OK", reussi("")),
                            "GetExternalIPAddress" => (
                                "200 OK",
                                reussi("<NewExternalIPAddress>203.0.113.7</NewExternalIPAddress>"),
                            ),
                            "DeletePortMapping" | "DeletePinhole" => ("200 OK", reussi("")),
                            _ => ("500 Internal Server Error", refus),
                        };
                        (statut, corps)
                    };
                    let ecrit = format!(
                        "HTTP/1.1 {statut}\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{corps}",
                        corps.len()
                    );
                    let _ = flux.write_all(ecrit.as_bytes()).await;
                    let _ = flux.shutdown().await;
                });
            }
        });
        let url = |chemin: &str| asl_upnp::url::lire(&format!("http://{ici}{chemin}")).unwrap();
        (url("/ctl/IPConn"), url("/ctl/Pare-feu"))
    }

    /// Une tâche de passerelle, sans sa boucle : les tours se mènent à la
    /// main, contre la fausse box.
    fn tache(dossier: std::path::PathBuf) -> (Tache, tokio::sync::mpsc::UnboundedReceiver<Accord>) {
        let (accorder, accords) = tokio::sync::mpsc::unbounded_channel();
        (
            Tache {
                port: PORT,
                dossier,
                reglage: Reglage::default(),
                boite: None,
                redirection: None,
                trou: None,
                pare_feu_inactif: false,
                double_nat: None,
                vu: None,
                locales: vec![
                    IpAddr::V6(v6("2001:db8::7")),
                    IpAddr::V4(v4("192.168.1.20")),
                ],
                constats: Vec::new(),
                accorder,
            },
            accords,
        )
    }

    /// Un tour contre `boite`, vu depuis `vu` : ce qu'il conclut.
    async fn un_tour(tache: &mut Tache, boite: &Boite, vu: &str) -> Accord {
        un_tour_dit(tache, boite, vu).await.0
    }

    /// Le même, avec ce qu'il a dit — les constats de la redirection.
    async fn un_tour_dit(tache: &mut Tache, boite: &Boite, vu: &str) -> (Accord, Vec<String>) {
        tache.vu = Some(vu.parse().unwrap());
        let mut constats = Vec::new();
        tache.tour_de_redirection(boite, &mut constats).await;
        tache.tour_de_trou(boite, &mut constats).await;
        (tache.conclure(), constats)
    }

    /// Une fausse box qui se comporte ainsi, et la `Boite` qui la désigne sous
    /// ce service — v1 ou v2.
    async fn box_reglee(
        service: &'static str,
        regler: impl FnOnce(&mut Comportement),
    ) -> (Boite, std::sync::Arc<std::sync::Mutex<Comportement>>) {
        let mut comportement = Comportement::default();
        regler(&mut comportement);
        let comportement = std::sync::Arc::new(std::sync::Mutex::new(comportement));
        let (redirection, pare_feu) =
            box_qui_refuse_le_trou(std::sync::Arc::clone(&comportement)).await;
        (
            Boite {
                redirection: Some((redirection, service, v4("127.0.0.1"))),
                pare_feu: Some(pare_feu),
                hote: IpAddr::V4(v4("127.0.0.1")),
            },
            comportement,
        )
    }

    /// Un répertoire d'état pour un essai, à lui.
    fn dossier_d_essai(quoi: &str) -> std::path::PathBuf {
        let dossier =
            std::env::temp_dir().join(format!("asl-passerelle-{quoi}-{}", std::process::id()));
        std::fs::create_dir_all(&dossier).unwrap();
        dossier
    }

    /// Les ports externes que la fausse box a vu demander, dans l'ordre.
    fn ports_demandes(
        comportement: &std::sync::Arc<std::sync::Mutex<Comportement>>,
        action: &str,
    ) -> Vec<u16> {
        comportement
            .lock()
            .unwrap()
            .actions
            .iter()
            .filter_map(|ligne| {
                let (nom, port) = ligne.split_once(' ')?;
                (nom == action).then(|| port.parse().ok())?
            })
            .collect()
    }

    /// **LE DÉFAUT DU 30/09, SUR SPEEDY** : le port de l'écho était déjà
    /// redirigé par la box pour l'écho d'oxygen, et l'on renonçait sur un
    /// seul `718`. On garde le port interne, et l'on demande un autre port
    /// externe — hors de la plage de l'écho, où vit celui du voisin.
    #[tokio::test]
    async fn un_port_externe_deja_pris_fait_demander_un_autre_port_externe() {
        let (boite, comportement) = box_reglee(super::description::WAN_IP_1, |regle| {
            regle.ports_pris = vec![PORT];
        })
        .await;
        let (mut tache, _accords) = tache(dossier_d_essai("718-v1"));
        let (accord, dits) = un_tour_dit(&mut tache, &boite, "203.0.113.7").await;

        let externe = accord.port.expect("la redirection est obtenue ailleurs");
        assert_ne!(externe, PORT, "un autre port externe");
        assert!(
            !(crate::echo::PREMIER_PORT..=crate::echo::DERNIER_PORT).contains(&externe),
            "hors de la plage de l'écho : {externe}"
        );
        // Le port INTERNE, lui, ne bouge pas : la box redirige vers l'écho.
        assert_eq!(tache.port, PORT);
        assert_eq!(
            ports_demandes(&comportement, "AddPortMapping"),
            vec![PORT, externe],
            "le port de l'écho d'abord, puis le port tiré"
        );
        assert!(
            dits.iter().any(|dit| *dit
                == format!(
                    "la box a déjà une redirection pour udp {PORT} (un autre appareil) — \
                     nouveau port externe demandé : udp {externe} → udp {PORT}"
                )),
            "le journal le dit : {dits:?}"
        );
        assert!(
            dits.iter()
                .any(|dit| dit.contains(&format!("box 203.0.113.7:{externe}"))),
            "la redirection obtenue est dite : {dits:?}"
        );
    }

    /// Tous les ports essayés sont pris : on renonce **proprement**, on le
    /// dit, et l'on n'essaie pas indéfiniment.
    #[tokio::test]
    async fn un_conflit_sur_tous_les_ports_renonce_et_le_dit() {
        let (boite, comportement) = box_reglee(super::description::WAN_IP_1, |regle| {
            regle.conflit_toujours = true;
        })
        .await;
        let (mut tache, _accords) = tache(dossier_d_essai("718-partout"));
        let (accord, dits) = un_tour_dit(&mut tache, &boite, "203.0.113.7").await;

        assert_eq!(accord.port, None, "rien n'est annoncé");
        assert!(tache.redirection.is_none());
        assert_eq!(
            ports_demandes(&comportement, "AddPortMapping").len(),
            usize::from(TIRAGES) + 1,
            "le port de l'écho, puis TIRAGES ports tirés, et pas un de plus"
        );
        assert!(
            dits.iter().any(|dit| dit.contains(&format!(
                "la box refuse tout port externe : udp {PORT} et {TIRAGES} port(s) tiré(s) sont \
                 déjà pris (718)"
            ))),
            "le renoncement est dit : {dits:?}"
        );
    }

    /// **UNE BOX IGD v2 QUI REFUSE QUAND MÊME** : `AddAnyPortMapping` aurait
    /// dû choisir un port libre ; sur `718`, on passe à `AddPortMapping` avec
    /// un port tiré, au lieu de renoncer.
    #[tokio::test]
    async fn une_box_v2_en_conflit_passe_a_add_port_mapping() {
        let (boite, comportement) = box_reglee(super::description::WAN_IP_2, |regle| {
            regle.any_en_conflit = Some(true);
        })
        .await;
        let (mut tache, _accords) = tache(dossier_d_essai("718-v2"));
        let (accord, dits) = un_tour_dit(&mut tache, &boite, "203.0.113.7").await;

        let externe = accord.port.expect("la redirection est obtenue ailleurs");
        assert_ne!(externe, PORT);
        assert_eq!(
            ports_demandes(&comportement, "AddAnyPortMapping"),
            vec![PORT]
        );
        assert_eq!(
            ports_demandes(&comportement, "AddPortMapping"),
            vec![externe],
            "la v1 reprend au port tiré, pas au port déjà refusé"
        );
        assert!(
            dits.iter()
                .any(|dit| dit
                    .starts_with(&format!("la box a déjà une redirection pour udp {PORT}"))),
            "{dits:?}"
        );
    }

    /// Une box qui se dit v2 **sans savoir** `AddAnyPortMapping` (`401`) :
    /// la voie de la v1, sur le même port externe que le port de l'écho.
    #[tokio::test]
    async fn une_box_v2_sans_add_any_port_mapping_reprend_la_v1() {
        let (boite, comportement) = box_reglee(super::description::WAN_IP_2, |regle| {
            regle.any_en_conflit = Some(false);
        })
        .await;
        let (mut tache, _accords) = tache(dossier_d_essai("401-v2"));
        let accord = un_tour(&mut tache, &boite, "203.0.113.7").await;

        assert_eq!(accord.port, Some(PORT), "le port de l'écho a suffi");
        assert_eq!(
            ports_demandes(&comportement, "AddAnyPortMapping"),
            vec![PORT]
        );
        assert_eq!(ports_demandes(&comportement, "AddPortMapping"), vec![PORT]);
    }

    /// **CE QU'ON RETIRE, ET CE QU'ON RETIENT, EST LE PORT EXTERNE** — et non
    /// le port de l'écho : c'est lui que la box connaît.
    #[tokio::test]
    async fn le_retrait_et_la_memoire_portent_le_port_externe() {
        let (boite, comportement) = box_reglee(super::description::WAN_IP_1, |regle| {
            regle.ports_pris = vec![PORT];
        })
        .await;
        let dossier = dossier_d_essai("718-memoire");
        let (mut tache, _accords) = tache(dossier.clone());
        let accord = un_tour(&mut tache, &boite, "203.0.113.7").await;
        let externe = accord.port.expect("obtenue ailleurs");
        tache.retenir();

        let retenu = std::fs::read_to_string(dossier.join(format!("upnp-{PORT}"))).unwrap();
        assert!(
            retenu.contains(&format!("redirection {externe} ")),
            "la mémoire retient le port externe : {retenu}"
        );
        assert!(
            !retenu.contains(&format!("redirection {PORT} ")),
            "et non le port de l'écho : {retenu}"
        );

        tache.boite = Some(boite.clone());
        tache.retirer_tout().await;
        assert_eq!(
            ports_demandes(&comportement, "DeletePortMapping"),
            vec![externe],
            "on retire le port externe"
        );
        let _ = std::fs::remove_dir_all(&dossier);
    }

    /// **LA LIVEBOX, SUR LA BOUCLE LOCALE** — le pare-feu IPv6 actif et les
    /// trous permis, `AddPinhole` refusé par `606`, la redirection accordée
    /// vers `203.0.113.7` : bail en IPv6, la passerelle dit de passer en
    /// IPv4 ; bail en IPv4 vu de l'adresse de la box, elle annonce le port et
    /// dit de rester ; vu d'ailleurs, double NAT, et elle ne redit plus de
    /// basculer vers cette adresse ; la box qui cesse de rediriger, ou qui
    /// perce enfin, ramène en IPv6 ; un pare-feu inactif n'en fait jamais
    /// sortir.
    #[tokio::test]
    async fn contre_une_box_qui_refuse_le_trou_et_redirige() {
        let comportement = std::sync::Arc::new(std::sync::Mutex::new(Comportement::default()));
        let (redirection, pare_feu) =
            box_qui_refuse_le_trou(std::sync::Arc::clone(&comportement)).await;
        let boite = Boite {
            redirection: Some((redirection, super::description::WAN_IP_1, v4("127.0.0.1"))),
            pare_feu: Some(pare_feu),
            hote: IpAddr::V4(v4("127.0.0.1")),
        };
        let dossier =
            std::env::temp_dir().join(format!("asl-passerelle-106-{}", std::process::id()));
        std::fs::create_dir_all(&dossier).unwrap();
        let (mut tache, _accords) = tache(dossier.clone());

        // IPv6 : le trou demandé, refusé ; la redirection, accordée.
        let accord = un_tour(&mut tache, &boite, "2001:db8::7").await;
        assert_eq!(
            accord,
            Accord {
                port: None,
                voeu: Voeu::Ipv4 {
                    externe: v4("203.0.113.7"),
                    port: PORT
                }
            }
        );
        assert!(
            comportement
                .lock()
                .unwrap()
                .actions
                .iter()
                .any(|a| a == "AddPinhole"),
            "le trou a été demandé"
        );
        assert!(tache.trou.is_none());
        assert_eq!(
            tache.conclusion(&accord),
            None,
            "l'écho le dit en basculant"
        );

        // IPv4, vu de l'adresse de la box : on annonce, on reste.
        let accord = un_tour(&mut tache, &boite, "203.0.113.7").await;
        assert_eq!(
            accord,
            Accord {
                port: Some(PORT),
                voeu: Voeu::Rester
            }
        );

        // IPv4, vu d'ailleurs : double NAT — retenu.
        let accord = un_tour(&mut tache, &boite, "198.51.100.9").await;
        assert_eq!(
            accord.voeu,
            Voeu::Ipv6(Retour::DoubleNat {
                boite: v4("203.0.113.7"),
                vu: v4("198.51.100.9")
            })
        );
        let accord = un_tour(&mut tache, &boite, "2001:db8::7").await;
        assert_eq!(
            accord.voeu,
            Voeu::Rester,
            "pas de nouvelle bascule vers la même box"
        );
        assert!(tache.conclusion(&accord).unwrap().starts_with(
            "double NAT déjà constaté derrière la box (203.0.113.7) : le bail reste en IPv6"
        ),);

        // Une autre tâche, sans ce souvenir : en IPv4, la box cesse de rediriger.
        let (mut tache, _accords) = tache_neuve(&dossier);
        assert!(matches!(
            un_tour(&mut tache, &boite, "2001:db8::7").await.voeu,
            Voeu::Ipv4 { .. }
        ));
        comportement.lock().unwrap().redirection_refusee = true;
        assert_eq!(
            un_tour(&mut tache, &boite, "203.0.113.7").await.voeu,
            Voeu::Ipv6(Retour::RedirectionPerdue)
        );
        comportement.lock().unwrap().redirection_refusee = false;

        // En IPv4, la box perce enfin : retour en IPv6, où le trou s'annonce.
        let (mut tache, _accords) = tache_neuve(&dossier);
        assert!(matches!(
            un_tour(&mut tache, &boite, "2001:db8::7").await.voeu,
            Voeu::Ipv4 { .. }
        ));
        comportement.lock().unwrap().trou_accorde = true;
        assert_eq!(
            un_tour(&mut tache, &boite, "203.0.113.7").await.voeu,
            Voeu::Ipv6(Retour::TrouObtenu)
        );
        assert_eq!(
            un_tour(&mut tache, &boite, "2001:db8::7").await,
            Accord {
                port: Some(PORT),
                voeu: Voeu::Rester
            }
        );
        comportement.lock().unwrap().trou_accorde = false;

        // Un pare-feu IPv6 inactif : on reste, et on le dit.
        comportement.lock().unwrap().pare_feu_inactif = true;
        let (mut tache, _accords) = tache_neuve(&dossier);
        let accord = un_tour(&mut tache, &boite, "2001:db8::7").await;
        assert_eq!(accord.voeu, Voeu::Rester);
        assert!(
            tache
                .conclusion(&accord)
                .unwrap()
                .starts_with("le pare-feu IPv6 de la box est inactif : le bail reste en IPv6"),
        );
        let _ = std::fs::remove_dir_all(&dossier);
    }

    fn tache_neuve(
        dossier: &std::path::Path,
    ) -> (Tache, tokio::sync::mpsc::UnboundedReceiver<Accord>) {
        tache(dossier.to_owned())
    }
}
