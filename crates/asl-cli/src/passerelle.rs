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
//!    (IGD v1 ; le même port d'abord, trois ports tirés au hasard sur
//!    conflit), bail d'une heure, permanent seulement si la box l'exige ;
//!    puis `GetExternalIPAddress`, et le trou IPv6 (`AddPinhole`) si la box
//!    le propose et le permet ;
//! 3. **elle recommence** toutes les trente minutes — le bail d'une heure est
//!    renouvelé à mi-course, une box redémarrée est retrouvée — et quand
//!    l'adresse de la machine change (décision 95 ; E23) ;
//! 4. **à l'arrêt**, elle retire tout, avant que l'écho ferme son bail.
//!
//! # CE QU'ELLE DIT À L'ÉCHO
//!
//! Un seul fait : le port à annoncer dans `passerelle`, ou rien
//! ([`Passerelle::accord`]). **Le port seul, jamais l'adresse** : l'annuaire
//! emploie celle qu'il a observée (décision 97 ; E21). Il n'y en a donc un
//! que si la redirection vaut pour CETTE adresse :
//!
//! - bail en IPv4 : l'adresse externe de la box **égale** à `vu_depuis` —
//!   sinon il y a un second NAT au-dessus, la redirection ne suffira pas, et
//!   on le dit sans rien annoncer (E19) ;
//! - bail en IPv6 : le trou ouvert pour l'adresse même que l'annuaire voit
//!   (le port est alors celui de l'écho).
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
    accords: mpsc::UnboundedReceiver<Option<u16>>,
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

    /// Le dernier accord arrivé depuis l'appel précédent : `Some(Some(port))`
    /// — annoncer ce port —, `Some(None)` — n'annoncer rien —, `None` — rien
    /// de neuf.
    pub fn accord(&mut self) -> Option<Option<u16>> {
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
}

impl std::fmt::Display for Echec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Injoignable(quoi) => write!(f, "injoignable ({quoi})"),
            Self::Illisible(quoi) => write!(f, "réponse illisible ({quoi})"),
            Self::Refus(code, description) if description.is_empty() => write!(f, "refus {code}"),
            Self::Refus(code, description) => write!(f, "refus {code} {description}"),
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
    vu: Option<IpAddr>,
    locales: Vec<IpAddr>,
    /// Ce que le dernier tour a conclu, tel qu'on l'a dit : un tour qui
    /// conclut la même chose ne le redit pas.
    constats: Vec<String>,
    accorder: mpsc::UnboundedSender<Option<u16>>,
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
                        let _ = self.accorder.send(self.conclure());
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
        let trouvee = self.chercher().await;
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
            constats = vec![
                "pas de passerelle UPnP : joignable depuis l'annuaire, peut-être pas d'ailleurs"
                    .to_owned(),
            ];
        }
        let accord = self.conclure();
        if let Some(conclusion) = self.conclusion(accord) {
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
        match self.rediriger(controle, service, *client).await {
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
    async fn rediriger(
        &self,
        controle: &Url,
        service: &'static str,
        client: Ipv4Addr,
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
        if service == WAN_IP_2 {
            let action = soap::ajouter_n_importe_lequel(voulu, self.port, client, BAIL_S);
            match demander(controle, service, &action).await {
                Ok(retour) => {
                    let externe = retour
                        .valeur("NewReservedPort")
                        .and_then(soap::port)
                        .unwrap_or(voulu);
                    return Ok(accordee(externe, false));
                }
                // Une box qui se dit v2 sans savoir `AddAnyPortMapping` :
                // la voie de la v1.
                Err(Echec::Refus(code::ACTION_INCONNUE, _)) => {}
                Err(autre) => return Err(autre),
            }
        }
        let mut externe = voulu;
        let mut bail = BAIL_S;
        let mut tirages = 0_u8;
        loop {
            let action = soap::ajouter(externe, self.port, client, bail);
            match demander(controle, service, &action).await {
                Ok(_) => return Ok(accordee(externe, bail == 0)),
                // **LE PERMANENT SEULEMENT SI LA BOX L'EXIGE** (E18) — et
                // c'est alors à nous de le retirer.
                Err(Echec::Refus(code::PERMANENT_SEULEMENT, _)) if bail != 0 => bail = 0,
                Err(Echec::Refus(code::CONFLIT, _)) if tirages < TIRAGES => {
                    tirages = tirages.saturating_add(1);
                    externe = port_tire();
                }
                Err(autre) => return Err(autre),
            }
        }
    }

    /// Le trou IPv6, si la box le propose et le permet — **en silence
    /// sinon**, hors du mode bavard (décision 97 ; E20).
    async fn tour_de_trou(&mut self, boite: &Boite, constats: &mut Vec<String>) {
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
            Ok(Some(trou)) => {
                constats.push(format!(
                    "trou IPv6 UPnP : udp {} vers [{client}], bail 1 h",
                    self.port
                ));
                self.trou = Some(trou);
            }
            Ok(None) => self.trou = None,
            Err(quoi) => {
                self.bavarder(&format!("la box refuse le trou IPv6 : {quoi}"));
                self.trou = None;
            }
        }
    }

    /// Demande (ou renouvelle) le trou IPv6.
    async fn trouer(&self, controle: &Url, client: Ipv6Addr) -> Result<Option<Trou>, Echec> {
        let service = description::PARE_FEU_6;
        let etat = demander(controle, service, &soap::etat_du_pare_feu()).await?;
        if etat.valeur("FirewallEnabled").and_then(soap::booleen) == Some(false) {
            self.bavarder("le pare-feu IPv6 de la box est inactif : rien à ouvrir");
            return Ok(None);
        }
        if etat.valeur("InboundPinholeAllowed").and_then(soap::booleen) == Some(false) {
            self.bavarder("la box n'autorise pas les trous IPv6 (InboundPinholeAllowed = 0)");
            return Ok(None);
        }
        if let Some(tenu) = &self.trou
            && tenu.controle == *controle
            && tenu.client == client
        {
            let renouveler = soap::renouveler_le_trou(tenu.identifiant, BAIL_S);
            if demander(controle, service, &renouveler).await.is_ok() {
                return Ok(Some(tenu.clone()));
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
        Ok(Some(Trou {
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

    /// Le port à annoncer dans `passerelle`, ou rien — voir l'en-tête du
    /// module.
    fn conclure(&self) -> Option<u16> {
        match self.vu.map(|vu| vu.to_canonical()) {
            Some(IpAddr::V4(vu)) => self
                .redirection
                .as_ref()
                .filter(|tenue| tenue.adresse_externe == Some(vu))
                .map(|tenue| tenue.externe),
            Some(IpAddr::V6(vu)) => self
                .trou
                .as_ref()
                .filter(|tenu| tenu.client == vu)
                .map(|_| self.port),
            None => None,
        }
    }

    /// Ce qu'on dit de l'accord : pourquoi une redirection obtenue n'est pas
    /// annoncée.
    fn conclusion(&self, accord: Option<u16>) -> Option<String> {
        if accord.is_some() {
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
            (_, IpAddr::V6(_)) => Some(
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
    async fn chercher(&self) -> Option<Boite> {
        let destinations = match &self.reglage.ssdp {
            Some(adresses) => adresses.clone(),
            None => groupes(&self.locales),
        };
        let entendues = self.ecouter_ssdp(&destinations).await;
        let mut boite: Option<Boite> = None;
        for location in entendues.iter().take(DESCRIPTIONS_MAX) {
            let (choix, locale) = match examiner(location).await {
                Ok(examinee) => examinee,
                Err(quoi) => {
                    self.bavarder(&format!("description {location} : {quoi}"));
                    continue;
                }
            };
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
        boite.filter(|trouvee| trouvee.redirection.is_some() || trouvee.pare_feu.is_some())
    }

    /// Envoie le `M-SEARCH` et écoute : rend les `LOCATION` admises, une par
    /// passerelle.
    async fn ecouter_ssdp(&self, destinations: &[SocketAddr]) -> Vec<Url> {
        let mut sockets = Vec::new();
        for six in [false, true] {
            let visees: Vec<&SocketAddr> = destinations
                .iter()
                .filter(|destination| destination.is_ipv6() == six)
                .collect();
            if visees.is_empty() {
                continue;
            }
            let lien = if six { "[::]:0" } else { "0.0.0.0:0" };
            let Ok(socket) = UdpSocket::bind(lien).await else {
                self.bavarder(&format!("SSDP : pas de socket {lien}"));
                continue;
            };
            // **UN SAUT** (§3 quater) : la box est sur le lien.
            if !six {
                let _ = socket.set_multicast_ttl_v4(1);
            }
            for destination in visees {
                let hote = hote_ssdp(*destination);
                for cible in ssdp::CIBLES {
                    if let Err(quoi) = socket
                        .send_to(&ssdp::recherche(cible, &hote), destination)
                        .await
                    {
                        self.bavarder(&format!("SSDP vers {destination} : {quoi}"));
                    }
                }
            }
            sockets.push(socket);
        }
        let mut entendues: Vec<Url> = Vec::new();
        let debut = Instant::now();
        let mut fin = debut.checked_add(ECOUTE_SSDP).unwrap_or(debut);
        let mut tampon = vec![0_u8; ssdp::REPONSE_MAX];
        while !sockets.is_empty() && Instant::now() < fin {
            for socket in &sockets {
                let tranche = Duration::from_millis(50);
                let Ok(Ok((lus, source))) =
                    tokio::time::timeout(tranche, socket.recv_from(&mut tampon)).await
                else {
                    continue;
                };
                let recu = tampon.get(..lus).unwrap_or_default();
                match ssdp::passerelle(recu, source.ip()) {
                    Ok(mut location) => {
                        // Un lien local se joint par l'interface d'où il a
                        // répondu.
                        if let SocketAddr::V6(source) = source
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
        }
        entendues
    }
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
    let etendue = u16::MAX.saturating_sub(PREMIER_PORT_TIRE);
    PREMIER_PORT_TIRE.saturating_add(tirage.checked_rem(etendue).unwrap_or(0))
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

/// Les groupes SSDP : IPv4, et IPv6 sur l'interface de nos adresses.
fn groupes(locales: &[IpAddr]) -> Vec<SocketAddr> {
    let v4 = SocketAddr::new(IpAddr::V4(ssdp::GROUPE_V4), ssdp::PORT);
    let portee = portee_du_lien(locales).unwrap_or(0);
    let v6 = SocketAddr::V6(SocketAddrV6::new(ssdp::GROUPE_V6, ssdp::PORT, 0, portee));
    vec![v4, v6]
}

/// **L'INTERFACE D'UNE DE NOS ADRESSES IPv6, SANS C** : un groupe de lien
/// local (`ff02::c`) ne se vise que sur une interface, et l'énumérer
/// demanderait `getifaddrs` (C4). Linux la dit dans `/proc/net/if_inet6` —
/// l'adresse en hexadécimal, puis l'index de l'interface. Ailleurs, rien :
/// la portée zéro laisse le noyau choisir, ou refuser — et c'est dit en mode
/// bavard.
fn portee_du_lien(locales: &[IpAddr]) -> Option<u32> {
    let table = std::fs::read_to_string("/proc/net/if_inet6").ok()?;
    let voulues: Vec<String> = locales
        .iter()
        .filter_map(|adresse| match adresse {
            IpAddr::V6(v6) => Some(
                v6.octets()
                    .iter()
                    .map(|octet| format!("{octet:02x}"))
                    .collect(),
            ),
            IpAddr::V4(_) => None,
        })
        .collect();
    table.lines().find_map(|ligne| {
        let mut champs = ligne.split_whitespace();
        let adresse = champs.next()?;
        let index = champs.next()?;
        voulues
            .iter()
            .any(|voulue| voulue == adresse)
            .then(|| u32::from_str_radix(index, 16).ok())
            .flatten()
    })
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

/// Cette version d'annuaire accepte-t-elle `passerelle` ? Une version qui ne
/// se lit pas ne l'accepte pas : dans le doute, on n'envoie rien.
#[must_use]
pub fn connait_la_passerelle(version: &str) -> bool {
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
            (majeure, mineure, corrective) >= VERSION_PASSERELLE
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
    use super::{adresses_ssdp, connait_la_passerelle, hote_ssdp, port_tire};

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
    fn un_port_tire_evite_les_ports_connus() {
        for _ in 0..64 {
            assert!(port_tire() >= 1_024);
        }
    }
}
