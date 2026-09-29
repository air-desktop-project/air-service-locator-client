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
         passerelle     aucune réponse SSDP reçue : sous macOS, le pare-feu applicatif jette les\n\
         passerelle     réponses d'un binaire `asl` non signé. Signez-le, ou autorisez-le :\n\
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
    use std::net::{IpAddr, SocketAddr, SocketAddrV6};

    use asl_upnp::ssdp;
    use tokio::net::UdpSocket;

    use super::{
        INDEX_MAX, adresses_ssdp, bilan_du_groupe_v6, connait_la_passerelle, envoyer, groupes,
        hote_ssdp, interfaces_du_lien, les_deux, liens_du_lien, port_tire, sans_passerelle,
        vers_le_groupe_v6,
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

    #[test]
    fn un_port_tire_evite_les_ports_connus() {
        for _ in 0..64 {
            assert!(port_tire() >= 1_024);
        }
    }
}
