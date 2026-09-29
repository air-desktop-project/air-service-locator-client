//! Le transport du client : **la seule crate de ce dépôt qui attend**.
//!
//! # POURQUOI ELLE EST SÉPARÉE D'`asl-client`
//!
//! C'est le découpage du serveur, appliqué ici. `asl-client` décide — la
//! politique de reprise, ce qu'une identité signe, ce qu'un enrôlement compose —
//! et ne fait aucune entrée-sortie. **C'est ce qui permet d'éprouver soixante-dix
//! échecs consécutifs de reconnexion en une boucle**, là où un vrai recul
//! exponentiel y mettrait des années.
//!
//! Cette crate-ci ouvre une socket, mène une poignée de main, attend une
//! réponse. Elle ne décide de rien.
//!
//! # LA PILE EST CELLE D'`air-mail-server`, ET JAMAIS UNE AUTRE (C15)
//!
//! Écrite sans une ligne de C, ce qui est la condition pour qu'un daemon tiers
//! l'embarque : une pile qui lierait sa propre libcrypto entrerait en conflit
//! avec celle du processus hôte — un interpréteur Python, une JVM.
//!
//! # UNE CONNEXION TENUE, ET LE BAIL AVEC ELLE
//!
//! `protocole.md` §1.2 : la connexion **est** le bail. Il n'y a pas de
//! réannonce périodique à écrire — le keepalive est celui de QUIC, et fermer la
//! connexion est le retrait. Ce que cette crate doit garantir est donc simple à
//! dire et facile à manquer : **tant que le daemon vit, la connexion vit**.

#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ams_proto_quic::{ConnectionId, StreamId};
use ams_quic_tls::Connection as ConnexionQuic;
use asl_cle::{ClePublique, Defi, LiaisonDeCanal};
use asl_client::Identite;
use asl_id::Identifiant;
use tokio::net::UdpSocket;

mod appareil;
mod attache;
mod confiance;
pub mod domaines;
mod pont;
mod racines;
mod reponse;

pub use appareil::{CompteCree, NOUVELLE_MAX, Nouvelle, Tenue};
pub use attache::{
    Annuaire, Attache, Etat, Reglages, cadence_du_bail, confiance_de, joindre, joindre_sur,
    membres_du_renvoi,
};
pub use confiance::{Confiance, Forme};
pub use pont::Pont;
pub use racines::{
    CACHE_MAX, FauteDeCache, LOCATEURS_MAX, LocateursAppris, Provenance, RELIRE_APRES_S,
    RacineApprise, apprendre_les_racines, est_une_racine_embarquee, racines_a_essayer,
    racines_embarquees,
};
pub use reponse::Reponse;

/// Ce qu'une connexion peut refuser.
#[derive(Debug)]
pub enum Faute {
    /// La socket ou le noyau ont refusé.
    Socket(std::io::Error),
    /// Le transport QUIC a refusé.
    Quic(ams_quic_tls::Error),
    /// Le conducteur HTTP/3 a refusé.
    Http3(ams_h3::Error),
    /// La poignée de main n'a pas abouti dans le temps imparti.
    ///
    /// **CE N'EST PAS UNE FAUTE DU PAIR** : elle dit seulement qu'on n'a rien
    /// obtenu. C'est à la politique de reprise d'en tirer une conséquence — et
    /// `asl_client::Reprise` n'abandonne jamais.
    Delai,
    /// L'annuaire a répondu autre chose que ce qu'on attendait.
    Statut(u16),
    /// Ce que l'annuaire a rendu ne se lit pas.
    Illisible,
    /// La liaison de canal ne s'exporte pas de cette connexion.
    ///
    /// **ELLE NE SE RATTRAPE PAS** : sans elle, aucune signature ne vaudrait, et
    /// s'en inventer une rouvrirait le relais que C14 ferme.
    SansLiaison,
    /// La configuration TLS ne se monte pas.
    Tls(String),
    /// L'annuaire renvoie ailleurs (`421`) : la machine est rangée dans un
    /// domaine confié à un annuaire local (`protocole.md` §3 ter).
    ///
    /// **LE CORPS EST GARDÉ**, tel qu'il est arrivé : il dit où aller
    /// (`asl_client::renvoi::Renvoi::lire`). [`Attache`] le suit ; un porteur
    /// qui tient sa propre boucle peut le suivre de même.
    Renvoye(Vec<u8>),
    /// Il n'y a aucun annuaire à essayer.
    ///
    /// **CE N'EST PAS UNE PANNE, C'EST UNE CONFIGURATION**, et c'est pourquoi
    /// elle est rendue au lieu d'être réessayée : un daemon sans annuaire
    /// tournerait en rond en silence, et son porteur croirait qu'il cherche.
    SansAnnuaire,
    /// Le plafond de recul est nul : la reprise tournerait en boucle serrée.
    PlafondNul,
}

impl core::fmt::Display for Faute {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Socket(quoi) => write!(f, "la socket a refusé : {quoi}"),
            Self::Quic(quoi) => write!(f, "le transport a refusé : {quoi}"),
            Self::Http3(quoi) => write!(f, "HTTP/3 a refusé : {quoi}"),
            Self::Delai => write!(f, "l'annuaire n'a pas répondu à temps"),
            Self::Statut(code) => write!(f, "l'annuaire a répondu {code}"),
            Self::Renvoye(_) => write!(f, "l'annuaire renvoie vers un annuaire local (421)"),
            Self::Illisible => write!(f, "la réponse de l'annuaire ne se lit pas"),
            Self::SansLiaison => write!(f, "la liaison de canal ne s'exporte pas"),
            Self::Tls(quoi) => write!(f, "la configuration TLS : {quoi}"),
            Self::SansAnnuaire => write!(f, "aucun annuaire à qui parler"),
            Self::PlafondNul => write!(f, "un plafond de recul nul"),
        }
    }
}

impl std::error::Error for Faute {}

/// Combien de temps on attend une poignée de main, en millisecondes.
///
/// **CINQ SECONDES, ET C'EST UNE BORNE DE REPRISE, PAS DE RÉSEAU.** Un annuaire
/// qui ne répond pas en cinq secondes ne répondra pas mieux en trente ; ce qu'on
/// veut est passer au suivant. `asl_client::Reprise` s'occupe du reste, et
/// n'abandonne jamais.
pub const POIGNEE_MS: u64 = 5_000;

/// Combien de temps on attend une réponse, en millisecondes.
pub const REPONSE_MS: u64 = 10_000;

/// Ce qu'un datagramme peut faire.
const DATAGRAMME_MAX: usize = 1_500;

/// Combien de datagrammes d'écho attendent, au plus, que le porteur les lise
/// ([`Connexion::echos`]).
///
/// **UNE BORNE, PARCE QUE CE QUI ARRIVE LÀ VIENT DE N'IMPORTE QUI** : la
/// socket partagée n'est pas connectée, et un inconnu peut y verser ce qu'il
/// veut. Au-delà, les nouveaux sont jetés — le porteur les aurait de toute
/// façon tus, puisque l'écho borne son débit à cinquante par seconde, et une
/// file ne se vide qu'entre deux lectures d'une demi-seconde au plus.
pub const ECHOS_EN_ATTENTE_MAX: usize = 64;

/// Comment une connexion tient sa socket.
#[derive(Debug)]
enum Voie {
    /// La socket est à elle, **connectée** à l'annuaire : le noyau jette tout
    /// datagramme d'une autre source. C'est le cas ordinaire.
    Connectee,
    /// La socket est **partagée avec l'écho** (`protocole.md` §3 quater,
    /// décision 90 ; E2) : non connectée, elle reçoit de partout, et chaque
    /// datagramme est TRIÉ à l'arrivée — voir [`trier`].
    Partagee {
        /// L'annuaire, tel qu'on l'a visé.
        distante: SocketAddr,
        /// La même adresse, telle qu'on l'écrit sur CETTE socket — une IPv4
        /// enfouie quand la socket est à double pile.
        envoi: SocketAddr,
        /// Les datagrammes d'écho arrivés, pas encore lus.
        echos: VecDeque<(Vec<u8>, SocketAddr)>,
    },
}

/// Ce qu'un datagramme arrivé sur une socket partagée est.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tri {
    /// De l'écho : son premier octet est de `0x04` à `0x0F`, d'où qu'il
    /// vienne.
    Echo,
    /// Du QUIC de l'annuaire.
    Quic,
    /// Ni l'un ni l'autre : du QUIC d'ailleurs, ou rien du tout. Jeté — c'est
    /// ce que le noyau faisait d'une socket connectée.
    Ailleurs,
}

/// Trie un datagramme **au premier octet**, puis à la source.
///
/// Un paquet QUIC v1 a toujours le bit `0x40` du premier octet posé (RFC 9000
/// §17 ; RFC 9443 §2) ; l'écho commence par un octet de `0x04` à `0x0F`, une
/// plage que ni QUIC, ni STUN, ni DTLS, ni RTP n'emploient (RFC 7983 §7).
/// **Un seul octet décide**, sans ambiguïté — `asl_echo::est_de_l_echo`, la
/// règle écrite une fois pour le serveur et le client.
///
/// Le reste n'est cru QUIC que s'il vient de l'annuaire : une socket non
/// connectée n'a plus le noyau pour faire ce tri-là, il se fait ici. Les deux
/// adresses sont comparées sous leur forme canonique — une socket à double
/// pile rend une IPv4 enfouie là où l'on avait visé une IPv4.
fn trier(datagramme: &[u8], source: SocketAddr, distante: SocketAddr) -> Tri {
    match datagramme.first() {
        Some(premier) if asl_echo::est_de_l_echo(*premier) => Tri::Echo,
        Some(_) if canonique(source) == canonique(distante) => Tri::Quic,
        _ => Tri::Ailleurs,
    }
}

/// Une adresse sous sa forme canonique : une IPv4 enfouie redevient une IPv4.
fn canonique(adresse: SocketAddr) -> SocketAddr {
    SocketAddr::new(adresse.ip().to_canonical(), adresse.port())
}

/// L'adresse telle qu'on l'écrit sur une socket IPv6 : **une IPv4 s'y
/// enfouit** (`::ffff:a.b.c.d`), sans quoi le noyau refuse l'envoi. Sur une
/// socket IPv4, elle reste telle quelle.
fn pour_la_socket(socket_v6: bool, cible: SocketAddr) -> SocketAddr {
    match cible.ip() {
        IpAddr::V4(v4) if socket_v6 => {
            SocketAddr::new(IpAddr::V6(v4.to_ipv6_mapped()), cible.port())
        }
        _ => cible,
    }
}

/// L'inactivité qu'on annonce à l'annuaire, en microsecondes.
///
/// **ELLE VIENT DU SERVEUR, ET CELLE-CI N'EST QU'UN PLAFOND.** `modele.md` §4.1 :
/// c'est l'annuaire qui annonce la cadence attendue, et la figer ici exigerait
/// de mettre à jour tous les daemons installés chez des tiers le jour où elle
/// changera. Ce qu'on annonce est ce qu'on accepte de tenir sans rien recevoir.
pub const INACTIVITE_US: u64 = 60 * 1_000_000;

/// L'horloge, en microsecondes depuis l'époque.
///
/// **MONOTONE, ELLE NE L'EST PAS**, et la pile empruntée n'en demande pas : elle
/// compare des instants entre eux sur une même connexion, et un saut d'horloge
/// coûte au pire une retransmission.
fn maintenant() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|ecoule| u64::try_from(ecoule.as_micros()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Une connexion vivante à un annuaire.
///
/// # ELLE NE SE PARTAGE PAS
///
/// L'authentification est portée par la CONNEXION (`protocole.md` §3) : ce
/// qu'une requête a le droit de faire dépend de la clé prouvée sur celle-ci.
/// Deux daemons qui partageraient une connexion partageraient donc leurs droits.
#[derive(Debug)]
pub struct Connexion {
    /// La socket — **partagée** quand elle est aussi celle de l'écho
    /// ([`Connexion::ouvrir_sur`]) : elle survit alors à la connexion, et la
    /// suivante s'ouvre dessus, sur le même port.
    socket: Arc<UdpSocket>,
    /// Connectée à l'annuaire, ou partagée avec l'écho.
    voie: Voie,
    /// La connexion QUIC, **derrière une boîte**.
    ///
    /// # CENT TRENTE-SIX KIBIOCTETS, ET C'EST MESURÉ
    ///
    /// `ams_quic_tls::Connection` porte ses fenêtres de réassemblage, ses
    /// tampons de sortie par espace, et l'état de trois flux `CRYPTO`. Laissée
    /// sur la pile, elle traverse chaque `await` de cette crate — et un essai
    /// qui en ouvre deux à la suite **débordait la pile**, ce qui est
    /// exactement ce qui est arrivé.
    ///
    /// La boîte coûte une indirection par datagramme, et rend cette structure
    /// déplaçable pour rien.
    quic: Box<ConnexionQuic>,
    h3: ams_h3::Http3Client,
    /// La liaison de canal de CETTE connexion, exportée de sa poignée de main.
    liaison: LiaisonDeCanal,
    /// Le nom qu'on met dans `:authority`.
    autorite: String,
    /// Le flux par lequel les verdicts arrivent, s'il est ouvert.
    ///
    /// # POURQUOI IL EST RETENU ICI, ET NON REDEMANDÉ
    ///
    /// C'est une requête dont la réponse ne se termine JAMAIS
    /// (`protocole.md` §1.4). `requete` attendrait donc pour toujours, et il n'y
    /// a rien à réclamer plus tard : on garde son numéro, et l'on relit ce qui
    /// s'y est accumulé.
    poussees: Option<StreamId>,
    /// Ce qui est arrivé sur ce flux et qu'on n'a pas fini de découper.
    ///
    /// **UN OBJET COUPÉ EN DEUX PAR UN DATAGRAMME EST LE CAS ORDINAIRE**, et
    /// `asl_proto::cadrage::objets` dit combien d'octets sont complets. Le reste
    /// attend ici la suite.
    reste: Vec<u8>,
    /// Le flux des nouvelles d'un appareil (`GET /v1/nouvelles`), s'il est
    /// ouvert — même raison que [`Self::poussees`] : sa réponse ne se termine
    /// jamais. Voir `appareil.rs`.
    nouvelles: Option<StreamId>,
    /// Ce qui est arrivé sur ce flux-là et qui n'a pas encore sa fin de ligne.
    lignes: appareil::Lignes,
    /// La forme de confiance que la poignée de main a crue.
    forme: confiance::Retenue,
}

impl Connexion {
    /// Ouvre une connexion à cet annuaire, et mène la poignée de main au bout.
    ///
    /// `identite` est le `n-…` qu'on doit trouver au bout : la clé de son
    /// certificat doit s'y déduire (`protocole.md` §0). `nom` ne va que dans
    /// `:authority` ; il n'est jamais vérifié ni résolu (C20).
    ///
    /// # L'ALÉA VIENT DU NOYAU, ET IL EN FAUT
    ///
    /// §7.2 de RFC 9000 : le client choisit un identifiant de destination d'au
    /// moins huit octets, et §5.2 en dérive les clés `Initial`. Un identifiant
    /// devinable rendrait ces clés-là devinables.
    ///
    /// # Errors
    ///
    /// [`Faute::Socket`], [`Faute::Tls`], [`Faute::Quic`], [`Faute::Delai`],
    /// [`Faute::SansLiaison`], [`Faute::Http3`].
    pub async fn ouvrir(
        annuaire: SocketAddr,
        nom: &str,
        identite: Identifiant,
        alea: &(dyn Fn() -> [u8; 16] + Sync),
    ) -> Result<Self, Faute> {
        Self::ouvrir_confiance(annuaire, nom, &Confiance::par_identites(&[identite]), alea).await
    }

    /// Ouvre une connexion à cet annuaire sous cette [`Confiance`] : les
    /// identités qu'on accepte de trouver au bout (`protocole.md` §0).
    ///
    /// `nom` ne va que dans `:authority`. La poignée de main ne vise que
    /// l'adresse, et c'est l'identité qu'on juge.
    ///
    /// # Errors
    ///
    /// Celles d'[`Self::ouvrir`].
    pub async fn ouvrir_confiance(
        annuaire: SocketAddr,
        nom: &str,
        confiance: &Confiance,
        alea: &(dyn Fn() -> [u8; 16] + Sync),
    ) -> Result<Self, Faute> {
        // **UNE SOCKET DE LA MÊME FAMILLE QUE LA CIBLE.** Se lier en IPv4 pour
        // joindre une adresse IPv6 échoue au premier envoi, et le message du
        // noyau ne dit pas pourquoi.
        let local = match annuaire {
            SocketAddr::V4(_) => "0.0.0.0:0",
            SocketAddr::V6(_) => "[::]:0",
        };
        let socket = UdpSocket::bind(local).await.map_err(Faute::Socket)?;
        socket.connect(annuaire).await.map_err(Faute::Socket)?;
        Self::etablir(
            Arc::new(socket),
            Voie::Connectee,
            annuaire,
            nom,
            confiance,
            alea,
        )
        .await
    }

    /// Ouvre une connexion à cet annuaire **sur cette socket**, sans la
    /// connecter : c'est la socket de l'écho, et le bail doit partir d'elle
    /// (`protocole.md` §3 quater, décision 90 ; E2).
    ///
    /// # POURQUOI LA MÊME SOCKET
    ///
    /// Derrière un NAT, le mapping ouvert par le bail est celui de la socket
    /// d'où le bail part, et le keepalive le tient ouvert : l'écho qui écoute
    /// sur cette socket-là devient joignable à l'adresse que l'annuaire
    /// observe, sans redirection de port. Une socket à part n'aurait aucun
    /// mapping, et personne pour le tenir.
    ///
    /// # CE QUE LE PORTEUR DOIT FAIRE, ET CE QU'IL RÉCUPÈRE
    ///
    /// La socket n'étant pas connectée, elle reçoit de partout. Chaque
    /// datagramme est trié au premier octet : le QUIC de l'annuaire va à la
    /// connexion, **l'écho est mis de côté** et rendu par
    /// [`Connexion::echos`], le reste est jeté. La connexion ne décide rien de
    /// ce que l'écho reçoit ; c'est au porteur de répondre, par
    /// [`Connexion::envoyer_a`].
    ///
    /// La socket est à la connexion ET au porteur : **elle survit à la
    /// connexion**, et la suivante s'ouvre dessus — le port reste le même
    /// d'une reconnexion à l'autre.
    ///
    /// # Errors
    ///
    /// Celles d'[`Self::ouvrir`].
    pub async fn ouvrir_sur(
        socket: Arc<UdpSocket>,
        annuaire: SocketAddr,
        nom: &str,
        confiance: &Confiance,
        alea: &(dyn Fn() -> [u8; 16] + Sync),
    ) -> Result<Self, Faute> {
        let socket_v6 = socket.local_addr().map_err(Faute::Socket)?.is_ipv6();
        let voie = Voie::Partagee {
            distante: annuaire,
            envoi: pour_la_socket(socket_v6, annuaire),
            echos: VecDeque::new(),
        };
        Self::etablir(socket, voie, annuaire, nom, confiance, alea).await
    }

    /// Monte la connexion QUIC sur cette socket, puis mène la poignée de main.
    async fn etablir(
        socket: Arc<UdpSocket>,
        voie: Voie,
        annuaire: SocketAddr,
        nom: &str,
        confiance: &Confiance,
        alea: &(dyn Fn() -> [u8; 16] + Sync),
    ) -> Result<Self, Faute> {
        let (config, retenue) = confiance::configuration(confiance)?;
        let serveur = confiance::nom_de_serveur(annuaire);

        let graine = alea();
        let notre = ConnectionId::new(graine.get(..8).unwrap_or_default())
            .map_err(|_| Faute::Tls("l'identifiant local ne se construit pas".to_owned()))?;
        let origine = ConnectionId::new(graine.get(8..).unwrap_or_default())
            .map_err(|_| Faute::Tls("l'identifiant d'origine ne se construit pas".to_owned()))?;

        let quic = Box::new(
            ConnexionQuic::connect(config, serveur, notre, origine, INACTIVITE_US, maintenant())
                .map_err(Faute::Quic)?,
        );

        let mut connexion = Self {
            socket,
            voie,
            quic,
            h3: ams_h3::Http3Client::new(),
            // **UNE VALEUR DE PASSAGE, REMPLACÉE AVANT TOUT USAGE.** La vraie
            // s'exporte de la poignée de main, qui n'a pas encore eu lieu ;
            // `poignee_de_main` la pose, et échoue plutôt que de la laisser.
            liaison: LiaisonDeCanal::depuis_octets([0; asl_cle::LIAISON_OCTETS]),
            autorite: nom.to_owned(),
            poussees: None,
            reste: Vec::new(),
            nouvelles: None,
            lignes: appareil::Lignes::default(),
            forme: retenue,
        };
        connexion.poignee_de_main().await?;
        Ok(connexion)
    }

    /// La forme de confiance qui a servi : l'identité par la clé. `None`
    /// avant la poignée de main — ce qu'une connexion ouverte n'est jamais.
    #[must_use]
    pub fn forme(&self) -> Option<Forme> {
        self.forme
            .lock()
            .ok()
            .and_then(|place| place.map(|(forme, _)| forme))
    }

    /// La clé d'identité de l'annuaire au bout, **telle que la poignée de
    /// main l'a jugée** : celle dont se déduit le `n-…` qu'on attendait.
    /// `None` avant la poignée de main — ce qu'une connexion ouverte n'est
    /// jamais.
    ///
    /// C'est sous elle que l'écho vérifie la sonde de l'annuaire qui tient son
    /// bail (décision 91 ; E4) — y compris celle d'un annuaire local qu'aucun
    /// binaire n'embarque.
    #[must_use]
    pub fn cle_distante(&self) -> Option<ClePublique> {
        self.forme
            .lock()
            .ok()
            .and_then(|place| place.map(|(_, cle)| cle))
    }

    /// La liaison de canal de cette connexion.
    #[must_use]
    pub const fn liaison(&self) -> LiaisonDeCanal {
        self.liaison
    }

    /// Mène la poignée de main, puis ouvre les flux HTTP/3.
    async fn poignee_de_main(&mut self) -> Result<(), Faute> {
        let echeance = maintenant().saturating_add(POIGNEE_MS.saturating_mul(1_000));
        while !self.quic.is_established() {
            if maintenant() >= echeance {
                return Err(Faute::Delai);
            }
            self.emettre().await?;
            self.recevoir(POIGNEE_MS.min(500)).await?;
        }
        // **LA LIAISON S'EXPORTE MAINTENANT, ET PAS AVANT** : le secret maître
        // n'existait pas. Voir `asl_cle::LiaisonDeCanal`.
        self.liaison = self
            .quic
            .export(asl_client::ETIQUETTE_LIAISON, None)
            .map(asl_cle::LiaisonDeCanal::depuis_octets)
            .map_err(|_| Faute::SansLiaison)?;

        let mut pont = Pont(&mut self.quic);
        self.h3.on_established(&mut pont).map_err(Faute::Http3)?;
        self.emettre().await?;
        Ok(())
    }

    /// Émet tout ce que la connexion a à dire.
    async fn emettre(&mut self) -> Result<(), Faute> {
        let mut place = [0_u8; DATAGRAMME_MAX];
        loop {
            let ecrit = self
                .quic
                .poll_transmit(&mut place, maintenant())
                .map_err(Faute::Quic)?;
            if ecrit == 0 {
                return Ok(());
            }
            let datagramme = place.get(..ecrit).unwrap_or_default();
            match &self.voie {
                Voie::Connectee => self.socket.send(datagramme).await,
                Voie::Partagee { envoi, .. } => self.socket.send_to(datagramme, *envoi).await,
            }
            .map_err(Faute::Socket)?;
        }
    }

    /// Attend un datagramme, au plus ce nombre de millisecondes.
    ///
    /// **UN DÉLAI ÉCOULÉ N'EST PAS UNE FAUTE** : c'est ce qui laisse la boucle
    /// faire échoir ses propres délais — retransmissions, keepalive.
    async fn recevoir(&mut self, attente_ms: u64) -> Result<(), Faute> {
        let mut recu = [0_u8; DATAGRAMME_MAX];
        let attente = tokio::time::Duration::from_millis(attente_ms);
        match tokio::time::timeout(attente, self.socket.recv_from(&mut recu)).await {
            Ok(Ok((lus, source))) => {
                let mut datagramme = recu.get_mut(..lus).unwrap_or_default().to_vec();
                // **SUR UNE SOCKET PARTAGÉE, LE TRI D'ABORD** : l'écho est mis
                // de côté pour le porteur, ce qui ne vient pas de l'annuaire
                // est jeté. Une socket connectée n'a rien à trier — le noyau
                // l'a fait.
                if let Voie::Partagee {
                    distante, echos, ..
                } = &mut self.voie
                {
                    match trier(&datagramme, source, *distante) {
                        Tri::Quic => {}
                        Tri::Echo => {
                            if echos.len() < ECHOS_EN_ATTENTE_MAX {
                                echos.push_back((datagramme, source));
                            }
                            return Ok(());
                        }
                        Tri::Ailleurs => return Ok(()),
                    }
                }
                self.quic
                    .on_datagram(&mut datagramme, maintenant())
                    .map_err(Faute::Quic)?;
            }
            Ok(Err(quoi)) => return Err(Faute::Socket(quoi)),
            // Rien n'est arrivé : les délais de la connexion échoient quand même.
            Err(_) => {
                self.quic.on_timeout(maintenant());
            }
        }
        Ok(())
    }

    /// Envoie cette requête, et attend sa réponse.
    ///
    /// # Errors
    ///
    /// [`Faute::Http3`], [`Faute::Socket`], [`Faute::Quic`], [`Faute::Delai`].
    pub async fn requete(
        &mut self,
        methode: &[u8],
        chemin: &[u8],
        champs: &[(&[u8], &[u8])],
        corps: &[u8],
    ) -> Result<Reponse, Faute> {
        let flux = {
            let mut pont = Pont(&mut self.quic);
            self.h3
                .request(
                    &mut pont,
                    methode,
                    chemin,
                    self.autorite.as_bytes(),
                    champs,
                    corps,
                )
                .map_err(Faute::Http3)?
        };
        self.emettre().await?;

        let echeance = maintenant().saturating_add(REPONSE_MS.saturating_mul(1_000));
        loop {
            if let Some(reponse) = self.h3.take_response(flux) {
                return Ok(Reponse::depuis(reponse));
            }
            if maintenant() >= echeance {
                return Err(Faute::Delai);
            }
            self.recevoir(REPONSE_MS.min(500)).await?;
            self.lire_les_flux(flux)?;
            self.emettre().await?;
        }
    }

    /// Fait lire au conducteur tout ce qui est lisible.
    fn lire_les_flux(&mut self, attendu: StreamId) -> Result<(), Faute> {
        let vivants: Vec<StreamId> = self.quic.streams_alive().collect();
        let mut pont = Pont(&mut self.quic);
        for flux in vivants {
            self.h3.on_readable(&mut pont, flux).map_err(Faute::Http3)?;
        }
        // Le flux de la réponse peut n'être dans aucune liste s'il vient de se
        // clore : on le relit explicitement.
        self.h3
            .on_readable(&mut pont, attendu)
            .map_err(Faute::Http3)
    }

    /// Ouvre le flux par lequel les verdicts de sonde arriveront.
    ///
    /// # POURQUOI IL FAUT LE DEMANDER, ET CE QU'ON PERD À NE PAS LE FAIRE
    ///
    /// L'annuaire répond souvent `en_cours` à une annonce : il ne fait pas
    /// attendre le démarrage d'un daemon le temps d'une sonde vers une machine
    /// qui peut ne jamais répondre. **Sans ce flux, le verdict n'arrive jamais**,
    /// et le daemon reste à croire que sa joignabilité est en cours de mesure.
    ///
    /// Ce n'est PAS ouvert d'office : un daemon qui ne veut pas savoir n'a pas à
    /// tenir une ressource des deux côtés.
    ///
    /// # ELLE N'ATTEND AUCUNE RÉPONSE, ET C'EST NORMAL
    ///
    /// La réponse ne se termine jamais. On écrit la requête, on garde le numéro
    /// du flux, et [`Connexion::poussees`] lit ce qui y arrive.
    ///
    /// Appeler deux fois ne rouvre rien.
    ///
    /// # Errors
    ///
    /// [`Faute::Http3`], [`Faute::Socket`], [`Faute::Quic`].
    pub async fn ecouter_les_poussees(&mut self) -> Result<(), Faute> {
        if self.poussees.is_some() {
            return Ok(());
        }
        let flux = {
            let mut pont = Pont(&mut self.quic);
            self.h3
                .request(
                    &mut pont,
                    b"GET",
                    b"/v1/poussees",
                    self.autorite.as_bytes(),
                    &[],
                    b"",
                )
                .map_err(Faute::Http3)?
        };
        self.poussees = Some(flux);
        self.emettre().await
    }

    /// Les verdicts arrivés depuis le dernier appel.
    ///
    /// **RIEN N'EST UNE RÉPONSE**, et la plus fréquente : une sonde met des
    /// secondes, et cette fonction se rappelle à chaque tour de boucle.
    ///
    /// # CHAQUE POUSSÉE PORTE LA LISTE ENTIÈRE, ET NON UN DELTA
    ///
    /// `protocole.md` §1.4 : un delta obligerait le receveur à fusionner, donc à
    /// décider quoi faire d'une entrée inconnue — et deux receveurs qui
    /// fusionnent différemment lisent deux états dans les mêmes messages. **La
    /// dernière rendue remplace tout ce qui précède.**
    ///
    /// # Errors
    ///
    /// [`Faute::Illisible`] si ce que l'annuaire écrit ne se découpe pas. **Ce
    /// n'est pas un objet incomplet** — celui-là attend simplement la suite.
    pub fn poussees(&mut self) -> Result<Vec<Vec<u8>>, Faute> {
        let Some(flux) = self.poussees else {
            return Ok(Vec::new());
        };
        if let Some(arrives) = self.h3.prendre_ce_qui_est_arrive(flux) {
            self.reste.extend_from_slice(&arrives);
        }

        let (trouves, consommes) =
            asl_proto::cadrage::objets(&self.reste).map_err(|_| Faute::Illisible)?;
        let rendus: Vec<Vec<u8>> = trouves.map(<[u8]>::to_vec).collect();
        self.reste.drain(..consommes);
        Ok(rendus)
    }

    /// Le flux des poussées est-il encore ouvert ?
    ///
    /// **UN FLUX QUI SE FERME EST UNE INFORMATION** : l'annuaire a fini de
    /// pousser, et ce qu'on attendait n'arrivera plus.
    #[must_use]
    pub fn ecoute_les_poussees(&self) -> bool {
        self.poussees.is_some_and(|flux| !self.h3.est_fini(flux))
    }

    /// Tient la connexion vivante, sans rien demander.
    ///
    /// **LA CONNEXION EST LE BAIL** (`protocole.md` §1.2) : il n'y a rien à
    /// réannoncer, seulement à ne pas disparaître. Un daemon appelle ceci dans sa
    /// boucle, et le keepalive de QUIC fait le reste.
    ///
    /// # Errors
    ///
    /// [`Faute::Socket`], [`Faute::Quic`], [`Faute::Http3`].
    pub async fn entretenir(&mut self, attente_ms: u64) -> Result<(), Faute> {
        self.recevoir(attente_ms).await?;
        let mut vivants: Vec<StreamId> = self.quic.streams_alive().collect();
        // **LE FLUX DES POUSSÉES PEUT N'ÊTRE DANS AUCUNE LISTE** : rien n'y est
        // arrivé depuis longtemps, et il n'a plus d'octets prêts. Le relire
        // explicitement est ce qui fait entrer un verdict — et une nouvelle.
        for flux in [self.poussees, self.nouvelles].into_iter().flatten() {
            if !vivants.contains(&flux) {
                vivants.push(flux);
            }
        }
        {
            let mut pont = Pont(&mut self.quic);
            for flux in vivants {
                self.h3.on_readable(&mut pont, flux).map_err(Faute::Http3)?;
            }
        }
        self.emettre().await
    }

    /// L'adresse locale que le noyau a choisie pour joindre cet annuaire.
    ///
    /// # POURQUOI ELLE VAUT MIEUX QU'UNE ÉNUMÉRATION D'INTERFACES
    ///
    /// C'est l'adresse par laquelle cette machine SORT vers cet annuaire, et
    /// c'est exactement celle qu'il faut annoncer pour que le verdict de NAT ait
    /// un sens : `derriere_nat` se décide en comparant ce que l'annuaire observe
    /// à ce qu'on a annoncé (`modele.md` §4.2).
    ///
    /// Une machine à six interfaces en annoncerait six, dont cinq qui ne mènent
    /// nulle part — et il faudrait `getifaddrs`, donc du C, que C4 interdit.
    /// Le noyau, lui, a déjà tranché en ouvrant la socket.
    ///
    /// # Errors
    ///
    /// [`Faute::Socket`] si la socket ne sait plus dire où elle est.
    pub fn locale(&self) -> Result<SocketAddr, Faute> {
        self.socket.local_addr().map_err(Faute::Socket)
    }

    /// L'adresse de l'annuaire que cette connexion a joint.
    ///
    /// **UN NOM QUI REND PLUSIEURS ADRESSES N'EN JOINT QU'UNE**, et la tournée
    /// choisit laquelle : ce qu'une réponse dit vaut pour cette racine-là, et
    /// une réponse ne dit pas d'où elle vient (`replication.md` §6). C'est ici
    /// qu'on l'apprend.
    ///
    /// # Errors
    ///
    /// [`Faute::Socket`] si la socket ne sait plus dire à qui elle parle.
    pub fn distante(&self) -> Result<SocketAddr, Faute> {
        match &self.voie {
            Voie::Connectee => self.socket.peer_addr().map_err(Faute::Socket),
            Voie::Partagee { distante, .. } => Ok(*distante),
        }
    }

    /// Les datagrammes d'écho arrivés sur la socket partagée depuis le
    /// dernier appel, chacun avec sa source — **dans l'ordre d'arrivée**, au
    /// plus [`ECHOS_EN_ATTENTE_MAX`].
    ///
    /// Ils arrivent pendant que la connexion lit — [`Connexion::entretenir`],
    /// [`Connexion::requete`] — et attendent ici. **Rien n'est décidé
    /// d'eux** : c'est au porteur de les juger, et de répondre ou de se taire.
    /// Toujours vide sur une connexion qui n'a pas été ouverte par
    /// [`Connexion::ouvrir_sur`].
    pub fn echos(&mut self) -> Vec<(Vec<u8>, SocketAddr)> {
        match &mut self.voie {
            Voie::Connectee => Vec::new(),
            Voie::Partagee { echos, .. } => echos.drain(..).collect(),
        }
    }

    /// Envoie ce datagramme à cette adresse, **depuis la socket partagée** —
    /// la réponse de l'écho part d'où la sonde est arrivée.
    ///
    /// # Errors
    ///
    /// [`Faute::Socket`] — y compris sur une connexion à socket connectée,
    /// qui n'envoie qu'à son annuaire.
    pub async fn envoyer_a(&self, octets: &[u8], destination: SocketAddr) -> Result<(), Faute> {
        if matches!(self.voie, Voie::Connectee) {
            return Err(Faute::Socket(std::io::Error::other(
                "cette connexion n'a pas de socket partagée",
            )));
        }
        let socket_v6 = self.socket.local_addr().map_err(Faute::Socket)?.is_ipv6();
        self.socket
            .send_to(octets, pour_la_socket(socket_v6, destination))
            .await
            .map_err(Faute::Socket)?;
        Ok(())
    }

    /// La connexion est-elle encore là ?
    #[must_use]
    pub const fn vivante(&self) -> bool {
        !self.quic.is_closed()
    }

    /// Maintient cette connexion à la cadence que l'annuaire a annoncée.
    ///
    /// # C'EST CE QUI TIENT LE MAPPAGE OUVERT, ET RIEN D'AUTRE NE LE FAIT
    ///
    /// `modele.md` §4.1 promet que « le mapping NAT reste ouvert par le
    /// keepalive lui-même ». **Cette promesse n'était tenue par personne** : la
    /// pile QUIC n'émettait rien de périodique, et cette boucle-ci ne fait que
    /// lire. Une annonce silencieuse mourait donc à chaque délai d'inactivité, et
    /// ne revenait que par une reconnexion complète.
    ///
    /// `bancs/nat/` a mesuré ce que le silence coûte : sur un lien résidentiel,
    /// le chemin meurt entre 28 et 30 secondes, en IPv4 comme en IPv6.
    ///
    /// # LA CADENCE VIENT DU SERVEUR, ET N'EST PAS FIGÉE ICI
    ///
    /// C'est tout l'objet du bail (`modele.md` §4.1) : la changer après une
    /// campagne de mesure ne doit pas exiger de mettre à jour les daemons
    /// installés chez des tiers. **Zéro arrête le maintien.**
    pub fn maintenir(&mut self, secondes: u16) {
        self.quic
            .set_keepalive(u64::from(secondes).saturating_mul(1_000_000), maintenant());
    }

    /// La cadence de maintien en cours, en microsecondes ; zéro si aucune.
    #[must_use]
    pub fn maintien_us(&self) -> u64 {
        self.quic.keepalive()
    }

    /// Retire l'annonce, en fermant proprement.
    ///
    /// # C'EST LE RETRAIT, ET IL N'Y EN A PAS D'AUTRE
    ///
    /// `protocole.md` §1.2 : la connexion EST le bail, donc la fermer EST le
    /// retrait. Il n'y a pas de `DELETE` à écrire.
    ///
    /// **LA DIFFÉRENCE ENTRE FERMER ET DISPARAÎTRE SE MESURE EN MINUTE.** Un
    /// daemon qui s'arrête en lâchant sa socket reste annoncé jusqu'à
    /// l'expiration d'inactivité — [`INACTIVITE_US`], soit une minute pendant
    /// laquelle ses clients reçoivent une adresse où plus rien n'écoute. Une
    /// trame `CONNECTION_CLOSE` coûte un datagramme et supprime cette minute.
    ///
    /// # Errors
    ///
    /// [`Faute::Socket`], [`Faute::Quic`]. **Elles ne changent rien** : la
    /// connexion est fermée de notre côté quoi qu'il arrive, et le pair finira
    /// par l'apprendre par son propre délai d'inactivité.
    pub async fn fermer(&mut self) -> Result<(), Faute> {
        // `H3_NO_ERROR` (§8.1 de RFC 9114) : on part, et rien n'a mal tourné.
        self.quic.close_with(0x0100, maintenant());
        self.emettre().await
    }
}

// ── Les verbes de l'annuaire ────────────────────────────────────────────────

impl Connexion {
    /// Tire un défi, et le rend.
    ///
    /// # Errors
    ///
    /// Celles de [`Connexion::requete`], plus [`Faute::Statut`] et
    /// [`Faute::Illisible`].
    pub async fn defi(&mut self) -> Result<Defi, Faute> {
        let reponse = self.requete(b"GET", b"/v1/defi", &[], b"").await?;
        reponse.exige(200)?;
        let mut octets = [0_u8; asl_cle::DEFI_OCTETS];
        if reponse.corps.len() != octets.len() {
            return Err(Faute::Illisible);
        }
        octets.copy_from_slice(&reponse.corps);
        Ok(Defi::depuis_octets(octets))
    }

    /// Prouve la clé de cette machine sur CETTE connexion.
    ///
    /// # L'AUTHENTIFICATION EST PORTÉE PAR LA CONNEXION
    ///
    /// `protocole.md` §3 : la clé est prouvée une fois, et toutes les requêtes de
    /// cette connexion en héritent. Il n'y a pas de jeton à joindre, donc pas de
    /// jeton à intercepter, à rejouer, ni à expirer.
    ///
    /// # Errors
    ///
    /// Celles de [`Connexion::requete`], plus [`Faute::Statut`].
    pub async fn authentifier(&mut self, identite: &Identite) -> Result<(), Faute> {
        let defi = self.defi().await?;
        let signature = identite
            .repondre(&defi, &self.liaison)
            .map_err(|_| Faute::Illisible)?;

        let mut preuve = Vec::with_capacity(81);
        preuve.push(asl_id::Genre::Machine.prefixe());
        preuve.extend_from_slice(identite.machine().octets());
        preuve.extend_from_slice(signature.octets());

        let reponse = self
            .requete(
                b"POST",
                b"/v1/defi",
                &[(b"content-type", b"application/octet-stream")],
                &preuve,
            )
            .await?;
        reponse.exige(204)
    }

    /// Présente un code d'enrôlement et une clé neuve, et rend la machine —
    /// et son propriétaire, quand l'annuaire le dit.
    ///
    /// # Errors
    ///
    /// Celles de [`Connexion::requete`], plus [`Faute::Statut`] et
    /// [`Faute::Illisible`].
    pub async fn enroler(
        &mut self,
        enrolement: &asl_client::Enrolement,
        code: &str,
    ) -> Result<Enrolee, Faute> {
        let defi = self.defi().await?;
        let corps = enrolement
            .corps(code, &defi, &self.liaison)
            .map_err(|_| Faute::Illisible)?;

        let reponse = self
            .requete(
                b"POST",
                b"/v1/enrolement",
                &[(b"content-type", b"application/octet-stream")],
                &corps,
            )
            .await?;
        reponse.exige(200)?;
        Ok(Enrolee {
            machine: reponse.identifiant("machine")?,
            // **ABSENT SUR UN ANNUAIRE D'AVANT 0.3.0**, et ce n'est pas une
            // faute : `GET /v1/moi` le rendra plus tard (`protocole.md` §2.0).
            proprietaire: reponse.identifiant("proprietaire").ok(),
        })
    }

    /// Qui est cette machine, et à qui elle appartient.
    ///
    /// **SUR UNE CONNEXION AUTHENTIFIÉE** : c'est `GET /v1/moi` (`protocole.md`
    /// §3), et l'annuaire ne répond qu'à une machine qui a prouvé sa clé.
    ///
    /// # Errors
    ///
    /// Celles de [`Connexion::requete`], plus [`Faute::Statut`] — `401` sans
    /// preuve, `404` sur un annuaire qui ne sert pas encore ce verbe — et
    /// [`Faute::Illisible`].
    pub async fn moi(&mut self) -> Result<Moi, Faute> {
        let reponse = self.requete(b"GET", b"/v1/moi", &[], b"").await?;
        reponse.exige(200)?;
        Ok(Moi {
            machine: reponse.identifiant("machine")?,
            proprietaire: reponse.identifiant("proprietaire")?,
        })
    }

    /// Demande où joindre toutes les instances d'un nom de service que le
    /// propriétaire de cette machine a le droit de voir.
    ///
    /// Rend une LISTE d'objets, chacun tel qu'`asl_proto::Reponse::decoder` le
    /// lit ; `asl_proto::cadrage::elements` la découpe.
    ///
    /// # Errors
    ///
    /// Celles de [`Connexion::requete`], plus [`Faute::Statut`].
    pub async fn ou_par_nom(&mut self, service: &str) -> Result<Vec<u8>, Faute> {
        let cible = format!("/v1/ou?service={service}");
        let reponse = self.requete(b"GET", cible.as_bytes(), &[], b"").await?;
        reponse.exige(200)?;
        Ok(reponse.corps)
    }

    /// Les machines de cet utilisateur que le propriétaire de cette machine a
    /// le droit de voir — les siennes, ou ce qu'une autorisation lui ouvre
    /// (`protocole.md` §2.2). **Une liste vide à qui n'a rien**, jamais un refus.
    ///
    /// Rend une LISTE de `{"machine":"m-…","nom":"…"}`, que
    /// `asl_proto::cadrage::elements` découpe.
    ///
    /// # Errors
    ///
    /// Celles de [`Connexion::requete`], plus [`Faute::Statut`].
    pub async fn machines_de(&mut self, compte: Identifiant) -> Result<Vec<u8>, Faute> {
        let cible = format!("/v1/utilisateurs/{}/machines", compte.texte());
        let reponse = self.requete(b"GET", cible.as_bytes(), &[], b"").await?;
        reponse.exige(200)?;
        Ok(reponse.corps)
    }

    /// Les machines du compte qui possède cette machine — « les miennes ».
    ///
    /// # DEUX REQUÊTES, PARCE QUE LA VOIE MACHINE N'A PAS `GET /v1/machines`
    ///
    /// `GET /v1/machines` est l'écran « Machines » d'un appareil, et la voie
    /// machine ne le sert pas. Ce qu'elle sert est `GET /v1/moi` — qui dit le
    /// propriétaire — puis `GET /v1/utilisateurs/{u}/machines`, qui rend les
    /// siennes à qui est lui (`protocole.md` §3). C'est le même chemin que
    /// [`Connexion::machines_de`] avec le compte que l'annuaire vient de
    /// nommer, et non celui qu'un fichier local croit.
    ///
    /// # Errors
    ///
    /// Celles de [`Connexion::moi`] et de [`Connexion::machines_de`].
    pub async fn machines_du_proprietaire(&mut self) -> Result<Vec<u8>, Faute> {
        let moi = self.moi().await?;
        self.machines_de(moi.proprietaire).await
    }

    /// Les appareils du compte qui possède cette machine, révoqués compris —
    /// `GET /v1/moi/appareils` (`protocole.md` §3).
    ///
    /// **POUR SOI SEULEMENT** : la liste est celle du propriétaire de la clé
    /// prouvée sur cette connexion, et il n'y a pas de forme qui nomme un
    /// compte — un appareil ne sort pas de son compte (C13). Rend une LISTE de
    /// `{"appareil":"a-…","attestation":"…","revoque":bool}`, avec
    /// `plateforme` et `modele` quand l'appareil s'est décrit ; c'est l'objet
    /// que `GET /v1/appareils` rend à un appareil, et
    /// `asl_proto::cadrage::elements` la découpe.
    ///
    /// # Errors
    ///
    /// Celles de [`Connexion::requete`], plus [`Faute::Statut`] — `401` sans
    /// preuve ou clé révoquée, `404` sur un annuaire d'avant 0.10.0.
    pub async fn appareils_du_proprietaire(&mut self) -> Result<Vec<u8>, Faute> {
        let reponse = self.requete(b"GET", b"/v1/moi/appareils", &[], b"").await?;
        reponse.exige(200)?;
        Ok(reponse.corps)
    }

    /// L'état de la voie entre cette racine et l'autre — `GET /v1/replication`
    /// (`replication.md` §8), **vu de la racine que cette connexion a jointe**.
    ///
    /// # SUR LA VOIE MACHINE, ET C'EST POURQUOI IL EST ICI
    ///
    /// L'annuaire ne le rend qu'à une machine qui a prouvé sa clé
    /// (`Exigence::Machine`, comme `/v1/moi`) : dire à un inconnu que la voie
    /// est coupée, c'est lui dire l'heure où une unicité se gagne sur une
    /// racine isolée. L'exploitant le demande depuis une machine enrôlée, ce
    /// qu'il a toujours sous la main — et ce verbe est le sien.
    ///
    /// Rend UN objet : `{"pair":"n-…","voie":"ouverte"|"coupée","compteur":N,
    /// "applique":M}` quand un pair est réglé, `{"voie":"seule","compteur":N}`
    /// quand la racine tourne seule — **sans `pair` ni `applique`**, et un
    /// lecteur regarde `voie` d'abord. Les deux nombres sont l'horloge de la
    /// racine et le curseur qu'elle tient pour le pair — l'estampille de la
    /// dernière opération du pair qu'elle a appliquée. **Leur différence n'est
    /// pas un retard** : l'horloge compte aussi les écritures de la racine
    /// elle-même. Rendus tels quels ; c'est à l'appelant de les lire depuis
    /// les deux racines.
    ///
    /// # Errors
    ///
    /// Celles de [`Connexion::requete`], plus [`Faute::Statut`] — `401` sans
    /// preuve ou clé révoquée, `404` sur un annuaire d'avant 0.8.0.
    pub async fn etat_de_la_replication(&mut self) -> Result<Vec<u8>, Faute> {
        let reponse = self.requete(b"GET", b"/v1/replication", &[], b"").await?;
        reponse.exige(200)?;
        Ok(reponse.corps)
    }

    /// Annonce ce service.
    ///
    /// Rend le corps de la réponse, tel qu'`asl_proto::Reponse::decoder` le lit.
    ///
    /// # Errors
    ///
    /// Celles de [`Connexion::requete`], plus [`Faute::Statut`].
    pub async fn annoncer(&mut self, annonce: &asl_proto::Annonce<'_>) -> Result<Vec<u8>, Faute> {
        self.annoncer_encodee(&encoder(annonce)?).await
    }

    /// La même chose, à partir d'une annonce déjà encodée.
    ///
    /// # POURQUOI CETTE PORTE EXISTE
    ///
    /// `asl_proto::Annonce` EMPRUNTE son nom de service, ses points d'écoute et
    /// ses adresses. Une tâche de fond qui la garderait pour la répéter à chaque
    /// reconnexion devrait donc emprunter tout cela pour toujours.
    ///
    /// Encoder une fois, dans la main de l'appelant, résout les deux problèmes à
    /// la fois : la tâche ne porte que des octets, et **une annonce invalide est
    /// une faute rendue tout de suite** plutôt qu'une faute découverte dans une
    /// tâche que personne ne regarde. Voir [`Attache::annoncer`].
    ///
    /// # Errors
    ///
    /// Celles de [`Connexion::requete`], plus [`Faute::Statut`] et
    /// [`Faute::Renvoye`].
    pub async fn annoncer_encodee(&mut self, annonce: &[u8]) -> Result<Vec<u8>, Faute> {
        let reponse = self
            .requete(
                b"POST",
                b"/v1/annonce",
                &[(b"content-type", b"application/json")],
                annonce,
            )
            .await?;
        // **UN `421` N'EST PAS UN REFUS** (0.28.0) : la machine s'annonce
        // ailleurs, et le corps dit où. Le rendre comme `Statut(421)` le
        // perdrait.
        if reponse.statut == 421 {
            return Err(Faute::Renvoye(reponse.corps));
        }
        reponse.exige(200)?;
        Ok(reponse.corps)
    }

    /// Demande où joindre ce service.
    ///
    /// # Errors
    ///
    /// Celles de [`Connexion::requete`], plus [`Faute::Statut`].
    pub async fn ou(&mut self, machine: Identifiant, service: &str) -> Result<Vec<u8>, Faute> {
        let cible = format!("/v1/ou/{}/{service}", machine.texte());
        let reponse = self.requete(b"GET", cible.as_bytes(), &[], b"").await?;
        reponse.exige(200)?;
        Ok(reponse.corps)
    }

    /// Demande où joindre cet annuaire local — son `asl-directory`
    /// (`annuaires.md` §2 quinquies, décisions 73 à 87 ; serveur 0.38.0).
    ///
    /// `annuaire` est le `n-…` du **titulaire**, qui nomme l'annuaire logique.
    /// Rend le corps du `200` tel quel ;
    /// `asl_client::renvoi::AnnuaireResolu::lire` le lit — la forme complète
    /// (`localiser`) ou la forme réduite (`voir` seul).
    ///
    /// **SUR LA VOIE MACHINE SEULEMENT** (décision 86) : la connexion doit
    /// avoir prouvé la clé d'une machine. Un appareil n'y passe pas.
    ///
    /// # Errors
    ///
    /// Celles de [`Connexion::requete`], plus [`Faute::Statut`] — **`404` pour
    /// « introuvable », « parti » ET « hors de vos droits »**, que la racine ne
    /// distingue pas (C9) ; `401` sans preuve ; `400` d'un annuaire d'avant
    /// 0.38.0, qui ne lit pas un `n-…` à la place d'une machine.
    pub async fn ou_annuaire(&mut self, annuaire: Identifiant) -> Result<Vec<u8>, Faute> {
        let cible = format!(
            "/v1/ou/{}/{}",
            annuaire.texte(),
            asl_client::renvoi::ASL_DIRECTORY
        );
        let reponse = self.requete(b"GET", cible.as_bytes(), &[], b"").await?;
        reponse.exige(200)?;
        Ok(reponse.corps)
    }

    /// Demande sous quelle adresse l'annuaire voit CETTE connexion.
    ///
    /// # ELLE N'EXIGE AUCUNE PREUVE, ET N'ANNONCE RIEN
    ///
    /// C'est tout son intérêt : la réponse à une annonce porte déjà le candidat
    /// réflexif, mais il faut avoir annoncé pour l'obtenir — donc porter la
    /// capacité d'annonce, et avoir un service à publier. Une machine de lecture
    /// seule, ou un daemon dont le port n'est pas encore ouvert, n'avaient aucun
    /// moyen de savoir sous quelle adresse ils sortent.
    ///
    /// **ELLE NE DIT RIEN DU NAT** : ce verdict se tranche en comparant cette
    /// adresse à celles qu'un daemon ANNONCE, et qui n'a rien annoncé n'a rien à
    /// comparer.
    ///
    /// # Errors
    ///
    /// [`Faute::Http3`], [`Faute::Socket`], [`Faute::Quic`], [`Faute::Delai`],
    /// et [`Faute::Statut`] si l'annuaire ne sert pas cette route.
    pub async fn vu(&mut self) -> Result<Vec<u8>, Faute> {
        let reponse = self.requete(b"GET", b"/v1/vu", &[], b"").await?;
        reponse.exige(200)?;
        Ok(reponse.corps)
    }

    /// Ce que l'annuaire dit de lui-même : sa version, et sa posture
    /// d'attestation (`protocole.md`, `GET /v1/version`).
    ///
    /// # ELLE N'EXIGE RIEN, ET C'EST TOUT SON INTÉRÊT
    ///
    /// C'est la ressource que peut lire **qui n'a pas encore de clé** : une
    /// machine qu'on installe, une application qui va créer un compte, un
    /// exploitant qui vérifie qu'un banc sert bien ce qu'il croit. La demander
    /// avant de s'authentifier est donc normal, et un diagnostic sur une
    /// machine non enrôlée la lit comme une autre.
    ///
    /// Le corps est rendu tel quel. La `posture` — `required`, `optional` ou
    /// `invitation` — n'est là que depuis la 0.16.0 de l'annuaire ; un annuaire
    /// plus ancien rend la version seule, et c'est à l'appelant de ne pas
    /// inventer ce qui manque.
    ///
    /// # Errors
    ///
    /// [`Faute::Http3`], [`Faute::Socket`], [`Faute::Quic`], [`Faute::Delai`],
    /// et [`Faute::Statut`] si l'annuaire ne sert pas cette route.
    pub async fn version(&mut self) -> Result<Vec<u8>, Faute> {
        let reponse = self.requete(b"GET", b"/v1/version", &[], b"").await?;
        reponse.exige(200)?;
        Ok(reponse.corps)
    }

    /// Demande un jeton pour sonder l'écho de cette machine —
    /// `POST /v1/echo/jetons` (`protocole.md` §3 quater, décision 91 ;
    /// serveur 0.42.0).
    ///
    /// **SUR LA VOIE MACHINE, AUX RACINES** : la connexion doit avoir prouvé
    /// la clé d'une machine qui porte `lecture`, et le jeton est lié à CETTE
    /// clé — la requête ne la dit pas, la connexion la porte. Il ne sert donc
    /// qu'à qui signe la sonde de la même clé.
    ///
    /// Le jeton rendu est **bien formé, pas encore cru** : c'est l'écho qui le
    /// croit. Le sondeur, lui, y lit la clé de la cible que la racine a signée,
    /// et c'est contre elle qu'il vérifie la réponse.
    ///
    /// # Errors
    ///
    /// Celles de [`Connexion::requete`], plus [`Faute::Statut`] — **`404` pour
    /// « pas de machine », « pas d'écho annoncé » ET « pas le droit »**, que
    /// la racine ne distingue pas (C9) ; `429` au-delà du débit ; `421` chez
    /// un annuaire local — et [`Faute::Illisible`].
    pub async fn jeton_d_echo(&mut self, machine: Identifiant) -> Result<asl_echo::Jeton, Faute> {
        let mut corps = [0_u8; 64];
        let ecrit = asl_api::echo::DemandeDeJeton { machine }
            .encoder(&mut corps)
            .map_err(|_| Faute::Illisible)?;
        let reponse = self
            .requete(
                b"POST",
                b"/v1/echo/jetons",
                &[(b"content-type", b"application/json")],
                corps.get(..ecrit).unwrap_or_default(),
            )
            .await?;
        reponse.exige(200)?;
        asl_api::echo::JetonRendu::decoder(&reponse.corps)
            .map(|rendu| rendu.jeton)
            .map_err(|_| Faute::Illisible)
    }
}

/// Ce qu'un enrôlement rend : la machine, et son propriétaire si l'annuaire
/// le dit.
///
/// La machine ne connaissait que le code ; elle repart en sachant qui elle est
/// et pour qui elle agit (`protocole.md` §2.0). Un annuaire d'avant 0.3.0 ne
/// rend que la machine — `proprietaire` est alors `None`, et [`Connexion::moi`]
/// le rendra plus tard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Enrolee {
    /// La machine que le code désignait.
    pub machine: Identifiant,
    /// Le compte qui la possède, quand l'annuaire l'a rendu.
    pub proprietaire: Option<Identifiant>,
}

/// Ce que `GET /v1/moi` rend : qui je suis, et à qui j'appartiens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Moi {
    /// La machine de cette connexion.
    pub machine: Identifiant,
    /// Son propriétaire.
    pub proprietaire: Identifiant,
}

/// Encode une annonce, telle qu'elle partira sur le fil.
///
/// **L'ENCODAGE EST UNE VALIDATION.** `asl_proto::Annonce::nouvelle` a déjà
/// refusé ce qui ne se dit pas ; ce qui reste ici est la mise en octets, et elle
/// se fait pendant que l'appelant peut encore en lire le refus.
///
/// # Errors
///
/// [`Faute::Illisible`] si l'annonce ne tient pas dans un message.
pub fn encoder(annonce: &asl_proto::Annonce<'_>) -> Result<Vec<u8>, Faute> {
    let mut sortie = vec![0_u8; asl_proto::cadrage::MESSAGE_MAX];
    let combien = annonce.encoder(&mut sortie).map_err(|_| Faute::Illisible)?;
    sortie.truncate(combien);
    Ok(sortie)
}

#[cfg(test)]
mod tests {
    use super::{Tri, canonique, pour_la_socket, trier};
    use std::net::SocketAddr;

    fn adresse(texte: &str) -> SocketAddr {
        texte.parse().expect("une adresse")
    }

    /// **UN SEUL OCTET DÉCIDE** : l'écho d'où qu'il vienne, le QUIC de
    /// l'annuaire seul, le reste jeté — ce que le noyau faisait d'une socket
    /// connectée.
    #[test]
    fn le_tri_se_fait_au_premier_octet_puis_a_la_source() {
        let annuaire = adresse("192.0.2.1:6630");
        let inconnu = adresse("198.51.100.9:40000");
        // Un paquet QUIC long (0xC0…) et court (0x40…), de l'annuaire.
        assert_eq!(trier(&[0xC3, 0], annuaire, annuaire), Tri::Quic);
        assert_eq!(trier(&[0x41], annuaire, annuaire), Tri::Quic);
        // Le même, d'ailleurs : jeté.
        assert_eq!(trier(&[0xC3, 0], inconnu, annuaire), Tri::Ailleurs);
        // L'écho, de toute source — y compris l'annuaire, qui sonde depuis
        // une autre socket mais pourrait venir de la même adresse.
        for premier in 0x04..=0x0F {
            assert_eq!(
                trier(&[premier, 1], inconnu, annuaire),
                Tri::Echo,
                "{premier:#x}"
            );
            assert_eq!(trier(&[premier], annuaire, annuaire), Tri::Echo);
        }
        // Hors de la plage de l'écho, et pas de l'annuaire : jeté.
        assert_eq!(trier(&[0x03], inconnu, annuaire), Tri::Ailleurs);
        assert_eq!(trier(&[0x10], inconnu, annuaire), Tri::Ailleurs);
        // Vide : rien.
        assert_eq!(trier(&[], annuaire, annuaire), Tri::Ailleurs);
        // **UNE IPv4 ENFOUIE EST L'ANNUAIRE** qu'on avait visé en IPv4 : c'est
        // ce qu'une socket à double pile rend.
        let enfouie = adresse("[::ffff:192.0.2.1]:6630");
        assert_eq!(trier(&[0xC3], enfouie, annuaire), Tri::Quic);
        assert_eq!(canonique(enfouie), annuaire);
        assert_ne!(canonique(adresse("[::ffff:192.0.2.1]:6631")), annuaire);
    }

    #[test]
    fn une_ipv4_s_enfouit_sur_une_socket_ipv6_et_seulement_la() {
        let v4 = adresse("192.0.2.1:6630");
        let v6 = adresse("[2001:db8::1]:6630");
        assert_eq!(pour_la_socket(true, v4), adresse("[::ffff:192.0.2.1]:6630"));
        assert_eq!(pour_la_socket(false, v4), v4);
        assert_eq!(pour_la_socket(true, v6), v6);
    }
}
