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

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ams_proto_quic::{ConnectionId, StreamId};
use ams_quic_tls::Connection as ConnexionQuic;
use asl_cle::{Defi, LiaisonDeCanal};
use asl_client::Identite;
use asl_id::Identifiant;
use tokio::net::UdpSocket;

mod attache;
mod pont;
mod reponse;

pub use attache::{Annuaire, Attache, Etat, Reglages, joindre};
pub use pont::Pont;
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
    socket: UdpSocket,
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
}

impl Connexion {
    /// Ouvre une connexion à cet annuaire, et mène la poignée de main au bout.
    ///
    /// `nom` est le nom exigé du certificat, et il sert aussi d'`:authority`.
    /// `racines` porte les certificats d'autorité en PEM.
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
        racines: &[u8],
        alea: &(dyn Fn() -> [u8; 16] + Sync),
    ) -> Result<Self, Faute> {
        let config = configuration_tls(racines)?;
        let serveur = rustls::pki_types::ServerName::try_from(nom.to_owned())
            .map_err(|_| Faute::Tls(format!("`{nom}` n'est pas un nom de serveur")))?;

        // **UNE SOCKET DE LA MÊME FAMILLE QUE LA CIBLE.** Se lier en IPv4 pour
        // joindre une adresse IPv6 échoue au premier envoi, et le message du
        // noyau ne dit pas pourquoi.
        let local = match annuaire {
            SocketAddr::V4(_) => "0.0.0.0:0",
            SocketAddr::V6(_) => "[::]:0",
        };
        let socket = UdpSocket::bind(local).await.map_err(Faute::Socket)?;
        socket.connect(annuaire).await.map_err(Faute::Socket)?;

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
            quic,
            h3: ams_h3::Http3Client::new(),
            // **UNE VALEUR DE PASSAGE, REMPLACÉE AVANT TOUT USAGE.** La vraie
            // s'exporte de la poignée de main, qui n'a pas encore eu lieu ;
            // `poignee_de_main` la pose, et échoue plutôt que de la laisser.
            liaison: LiaisonDeCanal::depuis_octets([0; asl_cle::LIAISON_OCTETS]),
            autorite: nom.to_owned(),
        };
        connexion.poignee_de_main().await?;
        Ok(connexion)
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
            self.socket
                .send(place.get(..ecrit).unwrap_or_default())
                .await
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
        match tokio::time::timeout(attente, self.socket.recv(&mut recu)).await {
            Ok(Ok(lus)) => {
                let mut datagramme = recu.get_mut(..lus).unwrap_or_default().to_vec();
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
        let vivants: Vec<StreamId> = self.quic.streams_alive().collect();
        {
            let mut pont = Pont(&mut self.quic);
            for flux in vivants {
                self.h3.on_readable(&mut pont, flux).map_err(Faute::Http3)?;
            }
        }
        self.emettre().await
    }

    /// La connexion est-elle encore là ?
    #[must_use]
    pub const fn vivante(&self) -> bool {
        !self.quic.is_closed()
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

    /// Présente un code d'enrôlement et une clé neuve, et rend la machine.
    ///
    /// # Errors
    ///
    /// Celles de [`Connexion::requete`], plus [`Faute::Statut`] et
    /// [`Faute::Illisible`].
    pub async fn enroler(
        &mut self,
        enrolement: &asl_client::Enrolement,
        code: &str,
    ) -> Result<Identifiant, Faute> {
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
        reponse.identifiant("machine")
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
    /// Celles de [`Connexion::requete`], plus [`Faute::Statut`].
    pub async fn annoncer_encodee(&mut self, annonce: &[u8]) -> Result<Vec<u8>, Faute> {
        let reponse = self
            .requete(
                b"POST",
                b"/v1/annonce",
                &[(b"content-type", b"application/json")],
                annonce,
            )
            .await?;
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

/// Monte la configuration TLS cliente.
///
/// # L'ALPN EST POSÉE ICI, ET PAS AILLEURS
///
/// §3.1 de RFC 9114 : le protocole applicatif se choisit par ALPN, et un client
/// qui n'en annoncerait pas verrait sa poignée de main refusée par un serveur
/// qui, lui, l'exige. La poser dans cette fonction plutôt que chez l'appelant
/// est ce qui rend l'oubli impossible.
fn configuration_tls(racines: &[u8]) -> Result<Arc<rustls::ClientConfig>, Faute> {
    use rustls::pki_types::pem::PemObject as _;

    let mut magasin = rustls::RootCertStore::empty();
    for der in rustls::pki_types::CertificateDer::pem_slice_iter(racines) {
        let der = der.map_err(|quoi| Faute::Tls(format!("certificat illisible : {quoi}")))?;
        magasin
            .add(der)
            .map_err(|quoi| Faute::Tls(format!("racine refusée : {quoi}")))?;
    }
    if magasin.is_empty() {
        return Err(Faute::Tls("aucune racine à qui faire confiance".to_owned()));
    }

    let mut config =
        rustls::ClientConfig::builder_with_provider(Arc::new(ams_tls::provider_quic()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|quoi| Faute::Tls(format!("TLS 1.3 : {quoi}")))?
            .with_root_certificates(magasin)
            .with_no_client_auth();
    config.alpn_protocols = ams_tls::alpn_h3();
    Ok(Arc::new(config))
}
