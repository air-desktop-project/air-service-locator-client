//! Qui l'on croit au bout d'une connexion (`protocole.md` §0, décisions 53
//! à 58).
//!
//! # L'IDENTITÉ EST LA CLÉ
//!
//! Un annuaire — racine ou local — présente un certificat **auto-signé par sa
//! clé d'identité** Ed25519, celle d'où se déduit son `n-…`. On le croit si
//! cette clé se déduit en un identifiant qu'on attend, et la poignée de main
//! prouve qu'il la tient. Ni autorité, ni nom, ni date : un locateur dit où
//! joindre, la clé dit qui l'on doit trouver au bout.
//!
//! # LA FORME D'HIER, LE TEMPS DE LA BASCULE (décision 58)
//!
//! Tant qu'un PEM d'autorité est configuré (`--roots`,
//! `asl_appareil_racines`), la chaîne signée par cette autorité et portant le
//! nom exigé est crue AUSSI : les racines d'aujourd'hui ne servent encore que
//! celle-là. La forme qui a servi est **retenue**, et se dit (`asl
//! diagnose`) : c'est ce qui permettra de savoir quand plus rien ne passe
//! par la vieille.
//!
//! # LA MÊME RÈGLE QUE LE SERVEUR, ÉCRITE UNE FOIS
//!
//! La moitié pure — un seul maillon, dont la clé se déduit en un `n-…`
//! attendu — est `asl_racines::identite_attendue`, la fonction même
//! qu'appelle `asl-loop-tokio::confiance` côté serveur. Ce qui reste ici est
//! ce qu'`asl-racines` ne peut pas porter sans entrée-sortie : le branchement
//! dans `rustls`, la preuve de possession (la signature de la poignée de main
//! contre cette même clé), le repli sur l'autorité d'hier, et la forme
//! retenue.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use asl_client::racines::identite_attendue;
use asl_id::Identifiant;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

use crate::Faute;

/// Ce qu'on croit d'une connexion.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Confiance {
    /// Les identités qu'on accepte de trouver au bout.
    identites: Vec<Identifiant>,
    /// L'autorité d'hier, en PEM — vide : aucune.
    autorite_pem: Vec<u8>,
}

impl Confiance {
    /// Croire ces identités, et elles seules.
    #[must_use]
    pub fn par_identites(identites: &[Identifiant]) -> Self {
        Self {
            identites: identites.to_vec(),
            autorite_pem: Vec::new(),
        }
    }

    /// Croire une chaîne signée par cette autorité (la forme d'hier).
    #[must_use]
    pub fn par_autorite(pem: &[u8]) -> Self {
        Self {
            identites: Vec::new(),
            autorite_pem: pem.to_vec(),
        }
    }

    /// Croire AUSSI cette autorité — la transition. Un PEM vide n'ajoute rien.
    #[must_use]
    pub fn avec_autorite(mut self, pem: &[u8]) -> Self {
        self.autorite_pem = pem.to_vec();
        self
    }

    /// Les identités attendues.
    #[must_use]
    pub fn identites(&self) -> &[Identifiant] {
        &self.identites
    }

    /// Une autorité d'hier est-elle configurée ?
    #[must_use]
    pub fn a_une_autorite(&self) -> bool {
        !self.autorite_pem.is_empty()
    }
}

/// La forme de confiance qui a servi.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Forme {
    /// Le certificat d'identité : la clé attendue.
    Identite,
    /// La chaîne d'une autorité et le nom (forme d'hier).
    Autorite,
}

impl core::fmt::Display for Forme {
    fn fmt(&self, sortie: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        sortie.write_str(match self {
            Self::Identite => "identité par la clé",
            Self::Autorite => "autorité et nom (forme d'hier)",
        })
    }
}

/// Où la poignée de main dépose la forme qu'elle a crue.
pub(crate) type Retenue = Arc<Mutex<Option<Forme>>>;

/// Monte la configuration TLS cliente pour cette confiance.
///
/// # L'ALPN EST POSÉE ICI, ET PAS AILLEURS
///
/// §3.1 de RFC 9114 : un client qui n'annonce pas `h3` voit sa poignée de main
/// refusée. La poser ici rend l'oubli impossible.
pub(crate) fn configuration(
    confiance: &Confiance,
) -> Result<(Arc<rustls::ClientConfig>, Retenue), Faute> {
    let fournisseur = Arc::new(ams_tls::provider_quic());
    let repli = if confiance.a_une_autorite() {
        Some(verificateur_d_autorite(
            &confiance.autorite_pem,
            &fournisseur,
        )?)
    } else if confiance.identites.is_empty() {
        return Err(Faute::Tls(
            "ni identité attendue ni autorité : rien à croire".to_owned(),
        ));
    } else {
        None
    };
    let retenue: Retenue = Arc::new(Mutex::new(None));
    let verificateur = Verificateur {
        identites: confiance.identites.clone(),
        repli,
        fournisseur: Arc::clone(&fournisseur),
        retenue: Arc::clone(&retenue),
    };
    let mut config = rustls::ClientConfig::builder_with_provider(fournisseur)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|quoi| Faute::Tls(format!("TLS 1.3 : {quoi}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verificateur))
        .with_no_client_auth();
    config.alpn_protocols = ams_tls::alpn_h3();
    Ok((Arc::new(config), retenue))
}

/// Le nom de serveur qu'on donne à la poignée de main.
///
/// # UN NOM N'EST ENVOYÉ QUE S'IL SERT À LA FORME D'HIER
///
/// Un annuaire en transition sert la chaîne d'hier à qui envoie un SNI qui la
/// nomme, le certificat d'identité sinon (décision 58, point 2). Sans autorité
/// configurée, on ne vise donc **que l'adresse** : l'annuaire rend son
/// identité, et c'est elle qu'on juge. Avec une autorité, on envoie le nom —
/// un annuaire d'hier y répond par sa chaîne, qu'on sait croire ; un annuaire
/// qui ne sert que son identité la rend quand même.
pub(crate) fn nom_de_serveur(
    confiance: &Confiance,
    nom: &str,
    cible: SocketAddr,
) -> Result<ServerName<'static>, Faute> {
    if !confiance.a_une_autorite() {
        return Ok(ServerName::IpAddress(cible.ip().into()));
    }
    ServerName::try_from(nom.to_owned())
        .map_err(|_| Faute::Tls(format!("`{nom}` n'est pas un nom de serveur")))
}

/// Le vérificateur WebPKI d'hier, sur cette autorité seule.
///
/// **AUCUN REPLI SUR LE MAGASIN DU SYSTÈME** : les annuaires de ce produit
/// sont signés par SA propre autorité.
fn verificateur_d_autorite(
    pem: &[u8],
    fournisseur: &Arc<CryptoProvider>,
) -> Result<Arc<WebPkiServerVerifier>, Faute> {
    use rustls::pki_types::pem::PemObject as _;

    let mut magasin = rustls::RootCertStore::empty();
    for der in CertificateDer::pem_slice_iter(pem) {
        let der = der.map_err(|quoi| Faute::Tls(format!("certificat illisible : {quoi}")))?;
        magasin
            .add(der)
            .map_err(|quoi| Faute::Tls(format!("racine refusée : {quoi}")))?;
    }
    if magasin.is_empty() {
        return Err(Faute::Tls("aucune racine à qui faire confiance".to_owned()));
    }
    WebPkiServerVerifier::builder_with_provider(Arc::new(magasin), Arc::clone(fournisseur))
        .build()
        .map_err(|quoi| Faute::Tls(format!("vérificateur : {quoi}")))
}

/// Le vérificateur : l'identité d'abord, la chaîne d'hier ensuite.
#[derive(Debug)]
struct Verificateur {
    identites: Vec<Identifiant>,
    repli: Option<Arc<WebPkiServerVerifier>>,
    fournisseur: Arc<CryptoProvider>,
    retenue: Retenue,
}

impl Verificateur {
    fn retenir(&self, forme: Forme) {
        if let Ok(mut place) = self.retenue.lock() {
            *place = Some(forme);
        }
    }
}

impl ServerCertVerifier for Verificateur {
    fn verify_server_cert(
        &self,
        certificat: &CertificateDer<'_>,
        intermediaires: &[CertificateDer<'_>],
        nom: &ServerName<'_>,
        ocsp: &[u8],
        maintenant: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // **UN SEUL MAILLON, ET SA CLÉ EST L'IDENTITÉ.** Une chaîne de deux
        // n'est pas un certificat d'identité, même si sa tête en porte un.
        let maillons = intermediaires.len().saturating_add(1);
        if identite_attendue(maillons, certificat, &self.identites).is_some() {
            self.retenir(Forme::Identite);
            return Ok(ServerCertVerified::assertion());
        }
        match &self.repli {
            Some(autorite) => {
                let verdict = autorite.verify_server_cert(
                    certificat,
                    intermediaires,
                    nom,
                    ocsp,
                    maintenant,
                )?;
                self.retenir(Forme::Autorite);
                Ok(verdict)
            }
            None => Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            )),
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _certificat: &CertificateDer<'_>,
        _signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // QUIC n'existe qu'en TLS 1.3 (RFC 9001 §4.2).
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls13RequiredForQuic,
        ))
    }

    /// **LA PREUVE DE POSSESSION** : la signature de la poignée de main, sous
    /// la clé du certificat — celle qu'on vient de reconnaître.
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificat: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            certificat,
            signature,
            &self.fournisseur.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.fournisseur
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::{Confiance, Forme, Verificateur};
    use asl_cle::CleSecrete;
    use rustls::client::danger::ServerCertVerifier as _;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use std::sync::{Arc, Mutex};

    fn monter(identites: &[&CleSecrete]) -> (Verificateur, super::Retenue) {
        let retenue: super::Retenue = Arc::new(Mutex::new(None));
        let verificateur = Verificateur {
            identites: identites
                .iter()
                .map(|cle| asl_cle::identifiant_de_racine(&cle.publique()))
                .collect(),
            repli: None,
            fournisseur: Arc::new(ams_tls::provider_quic()),
            retenue: Arc::clone(&retenue),
        };
        (verificateur, retenue)
    }

    fn juger(verificateur: &Verificateur, chaine: &[Vec<u8>]) -> bool {
        let (tete, suite) = chaine.split_first().expect("une tête");
        let suite: Vec<CertificateDer<'_>> = suite
            .iter()
            .map(|der| CertificateDer::from(der.as_slice()))
            .collect();
        verificateur
            .verify_server_cert(
                &CertificateDer::from(tete.as_slice()),
                &suite,
                &ServerName::try_from("127.0.0.1").expect("une adresse"),
                &[],
                UnixTime::now(),
            )
            .is_ok()
    }

    #[test]
    fn la_cle_attendue_seule_passe_et_la_forme_est_retenue() {
        let nous = CleSecrete::depuis_entropie([0x61; 32]);
        let autre = CleSecrete::depuis_entropie([0x62; 32]);
        let certificat = asl_cle::certificat_d_identite(&nous).to_vec();

        let (verificateur, retenue) = monter(&[&nous]);
        assert!(juger(&verificateur, std::slice::from_ref(&certificat)));
        assert_eq!(
            *retenue.lock().expect("pas empoisonné"),
            Some(Forme::Identite)
        );

        let (verificateur, retenue) = monter(&[&autre]);
        assert!(!juger(&verificateur, std::slice::from_ref(&certificat)));
        assert_eq!(*retenue.lock().expect("pas empoisonné"), None);
    }

    #[test]
    fn une_chaine_de_deux_n_est_pas_un_certificat_d_identite() {
        let nous = CleSecrete::depuis_entropie([0x63; 32]);
        let certificat = asl_cle::certificat_d_identite(&nous).to_vec();
        let (verificateur, _) = monter(&[&nous]);
        assert!(!juger(&verificateur, &[certificat.clone(), certificat]));
    }

    #[test]
    fn rien_a_croire_ne_se_monte_pas_et_les_formes_se_disent() {
        assert!(super::configuration(&Confiance::default()).is_err());
        assert!(super::configuration(&Confiance::par_autorite(b"pas un PEM")).is_err());
        assert!(super::configuration(&Confiance::par_autorite(b"")).is_err());
        let nous = CleSecrete::depuis_entropie([0x64; 32]);
        let id = asl_cle::identifiant_de_racine(&nous.publique());
        let confiance = Confiance::par_identites(&[id]);
        assert_eq!(confiance.identites(), [id]);
        assert!(!confiance.a_une_autorite());
        assert!(super::configuration(&confiance).is_ok());
        assert!(confiance.clone().avec_autorite(b"x").a_une_autorite());
        assert_eq!(Forme::Identite.to_string(), "identité par la clé");
        assert!(Forme::Autorite.to_string().contains("hier"));
    }
}
