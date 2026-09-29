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
//! # LA FORME D'HIER EST RETIRÉE (décision 58, étape 5)
//!
//! Le temps de la bascule, une chaîne signée par une autorité en PEM et
//! portant le nom exigé était crue AUSSI. Depuis le 2026-09-28, les racines
//! ne servent plus que leur certificat d'identité : cette porte est fermée,
//! et `asl_appareil_racines` / `asl_client_racines` / `--roots` avec elle.
//! Il ne reste qu'une règle, et une seule façon d'être cru.
//!
//! # LA MÊME RÈGLE QUE LE SERVEUR, ÉCRITE UNE FOIS
//!
//! La moitié pure — un seul maillon, dont la clé se déduit en un `n-…`
//! attendu — est `asl_racines::identite_attendue`, la fonction même
//! qu'appelle `asl-loop-tokio::confiance` côté serveur. Ce qui reste ici est
//! ce qu'`asl-racines` ne peut pas porter sans entrée-sortie : le branchement
//! dans `rustls`, la preuve de possession (la signature de la poignée de main
//! contre cette même clé), et la forme retenue.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use asl_cle::ClePublique;
use asl_client::racines::identite_attendue;
use asl_id::Identifiant;
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
}

impl Confiance {
    /// Croire ces identités, et elles seules.
    #[must_use]
    pub fn par_identites(identites: &[Identifiant]) -> Self {
        Self {
            identites: identites.to_vec(),
        }
    }

    /// Les identités attendues.
    #[must_use]
    pub fn identites(&self) -> &[Identifiant] {
        &self.identites
    }
}

/// La forme de confiance qui a servi.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
///
/// **UNE SEULE, DEPUIS LA FIN DE LA BASCULE** : elle reste nommée pour que
/// `asl diagnose` dise ce qui a été cru, et qu'une forme nouvelle, un jour,
/// s'ajoute ici sans que personne ait à deviner.
pub enum Forme {
    /// Le certificat d'identité : la clé attendue.
    Identite,
}

impl core::fmt::Display for Forme {
    fn fmt(&self, sortie: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        sortie.write_str(match self {
            Self::Identite => "identité par la clé",
        })
    }
}

/// Ce que la poignée de main a cru : la forme, et **la clé** du certificat
/// reconnu.
///
/// # POURQUOI LA CLÉ EST GARDÉE
///
/// L'écho croit la sonde de l'annuaire qui tient son bail (décision 91 ; E4),
/// et la vérifie sous SA clé d'identité — celle que la poignée de main vient
/// de juger. Un annuaire local joint par un `421` n'est pas dans le binaire :
/// c'est ici, et nulle part ailleurs, qu'on apprend sa clé.
pub(crate) type Retenue = Arc<Mutex<Option<(Forme, ClePublique)>>>;

/// Monte la configuration TLS cliente pour cette confiance.
///
/// # L'ALPN EST POSÉE ICI, ET PAS AILLEURS
///
/// §3.1 de RFC 9114 : un client qui n'annonce pas `h3` voit sa poignée de main
/// refusée. La poser ici rend l'oubli impossible.
pub(crate) fn configuration(
    confiance: &Confiance,
) -> Result<(Arc<rustls::ClientConfig>, Retenue), Faute> {
    if confiance.identites.is_empty() {
        return Err(Faute::Tls(
            "aucune identité attendue : rien à croire".to_owned(),
        ));
    }
    let fournisseur = Arc::new(ams_tls::provider_quic());
    let retenue: Retenue = Arc::new(Mutex::new(None));
    let verificateur = Verificateur {
        identites: confiance.identites.clone(),
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
/// **L'ADRESSE, JAMAIS UN NOM** : un annuaire rend son certificat d'identité à
/// qui vise une adresse, et c'est lui qu'on juge (C20 : aucun nom n'est
/// résolu, ni envoyé comme preuve).
pub(crate) fn nom_de_serveur(cible: SocketAddr) -> ServerName<'static> {
    ServerName::IpAddress(cible.ip().into())
}

/// Le vérificateur : un seul maillon, dont la clé est une identité attendue.
#[derive(Debug)]
struct Verificateur {
    identites: Vec<Identifiant>,
    fournisseur: Arc<CryptoProvider>,
    retenue: Retenue,
}

impl Verificateur {
    fn retenir(&self, forme: Forme, cle: ClePublique) {
        if let Ok(mut place) = self.retenue.lock() {
            *place = Some((forme, cle));
        }
    }
}

impl ServerCertVerifier for Verificateur {
    fn verify_server_cert(
        &self,
        certificat: &CertificateDer<'_>,
        intermediaires: &[CertificateDer<'_>],
        _nom: &ServerName<'_>,
        _ocsp: &[u8],
        _maintenant: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // **UN SEUL MAILLON, ET SA CLÉ EST L'IDENTITÉ.** Une chaîne de deux
        // n'est pas un certificat d'identité, même si sa tête en porte un.
        let maillons = intermediaires.len().saturating_add(1);
        if identite_attendue(maillons, certificat, &self.identites).is_some()
            && let Ok(cle) = asl_cle::cle_du_certificat(certificat)
        {
            self.retenir(Forme::Identite, cle);
            return Ok(ServerCertVerified::assertion());
        }
        Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::ApplicationVerificationFailure,
        ))
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
            Some((Forme::Identite, nous.publique()))
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
        let nous = CleSecrete::depuis_entropie([0x64; 32]);
        let id = asl_cle::identifiant_de_racine(&nous.publique());
        let confiance = Confiance::par_identites(&[id]);
        assert_eq!(confiance.identites(), [id]);
        assert!(super::configuration(&confiance).is_ok());
        assert_eq!(Forme::Identite.to_string(), "identité par la clé");
        let cible: std::net::SocketAddr = "[::1]:6630".parse().expect("une adresse");
        assert!(matches!(
            super::nom_de_serveur(cible),
            ServerName::IpAddress(_)
        ));
    }
}
