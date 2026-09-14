//! Ce qu'un APPAREIL compose — le téléphone qui administre un compte.
//!
//! # LA SIGNATURE SE FAIT PAR RAPPEL, ET C'EST TOUT LE DISPOSITIF
//!
//! Une machine détient sa clé Ed25519 dans un fichier, et [`crate::Identite`]
//! signe elle-même. **Un téléphone ne détient rien de tel** : sa clé P-256 vit
//! dans la Secure Enclave ou le Keystore, sous contrôle biométrique, et c'est
//! le matériel qui signe — après que le porteur a posé son doigt. Aucune crate
//! Rust ne peut faire ce geste à sa place.
//!
//! Ce module ne signe donc jamais. Il COMPOSE ce qu'il y a à signer, octet pour
//! octet comme le serveur le vérifiera (`asl-cle`), et il compose ce qui part
//! une fois la signature rendue. Entre les deux, c'est l'application qui parle
//! à son matériel. Le transport, lui, ne voit passer que des octets.
//!
//! # Pourquoi ce module est ici, et non dans le transport
//!
//! Parce que c'est une DÉCISION — quel message, quel domaine, quel corps —, et
//! non une entrée-sortie. Écrit dans le transport, il ne s'éprouverait qu'avec
//! un annuaire réel ; écrit ici, il s'éprouve sur des octets littéraux, et le
//! serveur peut les recouper avec les siens.

use asl_api::corps::{CreationDeCompte, PlateformeAttestation};
use asl_cle::{
    CLE_APPAREIL_OCTETS, CleAppareil, Defi, LiaisonDeCanal, MESSAGE_ATTESTATION_OCTETS,
    MESSAGE_OCTETS, MESSAGE_POSSESSION_APPAREIL_OCTETS, SIGNATURE_APPAREIL_OCTETS,
    message_a_signer, message_d_attestation, message_de_possession_appareil,
};
use asl_id::{Genre, Identifiant};

/// Ce qu'occupe le corps de `POST /v1/defi` pour un appareil : le genre, les
/// seize octets de l'identifiant, la signature.
///
/// **Le même dessin que pour une machine** — `asl_client_tokio::Connexion::
/// authentifier` compose quatre-vingt-un octets de la même façon —, avec le
/// genre `a` et une signature P-256 à la place d'Ed25519. Le message signé est
/// le même ; c'est la clé rangée dans l'annuaire qui dit, par sa forme, comment
/// vérifier.
pub const PREUVE_AUTHENTIFICATION_OCTETS: usize = 1 + 16 + SIGNATURE_APPAREIL_OCTETS;

/// La plate-forme d'attestation d'un appareil, telle que `POST /v1/comptes` la
/// note sur son premier octet.
///
/// `0` interdit toute attestation derrière, `1` et `2` l'exigent — et c'est
/// `asl_api` qui le refuse, avant que rien ne parte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plateforme {
    /// Aucune attestation : l'annuaire l'admet en posture `facultative` seulement.
    Aucune,
    /// App Attest.
    Apple,
    /// Play Integrity.
    Google,
}

impl Plateforme {
    /// L'octet qui la note sur le fil.
    #[must_use]
    pub const fn etiquette(self) -> u8 {
        match self {
            Self::Aucune => 0,
            Self::Apple => 1,
            Self::Google => 2,
        }
    }

    /// Depuis l'octet, ou rien s'il n'en désigne aucune.
    #[must_use]
    pub const fn depuis(octet: u8) -> Option<Self> {
        match octet {
            0 => Some(Self::Aucune),
            1 => Some(Self::Apple),
            2 => Some(Self::Google),
            _ => None,
        }
    }

    const fn vers_api(self) -> PlateformeAttestation {
        match self {
            Self::Aucune => PlateformeAttestation::Aucune,
            Self::Apple => PlateformeAttestation::Apple,
            Self::Google => PlateformeAttestation::Google,
        }
    }
}

/// Ce que ce module refuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FauteAppareil {
    /// Les trente-trois octets ne forment pas un point de P-256.
    ///
    /// **C'est une vérification réelle**, faite par `asl-cle` : un préfixe qui
    /// n'est ni `02` ni `03`, ou un `x` sans `y` sur la courbe, est refusé ici,
    /// et non au moment où une signature ne vérifie pas sans qu'on sache
    /// pourquoi.
    ClePubliqueInvalide,
    /// L'identifiant fourni n'est pas celui d'un appareil.
    PasUnAppareil {
        /// Le genre fourni.
        obtenu: Genre,
    },
    /// Le corps de création ne se compose pas : une attestation manquante ou
    /// inattendue, un tampon trop petit.
    Corps(asl_proto::Erreur),
}

/// Lit la clé publique d'un appareil, et la refuse si elle n'est pas sur la
/// courbe.
///
/// # Erreurs
///
/// [`FauteAppareil::ClePubliqueInvalide`].
pub fn cle_publique(octets: &[u8; CLE_APPAREIL_OCTETS]) -> Result<CleAppareil, FauteAppareil> {
    CleAppareil::depuis_octets(*octets).map_err(|_| FauteAppareil::ClePubliqueInvalide)
}

/// Le message que l'appareil signe pour prouver qu'il détient sa clé — celui de
/// `POST /v1/comptes`.
///
/// Il porte la clé elle-même, parce qu'il sert avant qu'il y ait un nom :
/// l'annuaire attribue l'identifiant APRÈS, et l'appareil n'a donc pas pu le
/// signer. Son domaine est distinct de celui de l'authentification, pour qu'une
/// preuve captée ailleurs ne vaille jamais ici.
///
/// # Erreurs
///
/// [`FauteAppareil::ClePubliqueInvalide`].
pub fn message_de_possession(
    cle: &[u8; CLE_APPAREIL_OCTETS],
    defi: &Defi,
    liaison: &LiaisonDeCanal,
) -> Result<[u8; MESSAGE_POSSESSION_APPAREIL_OCTETS], FauteAppareil> {
    Ok(message_de_possession_appareil(
        &cle_publique(cle)?,
        defi,
        liaison,
    ))
}

/// Le message que l'appareil signe à chaque connexion, une fois enrôlé — celui
/// de `POST /v1/defi`.
///
/// # Erreurs
///
/// [`FauteAppareil::PasUnAppareil`].
pub fn message_d_authentification(
    appareil: Identifiant,
    defi: &Defi,
    liaison: &LiaisonDeCanal,
) -> Result<[u8; MESSAGE_OCTETS], FauteAppareil> {
    if appareil.genre() != Genre::Appareil {
        return Err(FauteAppareil::PasUnAppareil {
            obtenu: appareil.genre(),
        });
    }
    Ok(message_a_signer(appareil, defi, liaison))
}

/// Ce dont App Attest hache le condensat, et ce que porte le nonce Play
/// Integrity : la clé, le défi, la liaison, sous un troisième domaine — pour que
/// l'attestation soit liée À LA clé présentée.
///
/// # Erreurs
///
/// [`FauteAppareil::ClePubliqueInvalide`].
pub fn message_pour_attestation(
    cle: &[u8; CLE_APPAREIL_OCTETS],
    defi: &Defi,
    liaison: &LiaisonDeCanal,
) -> Result<[u8; MESSAGE_ATTESTATION_OCTETS], FauteAppareil> {
    Ok(message_d_attestation(&cle_publique(cle)?, defi, liaison))
}

/// Compose le corps de `POST /v1/comptes` : `plate-forme (1) ‖ clé (33) ‖
/// preuve (64) ‖ attestation`, et rend combien d'octets il occupe.
///
/// `sortie` doit pouvoir contenir `asl_api::corps::COMPTE_CORPS_MAX` octets
/// pour qu'aucune attestation admise ne soit refusée faute de place.
///
/// # Erreurs
///
/// [`FauteAppareil::Corps`] : une attestation absente pour Apple ou Google,
/// présente pour « aucune », ou plus longue que ce que l'annuaire admet.
pub fn corps_de_compte(
    plateforme: Plateforme,
    cle: &[u8; CLE_APPAREIL_OCTETS],
    preuve: &[u8; SIGNATURE_APPAREIL_OCTETS],
    attestation: &[u8],
    sortie: &mut [u8],
) -> Result<usize, FauteAppareil> {
    CreationDeCompte {
        plateforme: plateforme.vers_api(),
        cle,
        preuve,
        attestation,
    }
    .encoder(sortie)
    .map_err(FauteAppareil::Corps)
}

/// Compose le corps de `POST /v1/defi` pour un appareil enrôlé : `a ‖
/// identifiant (16) ‖ signature (64)`.
///
/// # Erreurs
///
/// [`FauteAppareil::PasUnAppareil`].
pub fn preuve_d_authentification(
    appareil: Identifiant,
    signature: &[u8; SIGNATURE_APPAREIL_OCTETS],
) -> Result<[u8; PREUVE_AUTHENTIFICATION_OCTETS], FauteAppareil> {
    if appareil.genre() != Genre::Appareil {
        return Err(FauteAppareil::PasUnAppareil {
            obtenu: appareil.genre(),
        });
    }
    let mut corps = [0_u8; PREUVE_AUTHENTIFICATION_OCTETS];
    let genre = [appareil.genre().prefixe()];
    let source = genre
        .iter()
        .chain(appareil.octets().iter())
        .chain(signature.iter());
    for (place, octet) in corps.iter_mut().zip(source) {
        *place = *octet;
    }
    Ok(corps)
}
