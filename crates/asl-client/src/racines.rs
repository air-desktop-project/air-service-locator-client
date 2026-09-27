//! Les racines embarquées, et la liste qu'une racine rend — l'ancre
//! (`annuaires.md` §2 quater, décisions 53 à 58, C20).
//!
//! # CE QUI EST ÉPINGLÉ, C'EST LA CLÉ
//!
//! Pour chaque racine : son identifiant `n-…`, **sa clé d'identité**, et des
//! locateurs. Un locateur ne fait rien croire : il dit où joindre ; la clé dit
//! qui l'on doit trouver au bout (`protocole.md` §0, « Qui l'on croit »).
//!
//! # AUCUN NOM PAR DÉFAUT (C20)
//!
//! Les locateurs de [`RACINES`] sont des **adresses littérales** : IPv6
//! d'abord, IPv4 ensuite. Aucun chemin par défaut ne passe par un résolveur —
//! ASL fonctionne sans DNS. Les noms des racines (`nitrogen.air-desktop.org`…)
//! restent des locateurs qu'un porteur peut écrire à la main ; ils ne sont pas
//! ici.
//!
//! # POURQUOI UNE COPIE DE LA LISTE DU SERVEUR
//!
//! La même liste vit dans `asl-loop-tokio::racines`, un étage 3 du serveur que
//! ce dépôt ne tire pas : il porterait sa boucle et son entrepôt dans un
//! client. La copie est gardée honnête par un essai — chaque clé doit se
//! déduire en l'identifiant écrit à côté —, et c'est une relevée du même banc
//! (`/etc/asl-server/identite.key.pub`, le 2026-09-27).

use asl_api::annuaire::ListeDeRacines;
use asl_cle::{CLE_PUBLIQUE_OCTETS, ClePublique, identifiant_de_racine};
use asl_id::{Genre, Identifiant};

/// Une racine, telle que le logiciel la connaît avant tout contact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RacineEmbarquee {
    /// Son identifiant, qui se déduit de la clé.
    pub identifiant: &'static str,
    /// Sa clé d'identité Ed25519.
    pub cle: [u8; CLE_PUBLIQUE_OCTETS],
    /// Où la joindre — des adresses littérales, IPv6 d'abord.
    pub locateurs: &'static [&'static str],
}

impl RacineEmbarquee {
    /// Son identifiant, lu.
    ///
    /// # Errors
    ///
    /// [`FauteDeListe::Mensonge`] si la clé ne se déduit pas en l'identifiant
    /// écrit à côté — ce qu'un essai interdit pour [`RACINES`].
    pub fn identite(&self) -> Result<Identifiant, FauteDeListe> {
        let dit = Identifiant::analyser_genre(Genre::Annuaire, self.identifiant)
            .map_err(|_| FauteDeListe::Mensonge)?;
        let cle = ClePublique::depuis_octets(self.cle).map_err(|_| FauteDeListe::Mensonge)?;
        if identifiant_de_racine(&cle) == dit {
            Ok(dit)
        } else {
            Err(FauteDeListe::Mensonge)
        }
    }
}

/// Les deux racines d'`air-desktop-project`.
pub const RACINES: [RacineEmbarquee; 2] = [
    RacineEmbarquee {
        identifiant: "n-0PWT8HZD80QMSPPDZ5CQXXYHQC",
        cle: [
            0x42, 0x9c, 0x70, 0xc6, 0x36, 0x51, 0xb4, 0xbb, 0x14, 0x3c, 0xac, 0xa6, 0x79, 0x60,
            0xff, 0x70, 0xee, 0xde, 0x5d, 0x8e, 0x41, 0x8a, 0x9d, 0x0b, 0xc2, 0xbe, 0x12, 0xe1,
            0x9a, 0xc6, 0xf5, 0xfd,
        ],
        locateurs: &["[2001:41d0:20a:900::1dd4]:6630", "178.32.16.250:6630"],
    },
    RacineEmbarquee {
        identifiant: "n-3K3P6H252W8K9370QG1YYTWBWB",
        cle: [
            0x75, 0xa0, 0x31, 0xae, 0x9f, 0xb9, 0xb6, 0x49, 0x36, 0x76, 0x29, 0x83, 0x72, 0x12,
            0x13, 0x22, 0xcc, 0x04, 0x37, 0x9e, 0x3b, 0x70, 0xd8, 0xd5, 0xf0, 0x11, 0xac, 0x61,
            0xf6, 0x8a, 0x8a, 0x8d,
        ],
        locateurs: &["[2001:41d0:20a:900::1d32]:6630", "178.32.16.249:6630"],
    },
];

/// Ce qu'une liste de racines peut avoir de travers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FauteDeListe {
    /// Le corps ne se lit pas comme `GET /v1/racines` le rend.
    Illisible,
    /// Une racine dont la clé ne se déduit pas en l'identifiant écrit à côté —
    /// ou qui n'est pas un point de la courbe.
    Mensonge,
}

impl core::fmt::Display for FauteDeListe {
    fn fmt(&self, sortie: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        sortie.write_str(match self {
            Self::Illisible => "la liste des racines ne se lit pas",
            Self::Mensonge => {
                "une racine de la liste ne porte pas la clé de son identifiant : liste refusée"
            }
        })
    }
}

/// Lit et **juge** une liste de `GET /v1/racines` (décision 56).
///
/// **Une seule racine dont la clé ne donne pas l'identifiant écrit à côté
/// refuse la liste entière** : c'est une liste fausse, et l'on ne trie pas
/// dans une liste fausse. Ce qui l'a servie a été jugé par la connexion,
/// vérifiée par clé : c'est elle qui signe.
///
/// # Errors
///
/// [`FauteDeListe::Illisible`], [`FauteDeListe::Mensonge`].
pub fn lire_la_liste(corps: &[u8]) -> Result<ListeDeRacines<'_>, FauteDeListe> {
    let liste = ListeDeRacines::decoder(corps).map_err(|_| FauteDeListe::Illisible)?;
    for racine in liste.racines() {
        let cle = ClePublique::depuis_octets(racine.cle).map_err(|_| FauteDeListe::Mensonge)?;
        if identifiant_de_racine(&cle) != racine.annuaire {
            return Err(FauteDeListe::Mensonge);
        }
    }
    Ok(liste)
}
