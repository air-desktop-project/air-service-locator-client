//! Les racines embarquées, en annuaires à joindre, et la liste qu'une racine
//! rend (`GET /v1/racines`, décision 56).
//!
//! # SANS RÉSOLVEUR (C20)
//!
//! [`racines_embarquees`] ne rend que des adresses littérales : aucun chemin
//! par défaut ne passe par le DNS. Un nom reste un locateur qu'un porteur peut
//! écrire ; ce n'est pas celui qu'on joint quand on ne dit rien. La liste
//! embarquée (`asl-racines`, partagée avec le serveur) porte aussi le nom de
//! chaque racine : il ne se lit pas comme une adresse, et il est donc sauté.

use std::net::SocketAddr;

use asl_client::racines::{RACINES, verifier_la_liste};
use asl_id::Identifiant;

use crate::{Annuaire, Connexion, Faute};

/// Les racines embarquées, en annuaires à joindre : chaque adresse de
/// chacune, avec l'identité qu'on doit trouver au bout.
///
/// **IPv6 D'ABORD, POUR TOUTES** : les adresses IPv6 des deux racines, puis
/// leurs adresses IPv4 — `modele.md` §1, et c'est ce que la tournée attend.
#[must_use]
pub fn racines_embarquees() -> Vec<Annuaire> {
    let mut toutes: Vec<Annuaire> = RACINES
        .iter()
        // **LA CLÉ DOIT DONNER L'IDENTIFIANT ÉCRIT À CÔTÉ** : une racine
        // embarquée de travers ne se joint pas — elle ne se croirait pas.
        .filter_map(|racine| {
            let identite = racine.identite()?;
            let cle = racine.cle_publique()?;
            (asl_cle::identifiant_de_racine(&cle) == identite).then_some((racine, identite))
        })
        .flat_map(|(racine, identite)| {
            racine.locateurs.iter().filter_map(move |texte| {
                texte.parse::<SocketAddr>().ok().map(|adresse| Annuaire {
                    adresse,
                    nom: adresse.ip().to_string(),
                    identite: Some(identite),
                })
            })
        })
        .collect();
    // Un tri stable garde l'ordre des racines à l'intérieur d'une famille.
    toutes.sort_by_key(|annuaire| annuaire.adresse.is_ipv4());
    toutes
}

/// Une racine apprise d'une liste, **vérifiée** : sa clé se déduit en son
/// identifiant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RacineApprise {
    /// Son identité.
    pub identifiant: Identifiant,
    /// Sa clé d'identité.
    pub cle: [u8; 32],
    /// Où la joindre — sans valeur de confiance.
    pub locateurs: Vec<String>,
}

/// Demande `GET /v1/racines` à la racine au bout de cette connexion, et rend
/// la liste **vérifiée** (décision 56).
///
/// La connexion a déjà été jugée — c'est elle, vérifiée par la clé de la
/// racine jointe, qui signe la liste ; ce qui reste à juger est la liste
/// elle-même : **une seule clé fausse la refuse entière**.
///
/// # Errors
///
/// Celles de la requête ; [`Faute::Statut`] pour autre chose que `200` ;
/// [`Faute::Illisible`] pour une liste qui ne se lit pas ou qui ment.
pub async fn apprendre_les_racines(connexion: &mut Connexion) -> Result<Vec<RacineApprise>, Faute> {
    let reponse = connexion.requete(b"GET", b"/v1/racines", &[], b"").await?;
    reponse.exige(200)?;
    lire_les_racines(&reponse.corps)
}

/// La liste lue et jugée, en racines apprises.
///
/// # Errors
///
/// [`Faute::Illisible`].
fn lire_les_racines(corps: &[u8]) -> Result<Vec<RacineApprise>, Faute> {
    let liste = verifier_la_liste(corps).map_err(|_| Faute::Illisible)?;
    Ok(liste
        .racines()
        .map(|racine| RacineApprise {
            identifiant: racine.annuaire,
            cle: racine.cle,
            locateurs: racine
                .locateurs()
                .iter()
                .map(|&texte| texte.to_owned())
                .collect(),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::{lire_les_racines, racines_embarquees};

    #[test]
    fn les_racines_embarquees_sont_des_adresses_ipv6_d_abord_et_identifiees() {
        let toutes = racines_embarquees();
        assert_eq!(toutes.len(), 4);
        assert!(toutes[0].adresse.is_ipv6() && toutes[1].adresse.is_ipv6());
        assert!(toutes[2].adresse.is_ipv4() && toutes[3].adresse.is_ipv4());
        assert!(toutes.iter().all(|annuaire| annuaire.identite.is_some()));
        assert_ne!(toutes[0].identite, toutes[1].identite);
    }

    #[test]
    fn une_liste_de_travers_est_illisible() {
        assert!(matches!(
            lire_les_racines(b"pas une liste"),
            Err(crate::Faute::Illisible)
        ));
    }
}
