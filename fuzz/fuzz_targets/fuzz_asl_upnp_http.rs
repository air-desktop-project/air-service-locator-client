//! **Cible : la réponse HTTP d'une box** — la description et les réponses
//! SOAP arrivent par là, d'un appareil que personne n'authentifie.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quels que soient les octets et l'endroit où la
//!    lecture s'arrête.
//! 2. **La borne tient** : un corps rendu ne dépasse jamais `REPONSE_MAX`.
//! 3. **Lire plus ne change pas une réponse déjà complète** : ce qu'on a rendu
//!    à mi-chemin (longueur dite, ou morceau nul reçu) est ce qu'on aurait
//!    rendu à la fin — sinon la lecture dépendrait du découpage des paquets
//!    TCP.

#![no_main]

use arbitrary::Arbitrary;
use asl_upnp::http::{self, Lu, REPONSE_MAX};
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct Entree {
    octets: Vec<u8>,
    coupure: u16,
}

fuzz_target!(|entree: Entree| {
    let coupure = usize::from(entree.coupure).min(entree.octets.len());
    let debut = &entree.octets[..coupure];
    let partielle = http::lire(debut, false);
    let finale = http::lire(&entree.octets, true);
    for lu in [&partielle, &finale] {
        if let Ok(Lu::Complet(reponse)) = lu {
            assert!(reponse.corps.len() <= REPONSE_MAX);
            assert!((100..=599).contains(&reponse.statut));
        }
    }
    if entree.octets.len() <= REPONSE_MAX
        && let Ok(Lu::Complet(avant)) = &partielle
    {
        assert_eq!(finale.as_ref().ok(), Some(&Lu::Complet(avant.clone())));
    }
});
