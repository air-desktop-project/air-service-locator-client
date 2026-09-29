//! **Cible : le XML d'une box** — sa description, ses réponses SOAP.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, ni dans le lecteur, ni dans les deux lecteurs qui
//!    s'appuient sur lui (la description, SOAP).
//! 2. **Les bornes tiennent** : jamais plus de `PROFONDEUR_MAX` niveaux
//!    ouverts, jamais plus de `SERVICES_MAX` services ni de `VALEURS_MAX`
//!    valeurs.
//! 3. **Un document lu jusqu'au bout est équilibré** : autant de fermetures
//!    que d'ouvertures, chacune dans l'ordre.
//! 4. **Le choix ne sort jamais de l'hôte de la description.**

#![no_main]

use asl_upnp::description::{self, SERVICES_MAX};
use asl_upnp::soap::{self, Retour, VALEURS_MAX};
use asl_upnp::url;
use asl_upnp::xml::{Evenement, Lecteur, PROFONDEUR_MAX};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|octets: &[u8]| {
    if let Ok(mut lecteur) = Lecteur::nouveau(octets) {
        let mut pile = Vec::new();
        loop {
            match lecteur.suivant() {
                Ok(Some(Evenement::Ouvre(nom))) => {
                    pile.push(nom);
                    assert!(pile.len() <= PROFONDEUR_MAX);
                }
                Ok(Some(Evenement::Ferme(nom))) => assert_eq!(pile.pop(), Some(nom)),
                Ok(Some(Evenement::Texte(texte))) => assert!(!texte.trim().is_empty()),
                Ok(None) => {
                    assert!(pile.is_empty());
                    break;
                }
                Err(_) => break,
            }
        }
    }
    if let Ok(lue) = description::lire(octets) {
        assert!(lue.services.len() <= SERVICES_MAX);
        let location = url::lire("http://192.168.1.1:5000/d/root.xml").unwrap();
        let choix = description::choisir(&lue, &location);
        for choisie in choix
            .connexion
            .iter()
            .map(|(u, _)| u)
            .chain(choix.pare_feu.iter())
        {
            assert_eq!(choisie.hote, location.hote);
        }
    }
    if let Ok(Retour::Reussi(valeurs)) = soap::lire(octets, "AddAnyPortMapping") {
        assert!(valeurs.len() <= VALEURS_MAX);
    }
});
