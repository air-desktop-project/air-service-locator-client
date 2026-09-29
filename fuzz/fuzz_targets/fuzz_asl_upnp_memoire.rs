//! **Cible : la mémoire de ce que l'écho a ouvert** — un fichier de son
//! répertoire d'état, relu au démarrage pour retirer ce qu'un arrêt brutal a
//! laissé sur la box. Un disque abîmé, une main qui l'a édité : c'est une
//! entrée comme une autre.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique.**
//! 2. **La borne tient** : jamais plus de `OUVERTURES_MAX` ouvertures.
//! 3. **Ce qui se relit se réécrit à l'identique** : écrire ce qu'on a lu,
//!    puis le relire, redonne la même chose.

#![no_main]

use asl_upnp::memoire::{self, OUVERTURES_MAX};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|octets: &[u8]| {
    if let Ok(ouvertures) = memoire::lire(octets) {
        assert!(ouvertures.len() <= OUVERTURES_MAX);
        let ecrite = memoire::ecrire(&ouvertures);
        assert_eq!(memoire::lire(ecrite.as_bytes()), Ok(ouvertures));
    }
});
