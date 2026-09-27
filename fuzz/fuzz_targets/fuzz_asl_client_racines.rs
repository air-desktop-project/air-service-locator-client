//! **Cible : la liste des racines** — n'importe quel corps de `GET
//! /v1/racines` (décision 56).
//!
//! # Ce qu'elle protège
//!
//! La liste arrive du réseau, d'une racine jointe par sa clé — mais c'est elle
//! qui dira où joindre les racines la prochaine fois. La juger ne doit jamais
//! paniquer, et une liste admise doit être une liste jugée.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quels que soient les octets.
//! 2. **Une liste admise n'est pas vide**, et chacune de ses racines est un
//!    annuaire `n-…` — la clé, elle, a été jugée par `lire_la_liste`
//!    (éprouvé par `asl-client/tests/racines.rs`, défaut réintroduit compris).
//! 3. **Le jugement est stable** : relire les mêmes octets rend le même verdict.

#![no_main]

use asl_client::racines::lire_la_liste;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|corps: &[u8]| {
    let premier = lire_la_liste(corps);
    if let Ok(liste) = &premier {
        let mut combien = 0_usize;
        for racine in liste.racines() {
            assert!(racine.annuaire.texte().as_str().starts_with("n-"));
            combien += 1;
        }
        assert!(combien > 0, "une liste admise n'est pas vide");
    }
    assert_eq!(premier.is_ok(), lire_la_liste(corps).is_ok());
});
