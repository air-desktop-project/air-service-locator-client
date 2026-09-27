//! **Cible : le renvoi vers un annuaire local** — n'importe quel corps de
//! `421`, puis n'importe quelle suite de renvois, de réussites et de tours.
//!
//! # Ce qu'elle protège
//!
//! Le corps d'un `421` arrive du réseau : un annuaire (ou quiconque répond à
//! sa place) choisit ses octets. Le lire ne doit jamais paniquer, et ce qu'on
//! en garde doit être ce qu'on a vérifié. Et l'aiguillage qui le suit ne doit
//! jamais devenir une boucle serrée.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quels que soient les octets.
//! 2. **Un renvoi lu est un renvoi vérifié** : un annuaire `n-…`, entre une et
//!    `ADRESSES_MAX` adresses, chacune `hôte:port` au port non nul — et
//!    **chaque adresse a exactement une identité d'annuaire** (décision 59) :
//!    celle que `identites` met à côté, ou le titulaire pour un corps d'avant.
//! 3. **Un seul saut** : un renvoi reçu du côté local ne compte pas.
//! 4. **Un retour aux racines depuis le local se paie** : jamais d'attente
//!    nulle à ce moment-là.

#![no_main]

use arbitrary::Arbitrary;
use asl_client::Reprise;
use asl_client::renvoi::{ADRESSES_MAX, Aiguillage, Cote, Renvoi, separer_l_adresse};
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
enum Evenement {
    Prochaine { alea: u16 },
    Renvoye,
    Reussite,
}

#[derive(Debug, Arbitrary)]
struct Entree {
    corps: Vec<u8>,
    racines: u8,
    locaux: u8,
    evenements: Vec<Evenement>,
}

fn liste(combien: u8, base: u8) -> Vec<SocketAddr> {
    (0..combien % 5)
        .map(|i| {
            let ip = if i % 2 == 0 {
                IpAddr::V6(Ipv6Addr::new(
                    0x2001,
                    0xdb8,
                    0,
                    0,
                    0,
                    0,
                    u16::from(base),
                    u16::from(i),
                ))
            } else {
                IpAddr::V4(Ipv4Addr::new(192, 0, base, i))
            };
            SocketAddr::new(ip, 6630)
        })
        .collect()
}

fuzz_target!(|entree: Entree| {
    if let Ok(renvoi) = Renvoi::lire(&entree.corps) {
        assert!(renvoi.annuaire().texte().as_str().starts_with("n-"));
        let adresses = renvoi.adresses();
        assert!(!adresses.is_empty() && adresses.len() <= ADRESSES_MAX);
        for adresse in adresses {
            let (_, port) = separer_l_adresse(adresse).expect("vérifiée à la lecture");
            assert_ne!(port, 0);
        }
        let membres: Vec<_> = renvoi.membres().collect();
        assert_eq!(membres.len(), adresses.len());
        for ((adresse, identite), attendue) in membres.iter().zip(adresses) {
            assert_eq!(adresse, attendue);
            assert!(identite.texte().as_str().starts_with("n-"));
            if !renvoi.nomme_chaque_membre() {
                assert_eq!(*identite, renvoi.annuaire());
            }
        }
    }

    let racines = liste(entree.racines, 1);
    let locaux = liste(entree.locaux, 2);
    let mut aiguillage = Aiguillage::nouveau(Reprise::nouvelle(15_000).expect("plafond non nul"));
    for evenement in entree.evenements.iter().take(256) {
        match evenement {
            Evenement::Prochaine { alea } => {
                let avant = aiguillage.cote();
                match aiguillage.prochaine(&racines, &locaux, *alea) {
                    None => assert!(racines.is_empty()),
                    Some(etape) => {
                        if avant == Cote::Local && etape.cote == Cote::Racines {
                            assert!(etape.attendre_ms > 0, "le retour aux racines se paie");
                        }
                        if etape.cote == Cote::Local {
                            assert!(etape.place < locaux.len());
                        } else {
                            assert!(etape.place < racines.len());
                        }
                    }
                }
            }
            Evenement::Renvoye => {
                let avant = (aiguillage.cote(), aiguillage.renvois());
                let suivi = aiguillage.renvoye();
                assert_eq!(suivi, avant.0 == Cote::Racines, "un seul saut");
                if !suivi {
                    assert_eq!(aiguillage.renvois(), avant.1);
                }
            }
            Evenement::Reussite => {
                aiguillage.reussite();
                assert_eq!(aiguillage.tours_perdus(), 0);
            }
        }
    }
});
