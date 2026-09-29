//! **Cible : l'écho** — n'importe quelle suite de datagrammes, d'heures et de
//! sources présentée au répondeur d'`asl echo`, et n'importe quels octets
//! présentés au sondeur d'`asl ping`.
//!
//! # Ce qu'elle protège
//!
//! Tout ce qui arrive sur la socket de l'écho vient de n'importe qui : c'est
//! le port qu'un inconnu peut viser. Le lire ne doit jamais paniquer ; ce qui
//! en sort doit être une réponse de 132 octets ou rien ; et les états qui
//! bornent ce qu'un inconnu peut faire dépenser — le débit, la mémoire des
//! défis — ne doivent jamais laisser passer plus que leur borne.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quels que soient les octets, l'heure, la source.
//! 2. **Aucune amplification** : une réponse n'existe que pour un datagramme
//!    de 384 octets, et fait 132 octets.
//! 3. **Des octets quelconques ne font rien signer** : seule une sonde signée
//!    par l'annuaire du bail — composée ici — obtient une réponse, et cette
//!    réponse se vérifie sous la clé de la machine, pour cet annuaire.
//! 4. **Un défi ne sert qu'une fois** dans la fenêtre : la même sonde
//!    présentée deux fois à la même heure n'obtient pas deux réponses.
//! 5. **Le débit total tient** : jamais plus de cinquante réponses à la même
//!    milliseconde.
//! 6. **Le sondeur ne panique pas**, et ne conclut à la preuve que pour l'un
//!    de ses défis.

#![no_main]

use arbitrary::Arbitrary;
use asl_cle::{CleSecrete, identifiant_de_racine};
use asl_client::Identite;
use asl_client::echo::{Constat, DEBIT_TOTAL, Repondeur, constater};
use asl_echo::{DefiEcho, REPONSE_OCTETS, REQUETE_OCTETS, Reponse, SondeAnnuaire};
use asl_id::{Genre, Identifiant};
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
enum Evenement {
    /// Des octets quelconques, d'une source quelconque.
    Octets { octets: Vec<u8>, source: u16 },
    /// Une sonde authentique de l'annuaire du bail, datée à `decalage` de
    /// l'heure de la machine.
    Annuaire {
        defi: u8,
        decalage: i32,
        source: u16,
    },
    /// Le temps passe.
    Attendre { ms: u16 },
    /// Des octets présentés au sondeur.
    Constat {
        octets: Vec<u8>,
        defis: Vec<[u8; 16]>,
    },
}

fn source(n: u16) -> SocketAddr {
    let ip = if n % 3 == 0 {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, (n % 251) as u8))
    } else {
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, n, 0, 0, 0, 0, 1))
    };
    SocketAddr::new(ip, 40_000)
}

fuzz_target!(|evenements: Vec<Evenement>| {
    let annuaire = CleSecrete::depuis_entropie([0x11; 32]);
    let annuaire_id = identifiant_de_racine(&annuaire.publique());
    let moi = Identite::nouvelle(
        Identifiant::depuis_entropie(Genre::Machine, [0x70; 16]),
        [0x33; 32],
    )
    .expect("une machine");
    let mut repondeur = Repondeur::nouveau(&moi, 0x5EED);
    repondeur.tenir_le_bail(annuaire_id, annuaire.publique(), true);

    let mut maintenant: u64 = 1_789_217_751_000;
    let mut a_cette_milliseconde: (u64, u64) = (maintenant, 0);
    let mut repondues: Vec<[u8; 16]> = Vec::new();

    for evenement in evenements.iter().take(512) {
        match evenement {
            Evenement::Octets { octets, source: n } => {
                if let Ok(repondue) = repondeur.recevoir(&moi, octets, source(*n), maintenant) {
                    // Des octets quelconques ne portent pas une signature de
                    // l'annuaire — sauf à les avoir forgés, ce que rien ici ne
                    // sait faire. S'ils passent, ils sont au moins bornés.
                    assert_eq!(octets.len(), REQUETE_OCTETS);
                    assert_eq!(repondue.reponse.len(), REPONSE_OCTETS);
                }
            }
            Evenement::Annuaire {
                defi,
                decalage,
                source: n,
            } => {
                let emise_a = maintenant.saturating_add_signed(i64::from(*decalage));
                let sonde = SondeAnnuaire::signer(
                    DefiEcho::depuis_octets([*defi; 16]),
                    annuaire_id,
                    moi.machine(),
                    emise_a,
                    &annuaire,
                )
                .expect("les bons genres")
                .octets();
                if let Ok(repondue) = repondeur.recevoir(&moi, &sonde, source(*n), maintenant) {
                    let lue = Reponse::lire(&repondue.reponse).expect("elle se lit");
                    assert_eq!(
                        lue.verifier(
                            &DefiEcho::depuis_octets([*defi; 16]),
                            moi.machine(),
                            annuaire_id,
                            &moi.publique()
                        ),
                        Ok(())
                    );
                    // Un défi, une réponse, dans la fenêtre : le temps ne
                    // recule jamais ici, et il avance d'au plus 65 s par
                    // événement ; ce qui a déjà répondu à la même heure ne
                    // répond plus.
                    if a_cette_milliseconde.0 == maintenant {
                        assert!(!repondues.contains(&[*defi; 16]), "un rejeu a répondu");
                    }
                    if a_cette_milliseconde.0 != maintenant {
                        a_cette_milliseconde = (maintenant, 0);
                        repondues.clear();
                    }
                    a_cette_milliseconde.1 += 1;
                    assert!(
                        a_cette_milliseconde.1 <= DEBIT_TOTAL,
                        "le débit total est franchi"
                    );
                    repondues.push([*defi; 16]);
                }
            }
            Evenement::Attendre { ms } => {
                maintenant = maintenant.saturating_add(u64::from(*ms));
            }
            Evenement::Constat { octets, defis } => {
                let defis: Vec<DefiEcho> = defis
                    .iter()
                    .take(8)
                    .map(|d| DefiEcho::depuis_octets(*d))
                    .collect();
                if let Constat::Prouvee { rang, .. } =
                    constater(octets, &defis, moi.machine(), annuaire_id, &moi.publique())
                {
                    assert!(rang < defis.len());
                }
            }
        }
    }
});
