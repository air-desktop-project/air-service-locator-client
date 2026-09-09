//! **Cible : la politique de reprise** — n'importe quelle suite d'échecs, de
//! réussites et de bruits.
//!
//! # Ce qu'elle protège, et pourquoi ça compte autant
//!
//! Cette politique est **le mécanisme de haute disponibilité du produit** :
//! l'état vivant n'est pas répliqué entre les annuaires racines, et c'est la
//! reconnexion du client qui reconstruit tout. Si elle casse, ce n'est pas un
//! daemon qui se reconnecte mal — c'est la bascule qui n'a pas lieu.
//!
//! **Et une reprise mal bornée devient une attaque.** Un délai nul fait tourner
//! une boucle serrée ; un délai qui ne croît pas fait marteler l'annuaire par
//! mille daemons à la seconde où il se relève.
//!
//! # Les propriétés, vérifiées APRÈS CHAQUE ÉVÉNEMENT
//!
//! 1. **Rien ne panique**, y compris après des milliers d'échecs — là où un
//!    décalage non saturé rendrait un délai nul.
//! 2. **LE DÉLAI N'EST JAMAIS NUL.** C'est la boucle serrée qu'on évite.
//! 3. **IL NE DÉPASSE JAMAIS LE PLAFOND BRUITÉ.** Sinon un daemon attendrait
//!    plus longtemps que son propre keepalive, et son bail tomberait pendant
//!    qu'il patiente.
//! 4. **UNE RÉUSSITE REMET LE RECUL À ZÉRO** — sans quoi un daemon qui a connu
//!    une panne resterait lent pour toujours.
//! 5. **Le bruit reste dans ±20 %** du délai calculé.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asl_client::{BRUIT_CENTIEMES, RECUL_INITIAL_MS, Reprise};

/// Un événement de la vie d'une reprise.
#[derive(Arbitrary, Debug)]
enum Evenement {
    /// La connexion a échoué : on demande un délai.
    Echec {
        /// Le bruit.
        alea: u16,
    },
    /// La connexion a abouti.
    Reussite,
}

/// Ce qu'on soumet.
#[derive(Arbitrary, Debug)]
struct Entree {
    plafond_ms: u64,
    evenements: Vec<Evenement>,
}

fuzz_target!(|entree: Entree| {
    let Ok(mut reprise) = Reprise::nouvelle(entree.plafond_ms) else {
        // Le seul refus possible est un plafond nul.
        assert_eq!(entree.plafond_ms, 0);
        return;
    };
    assert_ne!(entree.plafond_ms, 0);

    let maximum = entree
        .plafond_ms
        .saturating_mul(100 + BRUIT_CENTIEMES)
        .saturating_div(100)
        .max(1);

    assert_eq!(reprise.essais(), 0);

    for evenement in &entree.evenements {
        match evenement {
            Evenement::Echec { alea } => {
                let avant = reprise.essais();
                let delai = reprise.prochain_delai(*alea);

                // PROPRIÉTÉ 2 : jamais nul.
                assert!(delai >= 1, "un délai nul : la boucle serrée est ouverte");

                // PROPRIÉTÉ 3 : jamais au-delà du plafond bruité.
                assert!(
                    delai <= maximum,
                    "délai {delai} au-delà du plafond bruité {maximum}"
                );

                // PROPRIÉTÉ 5 : le bruit reste dans ±20 % du délai calculé.
                let brut = RECUL_INITIAL_MS
                    .checked_shl(avant)
                    .unwrap_or(u64::MAX)
                    .min(entree.plafond_ms);
                let bas = brut.saturating_mul(100 - BRUIT_CENTIEMES) / 100;
                let haut = brut.saturating_mul(100 + BRUIT_CENTIEMES) / 100;
                assert!(
                    delai >= bas.max(1) && delai <= haut.max(1),
                    "délai {delai} hors de [{bas}, {haut}] pour un brut de {brut}"
                );

                // Le compteur avance, et il SATURE au lieu de déborder.
                assert!(reprise.essais() >= avant);
            }
            Evenement::Reussite => {
                reprise.reussite();
                // PROPRIÉTÉ 4 : le recul repart de zéro.
                assert_eq!(reprise.essais(), 0);

                // Et le délai suivant est celui du premier essai.
                let delai = reprise.prochain_delai(0);
                let premier = RECUL_INITIAL_MS.min(entree.plafond_ms);
                assert_eq!(
                    delai,
                    (premier.saturating_mul(100 - BRUIT_CENTIEMES) / 100).max(1),
                    "après une réussite, le recul ne repart pas du début"
                );
                reprise.reussite();
            }
        }
    }
});
