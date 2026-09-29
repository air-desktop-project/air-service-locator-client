//! **Cible : la réponse SSDP** — n'importe quels octets, venus de n'importe
//! quelle adresse, présentés comme la réponse d'une box à un `M-SEARCH`.
//!
//! # Ce qu'elle protège
//!
//! Tout appareil du réseau local peut répondre au `M-SEARCH`, ou se faire
//! passer pour la box : UPnP n'authentifie rien. Lire sa réponse ne doit
//! jamais paniquer, et ce qui en sort doit tenir la règle de C20.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique.**
//! 2. **Une URL suivie désigne l'adresse qui a répondu**, littérale et
//!    locale — jamais un nom, jamais une adresse de l'Internet ; **ou**, la
//!    source étant de lien local IPv6, une adresse unicast de l'un des
//!    préfixes passés (nos liens), qui n'est pas l'une des nôtres.
//! 3. **Une URL se relit comme elle s'écrit** : ce que l'écho retient d'une
//!    URL (sa forme écrite, dans sa mémoire) redonne la même URL.

#![no_main]

use arbitrary::Arbitrary;
use asl_upnp::ssdp::Admission;
use asl_upnp::{ssdp, url};
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct Entree {
    octets: Vec<u8>,
    source: [u8; 16],
    quatre: bool,
    /// Nos adresses de lien, et leur longueur de préfixe — quelconques.
    liens: Vec<([u8; 16], u8)>,
    /// Une source de lien local, pour atteindre la seconde règle.
    lien_local: bool,
}

fuzz_target!(|entree: Entree| {
    let source = if entree.quatre {
        let [a, b, c, d, ..] = entree.source;
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    } else {
        IpAddr::V6(Ipv6Addr::from(entree.source))
    };
    let source = match source {
        IpAddr::V6(v6) if entree.lien_local => IpAddr::V6(Ipv6Addr::from(
            v6.to_bits() & u128::from(u64::MAX) | (0xfe80_u128 << 112),
        )),
        autre => autre,
    };
    let liens: Vec<(Ipv6Addr, u8)> = entree
        .liens
        .iter()
        .take(8)
        .map(|(adresse, longueur)| (Ipv6Addr::from(*adresse), *longueur))
        .collect();
    match ssdp::passerelle(&entree.octets, source, &liens) {
        Ok((location, Admission::MemeHote)) => {
            assert!(url::meme_hote(location.hote, source));
            assert!(url::locale(location.hote));
            assert!(location.chemin.starts_with('/'));
        }
        Ok((location, Admission::SurLeLien { lien, .. })) => {
            let (IpAddr::V6(source), IpAddr::V6(hote)) = (source, location.hote) else {
                panic!("le lien local ne vaut qu'en IPv6");
            };
            assert!(source.is_unicast_link_local());
            assert!(!hote.is_unicast_link_local() && !hote.is_loopback());
            assert!(!hote.is_multicast() && !hote.is_unspecified());
            assert!(liens.contains(&lien));
            assert!(liens.iter().all(|(notre, _)| *notre != hote));
            let (notre, longueur) = lien;
            assert!((1..=128).contains(&longueur));
            let masque = u128::MAX << (128 - u32::from(longueur));
            assert_eq!(notre.to_bits() & masque, hote.to_bits() & masque);
            assert!(location.chemin.starts_with('/'));
        }
        Err(_) => {}
    }
    if let Ok(texte) = core::str::from_utf8(&entree.octets)
        && let Ok(lue) = url::lire(texte)
    {
        assert_eq!(url::lire(&lue.to_string()), Ok(lue));
    }
});
