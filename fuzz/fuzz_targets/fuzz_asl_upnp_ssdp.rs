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
//!    locale — jamais un nom, jamais une adresse de l'Internet.
//! 3. **Une URL se relit comme elle s'écrit** : ce que l'écho retient d'une
//!    URL (sa forme écrite, dans sa mémoire) redonne la même URL.

#![no_main]

use arbitrary::Arbitrary;
use asl_upnp::{ssdp, url};
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct Entree {
    octets: Vec<u8>,
    source: [u8; 16],
    quatre: bool,
}

fuzz_target!(|entree: Entree| {
    let source = if entree.quatre {
        let [a, b, c, d, ..] = entree.source;
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    } else {
        IpAddr::V6(Ipv6Addr::from(entree.source))
    };
    if let Ok(location) = ssdp::passerelle(&entree.octets, source) {
        assert!(url::meme_hote(location.hote, source));
        assert!(url::locale(location.hote));
        assert!(location.chemin.starts_with('/'));
    }
    if let Ok(texte) = core::str::from_utf8(&entree.octets)
        && let Ok(lue) = url::lire(texte)
    {
        assert_eq!(url::lire(&lue.to_string()), Ok(lue));
    }
});
