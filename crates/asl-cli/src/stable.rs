//! **L'adresse IPv6 STABLE de cette machine** (`protocole.md` §3 quater,
//! « L'écho se lie à l'adresse IPv6 STABLE », décision 108).
//!
//! # POURQUOI CE MODULE EXISTE
//!
//! Liée à `[::]`, la socket de l'écho laisse **le système** choisir son
//! adresse source — et, là où les adresses temporaires tournent (RFC 8981 ;
//! macOS par défaut, Linux souvent), c'est **une adresse qui aura disparu
//! demain**. L'écho s'en remettait au trou UPnP, qu'il redemande à chaque
//! tour pour l'adresse du moment ; mais **une box qui refuse UPnP** — la
//! Livebox d'oxygen : `AddPinhole` → `606`, et une liste fermée
//! d'équipements où elle propose une ancienne adresse temporaire dépréciée —
//! **n'a qu'une règle posée à la main**, et personne pour la redemander. Liée
//! à l'adresse stable, l'écho ne bouge plus.
//!
//! **Le revers est assumé** (Thierry, 2026-09-30, en connaissance) : une
//! adresse stable suit la machine sur l'Internet et permet de la reconnaître
//! d'un site à l'autre. La portée est bornée à la socket de `asl echo`.
//!
//! # CE QUI EST PUR, ET CE QUI LIT LE SYSTÈME
//!
//! [`choisir`] ne fait aucune entrée-sortie : on lui donne la table du
//! système et l'adresse source que le noyau prendrait pour l'annuaire, elle
//! rend l'adresse à laquelle se lier. [`table`] est la seule lecture, et elle
//! n'existe que sous Linux.

use std::net::Ipv6Addr;

/// `IFA_F_TEMPORARY` : l'adresse qui tourne (RFC 8981) — celle qu'on fuit.
const TEMPORAIRE: u32 = 0x01;

/// `IFA_F_DADFAILED` : le réseau a dit qu'elle est à un autre.
const DAD_ECHOUEE: u32 = 0x08;

/// `IFA_F_DEPRECATED` : elle ne sert plus qu'aux connexions en cours.
const DEPRECIEE: u32 = 0x20;

/// `IFA_F_TENTATIVE` : le réseau n'a pas encore dit qu'elle est à nous.
const PROVISOIRE: u32 = 0x40;

/// Les drapeaux qui écartent une adresse.
const ECARTEE: u32 = TEMPORAIRE | DAD_ECHOUEE | DEPRECIEE | PROVISOIRE;

/// Ce que le système dit de ses adresses IPv6, ou rien quand il ne le dit
/// pas — **`/proc/net/if_inet6` sous Linux, et lui seul**.
///
/// # AILLEURS, IL N'Y A PAS DE MOYEN SANS C (C4)
///
/// Sous macOS, les drapeaux d'une adresse se lisent par `getifaddrs` puis
/// l'ioctl `SIOCGIFAFLAG_IN6` (`IN6_IFF_TEMPORARY`, `IN6_IFF_DEPRECATED`) :
/// du C, donc de l'`unsafe`, qu'aucune crate du graphe n'enveloppe et que ce
/// dépôt refuse (`#![forbid(unsafe_code)]`). Analyser la sortie d'`ifconfig`
/// serait un programme tiers dont on lirait le texte — la voie déjà écartée
/// pour la table de routage (`crate::passerelle`, `interfaces_du_lien`).
/// **Donc : ailleurs, l'écho garde le choix du système, et le dit.**
#[must_use]
pub fn table() -> Option<String> {
    if cfg!(target_os = "linux") {
        std::fs::read_to_string("/proc/net/if_inet6").ok()
    } else {
        None
    }
}

/// Une ligne de la table : l'adresse, l'index de son interface, ses drapeaux.
fn ligne(texte: &str) -> Option<(Ipv6Addr, u32, u32)> {
    let mut champs = texte.split_whitespace();
    let hexa = champs.next()?;
    let index = u32::from_str_radix(champs.next()?, 16).ok()?;
    // La longueur du préfixe et la portée ne servent pas ici : la portée que
    // nous voulons se juge sur l'adresse elle-même, comme partout ailleurs
    // dans ce dépôt.
    let _prefixe = champs.next()?;
    let _portee = champs.next()?;
    let drapeaux = u32::from_str_radix(champs.next()?, 16).ok()?;
    if hexa.len() != 32 {
        return None;
    }
    let mut octets = [0_u8; 16];
    // Deux chiffres hexadécimaux par octet : on coupe la chaîne en paires.
    // `as_bytes().chunks(2)` plutôt qu'une arithmétique d'indices — la borne
    // est celle de la chaîne, et il n'y a rien à calculer.
    for (place, paire) in octets.iter_mut().zip(hexa.as_bytes().chunks(2)) {
        let paire = core::str::from_utf8(paire).ok()?;
        *place = u8::from_str_radix(paire, 16).ok()?;
    }
    Some((Ipv6Addr::from(octets), index, drapeaux))
}

/// Cette adresse est-elle **globale** au sens qui nous intéresse : le dehors
/// peut-il la joindre ?
///
/// **Une ULA (`fc00::/7`) ne l'est pas** : elle est stable, mais elle ne sort
/// pas de la maison — l'annuaire ne la verrait pas, aucune sonde du dehors ne
/// l'atteindrait, et le pare-feu de la box n'a rien à y ouvrir.
#[must_use]
pub fn globale(adresse: Ipv6Addr) -> bool {
    let ula = (adresse.segments().first().copied().unwrap_or(0) & 0xfe00) == 0xfc00;
    !ula && !adresse.is_unicast_link_local()
        && !adresse.is_loopback()
        && !adresse.is_unspecified()
        && !adresse.is_multicast()
        && adresse.to_ipv4_mapped().is_none()
}

/// **L'ADRESSE À LAQUELLE SE LIER**, ou rien.
///
/// `source` est l'adresse que le noyau prendrait pour joindre l'annuaire :
/// c'est elle qui désigne **l'interface qui sert le bail**, et l'on ne choisit
/// que parmi les adresses de cette interface — se lier ailleurs serait se lier
/// là où la route ne passe pas.
///
/// Rendue : la plus petite, **dans l'ordre de ses seize octets**, des adresses
/// de cette interface qui sont globales et stables — ni temporaire, ni
/// dépréciée, ni provisoire, ni en échec de DAD. Un redémarrage reprend donc
/// la même tant que le préfixe tient.
///
/// **Rien** quand la table ne dit pas l'interface de `source`, quand cette
/// interface n'a aucune adresse stable et globale, ou quand il n'y a pas de
/// table : l'appelant garde alors le choix du système, et le dit.
#[must_use]
pub fn choisir(table: Option<&str>, source: Ipv6Addr) -> Option<Ipv6Addr> {
    let table = table?;
    let lues: Vec<(Ipv6Addr, u32, u32)> = table.lines().filter_map(ligne).collect();
    // L'interface de la source. Si la source est elle-même absente de la
    // table — une adresse qui vient de tomber —, on ne devine pas.
    let interface = lues
        .iter()
        .find(|(adresse, _, _)| *adresse == source)
        .map(|(_, index, _)| *index)?;
    lues.iter()
        .filter(|(adresse, index, drapeaux)| {
            *index == interface && drapeaux & ECARTEE == 0 && globale(*adresse)
        })
        .map(|(adresse, _, _)| *adresse)
        .min_by_key(Ipv6Addr::octets)
}

#[cfg(test)]
mod tests {
    use super::{choisir, globale, ligne};
    use std::net::Ipv6Addr;

    /// La table d'oxygen, telle que Linux l'écrirait : `en5` (index 2) porte
    /// la stable retenue, une seconde stable plus grande, la temporaire du
    /// moment, une temporaire dépréciée — celle que la Livebox propose —, une
    /// provisoire, une ULA et son lien local ; `eth1` (index 3) porte une
    /// autre stable, sur une autre interface.
    const OXYGEN: &str = "\
2a01cb190d272f00144bb44159016706 02 40 00 80 en5
2a01cb190d272f00f00dbeefcafe0001 02 40 00 80 en5
2a01cb190d272f00157edb0b296af355 02 40 00 01 en5
2a01cb190d272f0000000000dead0001 02 40 00 21 en5
2a01cb190d272f0000000000beef0002 02 40 00 40 en5
fd00000000000000000000000000000a 02 40 00 80 en5
fe80000000000000144bb44159016706 02 40 20 80 en5
2001067c1562aaaa0000000000000001 03 40 00 80 eth1
";

    fn a(texte: &str) -> Ipv6Addr {
        texte.parse().unwrap()
    }

    #[test]
    fn la_stable_de_l_interface_du_bail_est_retenue() {
        // La source est la temporaire du moment : on remonte à son interface,
        // et l'on prend la plus petite stable globale de CETTE interface.
        let source = a("2a01:cb19:d27:2f00:157e:db0b:296a:f355");
        assert_eq!(
            choisir(Some(OXYGEN), source),
            Some(a("2a01:cb19:d27:2f00:144b:b441:5901:6706")),
            "la stable d'oxygen, et non la seconde ni l'ULA"
        );
        // Depuis la stable elle-même : la même réponse, rien ne change.
        assert_eq!(
            choisir(Some(OXYGEN), a("2a01:cb19:d27:2f00:144b:b441:5901:6706")),
            Some(a("2a01:cb19:d27:2f00:144b:b441:5901:6706"))
        );
        // Sur l'autre interface, c'est son adresse à elle.
        assert_eq!(
            choisir(Some(OXYGEN), a("2001:67c:1562:aaaa::1")),
            Some(a("2001:67c:1562:aaaa::1"))
        );
    }

    #[test]
    fn sans_table_sans_source_connue_ou_sans_stable_on_ne_choisit_rien() {
        let source = a("2a01:cb19:d27:2f00:157e:db0b:296a:f355");
        // Pas de table : macOS, ou un `/proc` qu'on ne lit pas.
        assert_eq!(choisir(None, source), None);
        // Une source que la table ne connaît pas : on ne devine pas
        // l'interface.
        assert_eq!(choisir(Some(OXYGEN), a("2001:db8::1")), None);
        // Une interface dont toutes les adresses sont écartées : temporaire,
        // dépréciée, provisoire, DAD en échec — et une ULA, stable mais
        // enfermée.
        let sans_stable = "\
2a01cb190d272f00157edb0b296af355 05 40 00 01 en9
2a01cb190d272f0000000000dead0001 05 40 00 21 en9
2a01cb190d272f0000000000beef0002 05 40 00 40 en9
2a01cb190d272f0000000000beef0003 05 40 00 08 en9
fd00000000000000000000000000000a 05 40 00 80 en9
fe80000000000000144bb44159016706 05 40 20 80 en9
";
        assert_eq!(
            choisir(
                Some(sans_stable),
                a("2a01:cb19:d27:2f00:157e:db0b:296a:f355")
            ),
            None
        );
    }

    #[test]
    fn une_ligne_de_travers_ne_fait_rien_conclure() {
        for tordue in [
            "",
            "pas une ligne",
            // L'adresse trop courte, puis pas de l'hexadécimal.
            "2a01cb19 02 40 00 80 en5",
            "2a01cb190d272f00144bb441590167zz 02 40 00 80 en5",
            // L'index, la longueur, la portée, les drapeaux manquants.
            "2a01cb190d272f00144bb44159016706",
            "2a01cb190d272f00144bb44159016706 02",
            "2a01cb190d272f00144bb44159016706 02 40",
            "2a01cb190d272f00144bb44159016706 02 40 00",
            "2a01cb190d272f00144bb44159016706 zz 40 00 80 en5",
            "2a01cb190d272f00144bb44159016706 02 40 00 zz en5",
        ] {
            assert_eq!(ligne(tordue), None, "« {tordue} »");
        }
        let (adresse, index, drapeaux) =
            ligne("2a01cb190d272f00144bb44159016706 02 40 00 80 en5").expect("elle se lit");
        assert_eq!(adresse, a("2a01:cb19:d27:2f00:144b:b441:5901:6706"));
        assert_eq!((index, drapeaux), (2, 0x80));
    }

    #[test]
    fn ce_qui_est_global_et_ce_qui_ne_l_est_pas() {
        assert!(globale(a("2a01:cb19:d27:2f00::1")));
        assert!(globale(a("2001:db8::1")), "la documentation est globale");
        for enfermee in [
            "fd00::a",          // ULA
            "fc00::1",          // ULA, l'autre moitié du /7
            "fe80::1",          // lien local
            "::1",              // boucle
            "::",               // indéterminée
            "ff02::c",          // multicast
            "::ffff:192.0.2.7", // IPv4 enfouie
        ] {
            assert!(!globale(a(enfermee)), "{enfermee}");
        }
    }
}
