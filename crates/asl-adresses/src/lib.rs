//! **LES ADRESSES IPv6 DE CETTE MACHINE, ET CE QUE LE SYSTÈME EN DIT**
//! (`protocole.md` §3 quater, « L'écho se lie à l'adresse IPv6 STABLE »,
//! décision 108).
//!
//! # POURQUOI CETTE CRATE EXISTE, À PART
//!
//! `asl echo` doit se lier à une adresse qui **ne tourne pas** : liée à
//! `[::]`, sa socket laisse le système choisir sa source, et là où les
//! adresses temporaires tournent (RFC 8981 ; macOS par défaut, Linux
//! souvent), c'est une adresse qui aura disparu demain — une règle posée à la
//! main dans une box qui refuse UPnP meurt avec elle.
//!
//! Savoir laquelle est stable demande de **demander au système**, et sous
//! macOS cela demande deux appels que Rust ne sait pas faire sans `unsafe`.
//! **Cette crate est le seul endroit du dépôt où `unsafe` est permis** : elle
//! ne fait que cela, ses appels sont comptés et commentés un par un, et tout
//! ce qui DÉCIDE ([`choisir`], [`globale`], [`lire_la_table`]) reste pur et
//! éprouvé sur des tables figées. **`asl-cli`, `asl-upnp`, `asl-client` et
//! `asl-client-tokio` portent `#![forbid(unsafe_code)]`** et le gardent ; les
//! deux façades d'ABI (`asl-client-ffi`, `asl-client-android`) en contiennent
//! par nature — ce sont des frontières C et JNI, ce que dit leur en-tête.
//!
//! # CE QU'ELLE NE FAIT PAS
//!
//! Elle ne choisit pas d'interface, ne joint personne, n'ouvre aucune socket
//! durable : elle **lit**, et rend ce qu'elle a lu. Qui s'en sert décide.
//!
//! # PAR SYSTÈME
//!
//! - **Linux** : `/proc/net/if_inet6`, sans un `unsafe` — une ligne par
//!   adresse, avec ses drapeaux (`IFA_F_TEMPORARY` et les autres).
//! - **macOS** : `getifaddrs`, puis **un `ioctl(SIOCGIFAFLAG_IN6)` par
//!   adresse** sur une socket `AF_INET6` — il n'y a pas de `/proc`, et c'est
//!   la seule façon d'apprendre qu'une adresse est temporaire ou dépréciée.
//! - **Ailleurs** : rien, et l'appelant garde le choix du système.

#![deny(unsafe_op_in_unsafe_fn)]

use std::net::Ipv6Addr;

// ── Ce que le système dit d'une adresse ─────────────────────────────────────

/// Ce que le système dit d'une adresse IPv6, **normalisé**.
///
/// # LES DRAPEAUX NE PORTENT PAS LES MÊMES NOMBRES D'UN SYSTÈME À L'AUTRE
///
/// **C'est le piège de ce module**, et il a mordu (0.27.0, relevé sur oxygen
/// le 2026-09-30) : sous Linux `IFA_F_TEMPORARY` vaut `0x01` et
/// `IFA_F_DEPRECATED` `0x20` ; sous macOS, `0x01` est `IN6_IFF_ANYCAST` et
/// `0x20` est `IN6_IFF_NODAD`, la temporaire étant `0x80` et la dépréciée
/// `0x10`. Une valeur d'un système employée sur l'autre ne rend pas une
/// erreur : elle rend un **mensonge plausible**. D'où cette structure, où
/// plus aucun nombre ne circule, et deux lectures séparées
/// ([`etat_linux`], [`etat_macos`]) dont les constantes sont, sur macOS,
/// **vérifiées à la compilation contre celles de `libc`**.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Etat {
    /// Elle tourne (RFC 8981 ; `IFA_F_TEMPORARY`, `IN6_IFF_TEMPORARY`) —
    /// c'est celle qu'on fuit.
    pub temporaire: bool,
    /// Elle ne sert plus qu'aux connexions en cours, et disparaîtra
    /// (`IFA_F_DEPRECATED`, `IN6_IFF_DEPRECATED`).
    pub depreciee: bool,
    /// Le réseau n'a pas encore dit qu'elle est à nous (`IFA_F_TENTATIVE`,
    /// `IN6_IFF_TENTATIVE`).
    pub provisoire: bool,
    /// Le réseau a dit qu'elle est à un autre, ou son lien est détaché
    /// (`IFA_F_DADFAILED` ; `IN6_IFF_DUPLICATED`, `IN6_IFF_DETACHED`).
    pub douteuse: bool,
    /// **Stabilisée au sens de RFC 7217** (`IN6_IFF_SECURED`) — macOS le dit,
    /// et l'on s'en sert pour DÉPARTAGER. **Linux n'a pas ce drapeau** : sa
    /// stable ne porte aucun drapeau du tout, et `securisee` y est donc
    /// toujours faux. « Préférer » ne doit jamais devenir « exiger », sans
    /// quoi Linux n'aurait plus aucune candidate.
    pub securisee: bool,
    /// **LE SYSTÈME A-T-IL DIT CES DRAPEAUX ?**
    ///
    /// Faux quand on n'a rien pu lui demander — pas de `/proc`, un `ioctl`
    /// refusé, un système qui ne les expose pas : l'adresse n'est alors **pas
    /// candidate**, et l'appelant garde le choix du système (`[::]`), qu'il
    /// journalise. **C'était le défaut de la 0.27.0** : un état « tout à
    /// faux » passait pour stable, et l'on se liait à la plus petite adresse
    /// de l'interface — sur oxygen, une temporaire DÉPRÉCIÉE. Mieux vaut le
    /// repli qu'une mauvaise adresse.
    pub connu: bool,
}

impl Etat {
    /// Ce qu'on sait d'une adresse dont le système n'a rien dit : rien.
    pub const INCONNU: Self = Self {
        temporaire: false,
        depreciee: false,
        provisoire: false,
        douteuse: false,
        securisee: false,
        connu: false,
    };

    /// **Peut-on s'y lier pour durer ?** Il faut que le système ait parlé, et
    /// qu'il n'ait dit ni temporaire, ni dépréciée, ni provisoire, ni
    /// douteuse. La façon dont l'adresse a été formée ne compte pas : une
    /// adresse stabilisée par RFC 7217 et une adresse posée à la main sont
    /// stables toutes les deux — `securisee` ne sert qu'à départager.
    #[must_use]
    pub const fn stable(&self) -> bool {
        self.connu && !self.temporaire && !self.depreciee && !self.provisoire && !self.douteuse
    }
}

/// Une adresse IPv6 de cette machine, telle que le système la déclare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Adresse {
    /// L'adresse.
    pub adresse: Ipv6Addr,
    /// L'interface qui la porte, **par son nom** : c'est ce que les deux
    /// systèmes donnent sans rien appeler de plus (`/proc` l'écrit en fin de
    /// ligne, `getifaddrs` le rend dans `ifa_name`).
    pub interface: String,
    /// Ce que le système en dit.
    pub etat: Etat,
}

// ── Ce qui décide, et ne lit rien ───────────────────────────────────────────

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
/// **Les candidates sont les adresses globales et stables de CETTE
/// interface** — une machine en a plusieurs qui portent une globale (helium
/// en a deux), et se lier sur celle où la route ne passe pas ne servirait à
/// rien. Parmi elles :
///
/// 1. **celles que le système dit stabilisées** (RFC 7217, `IN6_IFF_SECURED`)
///    d'abord, s'il y en a — c'est macOS qui le dit, et c'est exactement
///    l'adresse que son `ifconfig` marque « secured » ;
/// 2. **à défaut, toutes** : sous Linux, la stable ne porte aucun drapeau, et
///    exiger « secured » n'y laisserait aucune candidate ;
/// 3. puis **la plus petite, dans l'ordre de ses seize octets** — un
///    redémarrage reprend la même tant que le préfixe tient, et deux
///    exploitants qui regardent la même machine y trouvent la même réponse.
///
/// **Rien** quand la liste ne dit pas l'interface de `source`, ou quand cette
/// interface n'a aucune candidate — y compris parce que le système n'a rien
/// dit de ses drapeaux ([`Etat::connu`]) : l'appelant garde alors le choix du
/// système, et le dit. **Le repli vaut mieux qu'une mauvaise adresse.**
#[must_use]
pub fn choisir(adresses: &[Adresse], source: Ipv6Addr) -> Option<Ipv6Addr> {
    // L'interface de la source. Si la source est absente de la liste — une
    // adresse qui vient de tomber —, on ne devine pas.
    let interface = adresses
        .iter()
        .find(|lue| lue.adresse == source)
        .map(|lue| lue.interface.as_str())?;
    let candidates = || {
        adresses
            .iter()
            .filter(|lue| lue.interface == interface && lue.etat.stable() && globale(lue.adresse))
    };
    let securisees = candidates().filter(|lue| lue.etat.securisee);
    let plus_petite = |suite: &mut dyn Iterator<Item = &Adresse>| {
        suite.map(|lue| lue.adresse).min_by_key(Ipv6Addr::octets)
    };
    plus_petite(&mut { securisees }).or_else(|| plus_petite(&mut candidates()))
}

// ── Linux : `/proc/net/if_inet6` ────────────────────────────────────────────

/// `IFA_F_TEMPORARY`.
const LINUX_TEMPORAIRE: u32 = 0x01;
/// `IFA_F_DADFAILED`.
const LINUX_DAD_ECHOUEE: u32 = 0x08;
/// `IFA_F_DEPRECATED`.
const LINUX_DEPRECIEE: u32 = 0x20;
/// `IFA_F_TENTATIVE`.
const LINUX_PROVISOIRE: u32 = 0x40;

/// **LIT UNE TABLE `/proc/net/if_inet6`** — pure, et c'est elle qu'on éprouve
/// sur des tables figées.
///
/// Une ligne par adresse : l'adresse en trente-deux chiffres hexadécimaux,
/// l'index de l'interface, la longueur du préfixe, la portée, **les
/// drapeaux**, et le nom du périphérique. Une ligne de travers ne fait rien
/// conclure : elle est sautée.
#[must_use]
pub fn lire_la_table(texte: &str) -> Vec<Adresse> {
    texte.lines().filter_map(ligne_de_table).collect()
}

/// Une ligne de `/proc/net/if_inet6`, ou rien.
fn ligne_de_table(texte: &str) -> Option<Adresse> {
    let mut champs = texte.split_whitespace();
    let hexa = champs.next()?;
    // L'index de l'interface, la longueur du préfixe et la portée ne servent
    // pas : c'est le NOM qui désigne l'interface ici — `getifaddrs` ne donne
    // que lui —, et la portée se juge sur l'adresse ([`globale`]).
    let (_index, _prefixe, _portee) = (champs.next()?, champs.next()?, champs.next()?);
    let drapeaux = u32::from_str_radix(champs.next()?, 16).ok()?;
    let interface = champs.next()?;
    if hexa.len() != 32 {
        return None;
    }
    let mut octets = [0_u8; 16];
    // Deux chiffres hexadécimaux par octet : on coupe la chaîne en paires. La
    // borne est celle de la chaîne, et il n'y a pas d'indice à calculer.
    for (place, paire) in octets.iter_mut().zip(hexa.as_bytes().chunks(2)) {
        *place = u8::from_str_radix(core::str::from_utf8(paire).ok()?, 16).ok()?;
    }
    Some(Adresse {
        adresse: Ipv6Addr::from(octets),
        interface: interface.to_owned(),
        etat: Etat {
            temporaire: drapeaux & LINUX_TEMPORAIRE != 0,
            depreciee: drapeaux & LINUX_DEPRECIEE != 0,
            provisoire: drapeaux & LINUX_PROVISOIRE != 0,
            douteuse: drapeaux & LINUX_DAD_ECHOUEE != 0,
            connu: true,
            ..Etat::default()
        },
    })
}

// ── Ce que le système dit, ici et maintenant ────────────────────────────────

/// **LES ADRESSES IPv6 DE CETTE MACHINE**, avec ce que le système en dit —
/// vide quand il ne le dit pas, et l'appelant garde alors le choix du système.
///
/// **Linux** lit `/proc/net/if_inet6`, sans un `unsafe`. **Les autres Unix**
/// (macOS) passent par [`par_getifaddrs`].
#[must_use]
pub fn adresses() -> Vec<Adresse> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/net/if_inet6")
            .map(|texte| lire_la_table(&texte))
            .unwrap_or_default()
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        par_getifaddrs()
    }
    #[cfg(not(unix))]
    {
        Vec::new()
    }
}

/// Le système dit-il les drapeaux de ses adresses ? Sinon, qui s'en sert doit
/// le dire à l'exploitant : une règle posée à la main dans sa box ne tiendra
/// pas.
#[must_use]
pub fn systeme_bavard() -> bool {
    cfg!(unix)
}

// ── macOS : `getifaddrs`, puis un `ioctl` par adresse ───────────────────────

/// **LES ADRESSES PAR `getifaddrs`, ET LEURS DRAPEAUX PAR `ioctl`.**
///
/// C'est le seul endroit du dépôt qui appelle le système directement. Chaque
/// bloc `unsafe` dit ce qu'il suppose et pourquoi c'est vrai.
///
/// **Compilée sur tout Unix, employée sur macOS seulement** : la compiler
/// aussi sous Linux — où [`adresses`] lit `/proc` — la fait vérifier et
/// exécuter par les essais de la CI, ce qui est précisément ce qu'on veut
/// d'un code à pointeurs. Sous Linux, les drapeaux ne sont pas demandés (il
/// n'y a pas de `SIOCGIFAFLAG_IN6`) et [`Etat`] reste à sa valeur par défaut.
#[cfg(unix)]
#[must_use]
pub fn par_getifaddrs() -> Vec<Adresse> {
    let mut lues: Vec<Adresse> = Vec::new();
    let mut premiere: *mut libc::ifaddrs = core::ptr::null_mut();
    // SÛRETÉ : `getifaddrs` prend un pointeur vers notre variable et y écrit
    // la tête d'une liste qu'elle alloue ; `&mut premiere` est valide et
    // aligné. Sur échec (`!= 0`), elle n'écrit rien, et l'on ne lit rien.
    let issue = unsafe { libc::getifaddrs(&raw mut premiere) };
    if issue != 0 || premiere.is_null() {
        return lues;
    }
    // Une socket pour l'`ioctl` — `AF_INET6`, jamais connectée, fermée à la
    // fin. Un échec n'empêche pas de rendre les adresses : elles seront dites
    // stables, ce que l'appelant sait interpréter.
    //
    // SÛRETÉ : `socket` ne touche à aucune mémoire à nous ; elle rend un
    // descripteur, ou `-1`.
    let descripteur = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
    let mut courant = premiere;
    while !courant.is_null() {
        // SÛRETÉ : `courant` vient de `getifaddrs` (ou du `ifa_next` d'un
        // nœud qu'elle a écrit), il est non nul, aligné, et la liste reste
        // valide jusqu'à `freeifaddrs`, qui n'a pas encore été appelée. On
        // copie le nœud plutôt que d'en garder une référence : la copie ne
        // contient que des pointeurs, que l'on lit plus bas sous la même
        // garantie.
        let noeud = unsafe { core::ptr::read_unaligned(courant) };
        courant = noeud.ifa_next;
        if noeud.ifa_addr.is_null() || noeud.ifa_name.is_null() {
            continue;
        }
        // SÛRETÉ : `ifa_addr` pointe une `sockaddr` que `getifaddrs` a
        // écrite ; on n'en lit que `sa_family`, qui est le premier champ que
        // tout Unix y garantit (`libc::sockaddr` décrit la disposition du
        // système, `sa_len` compris là où il existe).
        let famille = unsafe { core::ptr::read_unaligned(noeud.ifa_addr) }.sa_family;
        if i32::from(famille) != libc::AF_INET6 {
            continue;
        }
        // SÛRETÉ : une `sockaddr` de famille `AF_INET6` **est** une
        // `sockaddr_in6` — c'est le contrat de l'API des sockets, et
        // `getifaddrs` l'a dimensionnée comme telle. `read_unaligned` ne
        // suppose rien de l'alignement.
        let six = unsafe { core::ptr::read_unaligned(noeud.ifa_addr.cast::<libc::sockaddr_in6>()) };
        let adresse = Ipv6Addr::from(six.sin6_addr.s6_addr);
        // SÛRETÉ : `ifa_name` pointe une chaîne terminée par un octet nul,
        // écrite par `getifaddrs` et valide tant que la liste vit. On la
        // copie tout de suite.
        let nom = unsafe { core::ffi::CStr::from_ptr(noeud.ifa_name) };
        let Ok(interface) = nom.to_str() else {
            continue;
        };
        lues.push(Adresse {
            adresse,
            interface: interface.to_owned(),
            etat: drapeaux_de(descripteur, nom, adresse, six.sin6_scope_id),
        });
    }
    if descripteur >= 0 {
        // SÛRETÉ : `descripteur` est celui que `socket` vient de rendre, il
        // n'a pas été fermé, et rien ne s'en sert après.
        unsafe { libc::close(descripteur) };
    }
    // SÛRETÉ : `premiere` est exactement ce que `getifaddrs` a rendu, non
    // nul, et libéré une seule fois. Plus rien ne pointe dans la liste : les
    // adresses et les noms ont été COPIÉS au-dessus.
    unsafe { libc::freeifaddrs(premiere) };
    lues
}

/// La taille de `struct in6_ifreq` de macOS, **telle que le code de l'`ioctl`
/// l'encode** : `SIOCGIFAFLAG_IN6` vaut `_IOWR('i', 73, struct in6_ifreq)`, et
/// les bits 16 à 28 de ce nombre disent cette taille. Seize octets de nom,
/// puis l'union `ifr_ifru`, dont le plus grand membre est une
/// `struct icmp6_ifstat` (trente-cinq compteurs de soixante-quatre bits) :
/// 16 + 280 = 296 = `0x128`, ce que porte `0xc128_6949`.
#[cfg(target_os = "macos")]
const IN6_IFREQ_OCTETS: usize = 296;

/// Le nom d'interface d'une `in6_ifreq` : `IFNAMSIZ`.
#[cfg(target_os = "macos")]
const IFNAMSIZ: usize = 16;

/// L'union `ifr_ifru`, en octets — le reste de la structure.
#[cfg(target_os = "macos")]
const IFRU_OCTETS: usize = 280;

/// Ce qu'une `sockaddr_in6` occupe : c'est ce qu'on écrit dans l'union.
#[cfg(target_os = "macos")]
const SOCKADDR_IN6_OCTETS: usize = 28;

/// `SIOCGIFAFLAG_IN6` sous macOS — les drapeaux d'UNE adresse d'UNE
/// interface. `libc` ne le déclare pas ; la valeur est celle de
/// `netinet6/in6_var.h`, et la taille qu'elle encode est vérifiée
/// ci-dessous.
#[cfg(target_os = "macos")]
const SIOCGIFAFLAG_IN6: libc::c_ulong = 0xc128_6949;

/// `IN6_IFF_TENTATIVE`.
#[cfg(target_os = "macos")]
const MACOS_PROVISOIRE: i32 = 0x02;
/// `IN6_IFF_DUPLICATED`.
#[cfg(target_os = "macos")]
const MACOS_DUPLIQUEE: i32 = 0x04;
/// `IN6_IFF_DETACHED`.
#[cfg(target_os = "macos")]
const MACOS_DETACHEE: i32 = 0x08;
/// `IN6_IFF_DEPRECATED`.
#[cfg(target_os = "macos")]
const MACOS_DEPRECIEE: i32 = 0x10;
/// `IN6_IFF_TEMPORARY`.
#[cfg(target_os = "macos")]
const MACOS_TEMPORAIRE: i32 = 0x80;

/// La requête de l'`ioctl` : le nom de l'interface, puis l'union `ifr_ifru`.
///
/// **On n'écrit dans l'union qu'une `sockaddr_in6`** — l'adresse dont on
/// demande les drapeaux — **et l'on n'y lit qu'un `int`** — les drapeaux
/// rendus : deux membres de la même union, au même offset, et c'est ainsi que
/// `SIOCGIFAFLAG_IN6` s'emploie. Les octets sont posés à la main, ce qui évite
/// un `transmute` et rend la disposition lisible.
#[cfg(target_os = "macos")]
#[repr(C, align(8))]
struct In6Ifreq {
    nom: [u8; IFNAMSIZ],
    ifru: [u8; IFRU_OCTETS],
}

/// La taille que le code de l'`ioctl` annonce est celle de ce que nous lui
/// donnons : sans quoi le noyau lirait au-delà de notre tampon.
#[cfg(target_os = "macos")]
const _: () = assert!(core::mem::size_of::<In6Ifreq>() == IN6_IFREQ_OCTETS);

/// Les drapeaux de cette adresse, par `ioctl(SIOCGIFAFLAG_IN6)` — macOS.
///
/// **Rien de conclu quand quoi que ce soit manque** : sans socket, avec un nom
/// qui ne tient pas, ou sur un `ioctl` refusé, on rend [`Etat::default`] —
/// l'adresse est alors dite inconnue, et [`choisir`] ne la retiendra pas. Le
/// repli du choix au système vaut mieux qu'une adresse potentiellement fausse.
#[cfg(target_os = "macos")]
fn drapeaux_de(
    descripteur: libc::c_int,
    nom: &core::ffi::CStr,
    adresse: Ipv6Addr,
    portee: u32,
) -> Etat {
    if descripteur < 0 {
        return Etat::default();
    }
    let mut requete = In6Ifreq {
        nom: [0; IFNAMSIZ],
        ifru: [0; IFRU_OCTETS],
    };
    // Le nom, avec la place de son octet nul final.
    let octets = nom.to_bytes();
    let Some(place) = requete
        .nom
        .get_mut(..octets.len())
        .filter(|_| octets.len() < IFNAMSIZ)
    else {
        return Etat::default();
    };
    place.copy_from_slice(octets);
    // La `sockaddr_in6` de macOS, à la main : longueur (28), famille
    // (`AF_INET6` = 30), port (0) et `flowinfo` (0) — les six premiers octets
    // —, puis l'adresse, puis la portée.
    let mut six = [0_u8; SOCKADDR_IN6_OCTETS];
    let entete: [u8; 8] = [28, 30, 0, 0, 0, 0, 0, 0];
    let mut curseur = 0_usize;
    for tranche in [
        entete.as_slice(),
        adresse.octets().as_slice(),
        portee.to_ne_bytes().as_slice(),
    ] {
        let fin = curseur.saturating_add(tranche.len());
        if let Some(place) = six.get_mut(curseur..fin) {
            place.copy_from_slice(tranche);
        }
        curseur = fin;
    }
    if let Some(place) = requete.ifru.get_mut(..SOCKADDR_IN6_OCTETS) {
        place.copy_from_slice(&six);
    }
    // SÛRETÉ : `descripteur` est une socket ouverte ; `SIOCGIFAFLAG_IN6`
    // attend un pointeur vers une `struct in6_ifreq` de `IN6_IFREQ_OCTETS`
    // octets — ce que `requete` est exactement, vérifié à la compilation —, et
    // le noyau n'écrit que dedans. La socket n'est pas partagée, et `requete`
    // vit jusqu'à la fin de cette fonction.
    let issue = unsafe { libc::ioctl(descripteur, SIOCGIFAFLAG_IN6, &raw mut requete) };
    if issue != 0 {
        return Etat::default();
    }
    // Les drapeaux sont l'`int` du début de l'union.
    let mut quatre = [0_u8; 4];
    let Some(debut) = requete.ifru.get(..4) else {
        return Etat::default();
    };
    quatre.copy_from_slice(debut);
    let drapeaux = i32::from_ne_bytes(quatre);
    Etat {
        temporaire: drapeaux & MACOS_TEMPORAIRE != 0,
        depreciee: drapeaux & MACOS_DEPRECIEE != 0,
        provisoire: drapeaux & MACOS_PROVISOIRE != 0,
        douteuse: drapeaux & (MACOS_DUPLIQUEE | MACOS_DETACHEE) != 0,
        securisee: drapeaux & libc::IN6_IFF_SECURED != 0,
        connu: true,
    }
}

/// Ailleurs que sous macOS, `getifaddrs` ne dit pas les drapeaux, et il n'y a
/// pas d'`ioctl` pour les demander : Linux les lit dans `/proc`
/// ([`lire_la_table`]), et c'est par là qu'[`adresses`] passe.
#[cfg(all(unix, not(target_os = "macos")))]
fn drapeaux_de(
    _descripteur: libc::c_int,
    _nom: &core::ffi::CStr,
    _adresse: Ipv6Addr,
    _portee: u32,
) -> Etat {
    Etat::default()
}

#[cfg(test)]
mod tests {
    use super::{Adresse, Etat, choisir, globale, lire_la_table};
    use std::net::Ipv6Addr;

    /// La table d'oxygen, telle que Linux l'écrirait : `en5` porte la stable
    /// retenue, une seconde stable plus grande, la temporaire du moment, une
    /// temporaire dépréciée — celle que la Livebox propose —, une provisoire,
    /// une ULA et son lien local ; `eth1` porte une autre stable, sur une
    /// autre interface.
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
    fn la_table_d_oxygen_se_lit_ligne_par_ligne() {
        let lues = lire_la_table(OXYGEN);
        assert_eq!(lues.len(), 8, "huit adresses");
        assert_eq!(lues[0].adresse, a("2a01:cb19:d27:2f00:144b:b441:5901:6706"));
        assert_eq!(lues[0].interface, "en5");
        assert!(lues[0].etat.stable(), "la stable");
        assert!(lues[2].etat.temporaire && !lues[2].etat.stable());
        assert!(lues[3].etat.temporaire && lues[3].etat.depreciee);
        assert!(lues[4].etat.provisoire);
        assert_eq!(lues[7].interface, "eth1");
    }

    #[test]
    fn la_stable_de_l_interface_du_bail_est_retenue() {
        let lues = lire_la_table(OXYGEN);
        // La source est la temporaire du moment : on remonte à son
        // interface, et l'on prend la plus petite stable globale de
        // CELLE-LÀ.
        assert_eq!(
            choisir(&lues, a("2a01:cb19:d27:2f00:157e:db0b:296a:f355")),
            Some(a("2a01:cb19:d27:2f00:144b:b441:5901:6706")),
            "la stable d'oxygen, et non la seconde ni l'ULA"
        );
        // Depuis la stable elle-même : la même réponse.
        assert_eq!(
            choisir(&lues, a("2a01:cb19:d27:2f00:144b:b441:5901:6706")),
            Some(a("2a01:cb19:d27:2f00:144b:b441:5901:6706"))
        );
        // Sur l'autre interface, c'est son adresse à elle.
        assert_eq!(
            choisir(&lues, a("2001:67c:1562:aaaa::1")),
            Some(a("2001:67c:1562:aaaa::1"))
        );
    }

    #[test]
    fn sans_source_connue_ou_sans_stable_on_ne_choisit_rien() {
        let lues = lire_la_table(OXYGEN);
        // Rien du tout : macOS sans drapeaux, ou un `/proc` qu'on ne lit pas.
        assert_eq!(choisir(&[], a("2001:db8::1")), None);
        // Une source que la liste ne connaît pas : on ne devine pas
        // l'interface.
        assert_eq!(choisir(&lues, a("2001:db8::1")), None);
        // Une interface dont toutes les adresses sont écartées.
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
                &lire_la_table(sans_stable),
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
            // Les champs qui manquent, un par un.
            "2a01cb190d272f00144bb44159016706",
            "2a01cb190d272f00144bb44159016706 02",
            "2a01cb190d272f00144bb44159016706 02 40",
            "2a01cb190d272f00144bb44159016706 02 40 00",
            "2a01cb190d272f00144bb44159016706 02 40 00 80",
            "2a01cb190d272f00144bb44159016706 02 40 00 zz en5",
        ] {
            assert!(lire_la_table(tordue).is_empty(), "« {tordue} »");
        }
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

    #[test]
    fn un_etat_se_juge_drapeau_par_drapeau() {
        assert!(!Etat::default().stable());
        assert!(
            Etat {
                connu: true,
                ..Etat::default()
            }
            .stable()
        );
        for ecartee in [
            Etat {
                temporaire: true,
                ..Etat::default()
            },
            Etat {
                depreciee: true,
                ..Etat::default()
            },
            Etat {
                provisoire: true,
                ..Etat::default()
            },
            Etat {
                douteuse: true,
                ..Etat::default()
            },
        ] {
            assert!(!ecartee.stable(), "{ecartee:?}");
        }
    }

    /// **CE QUE LE SYSTÈME DIT VRAIMENT, SUR CETTE MACHINE** — l'essai qui
    /// exécute les appels à pointeurs. **Il ne conclut rien** : une machine
    /// sans IPv6 n'en rend aucune, et c'est licite. Ce qu'il éprouve est que
    /// le parcours de la liste ne fasse rien de mal, et que ce qui en sort
    /// soit cohérent.
    #[cfg(unix)]
    #[test]
    fn le_systeme_se_lit_sans_rien_casser() {
        for lue in super::par_getifaddrs() {
            assert!(!lue.interface.is_empty(), "une interface se nomme");
            assert!(!lue.adresse.is_unspecified(), "{lue:?}");
        }
        // `adresses()` passe par `/proc` sous Linux, par `getifaddrs`
        // ailleurs : les deux doivent rendre quelque chose de lisible.
        for lue in super::adresses() {
            assert!(!lue.interface.is_empty());
        }
        // Et la boucle locale est là, sur tout système qui a IPv6 : elle
        // n'est pas globale, donc jamais choisie.
        let lues: Vec<Adresse> = super::adresses();
        if lues.iter().any(|lue| lue.adresse.is_loopback()) {
            assert_eq!(choisir(&lues, Ipv6Addr::LOCALHOST), None);
        }
    }
}
