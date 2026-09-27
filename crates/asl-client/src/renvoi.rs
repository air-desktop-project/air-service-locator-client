//! Le renvoi vers un annuaire local — ce qu'un daemon fait d'un `421`.
//!
//! # LE PROBLÈME
//!
//! Depuis 0.28.0 (`protocole.md` §3 ter, décision 52), une machine rangée dans
//! un domaine **confié à un annuaire local** ne s'annonce plus aux racines :
//! une racine qui reçoit son annonce la refuse en `421` (« mauvais
//! destinataire », RFC 9110 §15.5.20) et dit où aller :
//!
//! ```text
//! {"annuaire":"n-…","adresses":["hôte:port",…],"identites":"n-A n-A n-B"}
//! ```
//!
//! — l'annuaire, les locateurs de chacun de ses membres acceptés (une paire en
//! a deux), et, depuis 0.31.0 (décision 59), **l'identité du membre au bout de
//! chaque adresse** : le i-ème `n-…` de `identites` est celui qu'on doit
//! trouver à la i-ème adresse. Le daemon le suit, comme une redirection.
//!
//! # CHAQUE MEMBRE SOUS SA PROPRE CLÉ
//!
//! Une paire, ce sont deux machines et **deux clés** (décision 49) : speedy et
//! helium ne sont pas le même `n-…`. Sans `identites`, le corps ne nommait que
//! le titulaire, et un client qui attendait sa clé au bout de toutes les
//! adresses refusait l'autre membre. Un corps d'avant 0.31.0 (sans
//! `identites`) se lit comme hier : chaque adresse sous l'identité du
//! titulaire.
//!
//! **UNE CHAÎNE, PAS UNE LISTE D'OBJETS** : un lecteur d'hier saute une clé
//! inconnue seulement si sa valeur est une chaîne. Le serveur l'a écrite
//! ainsi pour ne pas casser les clients déployés ; ce lecteur-ci la lit.
//!
//! # CE QUI EST ICI, ET CE QUI N'Y EST PAS
//!
//! **Ici, les deux décisions** : lire ce corps sans rien croire de plus que ce
//! qu'il dit ([`Renvoi::lire`], [`separer_l_adresse`]), et choisir, tour après
//! tour, à qui parler — les racines, ou l'annuaire local — et combien attendre
//! ([`Aiguillage`]). Sans une entrée-sortie, éprouvées sur des listes
//! littérales, comme [`crate::Tournee`].
//!
//! **Pas ici** : la résolution des noms, la confiance TLS et les sockets —
//! `asl-client-tokio` obéit.
//!
//! # CE QUI EMPÊCHE LE RENVOI DE DEVENIR UNE BOUCLE
//!
//! Trois règles, et chacune a son essai :
//!
//! 1. **Un seul saut.** Seule une RACINE renvoie. Un `421` reçu d'un annuaire
//!    local est un échec de ce membre, pas un nouveau renvoi : une chaîne de
//!    renvois serait une boucle que personne n'aurait écrite.
//! 2. **Le retour se paie.** Quand un tour entier de l'annuaire local échoue,
//!    on revient aux racines — c'est là qu'on réapprend si le domaine a changé
//!    d'hébergeur —, et **ce retour est un tour perdu** : le recul s'y applique,
//!    et il grandit tant qu'aucune annonce n'aboutit. Racine → `421` → local
//!    muet → racine → `421` … ne tourne donc jamais plus vite que la reprise.
//! 3. **Le recul ne repart de zéro que sur une annonce acceptée**, comme
//!    partout ailleurs : un renvoi n'est pas une réussite.

use asl_id::{Genre, Identifiant};
use core::net::{Ipv6Addr, SocketAddr};

use crate::{Reprise, place_en_ordre};

/// Le nombre d'adresses qu'un renvoi peut porter.
///
/// **UNE PAIRE EN A DEUX** (décision 49). La borne est large exprès — un corps
/// qui en porterait davantage est refusé plutôt que tronqué, parce qu'une
/// adresse ignorée en silence serait un membre qu'on n'essaierait jamais.
pub const ADRESSES_MAX: usize = 8;

/// Ce qui peut clocher dans un renvoi.
///
/// **AUCUNE N'EST SUIVIE** : un renvoi illisible est traité comme un refus de
/// la racine qui l'a envoyé, et la tournée passe à la suivante. Suivre à
/// moitié ce qu'on n'a pas compris serait pire que ne pas le suivre.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FauteDeRenvoi {
    /// Le corps n'a pas la forme `{"annuaire":…,"adresses":[…]}`.
    Forme,
    /// `annuaire` n'est pas un identifiant d'annuaire (`n-…`).
    Annuaire,
    /// Le corps ne donne aucune adresse : il n'y a nulle part où aller.
    SansAdresse,
    /// Plus de [`ADRESSES_MAX`] adresses.
    TropDAdresses,
    /// Une adresse n'est pas `hôte:port`.
    Adresse,
}

/// Le séparateur de `identites` : une seule espace entre deux `n-…`.
const SEPARATEUR_D_IDENTITES: char = ' ';

/// Un `421` lu : l'annuaire local, et où joindre ses membres.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Renvoi<'a> {
    annuaire: Identifiant,
    adresses: [&'a str; ADRESSES_MAX],
    /// L'identité attendue au bout de chaque adresse — celle du titulaire
    /// partout pour un corps d'avant 0.31.0.
    identites: [Identifiant; ADRESSES_MAX],
    combien: usize,
    /// Le corps nommait-il chaque membre ?
    par_membre: bool,
}

impl<'a> Renvoi<'a> {
    /// Lit le corps d'un `421`.
    ///
    /// # LA FORME ACCEPTÉE
    ///
    /// Un objet JSON, les clés dans n'importe quel ordre, des blancs où JSON
    /// les permet. **Une clé inconnue dont la valeur est une chaîne se saute** :
    /// un annuaire plus récent peut en ajouter. Tout le reste est refusé — en
    /// particulier la barre oblique inverse dans une chaîne : les adresses sont
    /// de l'ASCII sans guillemet ni barre (`asl_registre::Adresse`), et un
    /// échappement n'y a rien à faire.
    ///
    /// Chaque adresse est vérifiée ([`separer_l_adresse`]) dès la lecture : un
    /// renvoi dont une seule adresse est fausse est refusé en entier.
    ///
    /// # Errors
    ///
    /// Voir [`FauteDeRenvoi`].
    pub fn lire(corps: &'a [u8]) -> Result<Self, FauteDeRenvoi> {
        let texte = core::str::from_utf8(corps).map_err(|_| FauteDeRenvoi::Forme)?;
        let mut lu = Lecture { texte, place: 0 };
        let mut annuaire = None;
        let mut adresses = [""; ADRESSES_MAX];
        let mut combien = None;
        let mut identites_lues = None;

        lu.attendre(b'{')?;
        loop {
            let cle = lu.chaine()?;
            lu.attendre(b':')?;
            match cle {
                "annuaire" if annuaire.is_none() => {
                    let valeur = lu.chaine()?;
                    annuaire = Some(
                        Identifiant::analyser_genre(Genre::Annuaire, valeur)
                            .map_err(|_| FauteDeRenvoi::Annuaire)?,
                    );
                }
                "adresses" if combien.is_none() => {
                    combien = Some(lu.liste(&mut adresses)?);
                }
                "identites" if identites_lues.is_none() => {
                    identites_lues = Some(lu.chaine()?);
                }
                "annuaire" | "adresses" | "identites" => return Err(FauteDeRenvoi::Forme),
                // **UNE CLÉ INCONNUE SE SAUTE**, si sa valeur est une chaîne.
                _ => {
                    lu.chaine()?;
                }
            }
            match lu.suivant()? {
                b',' => {}
                b'}' => break,
                _ => return Err(FauteDeRenvoi::Forme),
            }
        }
        if lu.blancs() != texte.len() {
            return Err(FauteDeRenvoi::Forme);
        }

        let annuaire = annuaire.ok_or(FauteDeRenvoi::Forme)?;
        let combien = combien.ok_or(FauteDeRenvoi::Forme)?;
        if combien == 0 {
            return Err(FauteDeRenvoi::SansAdresse);
        }
        for adresse in adresses.iter().take(combien) {
            separer_l_adresse(adresse)?;
        }
        let mut identites = [annuaire; ADRESSES_MAX];
        if let Some(texte) = identites_lues {
            lire_les_identites(texte, combien, &mut identites)?;
        }
        Ok(Self {
            annuaire,
            adresses,
            identites,
            combien,
            par_membre: identites_lues.is_some(),
        })
    }

    /// L'annuaire local vers lequel on est renvoyé.
    #[must_use]
    pub const fn annuaire(&self) -> Identifiant {
        self.annuaire
    }

    /// Ses adresses, dans l'ordre du corps — chacune `hôte:port`, vérifiée.
    #[must_use]
    pub fn adresses(&self) -> &[&'a str] {
        self.adresses.get(..self.combien).unwrap_or_default()
    }

    /// Chaque adresse, avec l'identité qu'on doit trouver à son bout.
    ///
    /// **C'EST CELLE-LÀ QU'ON ATTEND, ET AUCUNE AUTRE** : le membre au bout de
    /// l'adresse de speedy doit prouver la clé de speedy, et non celle
    /// d'helium — un membre qui présenterait la clé de l'autre est refusé.
    pub fn membres(&self) -> impl Iterator<Item = (&'a str, Identifiant)> + '_ {
        self.adresses()
            .iter()
            .zip(self.identites.iter())
            .map(|(&adresse, &identite)| (adresse, identite))
    }

    /// Le corps nommait-il chaque membre (`identites`, depuis 0.31.0) ?
    /// Sinon, chaque adresse est attendue sous l'identité du titulaire.
    #[must_use]
    pub const fn nomme_chaque_membre(&self) -> bool {
        self.par_membre
    }
}

/// Lit `identites` : exactement `combien` identifiants d'annuaire, séparés
/// chacun par UNE espace — ni plus, ni moins, ni blanc en tête ou en queue.
///
/// **UN DÉCOMPTE QUI NE TOMBE PAS JUSTE EST UN REFUS** : une identité de trop
/// ou de moins, et l'on ne saurait plus laquelle va avec quelle adresse.
///
/// # Errors
///
/// [`FauteDeRenvoi::Forme`] pour un décompte faux ou une case vide,
/// [`FauteDeRenvoi::Annuaire`] pour un identifiant qui n'en est pas un.
fn lire_les_identites(
    texte: &str,
    combien: usize,
    identites: &mut [Identifiant; ADRESSES_MAX],
) -> Result<(), FauteDeRenvoi> {
    let mut lues = 0_usize;
    for morceau in texte.split(SEPARATEUR_D_IDENTITES) {
        let case = identites
            .get_mut(lues)
            .filter(|_| lues < combien)
            .ok_or(FauteDeRenvoi::Forme)?;
        *case = Identifiant::analyser_genre(Genre::Annuaire, morceau)
            .map_err(|_| FauteDeRenvoi::Annuaire)?;
        lues = lues.saturating_add(1);
    }
    if lues == combien {
        Ok(())
    } else {
        Err(FauteDeRenvoi::Forme)
    }
}

/// Sépare `hôte:port` : l'hôte (sans crochets), et le port.
///
/// L'hôte ne sert plus qu'à joindre et à remplir `:authority` : ce qu'on
/// croit est l'identité du membre ([`Renvoi::membres`], décisions 53 et 59).
/// Un annuaire local d'hier qui ne servirait qu'une chaîne le reçoit encore
/// comme nom exigé, le temps de la bascule (décision 58).
///
/// Formes acceptées : `nom.exemple:6630`, `192.0.2.7:6630`,
/// `[2001:db8::7]:6630`. Un nom ne porte que des lettres ASCII, des chiffres,
/// des tirets et des points ; le port n'est jamais nul.
///
/// # Errors
///
/// [`FauteDeRenvoi::Adresse`].
pub fn separer_l_adresse(adresse: &str) -> Result<(&str, u16), FauteDeRenvoi> {
    let faute = FauteDeRenvoi::Adresse;
    let (hote, port) = match adresse.strip_prefix('[') {
        Some(reste) => {
            let (hote, port) = reste.split_once("]:").ok_or(faute)?;
            hote.parse::<Ipv6Addr>().map_err(|_| faute)?;
            (hote, port)
        }
        None => {
            let (hote, port) = adresse.split_once(':').ok_or(faute)?;
            let permis =
                |octet: u8| octet.is_ascii_alphanumeric() || octet == b'-' || octet == b'.';
            if hote.is_empty() || !hote.bytes().all(permis) {
                return Err(faute);
            }
            (hote, port)
        }
    };
    let port = port.parse::<u16>().map_err(|_| faute)?;
    if port == 0 {
        return Err(faute);
    }
    Ok((hote, port))
}

/// Un curseur sur le texte d'un renvoi.
struct Lecture<'a> {
    texte: &'a str,
    place: usize,
}

impl<'a> Lecture<'a> {
    /// Saute les blancs ; rend la place atteinte.
    fn blancs(&mut self) -> usize {
        while let Some(octet) = self.texte.as_bytes().get(self.place) {
            if !matches!(octet, b' ' | b'\t' | b'\n' | b'\r') {
                break;
            }
            self.place = self.place.saturating_add(1);
        }
        self.place
    }

    /// Le prochain octet après les blancs, consommé.
    fn suivant(&mut self) -> Result<u8, FauteDeRenvoi> {
        let place = self.blancs();
        let octet = *self
            .texte
            .as_bytes()
            .get(place)
            .ok_or(FauteDeRenvoi::Forme)?;
        self.place = place.saturating_add(1);
        Ok(octet)
    }

    /// Exige cet octet.
    fn attendre(&mut self, attendu: u8) -> Result<(), FauteDeRenvoi> {
        if self.suivant()? == attendu {
            Ok(())
        } else {
            Err(FauteDeRenvoi::Forme)
        }
    }

    /// Une chaîne, sans échappement.
    fn chaine(&mut self) -> Result<&'a str, FauteDeRenvoi> {
        self.attendre(b'"')?;
        let debut = self.place;
        let reste = self.texte.get(debut..).unwrap_or_default();
        let (valeur, _) = reste.split_once('"').ok_or(FauteDeRenvoi::Forme)?;
        if valeur.contains('\\') {
            return Err(FauteDeRenvoi::Forme);
        }
        self.place = debut.saturating_add(valeur.len()).saturating_add(1);
        Ok(valeur)
    }

    /// Une liste de chaînes, rangées dans `place` ; rend leur nombre.
    fn liste(&mut self, place: &mut [&'a str; ADRESSES_MAX]) -> Result<usize, FauteDeRenvoi> {
        self.attendre(b'[')?;
        let debut = self.place;
        if self.suivant()? == b']' {
            return Ok(0);
        }
        self.place = debut;
        let mut combien = 0_usize;
        loop {
            let valeur = self.chaine()?;
            let case = place.get_mut(combien).ok_or(FauteDeRenvoi::TropDAdresses)?;
            *case = valeur;
            combien = combien.saturating_add(1);
            match self.suivant()? {
                b',' => {}
                b']' => return Ok(combien),
                _ => return Err(FauteDeRenvoi::Forme),
            }
        }
    }
}

// ── L'aiguillage ────────────────────────────────────────────────────────────

/// De quel côté vient l'annuaire à essayer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cote {
    /// Les racines — la liste que le porteur a configurée.
    Racines,
    /// L'annuaire local vers lequel une racine nous a renvoyés.
    Local,
}

/// Ce qu'un aiguillage dit de faire : attendre, puis essayer celui-là.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EtapeAiguillee {
    /// La liste où chercher.
    pub cote: Cote,
    /// La place, dans cette liste, de l'annuaire à essayer.
    pub place: usize,
    /// Combien de millisecondes attendre AVANT de l'essayer.
    pub attendre_ms: u64,
}

/// La tournée d'un daemon qui peut être renvoyé vers un annuaire local.
///
/// # LA MÊME RÈGLE QUE [`crate::Tournee`], ET UNE DE PLUS
///
/// Chaque liste se parcourt en entier sans attendre, IPv6 d'abord ; le recul
/// sépare les TOURS. Ce qui s'ajoute : un tour complet de l'annuaire local
/// qui échoue ramène aux racines, **et ce retour est un tour perdu** — voir
/// les trois règles en tête de ce module.
///
/// # APRÈS UNE RUPTURE, L'ANNUAIRE LOCAL D'ABORD
///
/// Une attache établie chez l'annuaire local qui se rompt recommence par lui :
/// le renvoi reste vrai tant qu'une racine ne dit pas autre chose, et
/// redemander aux racines à chaque rupture leur ferait porter la charge que
/// l'annuaire local existe pour prendre.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Aiguillage {
    reprise: Reprise,
    rang: usize,
    cote: Cote,
    renvois: u32,
}

impl Aiguillage {
    /// Un aiguillage qui commence par les racines, et recule selon cette
    /// politique.
    #[must_use]
    pub const fn nouveau(reprise: Reprise) -> Self {
        Self {
            reprise,
            rang: 0,
            cote: Cote::Racines,
            renvois: 0,
        }
    }

    /// L'annuaire suivant, et ce qu'il faut attendre avant de l'essayer.
    ///
    /// `local` est la liste des adresses de l'annuaire local, telle que le
    /// dernier renvoi l'a donnée (vide tant qu'aucun renvoi n'est venu).
    ///
    /// Rend `None` si, et seulement si, il n'y a aucune racine : c'est une
    /// configuration, pas une panne.
    pub fn prochaine(
        &mut self,
        racines: &[SocketAddr],
        local: &[SocketAddr],
        alea: u16,
    ) -> Option<EtapeAiguillee> {
        if racines.is_empty() {
            return None;
        }
        if self.cote == Cote::Local {
            if let Some(place) = place_en_ordre(local, self.rang) {
                self.rang = self.rang.saturating_add(1);
                return Some(EtapeAiguillee {
                    cote: Cote::Local,
                    place,
                    attendre_ms: 0,
                });
            }
            // **LE TOUR DE L'ANNUAIRE LOCAL A ÉCHOUÉ** : retour aux racines,
            // qui diront si le domaine a changé d'hébergeur — et le recul se
            // paie ici, pour que le va-et-vient ne soit jamais une boucle
            // serrée.
            self.cote = Cote::Racines;
            self.rang = racines.len();
        }
        let attendre_ms = if self.rang >= racines.len() {
            self.rang = 0;
            self.reprise.prochain_delai(alea)
        } else {
            0
        };
        let place = place_en_ordre(racines, self.rang).expect(
            "le rang vient d'être ramené sous la longueur, et la liste n'est pas vide : \
             `place_en_ordre` rend toujours une place pour un rang qui est dans la liste",
        );
        self.rang = self.rang.saturating_add(1);
        Some(EtapeAiguillee {
            cote: Cote::Racines,
            place,
            attendre_ms,
        })
    }

    /// Une racine vient de renvoyer vers l'annuaire local.
    ///
    /// Rend `false` — et ne change rien — si l'on parlait déjà à l'annuaire
    /// local : **un seul saut** ; ce `421`-là est un échec de ce membre.
    pub const fn renvoye(&mut self) -> bool {
        match self.cote {
            Cote::Racines => {
                self.cote = Cote::Local;
                self.rang = 0;
                self.renvois = self.renvois.saturating_add(1);
                true
            }
            Cote::Local => false,
        }
    }

    /// L'annonce a été acceptée : le recul repart de zéro, et le tour du haut
    /// — du côté où l'on est.
    pub const fn reussite(&mut self) {
        self.rang = 0;
        self.reprise.reussite();
    }

    /// Le côté vers lequel on regarde.
    #[must_use]
    pub const fn cote(&self) -> Cote {
        self.cote
    }

    /// Combien de renvois ont été suivis depuis le départ.
    #[must_use]
    pub const fn renvois(&self) -> u32 {
        self.renvois
    }

    /// Le nombre de TOURS complets qui ont échoué — un retour aux racines
    /// après un annuaire local muet en est un.
    #[must_use]
    pub const fn tours_perdus(&self) -> u32 {
        self.reprise.essais()
    }
}
