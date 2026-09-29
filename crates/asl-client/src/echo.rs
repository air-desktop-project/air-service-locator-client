//! L'écho (`protocole.md` §3 quater, décisions 89 à 93) : ce que `asl echo`
//! décide d'un datagramme reçu, et ce que `asl ping` conclut d'une réponse.
//!
//! # CE QUI EST ICI, ET CE QUI N'Y EST PAS
//!
//! Le **codec** est `asl-echo`, tiré du dépôt serveur : il lit, écrit et
//! vérifie les datagrammes, hors ligne, et laisse à qui écoute deux états —
//! **le débit par source et la mémoire des défis vus** — et deux réglages —
//! **les racines crues et l'annuaire du bail**. Ce module tient ces états et
//! ces réglages, sans une entrée-sortie : l'heure est un paramètre, l'aléa
//! aussi. C'est ce qui permet d'éprouver une rafale de mille sondes, une
//! horloge qui dérive ou un rejeu en une boucle, sans une socket.
//!
//! La socket, elle, est celle du bail (décision 90 ; E2) : `asl-client-tokio`
//! la trie au premier octet et rend à l'appelant ce qui n'est pas du QUIC.
//! L'appelant passe chaque datagramme à [`Repondeur::recevoir`], et renvoie
//! ce qui en sort — ou rien.
//!
//! # L'ORDRE DE CE QUE L'ÉCHO REGARDE, ET POURQUOI IL EST CELUI-LÀ
//!
//! 1. **La longueur.** Une requête fait 384 octets, et rien d'autre ne se lit :
//!    une comparaison, avant de dépenser quoi que ce soit.
//! 2. **Le débit, AVANT toute vérification** : une signature coûte des
//!    dizaines de microsecondes, et un inconnu ne doit pas pouvoir les faire
//!    dépenser à volonté. Cinq par seconde et par source (une `/64` en IPv6,
//!    une adresse en IPv4), dix d'avance ; cinquante par seconde en tout.
//! 3. **La sonde elle-même** (`asl_echo::accepter`) : la signature de
//!    l'annuaire ou du jeton, la cible, la date.
//! 4. **La mémoire des défis vus**, APRÈS : un défi ne se retient que d'une
//!    sonde authentique, faute de quoi un inconnu remplirait la mémoire de
//!    défis inventés et en chasserait les vrais.
//!
//! **Tout refus est un silence** ([`Silence`]) : rien ne part sur le fil. La
//! raison sert au journal, et à rien d'autre.

use core::net::{IpAddr, SocketAddr};

use asl_cle::ClePublique;
use asl_echo::{
    DefiEcho, FENETRE_HORLOGE_MS, REPONSE_OCTETS, REQUETE_OCTETS, Refus, RefusReponse, RefusSonde,
    Reponse,
};
use asl_id::Identifiant;

use crate::Identite;

pub use asl_echo::{Jeton, NOM_SERVICE, SondeJeton};

/// Combien de réponses par seconde une même source obtient, en régime.
pub const DEBIT_PAR_SOURCE: u64 = 5;

/// Combien une même source en obtient d'avance, d'un coup.
pub const RAFALE_PAR_SOURCE: u64 = 10;

/// Combien de réponses par seconde l'écho rend en tout, toutes sources
/// confondues — et autant d'avance.
pub const DEBIT_TOTAL: u64 = 50;

/// Le nombre de seaux entre lesquels les sources se répartissent.
///
/// # UNE TABLE DE SEAUX, ET NON UNE TABLE DE SOURCES
///
/// Une source ne s'inscrit pas : son préfixe choisit un seau par un hachage
/// **à graine**, et deux sources qui tombent dans le même seau le partagent.
/// Rien ne grossit donc avec le nombre de sources — un balayage depuis mille
/// adresses ne remplit rien —, et la recherche est d'un pas, quel que soit le
/// débit d'arrivée : c'est elle qui tourne AVANT toute vérification, donc au
/// rythme de l'attaquant.
///
/// Le partage est prudent : deux sources dans un seau ont à elles deux le
/// débit d'une. La graine, tirée au démarrage, empêche d'en viser une exprès.
pub const SEAUX: usize = 1_024;

/// Le nombre de défis que l'écho retient, les plus vieux sortant d'abord.
pub const DEFIS_RETENUS: usize = 4_096;

/// Les racines embarquées qu'on garde, au plus.
const RACINES_MAX: usize = 4;

/// Mille millièmes : un jeton de seau.
const UN_JETON: u64 = 1_000;

// ── Le débit ────────────────────────────────────────────────────────────────

/// Un seau à jetons, compté en millièmes pour qu'un débit de cinq par seconde
/// se remplisse de cinq millièmes par milliseconde, sans division.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Seau {
    /// Ce qui reste, en millièmes de jeton.
    millijetons: u64,
    /// Quand il a été rempli pour la dernière fois, en millisecondes.
    a: u64,
}

impl Seau {
    /// Un seau plein : la rafale est disponible d'emblée.
    const fn plein(rafale: u64) -> Self {
        Self {
            millijetons: rafale.saturating_mul(UN_JETON),
            a: 0,
        }
    }

    /// Le remplit de ce qui s'est écoulé depuis la dernière fois.
    ///
    /// **UNE HORLOGE QUI RECULE NE REMPLIT RIEN** : l'écart est nul, et
    /// l'instant retenu reste le plus récent — sans quoi un recul d'horloge
    /// suivi d'un retour compterait deux fois le même temps.
    fn remplir(&mut self, maintenant_ms: u64, debit: u64, rafale: u64) {
        let ecoule = maintenant_ms.saturating_sub(self.a);
        let gagne = ecoule.saturating_mul(debit);
        self.millijetons = self
            .millijetons
            .saturating_add(gagne)
            .min(rafale.saturating_mul(UN_JETON));
        self.a = self.a.max(maintenant_ms);
    }

    /// Reste-t-il un jeton ?
    const fn a_un_jeton(&self) -> bool {
        self.millijetons >= UN_JETON
    }

    /// En prend un — l'appelant a vérifié qu'il y en avait.
    const fn prendre(&mut self) {
        self.millijetons = self.millijetons.saturating_sub(UN_JETON);
    }
}

/// Ce qui identifie une source pour le débit : **une `/64` en IPv6, une
/// adresse en IPv4**.
///
/// Une machine IPv6 dispose d'ordinaire de toute sa `/64` ; la compter adresse
/// par adresse lui donnerait dix-huit milliards de milliards de débits. Une
/// IPv4 enfouie (`::ffff:a.b.c.d`), telle qu'une socket à double pile la
/// rend, est une IPv4.
#[must_use]
pub fn prefixe_de_source(source: IpAddr) -> [u8; 9] {
    let mut prefixe = [0_u8; 9];
    let (famille, octets): (u8, &[u8]) = match source.to_canonical() {
        IpAddr::V4(v4) => (4, &v4.octets()),
        IpAddr::V6(v6) => (6, &v6.octets()),
    };
    let places = prefixe.iter_mut();
    for (place, octet) in places.zip(core::iter::once(&famille).chain(octets.iter().take(8))) {
        *place = *octet;
    }
    prefixe
}

/// Le débit de l'écho : par source, puis en tout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Debit {
    graine: u64,
    seaux: [Seau; SEAUX],
    total: Seau,
}

impl Debit {
    /// Tous les seaux pleins.
    ///
    /// `graine` vient de l'aléa du noyau : c'est elle qui empêche un
    /// attaquant de choisir une source qui partage le seau d'une autre.
    #[must_use]
    pub const fn nouveau(graine: u64) -> Self {
        Self {
            graine,
            seaux: [Seau::plein(RAFALE_PAR_SOURCE); SEAUX],
            total: Seau::plein(DEBIT_TOTAL),
        }
    }

    /// Le seau de ce préfixe : FNV-1a, à graine, sur ses neuf octets.
    fn place(&self, prefixe: &[u8; 9]) -> usize {
        const PREMIER: u64 = 0x0000_0100_0000_01b3;
        let mut empreinte = self.graine ^ 0xcbf2_9ce4_8422_2325;
        for octet in prefixe {
            empreinte = (empreinte ^ u64::from(*octet)).wrapping_mul(PREMIER);
        }
        // `SEAUX` est une puissance de deux : le masque est le reste.
        let masque = u64::try_from(SEAUX).unwrap_or(1).wrapping_sub(1);
        usize::try_from(empreinte & masque).unwrap_or(0)
    }

    /// Cette source a-t-elle droit à une réponse maintenant ? Si oui, elle
    /// la paie — de son seau ET du seau commun.
    ///
    /// **Le seau commun se regarde d'abord, sans rien prendre** : quand
    /// l'écho est saturé, une arrivée coûte une comparaison et rien d'autre.
    /// Et une source déjà à sec n'entame pas le commun : un bavard seul ne
    /// fait pas taire les autres.
    ///
    /// # Erreurs
    ///
    /// [`Silence::DebitTotal`], [`Silence::DebitSource`].
    pub fn admettre(&mut self, source: IpAddr, maintenant_ms: u64) -> Result<(), Silence> {
        self.total.remplir(maintenant_ms, DEBIT_TOTAL, DEBIT_TOTAL);
        if !self.total.a_un_jeton() {
            return Err(Silence::DebitTotal);
        }
        let place = self.place(&prefixe_de_source(source));
        // `place` est masquée par `SEAUX - 1` : l'index ne sort jamais.
        let seau = &mut self.seaux[place];
        seau.remplir(maintenant_ms, DEBIT_PAR_SOURCE, RAFALE_PAR_SOURCE);
        if !seau.a_un_jeton() {
            return Err(Silence::DebitSource);
        }
        seau.prendre();
        self.total.prendre();
        Ok(())
    }
}

// ── La mémoire des défis ────────────────────────────────────────────────────

/// Les défis des sondes auxquelles l'écho a répondu, **deux minutes** durant,
/// [`DEFIS_RETENUS`] au plus — l'anti-rejeu.
///
/// Un anneau : le plus vieux sort quand un nouveau entre. Il ne se parcourt
/// que pour une sonde AUTHENTIQUE, donc au plus [`DEBIT_TOTAL`] fois par
/// seconde.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoireDesDefis {
    vus: [([u8; 16], u64); DEFIS_RETENUS],
    /// La place du prochain défi retenu.
    prochain: usize,
    /// Combien de places sont occupées.
    occupees: usize,
}

impl Default for MemoireDesDefis {
    fn default() -> Self {
        Self::nouvelle()
    }
}

impl MemoireDesDefis {
    /// Vide.
    #[must_use]
    pub const fn nouvelle() -> Self {
        Self {
            vus: [([0; 16], 0); DEFIS_RETENUS],
            prochain: 0,
            occupees: 0,
        }
    }

    /// Retient ce défi, s'il n'a pas été vu dans les deux dernières minutes ;
    /// rend `false` — et ne retient rien — s'il l'a été.
    pub fn retenir(&mut self, defi: &DefiEcho, maintenant_ms: u64) -> bool {
        let deja =
            self.vus.iter().take(self.occupees).any(|(vu, a)| {
                vu == defi.octets() && maintenant_ms.abs_diff(*a) <= FENETRE_HORLOGE_MS
            });
        if deja {
            return false;
        }
        // `prochain` est pris modulo `DEFIS_RETENUS` : l'index ne sort jamais.
        self.vus[self.prochain] = (*defi.octets(), maintenant_ms);
        self.prochain = self
            .prochain
            .saturating_add(1)
            .checked_rem(DEFIS_RETENUS)
            .unwrap_or(0);
        self.occupees = self.occupees.saturating_add(1).min(DEFIS_RETENUS);
        true
    }
}

// ── Le répondeur ────────────────────────────────────────────────────────────

/// Pourquoi l'écho se tait. **Rien de ceci ne part sur le fil.**
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Silence {
    /// Cette source a épuisé son débit.
    DebitSource,
    /// L'écho a épuisé son débit total.
    DebitTotal,
    /// Ce n'est pas une sonde lisible — longueur, en-tête, bourrage, jeton.
    Illisible(Refus),
    /// Une sonde lisible, que l'écho ne croit pas. [`RefusSonde::HorsFenetre`]
    /// est celle qui dit que **l'horloge de cette machine dérive** : la
    /// signature d'un annuaire cru a tenu, la date non.
    Refusee(RefusSonde),
    /// Ce défi a déjà servi dans les deux dernières minutes.
    Rejeu,
}

/// Une réponse à envoyer, et à qui elle est faite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Repondue {
    /// Les 132 octets à renvoyer à la source.
    pub reponse: [u8; REPONSE_OCTETS],
    /// Qui a sondé : le `n-…` d'un annuaire, ou le `m-…` du porteur d'un
    /// jeton.
    pub sondeur: Identifiant,
}

/// L'annuaire qui tient le bail, tel que la poignée de main l'a vérifié.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Bail {
    annuaire: Identifiant,
    cle: ClePublique,
    /// Est-ce une racine au sens de cette invocation — une racine embarquée,
    /// ou l'annuaire que l'utilisateur a nommé comme tel —, et non un annuaire
    /// local joint par un renvoi ? Seule une racine délivre des jetons.
    racine: bool,
}

/// Ce que `asl echo` tient : qui il croit, ce qu'il a vu, ce qu'il a dépensé.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repondeur {
    moi: Identifiant,
    ma_cle: ClePublique,
    racines: [Option<(Identifiant, ClePublique)>; RACINES_MAX],
    bail: Option<Bail>,
    debit: Debit,
    vus: MemoireDesDefis,
}

impl Repondeur {
    /// Le répondeur de cette machine, qui croit les racines embarquées et
    /// aucun bail encore.
    ///
    /// `graine` est celle du [`Debit`] ; elle vient de l'aléa du noyau.
    #[must_use]
    pub fn nouveau(identite: &Identite, graine: u64) -> Self {
        let mut racines = [None; RACINES_MAX];
        let embarquees = crate::racines::RACINES
            .iter()
            .filter_map(|racine| racine.identite().zip(racine.cle_publique()));
        for (place, racine) in racines.iter_mut().zip(embarquees) {
            *place = Some(racine);
        }
        Self {
            moi: identite.machine(),
            ma_cle: identite.publique(),
            racines,
            bail: None,
            debit: Debit::nouveau(graine),
            vus: MemoireDesDefis::nouvelle(),
        }
    }

    /// L'annuaire qui tient le bail maintenant — son `n-…` et la clé que la
    /// poignée de main a vérifiée —, et s'il est une racine.
    ///
    /// **C'est le seul annuaire non embarqué que l'écho croit** (décision 91 ;
    /// E4) : le membre d'un annuaire local vers lequel un `421` a renvoyé, ou
    /// l'annuaire nommé par `--directory`. Un annuaire local ne délivre pas de
    /// jeton — `racine` le dit.
    pub const fn tenir_le_bail(&mut self, annuaire: Identifiant, cle: ClePublique, racine: bool) {
        self.bail = Some(Bail {
            annuaire,
            cle,
            racine,
        });
    }

    /// Le bail est perdu : jusqu'au prochain, seules les racines embarquées
    /// sont crues.
    pub const fn lacher_le_bail(&mut self) {
        self.bail = None;
    }

    /// La clé d'un annuaire qu'on croit pour une sonde d'annuaire : celui du
    /// bail, ou une racine embarquée.
    fn cle_d_annuaire(&self, annuaire: Identifiant) -> Option<ClePublique> {
        self.bail
            .filter(|bail| bail.annuaire == annuaire)
            .map(|bail| bail.cle)
            .or_else(|| self.cle_de_racine_embarquee(annuaire))
    }

    /// La clé d'une racine qu'on croit pour un jeton : une racine embarquée,
    /// ou l'annuaire du bail s'il est une racine.
    fn cle_de_racine(&self, annuaire: Identifiant) -> Option<ClePublique> {
        self.bail
            .filter(|bail| bail.racine && bail.annuaire == annuaire)
            .map(|bail| bail.cle)
            .or_else(|| self.cle_de_racine_embarquee(annuaire))
    }

    fn cle_de_racine_embarquee(&self, annuaire: Identifiant) -> Option<ClePublique> {
        self.racines
            .iter()
            .flatten()
            .find(|(racine, _)| *racine == annuaire)
            .map(|(_, cle)| *cle)
    }

    /// Ce datagramme appelle-t-il une réponse ? Si oui, la voici, signée.
    ///
    /// `identite` est celle de cette machine — la même que celle du
    /// constructeur ; `source` l'adresse d'où le datagramme est venu, telle
    /// que la socket la rend ; `maintenant_ms` l'heure murale.
    ///
    /// # Erreurs
    ///
    /// [`Silence`] : la raison de se taire.
    pub fn recevoir(
        &mut self,
        identite: &Identite,
        datagramme: &[u8],
        source: SocketAddr,
        maintenant_ms: u64,
    ) -> Result<Repondue, Silence> {
        if datagramme.len() != REQUETE_OCTETS {
            return Err(Silence::Illisible(Refus::Longueur {
                attendue: REQUETE_OCTETS,
                obtenue: datagramme.len(),
            }));
        }
        self.debit.admettre(source.ip(), maintenant_ms)?;
        let acceptee = asl_echo::accepter(
            datagramme,
            self.moi,
            &self.ma_cle,
            &|annuaire| self.cle_d_annuaire(annuaire),
            &|annuaire| self.cle_de_racine(annuaire),
            maintenant_ms,
        )
        .map_err(|refus| match refus {
            asl_echo::RefusRequete::Illisible(quoi) => Silence::Illisible(quoi),
            asl_echo::RefusRequete::Refusee(quoi) => Silence::Refusee(quoi),
        })?;
        if !self.vus.retenir(&acceptee.defi(), maintenant_ms) {
            return Err(Silence::Rejeu);
        }
        Ok(Repondue {
            reponse: identite.repondre_a_l_echo(&acceptee, source).octets(),
            sondeur: acceptee.sondeur(),
        })
    }
}

// ── Le sondeur ──────────────────────────────────────────────────────────────

/// Ce que `asl ping` conclut d'un datagramme revenu d'un candidat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Constat {
    /// **Joignable, et c'est elle** : la réponse à l'un de nos défis — celui
    /// de rang `rang` —, faite pour nous, signée par la clé que le jeton
    /// porte.
    Prouvee {
        /// Le rang du défi auquel elle répond, dans la liste passée.
        rang: usize,
        /// L'adresse sous laquelle l'écho a vu la sonde — la nôtre, signée.
        vu_comme: SocketAddr,
    },
    /// **Quelqu'un d'autre répond à cette adresse** : une réponse bien formée,
    /// à notre défi, mais d'une autre machine ou sous une autre clé — une
    /// adresse réattribuée, un NAT partagé, un port repris.
    AutreCle,
    /// Une réponse mal formée, ou d'une autre longueur.
    Illisible(Refus),
    /// Une réponse qui n'est pas pour nous — un autre défi, un autre
    /// sondeur : on l'ignore, et l'on attend.
    PasPourMoi,
}

/// Juge un datagramme revenu : est-ce la preuve attendue ?
///
/// `defis` sont ceux qu'on a envoyés à ce candidat ; `cible` la machine
/// visée, `moi` la machine qui sonde, `cle_cible` la clé que le jeton porte
/// pour la cible — **signée par la racine**, c'est contre elle, et non
/// contre ce que la réponse dit, qu'on vérifie.
#[must_use]
pub fn constater(
    datagramme: &[u8],
    defis: &[DefiEcho],
    cible: Identifiant,
    moi: Identifiant,
    cle_cible: &ClePublique,
) -> Constat {
    let reponse = match Reponse::lire(datagramme) {
        Ok(reponse) => reponse,
        Err(quoi) => return Constat::Illisible(quoi),
    };
    let Some(rang) = defis.iter().position(|defi| *defi == reponse.defi()) else {
        return Constat::PasPourMoi;
    };
    match reponse.verifier(&reponse.defi(), cible, moi, cle_cible) {
        Ok(()) => Constat::Prouvee {
            rang,
            vu_comme: reponse.adresse().source(),
        },
        Err(RefusReponse::AutreDefi | RefusReponse::AutreSondeur) => Constat::PasPourMoi,
        Err(RefusReponse::AutreMachine | RefusReponse::Signature) => Constat::AutreCle,
    }
}
