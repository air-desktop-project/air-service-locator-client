//! La bibliothèque des DEUX bouts : ce qu'un daemon lie pour s'annoncer, et ce
//! qu'un de ses clients lie pour retrouver le port où le joindre.
//!
//! # Le problème que tout ceci existe pour résoudre
//!
//! Un daemon qui n'a pas de numéro de port fixe est un daemon qu'on ne peut pas
//! joindre — sauf si quelque chose sait où il est. Cette crate est ce quelque
//! chose, vu des deux côtés :
//!
//! - au démarrage, le daemon obtient un port du système, puis l'ANNONCE ;
//! - plus tard, son client DEMANDE ce port et ouvre la connexion.
//!
//! # Ce qui contraint cette crate plus que les autres
//!
//! **Elle est liée par du code qui n'est pas le nôtre.** Sa surface publique est
//! donc un engagement, et son graphe de dépendances aussi : ce qu'elle tire, un
//! daemon tiers l'embarque. Elle ne doit jamais dépendre d'`asl-store` ni
//! d'`asl-annuaire` — s'annoncer ne doit pas coûter d'embarquer la base de
//! données du service.
//!
//! **Et elle doit survivre à l'annuaire.** Un service de découverte injoignable
//! ne doit pas empêcher un daemon de démarrer. La règle est arrêtée
//! (`protocole.md` §1.4) : rendre la main immédiatement, se connecter en
//! arrière-plan, essayer les annuaires dans l'ordre — IPv6 avant IPv4 —,
//! réessayer avec un recul exponentiel et un bruit de ±20 %, et **ne jamais
//! abandonner**.
//!
//! **Ce mécanisme EST aussi la bascule entre les deux annuaires racines**, et il
//! n'y en a pas d'autre : l'état vivant n'est délibérément pas répliqué, parce
//! qu'il se reconstruit ici, tout seul, en un keepalive (`annuaires.md` §3). Ce
//! qui ressemble à du code de reprise est en réalité le mécanisme de haute
//! disponibilité du produit entier.
//!
//! # Le transport
//!
//! **HTTP/3 sur QUIC, connexion TENUE, IPv6 d'abord.** Le daemon ouvre une
//! connexion et la maintient par un keepalive : la connexion *est* le bail. Il
//! n'y a pas de réannonce périodique à écrire.
//!
//! Les valeurs de temps — keepalive, délai d'inactivité — **viennent du
//! serveur** et ne sont jamais figées ici. Le bon delta se mesure sur des NAT
//! réels et n'est pas encore mesuré ; le figer dans cette crate exigerait de
//! mettre à jour tous les daemons installés chez des tiers, ce qui ne se
//! produira jamais.
//!
//! # Ce que le porteur doit poser sur la machine
//!
//! **Rien. La bibliothèque génère sa propre paire de clés Ed25519**
//! (`docs/modele.md` §2.3), et la partie privée ne quitte jamais la machine.
//!
//! **AUCUN SECRET PARTAGÉ N'EST POSÉ** (contrainte C14). L'enrôlement se fait
//! avec un code court, à usage unique et valable quelques minutes, que
//! l'application affiche : `asl enrole <code>`. La bibliothèque génère alors sa
//! paire et présente sa clé publique. Le code n'ouvre qu'une opération — lier une
//! clé —, et le justificatif durable est la clé, que personne n'a jamais
//! transmise.
//!
//! Le même objet des deux côtés : la machine qui héberge le daemon porte la
//! capacité `annonce`, celle qui consomme porte `lecture`. Une machine n'est pas
//! « une machine à daemon » — c'est n'importe quelle machine d'un utilisateur.
//!
//! **L'authentification est portée par la CONNEXION** : la clé est prouvée une
//! fois à l'établissement, et toutes les requêtes en héritent. Il n'y a pas de
//! jeton à joindre à chaque appel, donc pas de jeton à faire fuir.
//!
//! **Il n'y a aucun mode anonyme à implémenter** (contrainte C10) : une
//! résolution hors d'une connexion authentifiée n'existe pas, et un client qui
//! prévoirait un chemin de repli « sans authentification » coderait une porte
//! que le serveur n'ouvre pas.
//!
//! # Ce qui est écrit, et ce qui ne l'est pas
//!
//! **Écrit** : [`Reprise`], le recul entre deux tentatives ; [`Tournee`], le
//! parcours des annuaires qui l'emploie — IPv6 d'abord, l'attente entre les
//! TOURS et non entre les annuaires ; [`Identite`], ce qu'une machine détient et
//! ce qu'elle en fait ; et [`Enrolement`], comment elle acquiert tout cela.
//!
//! **Pas écrit** : le transport. Tant que la pile QUIC n'est pas câblée, cette
//! crate ne fait aucune entrée-sortie et reste `no_std`. Ce n'est pas un état
//! provisoire subi : c'est ce qui permet d'éprouver la politique de reprise sans
//! attendre une seconde de délai, comme l'étage 2 du serveur éprouve une
//! expiration sans attendre quarante-cinq secondes.

#![no_std]

use asl_cle::{ClePublique, CleSecrete, CodeEnrolement, Defi, LiaisonDeCanal, Signature};

/// L'étiquette que les deux camps donnent à leur exportateur TLS.
///
/// # ELLE EST RÉEXPORTÉE POUR QUE PERSONNE N'EN INVENTE UNE
///
/// La liaison de canal se dérive de la poignée de main (RFC 8446 §7.5), et
/// **les deux camps doivent employer la même étiquette** : si elles divergeaient
/// d'un octet, aucune signature ne vérifierait plus, et la panne serait
/// indiscernable d'une clé fausse.
///
/// Un porteur qui écrirait la chaîne à la main dans son propre code aurait une
/// chance de se tromper, et zéro chance de s'en apercevoir avant la production.
pub use asl_cle::ETIQUETTE_LIAISON;

/// Les fautes d'`asl-cle`, réexportées pour que l'appelant n'ait pas à dépendre
/// de cette crate pour lire un refus.
pub use asl_cle::Faute as FauteDeCle;
use asl_id::{Genre, Identifiant};
use asl_proto::{Annonce, Erreur as ErreurProto, NomService, PointEcoute};
use core::net::{IpAddr, SocketAddr};

// ── La reprise ──────────────────────────────────────────────────────────────

/// Le délai avant le premier réessai, en millisecondes.
pub const RECUL_INITIAL_MS: u64 = 1_000;

/// Le bruit appliqué au délai, en centièmes.
///
/// ±20 % : le délai rendu vaut entre 80 % et 120 % du délai calculé.
pub const BRUIT_CENTIEMES: u64 = 20;

/// Ce qui peut clocher dans la construction d'une reprise ou d'une identité.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Faute {
    /// Le plafond de recul est nul : la reprise tournerait en boucle serrée.
    PlafondNul,
    /// L'identifiant fourni n'est pas celui d'une machine.
    PasUneMachine {
        /// Le genre fourni.
        obtenu: Genre,
    },
    /// La composition de l'annonce a été refusée par le protocole.
    Protocole(ErreurProto),
    /// Le texte donné n'est pas un code d'enrôlement.
    ///
    /// Longueur, symbole hors de l'alphabet, tiret égaré. **Le détail vient
    /// d'`asl-cle`**, parce que c'est là que la grammaire est écrite — et
    /// qu'elle est écrite une fois, pour les deux camps.
    CodeRefuse(FauteDeCle),
}

/// La politique de reconnexion à l'annuaire.
///
/// # CE CODE N'EST PAS DU CODE DE REPRISE, C'EST LE MÉCANISME DE HAUTE DISPONIBILITÉ
///
/// L'état vivant n'est délibérément pas répliqué entre les annuaires racines
/// (`annuaires.md` §3) : quand l'un tombe, le daemon se reconnecte à l'autre et
/// réannonce, et l'état se reconstruit en un keepalive. **Il n'y a pas d'autre
/// bascule à écrire — c'est celle-ci.** Ce qui ressemble à de la robustesse
/// d'appoint est en réalité la moitié du plan de continuité du produit.
///
/// # LE BRUIT N'EST PAS DU RAFFINEMENT
///
/// Sans lui, mille daemons dont l'annuaire vient de tomber réessaient à la même
/// seconde et le remettent à terre à l'instant où il se relève. Il coûte une
/// ligne, et il est ce qui distingue une reprise d'une attaque par déni de
/// service que l'on s'inflige à soi-même.
///
/// # ELLE N'ABANDONNE JAMAIS
///
/// Un daemon qui tourne depuis un mois doit se réannoncer tout seul quand
/// l'annuaire revient. Le compteur d'essais SATURE au lieu de déborder : après
/// soixante-quatre échecs, un décalage non saturé rendrait un délai nul, et la
/// reprise deviendrait la boucle serrée qu'elle existe pour éviter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reprise {
    plafond_ms: u64,
    essais: u32,
}

impl Reprise {
    /// Une politique de reprise, plafonnée à la cadence de keepalive.
    ///
    /// **Le plafond vient du serveur** : c'est lui qui annonce la cadence
    /// attendue (`modele.md` §4.1). Le figer ici exigerait de mettre à jour tous
    /// les daemons installés chez des tiers le jour où elle changera.
    ///
    /// # Erreurs
    ///
    /// [`Faute::PlafondNul`].
    pub const fn nouvelle(plafond_ms: u64) -> Result<Self, Faute> {
        if plafond_ms == 0 {
            return Err(Faute::PlafondNul);
        }
        Ok(Self {
            plafond_ms,
            essais: 0,
        })
    }

    /// Le délai avant le prochain essai, en millisecondes.
    ///
    /// `alea` est **fourni par l'appelant** : cette crate ne tire rien
    /// elle-même, ce qui la garde éprouvable et sans entrée-sortie. N'importe
    /// quelle valeur convient — le bruit n'a pas besoin d'être imprévisible,
    /// seulement d'être réparti.
    #[must_use]
    pub fn prochain_delai(&mut self, alea: u16) -> u64 {
        // `1_000 * 2^essais`, sans jamais déborder : au-delà du plafond, la
        // valeur exacte n'a plus d'importance.
        let brut = RECUL_INITIAL_MS
            .checked_shl(self.essais)
            .unwrap_or(u64::MAX)
            .min(self.plafond_ms);

        self.essais = self.essais.saturating_add(1);

        // Le bruit, en arithmétique entière : de 80 % à 120 %.
        //
        // **L'ORDRE DES OPÉRATIONS COMPTE.** Multiplier avant de diviser garde
        // la précision ; l'inverse ramènerait tous les petits délais à zéro, et
        // un délai nul est la boucle serrée qu'on évite.
        let centiemes = 100_u64.saturating_sub(BRUIT_CENTIEMES).saturating_add(
            u64::from(alea)
                .saturating_mul(BRUIT_CENTIEMES.saturating_mul(2))
                .checked_div(u64::from(u16::MAX))
                .unwrap_or(0),
        );
        let bruite = brut
            .saturating_mul(centiemes)
            .checked_div(100)
            .unwrap_or(brut);

        // **JAMAIS ZÉRO.** Un délai nul ferait tourner la reprise en boucle
        // serrée, ce qui est exactement l'inverse de ce qu'elle protège.
        bruite.max(1)
    }

    /// La connexion a abouti : le recul repart de zéro.
    pub const fn reussite(&mut self) {
        self.essais = 0;
    }

    /// Le nombre d'échecs consécutifs.
    #[must_use]
    pub const fn essais(&self) -> u32 {
        self.essais
    }
}

// ── La tournée des annuaires ────────────────────────────────────────────────

/// La place, dans la liste, du `rang`-ième annuaire à essayer.
///
/// # IPv6 D'ABORD, ET C'EST UNE DÉCISION DE PRODUIT
///
/// `annuaires.md` §1 : ce service existe pour des daemons qui n'ont pas de port
/// fixe, et la moitié d'entre eux vivront derrière un NAT qu'IPv6 supprime. Un
/// client qui essaierait IPv4 en premier prendrait le chemin dégradé chaque fois
/// que les deux existent — c'est-à-dire toujours, puisque les annuaires racines
/// publient les deux.
///
/// **L'ORDRE EST STABLE À L'INTÉRIEUR DE CHAQUE FAMILLE.** L'opérateur a écrit
/// sa liste dans un ordre, et cet ordre est sa préférence ; la seule chose qui
/// la réécrit est la règle ci-dessus.
///
/// # POURQUOI CETTE FONCTION VIT ICI, ET NON DANS LE TRANSPORT
///
/// Parce que c'est une DÉCISION, pas une entrée-sortie. Écrite dans la boucle
/// asynchrone, elle ne s'éprouverait qu'avec deux annuaires réels dont l'un est
/// éteint ; écrite ici, elle s'éprouve sur une liste littérale.
///
/// Rend `None` quand `rang` est au-delà de la liste — c'est ce qui dit à
/// [`Tournee`] qu'un tour complet vient d'échouer.
#[must_use]
pub fn place_en_ordre(annuaires: &[SocketAddr], rang: usize) -> Option<usize> {
    let combien_v6 = annuaires.iter().filter(|ou| ou.is_ipv6()).count();
    let (cherche_v6, mut reste) = match rang.checked_sub(combien_v6) {
        // Au-delà des IPv6 : on cherche la `apres`-ième IPv4.
        Some(apres) => (false, apres),
        // Encore dans les IPv6.
        None => (true, rang),
    };
    for (place, ou) in annuaires.iter().enumerate() {
        if ou.is_ipv6() == cherche_v6 {
            if reste == 0 {
                return Some(place);
            }
            reste = reste.saturating_sub(1);
        }
    }
    None
}

/// Ce qu'une tournée dit de faire : attendre, puis essayer celui-là.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Etape {
    /// La place, dans la liste qu'on a passée, de l'annuaire à essayer.
    pub place: usize,
    /// Combien de millisecondes attendre AVANT de l'essayer.
    ///
    /// **Zéro tant que le tour n'est pas bouclé** — voir [`Tournee::prochaine`].
    pub attendre_ms: u64,
}

/// Le parcours des annuaires, et le recul entre deux tours.
///
/// # LE RECUL SÉPARE LES TOURS, ET NON LES ANNUAIRES
///
/// C'est la décision qui donne à ce type sa raison d'exister. Reculer après
/// chaque annuaire rendrait la bascule vers le second annuaire racine plus lente
/// que la panne du premier : le daemon attendrait une seconde, puis deux, avant
/// d'essayer une machine qui, elle, répond tout de suite.
///
/// On essaie donc TOUS les annuaires d'affilée, sans attendre, et l'on ne recule
/// qu'une fois le tour bouclé — c'est-à-dire une fois établi que le service
/// entier est injoignable, ce qui est le seul cas où attendre a un sens.
///
/// # ELLE REPART DU HAUT APRÈS CHAQUE RÉUSSITE, ET CELA COÛTE
///
/// Quand le premier annuaire est éteint et le second répond, chaque
/// reconnexion recommence par le premier et perd le délai de poignée de main
/// avant d'arriver au second.
///
/// **C'est le prix de l'ordre annoncé, et il est payé exprès.** Une tournée qui
/// resterait sur le second parce qu'il a marché une fois ferait de « IPv6
/// d'abord, puis l'ordre de l'opérateur » une phrase fausse dès la première
/// panne — et personne ne s'en apercevrait, puisque tout marcherait.
///
/// # ELLE N'ABANDONNE JAMAIS
///
/// Elle rend `None` dans un seul cas : une liste vide. Ce n'est pas un échec de
/// connexion, c'est une CONFIGURATION — un daemon sans annuaire doit
/// l'apprendre, pas tourner en rond en silence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tournee {
    reprise: Reprise,
    rang: usize,
}

impl Tournee {
    /// Une tournée qui recule selon cette politique.
    #[must_use]
    pub const fn nouvelle(reprise: Reprise) -> Self {
        Self { reprise, rang: 0 }
    }

    /// L'annuaire suivant, et ce qu'il faut attendre avant de l'essayer.
    ///
    /// `alea` est fourni par l'appelant, comme pour [`Reprise::prochain_delai`] :
    /// cette crate ne tire rien elle-même.
    ///
    /// Rend `None` si, et seulement si, la liste est vide.
    pub fn prochaine(&mut self, annuaires: &[SocketAddr], alea: u16) -> Option<Etape> {
        if annuaires.is_empty() {
            return None;
        }

        // Le tour est bouclé : c'est ici, et nulle part ailleurs, qu'on attend.
        let attendre_ms = if self.rang >= annuaires.len() {
            self.rang = 0;
            self.reprise.prochain_delai(alea)
        } else {
            0
        };

        let place = place_en_ordre(annuaires, self.rang).expect(
            "le rang vient d'être ramené sous la longueur, et la liste n'est pas vide : \
             `place_en_ordre` rend toujours une place pour un rang qui est dans la liste",
        );
        self.rang = self.rang.saturating_add(1);
        Some(Etape { place, attendre_ms })
    }

    /// La connexion a abouti : le recul repart de zéro, et le tour du haut.
    pub const fn reussite(&mut self) {
        self.rang = 0;
        self.reprise.reussite();
    }

    /// Le nombre de TOURS complets qui ont échoué.
    ///
    /// Ce n'est pas le nombre d'annuaires essayés : c'est le nombre de fois où
    /// le service entier s'est révélé injoignable, ce qui est la grandeur dont
    /// dépend le recul.
    #[must_use]
    pub const fn tours_perdus(&self) -> u32 {
        self.reprise.essais()
    }
}

// ── La liaison de canal ─────────────────────────────────────────────────────

/// La liaison de canal de cette connexion, depuis ce que l'exportateur a rendu.
///
/// # CE QU'IL FAUT LUI DONNER, ET RIEN D'AUTRE
///
/// Les trente-deux octets que la pile TLS de la connexion en cours a exportés
/// avec [`ETIQUETTE_LIAISON`] et **aucun contexte** :
///
/// ```text
/// connexion.export(asl_client::ETIQUETTE_LIAISON, None)
/// ```
///
/// # POURQUOI CETTE FONCTION EXISTE, PUISQU'ELLE NE FAIT RIEN
///
/// Elle ne calcule rien, en effet : elle NOMME. `asl_cle::LiaisonDeCanal::
/// depuis_octets` accepte n'importe quels trente-deux octets — c'est ce qu'il
/// faut, puisque cette crate ne peut pas vérifier d'où ils viennent. Ce qu'on
/// peut faire, c'est mettre l'étiquette et l'appel au même endroit que le type,
/// pour que le porteur n'ait rien à recopier depuis un document.
///
/// **Elle ne peut pas vérifier que ce qu'on lui donne est un exporteur.** Un
/// condensat de certificat y passerait, et l'authentification échouerait alors
/// à la première connexion — bruyamment, ce qui est le bon moment.
#[must_use]
pub const fn liaison_exportee(octets: [u8; asl_cle::LIAISON_OCTETS]) -> LiaisonDeCanal {
    LiaisonDeCanal::depuis_octets(octets)
}

// ── L'enrôlement ────────────────────────────────────────────────────────────

/// Ce qu'occupe le corps de `POST /v1/enrolement`, en octets.
///
/// Le code, la clé publique, la preuve de possession : dix, trente-deux,
/// soixante-quatre. **Trois champs de longueur fixe, aucun préfixe, aucune
/// ambiguïté** — c'est l'argument d'`asl_cle::message_a_signer`, appliqué au
/// transport de la preuve.
pub const ENROLEMENT_OCTETS: usize =
    asl_cle::CODE_SYMBOLES + asl_cle::CLE_PUBLIQUE_OCTETS + asl_cle::SIGNATURE_OCTETS;

/// Une clé fraîchement générée, qui n'a pas encore de nom.
///
/// # POURQUOI CET ÉTAT EXISTE, ET N'EST PAS UNE [`Identite`] INCOMPLÈTE
///
/// `POST /v1/enrolement` **ne nomme pas la machine** : le code la désigne, et
/// personne d'autre ne la désigne — sans quoi l'annuaire croirait sur parole
/// celui qui la nomme. La machine ne connaît donc son identifiant qu'APRÈS,
/// dans la réponse.
///
/// Entre les deux, elle détient une clé et rien d'autre. Faire porter cet état à
/// [`Identite`] aurait demandé un identifiant facultatif, c'est-à-dire une
/// identité qui ne sait pas qui elle est — et un `unwrap` quelque part.
///
/// # LA CLÉ EST GÉNÉRÉE ICI, ET ELLE NE SORT PAS
///
/// C'est le point de `modele.md` §2.3 : ce qui se tape sur la machine est un
/// code à usage unique, jamais une clé. Le justificatif durable est la paire, et
/// sa moitié privée ne quitte pas la machine.
#[derive(Debug)]
pub struct Enrolement {
    secrete: CleSecrete,
}

impl Enrolement {
    /// Génère une paire, à partir de trente-deux octets d'entropie.
    ///
    /// **L'aléa vient de l'appelant**, et sa qualité est sa responsabilité :
    /// une clé tirée d'un compteur serait devinable, et toute
    /// l'authentification du produit repose là-dessus.
    #[must_use]
    pub fn nouveau(entropie: [u8; 32]) -> Self {
        Self {
            secrete: CleSecrete::depuis_entropie(entropie),
        }
    }

    /// La clé publique qu'on va présenter.
    #[must_use]
    pub fn publique(&self) -> ClePublique {
        self.secrete.publique()
    }

    /// Compose le corps de `POST /v1/enrolement`.
    ///
    /// `code` est ce que l'administrateur a tapé — `asl enrole 4K9M2-P7R1T`. Il
    /// est **canonisé ici** : la casse est indifférente, le tiret d'affichage
    /// facultatif, et les confusions de Crockford rattrapées. C'est indispensable
    /// et non commode — l'annuaire cherche par l'empreinte de la forme
    /// canonique, et un `O` envoyé pour un `0` ne trouverait rien.
    ///
    /// `defi` et `liaison` viennent de la connexion en cours : le premier de
    /// `GET /v1/defi`, la seconde de [`liaison_exportee`].
    ///
    /// # LA PREUVE PORTE SUR LA CLÉ, ET NON SUR UN IDENTIFIANT
    ///
    /// Elle ne peut pas porter sur un identifiant : il n'existe pas encore.
    /// Signer la clé qu'on présente prouve exactement ce qu'il faut prouver —
    /// qu'on en détient la partie privée — et son séparateur de domaine est
    /// distinct, pour qu'une preuve d'authentification captée ailleurs ne vaille
    /// jamais preuve de possession ici.
    ///
    /// # Erreurs
    ///
    /// [`Faute::CodeRefuse`] si le texte n'est pas un code.
    pub fn corps(
        &self,
        code: &str,
        defi: &Defi,
        liaison: &LiaisonDeCanal,
    ) -> Result<[u8; ENROLEMENT_OCTETS], Faute> {
        let code = CodeEnrolement::analyser(code).map_err(Faute::CodeRefuse)?;
        let publique = self.secrete.publique().octets();
        let preuve = self.secrete.prouver_la_possession(defi, liaison);

        let source = code
            .texte()
            .as_bytes()
            .iter()
            .chain(publique.iter())
            .chain(preuve.octets().iter());

        let mut corps = [0_u8; ENROLEMENT_OCTETS];
        for (place, octet) in corps.iter_mut().zip(source) {
            *place = *octet;
        }
        Ok(corps)
    }

    /// L'annuaire a nommé cette machine : voici son identité.
    ///
    /// **LA CLÉ NE CHANGE PAS**, et c'est le point : celle qui vient d'être liée
    /// est celle qui signera. Fabriquer une identité neuve ici perdrait la paire
    /// que l'annuaire vient d'accepter.
    ///
    /// # Erreurs
    ///
    /// [`Faute::PasUneMachine`] si la réponse ne nomme pas une machine.
    pub fn nommee(self, machine: Identifiant) -> Result<Identite, Faute> {
        if machine.genre() != Genre::Machine {
            return Err(Faute::PasUneMachine {
                obtenu: machine.genre(),
            });
        }
        Ok(Identite {
            machine,
            secrete: self.secrete,
        })
    }
}

// ── L'identité d'une machine ────────────────────────────────────────────────

/// Ce qu'une machine détient, et ce qu'elle en fait.
///
/// # LA CLÉ EST GÉNÉRÉE ICI, ET ELLE NE SORT PAS
///
/// L'annuaire ne connaît que la partie publique (`modele.md` §2.3). **Aucun
/// secret partagé n'est posé sur la machine** : ce qui s'y tape est un code
/// d'enrôlement à usage unique, qui n'ouvre qu'une opération — lier cette clé.
#[derive(Debug)]
pub struct Identite {
    machine: Identifiant,
    secrete: CleSecrete,
}

impl Identite {
    /// Fabrique une identité à partir de trente-deux octets d'entropie.
    ///
    /// **L'aléa vient de l'appelant**, et sa qualité est sa responsabilité :
    /// une clé tirée d'un compteur serait devinable, et toute
    /// l'authentification du produit repose là-dessus.
    ///
    /// # Erreurs
    ///
    /// [`Faute::PasUneMachine`].
    pub fn nouvelle(machine: Identifiant, entropie: [u8; 32]) -> Result<Self, Faute> {
        if machine.genre() != Genre::Machine {
            return Err(Faute::PasUneMachine {
                obtenu: machine.genre(),
            });
        }
        Ok(Self {
            machine,
            secrete: CleSecrete::depuis_entropie(entropie),
        })
    }

    /// L'identifiant de la machine.
    #[must_use]
    pub const fn machine(&self) -> Identifiant {
        self.machine
    }

    /// La clé publique, celle qu'on confie à l'annuaire à l'enrôlement.
    #[must_use]
    pub fn publique(&self) -> ClePublique {
        self.secrete.publique()
    }

    /// Répond au défi de l'annuaire.
    ///
    /// **LA LIAISON EST CELLE DE LA CONNEXION EN COURS**, exportée de sa
    /// poignée de main — voir [`liaison_exportee`]. C'est elle qui ferme le
    /// relais : un intermédiaire qui transmettrait le défi du vrai annuaire à
    /// cette machine, puis la signature en retour, mène SA propre poignée de
    /// main avec elle, et n'obtient donc pas la même valeur.
    ///
    /// # Erreurs
    ///
    /// Celles d'`asl_cle`. **Elles ne peuvent pas arriver ici** : le
    /// constructeur a déjà refusé tout identifiant qui n'est pas une machine.
    ///
    /// Le `Result` est donc une formalité, et il est PROPAGÉ TEL QUEL plutôt
    /// que traduit. Une traduction aurait posé une branche que rien ne peut
    /// atteindre — du code mort sur un chemin cryptographique, c'est-à-dire
    /// du code que personne n'éprouvera jamais et que tout le monde croira
    /// éprouvé.
    pub fn repondre(&self, defi: &Defi, liaison: &LiaisonDeCanal) -> Result<Signature, FauteDeCle> {
        self.secrete.signer(self.machine, defi, liaison)
    }

    /// Compose l'annonce de ce daemon.
    ///
    /// **L'annonce est validée à la construction** : une annonce qui existe est
    /// une annonce valide, et le daemon apprend ici — et non après un
    /// aller-retour réseau — qu'il annonce deux fois le même point ou qu'il n'en
    /// annonce aucun.
    ///
    /// # Erreurs
    ///
    /// [`Faute::Protocole`].
    pub fn annoncer<'a>(
        &self,
        service: NomService<'a>,
        points: &'a [PointEcoute],
        adresses_locales: &'a [IpAddr],
    ) -> Result<Annonce<'a>, Faute> {
        Annonce::nouvelle(self.machine, service, points, adresses_locales).map_err(Faute::Protocole)
    }
}
