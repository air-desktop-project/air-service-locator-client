//! La reprise : ce qui déroule [`asl_client::Tournee`] sur de vraies sockets.
//!
//! # CE N'EST PAS DU CODE DE ROBUSTESSE, C'EST LE PLAN DE CONTINUITÉ
//!
//! `annuaires.md` §3 : l'état vivant n'est **délibérément pas répliqué** entre
//! les deux annuaires racines. Quand l'un tombe, rien ne bascule côté serveur —
//! ce sont les daemons qui se reconnectent à l'autre et se réannoncent, et
//! l'état s'y reconstruit en un keepalive.
//!
//! **Il n'y a pas d'autre bascule à écrire : c'est celle-ci.** Ce fichier est
//! donc la moitié du plan de haute disponibilité du produit, et non un filet de
//! sécurité qu'on ajoute à la fin.
//!
//! # LA POLITIQUE N'EST PAS ICI
//!
//! Quel annuaire essayer, dans quel ordre, après quelle attente : tout cela est
//! décidé par [`asl_client::Tournee`], sans une entrée-sortie, et éprouvé sur
//! des listes littérales. Ce fichier-ci ne fait qu'obéir — il ouvre, il attend,
//! il recommence.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::time::Duration;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use asl_client::renvoi::{Aiguillage, Cote, Renvoi, separer_l_adresse};
use asl_client::{Identite, Reprise, Tournee};

use asl_id::Identifiant;
use tokio::net::UdpSocket;

use crate::{Confiance, Connexion, Faute};

/// Combien de temps la boucle d'entretien dort entre deux réveils.
///
/// **CE N'EST PAS LA CADENCE DU KEEPALIVE.** Celle-là appartient à QUIC, qui
/// émet ses `PING` selon les paramètres que l'annuaire a annoncés
/// (`modele.md` §4.1). Cette constante-ci ne décide que d'une chose : combien de
/// temps un retrait peut mettre à être vu.
const ENTRETIEN_MS: u64 = 500;

/// Combien de temps [`Attache::retirer`] laisse à la tâche pour fermer proprement.
const RETRAIT_MS: u64 = 2_000;

/// Un annuaire à qui parler.
#[derive(Debug, Clone)]
pub struct Annuaire {
    /// Où le joindre.
    pub adresse: SocketAddr,
    /// Le nom qu'on met dans `:authority`.
    ///
    /// **IL NE PROUVE RIEN** (C20) : on ne vise que l'adresse, et c'est
    /// l'[identité](Self::identite) qu'on juge. Il n'est ni vérifié ni résolu
    /// ici.
    pub nom: String,
    /// L'identité `n-…` qu'on doit trouver au bout (`protocole.md` §0) :
    /// sa clé est ce que le certificat présenté doit porter.
    ///
    /// **ELLE N'EST PLUS FACULTATIVE** (décision 58, étape 5) : l'autorité
    /// d'hier est retirée, et un annuaire sans identité attendue ne serait
    /// cru par rien.
    pub identite: Identifiant,
}

/// Ce qu'il faut savoir pour joindre le service, quelle que soit la machine.
#[derive(Debug, Clone)]
pub struct Reglages {
    annuaires: Vec<Annuaire>,
    /// Les mêmes adresses, à plat : c'est ce que la tournée parcourt.
    adresses: Vec<SocketAddr>,
    reprise: Reprise,
}

impl Reglages {
    /// Vérifie la configuration, une fois pour toutes.
    ///
    /// # POURQUOI CE CONSTRUCTEUR EXISTE
    ///
    /// Pour que les deux fautes qui ne sont **pas** des pannes — aucun annuaire,
    /// un plafond nul — soient rendues à qui a écrit la configuration, dans sa
    /// main, avant qu'une tâche de fond parte les découvrir toute seule.
    ///
    /// `plafond_ms` est la cadence de keepalive annoncée par l'annuaire : c'est
    /// le plafond du recul, et il ne sert à rien de réessayer plus lentement que
    /// le rythme auquel on aurait parlé.
    ///
    /// # Errors
    ///
    /// [`Faute::SansAnnuaire`], [`Faute::PlafondNul`].
    pub fn nouveaux(annuaires: Vec<Annuaire>, plafond_ms: u64) -> Result<Self, Faute> {
        if annuaires.is_empty() {
            return Err(Faute::SansAnnuaire);
        }
        let reprise = Reprise::nouvelle(plafond_ms).map_err(|_| Faute::PlafondNul)?;
        let adresses = annuaires.iter().map(|ou| ou.adresse).collect();
        Ok(Self {
            annuaires,
            adresses,
            reprise,
        })
    }

    /// Les annuaires, dans l'ordre où ils ont été écrits.
    #[must_use]
    pub fn annuaires(&self) -> &[Annuaire] {
        &self.annuaires
    }
}

/// Ce qu'un pas de tournée a donné.
enum Pas {
    /// Une connexion s'est ouverte. **Ce n'est pas encore une attache.**
    Ouverte(Box<Connexion>),
    /// Cet annuaire n'a pas répondu. On passe au suivant.
    Ratee,
    /// Réessayer ne servirait à rien.
    Impossible(Faute),
    /// On nous a demandé de partir.
    Arret,
}

/// Deux octets d'aléa pour le bruit du recul.
///
/// **UNE SEULE SOURCE D'ALÉA**, celle de l'appelant : deux octets suffisent
/// au bruit du recul, et il ne mérite pas un générateur à lui.
fn bruit(alea: &(dyn Fn() -> [u8; 16] + Sync)) -> u16 {
    let graine = alea();
    u16::from_le_bytes([
        graine.first().copied().unwrap_or(0),
        graine.get(1).copied().unwrap_or(0),
    ])
}

/// Un pas de la tournée : attendre s'il le faut, puis essayer un annuaire.
async fn un_pas(
    reglages: &Reglages,
    alea: &(dyn Fn() -> [u8; 16] + Sync),
    tournee: &mut Tournee,
    arret: Option<&AtomicBool>,
    socket: Option<&Arc<UdpSocket>>,
) -> Pas {
    if arret.is_some_and(|drapeau| drapeau.load(Ordering::Acquire)) {
        return Pas::Arret;
    }
    let Some(etape) = tournee.prochaine(&reglages.adresses, bruit(alea)) else {
        // `Reglages::nouveaux` a déjà refusé la liste vide ; on ne peut arriver
        // ici qu'en ayant contourné le constructeur.
        return Pas::Impossible(Faute::SansAnnuaire);
    };
    let cible = reglages.annuaires.get(etape.place);
    essayer(cible, etape.attendre_ms, alea, arret, true, socket).await
}

/// Un pas de la tournée d'une attache, qui peut avoir été renvoyée vers un
/// annuaire local : l'[`Aiguillage`] dit de quel côté chercher.
async fn un_pas_aiguille(
    reglages: &Reglages,
    local: &[Annuaire],
    alea: &(dyn Fn() -> [u8; 16] + Sync),
    aiguillage: &mut Aiguillage,
    arret: Option<&AtomicBool>,
) -> Pas {
    if arret.is_some_and(|drapeau| drapeau.load(Ordering::Acquire)) {
        return Pas::Arret;
    }
    let adresses_locales: Vec<SocketAddr> = local.iter().map(|ou| ou.adresse).collect();
    let Some(etape) = aiguillage.prochaine(&reglages.adresses, &adresses_locales, bruit(alea))
    else {
        return Pas::Impossible(Faute::SansAnnuaire);
    };
    let (cible, racine) = match etape.cote {
        Cote::Racines => (reglages.annuaires.get(etape.place), true),
        Cote::Local => (local.get(etape.place), false),
    };
    essayer(cible, etape.attendre_ms, alea, arret, racine, None).await
}

/// Attendre, puis ouvrir une connexion vers cet annuaire.
///
/// `configure` dit si l'annuaire vient de la configuration du porteur (une
/// racine) ou d'un renvoi : seule une faute TLS sur un annuaire CONFIGURÉ est
/// une faute de configuration qui arrête l'attache. Un nom de serveur illisible
/// venu d'un `421` est un échec de ce membre, et la tournée continue — sans
/// quoi un annuaire local mal déclaré suffirait à faire taire le daemon.
///
/// `socket` est celle de l'écho, quand la connexion doit partir d'elle
/// ([`Connexion::ouvrir_sur`]) ; sinon, chaque essai lie la sienne.
async fn essayer(
    cible: Option<&Annuaire>,
    attendre_ms: u64,
    alea: &(dyn Fn() -> [u8; 16] + Sync),
    arret: Option<&AtomicBool>,
    configure: bool,
    socket: Option<&Arc<UdpSocket>>,
) -> Pas {
    let parti = || arret.is_some_and(|drapeau| drapeau.load(Ordering::Acquire));
    if attendre_ms > 0 {
        tokio::time::sleep(Duration::from_millis(attendre_ms)).await;
        if parti() {
            return Pas::Arret;
        }
    }

    let Some(cible) = cible else {
        return Pas::Ratee;
    };
    let confiance = confiance_de(cible);
    let ouverture = match socket {
        Some(socket) => {
            Connexion::ouvrir_sur(
                Arc::clone(socket),
                cible.adresse,
                &cible.nom,
                &confiance,
                alea,
            )
            .await
        }
        None => Connexion::ouvrir_confiance(cible.adresse, &cible.nom, &confiance, alea).await,
    };
    match ouverture {
        Ok(connexion) => Pas::Ouverte(Box::new(connexion)),
        // **UNE CONFIGURATION TLS QUI NE SE CONSTRUIT PAS NE SE CONSTRUIRA PAS
        // EN RÉESSAYANT.** Une faute de configuration réessayée à l'infini est
        // une panne muette : le porteur voit un daemon qui « cherche », alors
        // qu'il ne trouvera jamais. Depuis que l'autorité d'hier est retirée,
        // il n'y a plus de PEM à mal lire : il ne reste que ce que `rustls`
        // refuserait de monter.
        Err(Faute::Tls(quoi)) if configure => Pas::Impossible(Faute::Tls(quoi)),
        Err(_) => Pas::Ratee,
    }
}

/// Ce qu'on croit au bout de cet annuaire : son identité, et rien d'autre
/// (décision 58, étape 5).
#[must_use]
pub fn confiance_de(annuaire: &Annuaire) -> Confiance {
    Confiance::par_identites(&[annuaire.identite])
}

/// Les annuaires qu'un renvoi désigne, résolus.
///
/// **L'IDENTITÉ ATTENDUE EST CELLE QUE LE RENVOI NOMME** (`protocole.md`
/// §0, décision 53) : le `421` dit l'annuaire local `n-…`, et c'est sa clé
/// qu'on doit trouver au bout. L'hôte de chaque locateur ne va que dans
/// `:authority`. Un locateur littéral est gardé tel
/// quel ; un nom — une commodité, jamais une preuve (C20) — est résolu, et
/// **toutes** ses adresses sont gardées.
///
/// **CHAQUE ADRESSE SOUS L'IDENTITÉ DE SON MEMBRE** (décision 59) : depuis
/// 0.31.0, le `421` dit quel `n-…` on doit trouver au bout de chaque adresse
/// — speedy sous sa clé, helium sous la sienne. Un corps d'avant ne nomme que
/// le titulaire, et chaque adresse est alors attendue sous lui, comme hier.
///
/// Une adresse qui ne se résout pas est sautée : c'est un membre qu'on ne
/// peut pas joindre, pas une raison de ne pas essayer l'autre.
///
/// **PUBLIQUE POUR QU'UN DIAGNOSTIC ESSAIE LES MÊMES** que l'attache : `asl
/// diagnose` dit si l'annuaire local qu'une racine désigne est joignable, et
/// il doit le dire des adresses et des noms qu'une attache emploierait.
pub async fn membres_du_renvoi(renvoi: &Renvoi<'_>) -> Vec<Annuaire> {
    let mut trouves = Vec::new();
    for (texte, identite) in renvoi.membres() {
        let Ok((hote, port)) = separer_l_adresse(texte) else {
            continue;
        };
        if let Ok(ip) = hote.parse::<std::net::IpAddr>() {
            trouves.push(Annuaire {
                adresse: SocketAddr::new(ip, port),
                nom: hote.to_owned(),
                identite,
            });
            continue;
        }
        if let Ok(adresses) = tokio::net::lookup_host((hote, port)).await {
            for adresse in adresses {
                trouves.push(Annuaire {
                    adresse,
                    nom: hote.to_owned(),
                    identite,
                });
            }
        }
    }
    trouves
}

/// Ouvre une connexion à l'un de ces annuaires, et n'abandonne pas.
///
/// IPv6 d'abord, puis l'ordre de l'opérateur ; tous d'affilée, et le recul
/// n'intervient qu'entre deux tours complets — voir [`asl_client::Tournee`].
///
/// # ELLE NE REND PAS LA MAIN TANT QU'ELLE N'A PAS RÉUSSI
///
/// C'est la règle (`protocole.md` §1.4), et ce n'est pas négociable ici : un
/// service de découverte injoignable ne doit pas faire échouer ce qui le
/// consulte, il doit le faire attendre.
///
/// **Qui veut une borne l'applique lui-même** — `tokio::time::timeout` est fait
/// pour cela, et c'est à l'appelant de savoir combien de temps il peut attendre.
/// Un `asl ou` tapé dans un terminal n'a pas la même patience qu'un daemon.
///
/// # Errors
///
/// Seulement ce que réessayer ne réparerait pas : [`Faute::Tls`] pour une
/// configuration TLS qui ne se monte pas, [`Faute::SansAnnuaire`] pour une
/// liste vide.
pub async fn joindre(
    reglages: &Reglages,
    alea: &(dyn Fn() -> [u8; 16] + Sync),
) -> Result<Connexion, Faute> {
    joindre_par(reglages, alea, None).await
}

/// [`joindre`], **sur la socket de l'écho** : chaque essai s'ouvre sur elle,
/// sans la connecter ([`Connexion::ouvrir_sur`], décision 90 ; E2).
///
/// La même tournée, la même patience infinie ; seule la socket change — et
/// c'est ce qui garde le port de l'écho d'un annuaire à l'autre.
///
/// # Errors
///
/// Celles de [`joindre`].
pub async fn joindre_sur(
    reglages: &Reglages,
    socket: &Arc<UdpSocket>,
    alea: &(dyn Fn() -> [u8; 16] + Sync),
) -> Result<Connexion, Faute> {
    joindre_par(reglages, alea, Some(socket)).await
}

/// La tournée de [`joindre`] et de [`joindre_sur`].
async fn joindre_par(
    reglages: &Reglages,
    alea: &(dyn Fn() -> [u8; 16] + Sync),
    socket: Option<&Arc<UdpSocket>>,
) -> Result<Connexion, Faute> {
    let mut tournee = Tournee::nouvelle(reglages.reprise);
    loop {
        match un_pas(reglages, alea, &mut tournee, None, socket).await {
            Pas::Ouverte(connexion) => return Ok(*connexion),
            Pas::Impossible(quoi) => return Err(quoi),
            // Sans drapeau d'arrêt, `Arret` ne se produit pas ; et s'il se
            // produisait, continuer est ce que cette fonction promet.
            Pas::Ratee | Pas::Arret => {}
        }
    }
}

/// Ce que l'attache a fait jusqu'ici.
///
/// # POURQUOI CE COMPTE EST PUBLIC
///
/// Une tâche de fond qui n'expose rien est une tâche dont personne ne sait si
/// elle vit. Ces quatre nombres sont ce qu'un daemon met dans son `/health` ou
/// dans `asl diagnose` — et [`Etat::abandonnee`] est le seul état dont un
/// humain doit être averti.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Etat {
    /// L'annuaire nous connaît en ce moment : authentifiés ET annoncés.
    ///
    /// **PAS « la socket est ouverte ».** Une connexion qui s'ouvre puis se fait
    /// refuser l'authentification n'annonce rien, et ce drapeau reste faux.
    pub attachee: bool,
    /// Combien de fois on s'est attaché depuis le départ.
    pub attaches: u64,
    /// Combien de fois une attache établie s'est rompue.
    pub ruptures: u64,
    /// La tâche a renoncé, et ne réessaiera pas.
    ///
    /// **ELLE NE RENONCE QUE SUR UNE FAUTE DE CONFIGURATION** — une
    /// configuration TLS qui ne se monte pas, une liste vide. Jamais sur une panne de réseau, quelle qu'en
    /// soit la durée.
    pub abandonnee: bool,
    /// Combien de poussées de verdict sont arrivées depuis le départ.
    ///
    /// **ZÉRO N'EST PAS UNE ANOMALIE** : l'annuaire ne pousse que ce qui a
    /// CHANGÉ, et un service dont les sondes confirment ce qu'il disait déjà n'en
    /// produit aucune.
    pub poussees: u64,
    /// Combien de renvois vers un annuaire local ont été suivis (`421`).
    ///
    /// **ZÉRO POUR UNE MACHINE DONT LE DOMAINE EST AUX RACINES** — le cas
    /// ordinaire. Un compte qui monte sans que [`Etat::attachee`] tienne dit
    /// qu'on est renvoyé vers un annuaire local qui ne répond pas :
    /// [`Attache::annuaire_local`] dit lequel.
    pub renvois: u64,
}

/// Ce que la tâche et son propriétaire se disent.
#[derive(Debug, Default)]
struct Partage {
    attachee: AtomicBool,
    attaches: AtomicU64,
    ruptures: AtomicU64,
    poussees: AtomicU64,
    abandonnee: AtomicBool,
    retrait: AtomicBool,
    /// La dernière poussée de verdict, telle qu'elle est arrivée.
    ///
    /// # UNE SEULE, ET C'EST SUFFISANT
    ///
    /// Chaque poussée porte la liste ENTIÈRE (`protocole.md` §1.4) : la dernière
    /// remplace tout ce qui précède. En garder une file obligerait à décider
    /// quoi faire de celles qu'on n'a pas lues, et la réponse serait « les
    /// jeter » — autant ne garder que la bonne.
    ///
    /// **Un `Mutex` et non un atomique** : ce sont des octets, pas un nombre. Il
    /// n'est pris que le temps d'un remplacement ou d'une lecture, jamais
    /// pendant une attente réseau.
    poussee: Mutex<Option<Vec<u8>>>,
    renvois: AtomicU64,
    /// L'annuaire local vers lequel le dernier renvoi a dirigé l'attache.
    annuaire_local: Mutex<Option<String>>,
}

/// Une annonce tenue vivante, quoi qu'il arrive au réseau.
///
/// # ELLE REND LA MAIN TOUT DE SUITE
///
/// `protocole.md` §1.4 : **un annuaire injoignable ne doit pas empêcher un
/// daemon de démarrer.** [`Attache::annoncer`] ne fait donc aucune
/// entrée-sortie — elle valide ce qu'elle peut valider, lance la tâche, et rend
/// la main. Le daemon écoute déjà pendant que l'attache cherche encore.
///
/// # LA LÂCHER, C'EST SE RETIRER
///
/// La connexion EST le bail (`protocole.md` §1.2). Cette structure la possède,
/// et sa destruction interrompt la tâche : l'annonce disparaît.
///
/// **C'est délibéré, et c'est ce qui évite le pire des deux mondes** — une
/// annonce que plus personne ne tient et que l'annuaire continue de publier.
/// Un daemon garde donc son [`Attache`] aussi longtemps qu'il écoute.
///
/// Pour partir proprement, préférez [`Attache::retirer`] : la destruction seule
/// coupe sans prévenir, et l'annuaire ne l'apprend qu'à l'expiration
/// d'inactivité — une minute pendant laquelle il donne une adresse morte.
#[derive(Debug)]
pub struct Attache {
    tache: Option<tokio::task::JoinHandle<()>>,
    partage: Arc<Partage>,
}

impl Attache {
    /// Annonce ces services, et tient l'annonce jusqu'à ce qu'on la retire.
    ///
    /// `annonces` sont des annonces DÉJÀ ENCODÉES — voir [`crate::encoder`].
    /// C'est ce qui permet à la tâche de les répéter à chaque reconnexion sans
    /// rien emprunter, et ce qui fait qu'une annonce invalide est refusée dans
    /// la main de l'appelant plutôt que dans une tâche que personne ne regarde.
    ///
    /// Une liste vide est acceptée : une machine peut vouloir une connexion
    /// authentifiée pour interroger l'annuaire, sans rien annoncer elle-même.
    ///
    /// # CE QUE LA TÂCHE REFAIT À CHAQUE RECONNEXION
    ///
    /// S'authentifier, puis réannoncer — dans cet ordre, et en entier.
    /// **L'annuaire d'en face n'a rien gardé** : soit il vient de redémarrer,
    /// soit c'est l'autre annuaire racine, qui n'a jamais rien su de nous
    /// (`annuaires.md` §3). Reprendre là où l'on s'était arrêté n'a donc aucun
    /// sens — il n'y a pas de « là ».
    ///
    /// # UNE CONNEXION QUI S'OUVRE N'EST PAS UNE ATTACHE
    ///
    /// Le recul ne repart de zéro qu'une fois l'authentification ET l'annonce
    /// passées. Sans cela, une machine dont la clé a été révoquée rouvrirait une
    /// connexion, se ferait refuser, et recommencerait aussitôt — **une boucle
    /// serrée contre l'annuaire, menée par le daemon qui vient précisément
    /// d'être renvoyé.**
    #[must_use]
    pub fn annoncer(
        reglages: Reglages,
        identite: Identite,
        annonces: Vec<Vec<u8>>,
        alea: Arc<dyn Fn() -> [u8; 16] + Send + Sync>,
    ) -> Self {
        let partage = Arc::new(Partage::default());
        let sienne = Arc::clone(&partage);
        let tache = tokio::spawn(async move {
            tenir_toujours(reglages, identite, annonces, alea, sienne).await;
        });
        Self {
            tache: Some(tache),
            partage,
        }
    }

    /// Ce que l'attache a fait jusqu'ici.
    #[must_use]
    pub fn etat(&self) -> Etat {
        Etat {
            attachee: self.partage.attachee.load(Ordering::Acquire),
            attaches: self.partage.attaches.load(Ordering::Relaxed),
            ruptures: self.partage.ruptures.load(Ordering::Relaxed),
            abandonnee: self.partage.abandonnee.load(Ordering::Acquire),
            poussees: self.partage.poussees.load(Ordering::Relaxed),
            renvois: self.partage.renvois.load(Ordering::Relaxed),
        }
    }

    /// L'annuaire local (`n-…`) vers lequel une racine a renvoyé l'attache,
    /// s'il y en a eu un.
    ///
    /// `None` pour une machine dont le domaine est tenu par les racines.
    #[must_use]
    pub fn annuaire_local(&self) -> Option<String> {
        self.partage
            .annuaire_local
            .lock()
            .ok()
            .and_then(|quoi| quoi.clone())
    }

    /// La dernière poussée de verdict, telle qu'elle est arrivée.
    ///
    /// # ELLE PORTE LA LISTE ENTIÈRE, ET NON UN DELTA
    ///
    /// `protocole.md` §1.4 : la dernière remplace tout ce qui précède. Elle se
    /// lit avec `asl_proto::Poussee::decoder`, et l'appeler deux fois rend deux
    /// fois la même chose tant qu'aucune autre n'est arrivée.
    ///
    /// `None` tant qu'aucune sonde n'a changé d'avis — ce qui est le cas le plus
    /// fréquent, et n'est pas une anomalie.
    #[must_use]
    pub fn derniere_poussee(&self) -> Option<Vec<u8>> {
        self.partage
            .poussee
            .lock()
            .ok()
            .and_then(|quoi| quoi.clone())
    }

    /// Retire l'annonce, en fermant la connexion proprement.
    ///
    /// # LA MINUTE QUE CELA ÉCONOMISE
    ///
    /// Un daemon qui s'arrête en lâchant son attache reste annoncé jusqu'à
    /// l'expiration d'inactivité — [`crate::INACTIVITE_US`] —, et ses clients
    /// reçoivent pendant tout ce temps une adresse où plus rien n'écoute.
    /// Fermer coûte un datagramme.
    ///
    /// La tâche voit la demande à son prochain réveil, au plus tard après
    /// [`ENTRETIEN_MS`]. Si elle dormait dans un recul, elle est interrompue au
    /// bout de deux secondes — il n'y avait alors rien à retirer, puisqu'elle
    /// n'était pas attachée.
    pub async fn retirer(mut self) {
        self.partage.retrait.store(true, Ordering::Release);
        if let Some(mut tache) = self.tache.take() {
            let patience = Duration::from_millis(RETRAIT_MS);
            if tokio::time::timeout(patience, &mut tache).await.is_err() {
                tache.abort();
            }
        }
    }
}

impl Drop for Attache {
    fn drop(&mut self) {
        if let Some(tache) = self.tache.take() {
            tache.abort();
        }
    }
}

/// La boucle qui ne s'arrête pas.
async fn tenir_toujours(
    reglages: Reglages,
    identite: Identite,
    annonces: Vec<Vec<u8>>,
    alea: Arc<dyn Fn() -> [u8; 16] + Send + Sync>,
    partage: Arc<Partage>,
) {
    let mut aiguillage = Aiguillage::nouveau(reglages.reprise);
    // Les membres de l'annuaire local, tels que le dernier renvoi les a
    // donnés. Vide tant qu'aucune racine n'a renvoyé.
    let mut local: Vec<Annuaire> = Vec::new();
    loop {
        let connexion = match un_pas_aiguille(
            &reglages,
            &local,
            &*alea,
            &mut aiguillage,
            Some(&partage.retrait),
        )
        .await
        {
            Pas::Ouverte(connexion) => connexion,
            Pas::Ratee => continue,
            Pas::Arret => return,
            Pas::Impossible(_) => {
                partage.abandonnee.store(true, Ordering::Release);
                return;
            }
        };

        let mut connexion = connexion;
        match tenir(&mut connexion, &identite, &annonces, &partage).await {
            // **LE RECUL NE REPART DE ZÉRO QU'ICI** : une connexion ouverte ne
            // prouve rien, une annonce acceptée prouve tout.
            //
            // **ET C'EST AUSSI CE QUI REND UN `401` NON DÉFINITIF**
            // (`replication.md` §6). Une machine tout juste enrôlée chez une
            // racine n'est pas encore connue de l'autre, qui refuse alors sa
            // preuve. Comme `tenir` n'a pas rendu `Attachee`, on ne rappelle
            // pas `reussite` : le rang n'est pas remis à zéro, et le pas
            // suivant essaie l'annuaire SUIVANT, sans attendre — le recul
            // n'arrive qu'une fois le tour bouclé. Éprouvé par
            // `un_401_sur_une_racine_n_est_pas_definitif`.
            Issue::Attachee => {
                aiguillage.reussite();
                partage.attachee.store(false, Ordering::Release);
                partage.ruptures.fetch_add(1, Ordering::Relaxed);
            }
            Issue::Refusee => {}
            // **UN RENVOI SE SUIT, UNE FOIS** (`asl_client::renvoi`) : l'aiguillage
            // refuse un second saut, et un corps illisible ou sans adresse
            // joignable n'emmène nulle part — c'est alors un refus de cette
            // racine, et la tournée continue.
            Issue::Renvoyee(corps) => {
                if let Ok(renvoi) = Renvoi::lire(&corps) {
                    let membres = membres_du_renvoi(&renvoi).await;
                    if !membres.is_empty() && aiguillage.renvoye() {
                        local = membres;
                        partage.renvois.fetch_add(1, Ordering::Relaxed);
                        if let Ok(mut place) = partage.annuaire_local.lock() {
                            *place = Some(renvoi.annuaire().texte().as_str().to_owned());
                        }
                    }
                }
                let _ = connexion.fermer().await;
            }
        }

        if partage.retrait.load(Ordering::Acquire) {
            let _ = connexion.fermer().await;
            return;
        }
    }
}

/// Ce qu'une connexion a donné.
enum Issue {
    /// Authentifiés et annoncés, puis la connexion est tombée.
    Attachee,
    /// Refusés avant d'être attachés.
    Refusee,
    /// Renvoyés vers un annuaire local : le corps du `421`.
    Renvoyee(Vec<u8>),
}

/// S'authentifier, réannoncer, puis ne plus disparaître.
///
/// Rend [`Issue::Attachee`] si l'attache a bien été établie — c'est ce qui
/// distingue une rupture d'un refus, et le recul en dépend — et le corps du
/// `421` si une racine renvoie ailleurs.
async fn tenir(
    connexion: &mut Connexion,
    identite: &Identite,
    annonces: &[Vec<u8>],
    partage: &Partage,
) -> Issue {
    if connexion.authentifier(identite).await.is_err() {
        return Issue::Refusee;
    }
    for annonce in annonces {
        let reponse = match connexion.annoncer_encodee(annonce).await {
            Ok(reponse) => reponse,
            Err(Faute::Renvoye(corps)) => return Issue::Renvoyee(corps),
            Err(_) => return Issue::Refusee,
        };
        // **LA CADENCE DE MAINTIEN VIENT D'ICI, ET DE NULLE PART AILLEURS.**
        // `modele.md` §4.1 : les deux valeurs du bail viennent du serveur,
        // précisément pour qu'on puisse les changer sans mettre à jour les
        // daemons installés chez des tiers. Les figer dans cette boucle aurait
        // rendu la mesure inutile le jour où elle a eu lieu.
        //
        // **UNE RÉPONSE ILLISIBLE NE ROMPT PAS L'ATTACHE** : l'annonce est
        // prise — l'annuaire a rendu 200 —, et ce qu'on perd est le maintien.
        // Sans lui la connexion vit quand même, elle se refait simplement à
        // chaque délai d'inactivité, ce qui était le comportement d'avant.
        if let Ok(bail) = cadence_du_bail(&reponse) {
            connexion.maintenir(bail);
        }
    }

    // **LE FLUX DES VERDICTS S'OUVRE APRÈS L'ANNONCE, ET NON AVANT.**
    //
    // Il ne dirait rien d'utile plus tôt : l'annuaire pousse ce qu'il apprend des
    // services de CETTE connexion, et avant l'annonce il n'y en a aucun.
    //
    // **UN ÉCHEC ICI NE ROMPT PAS L'ATTACHE.** L'annonce tient ; ce qu'on perd
    // est de SAVOIR si elle est joignable, ce qui est moins grave que de ne plus
    // être annoncé du tout.
    let _ = connexion.ecouter_les_poussees().await;

    partage.attachee.store(true, Ordering::Release);
    partage.attaches.fetch_add(1, Ordering::Relaxed);

    // **IL N'Y A RIEN À RÉANNONCER PÉRIODIQUEMENT.** La connexion est le bail :
    // tenir l'une tient l'autre, et le maintien posé plus haut la tient ouverte
    // — c'est `poll_transmit`, appelé par `entretenir`, qui pose le `PING`.
    while connexion.vivante() && !partage.retrait.load(Ordering::Acquire) {
        if connexion.entretenir(ENTRETIEN_MS).await.is_err() {
            break;
        }
        recueillir_les_poussees(connexion, partage);
    }
    Issue::Attachee
}

/// Range la dernière poussée arrivée, s'il en est arrivé.
///
/// **ON NE GARDE QUE LA DERNIÈRE** : chacune porte la liste entière, donc celle
/// qui précède ne dit plus rien de vrai. Le compteur, lui, monte de toutes —
/// c'est ce qui permet à un porteur de voir que le flux vit.
fn recueillir_les_poussees(connexion: &mut Connexion, partage: &Partage) {
    // **UNE POUSSÉE ILLISIBLE NE ROMPT RIEN.** Elle serait notre faute ou celle
    // de l'annuaire, et dans les deux cas l'annonce reste bonne : on ignore ce
    // qu'on ne sait pas lire plutôt que de retirer un service qui écoute.
    let Ok(arrivees) = connexion.poussees() else {
        return;
    };
    // Le compteur monte de TOUTES : deux poussées lues d'un coup restent deux
    // poussées, et un porteur qui ne verrait qu'un tour croirait le flux muet.
    let combien = u64::try_from(arrivees.len()).unwrap_or(u64::MAX);
    let Some(derniere) = arrivees.into_iter().next_back() else {
        return;
    };
    partage.poussees.fetch_add(combien, Ordering::Relaxed);
    if let Ok(mut place) = partage.poussee.lock() {
        *place = Some(derniere);
    }
}

/// La cadence de maintien qu'une réponse d'annonce annonce, en secondes.
///
/// **PUBLIQUE POUR QU'UN PORTEUR QUI TIENT SA PROPRE BOUCLE PUISSE LA POSER.**
/// `Attache` s'en charge seule ; un daemon qui n'emploie que `Connexion` doit
/// pouvoir faire la même chose, sans réécrire un décodeur.
///
/// # POURQUOI ON DÉCODE LA RÉPONSE ENTIÈRE POUR DEUX OCTETS
///
/// Parce que c'est le décodeur du protocole, et qu'il refuse ce qui n'est pas
/// une réponse. Chercher `"keepalive_secondes":` dans le texte marcherait
/// aujourd'hui et accepterait demain une réponse mal formée dont ce champ
/// seul serait lisible — c'est-à-dire qu'on réglerait une cadence sur un message
/// qu'on n'a pas compris.
pub fn cadence_du_bail(corps: &[u8]) -> Result<u16, asl_proto::Erreur> {
    let mut tampons = asl_proto::cadrage::TamponsReponse::nouveaux();
    let lue = asl_proto::Reponse::decoder(corps, &mut tampons)?;
    Ok(lue.bail.keepalive_secondes())
}
