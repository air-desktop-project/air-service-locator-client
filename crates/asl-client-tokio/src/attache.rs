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

use asl_client::{Identite, Reprise, Tournee};

use crate::{Connexion, Faute};

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
    /// Le nom qu'on exige de son certificat, et qu'on met dans `:authority`.
    ///
    /// **IL N'EST PAS DÉDUIT DE L'ADRESSE**, et il ne peut pas l'être : c'est
    /// lui qui est vérifié. Le déduire d'une adresse reviendrait à faire
    /// confiance à qui répond à cette adresse, ce qui est exactement ce que le
    /// certificat existe pour éviter.
    pub nom: String,
}

/// Ce qu'il faut savoir pour joindre le service, quelle que soit la machine.
#[derive(Debug, Clone)]
pub struct Reglages {
    annuaires: Vec<Annuaire>,
    /// Les mêmes adresses, à plat : c'est ce que la tournée parcourt.
    adresses: Vec<SocketAddr>,
    racines: Vec<u8>,
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
    pub fn nouveaux(
        annuaires: Vec<Annuaire>,
        racines: Vec<u8>,
        plafond_ms: u64,
    ) -> Result<Self, Faute> {
        if annuaires.is_empty() {
            return Err(Faute::SansAnnuaire);
        }
        let reprise = Reprise::nouvelle(plafond_ms).map_err(|_| Faute::PlafondNul)?;
        let adresses = annuaires.iter().map(|ou| ou.adresse).collect();
        Ok(Self {
            annuaires,
            adresses,
            racines,
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

/// Un pas de la tournée : attendre s'il le faut, puis essayer un annuaire.
async fn un_pas(
    reglages: &Reglages,
    alea: &(dyn Fn() -> [u8; 16] + Sync),
    tournee: &mut Tournee,
    arret: Option<&AtomicBool>,
) -> Pas {
    let parti = || arret.is_some_and(|drapeau| drapeau.load(Ordering::Acquire));
    if parti() {
        return Pas::Arret;
    }

    // **UNE SEULE SOURCE D'ALÉA**, celle de l'appelant : deux octets suffisent
    // au bruit du recul, et il ne mérite pas un générateur à lui.
    let graine = alea();
    let bruit = u16::from_le_bytes([
        graine.first().copied().unwrap_or(0),
        graine.get(1).copied().unwrap_or(0),
    ]);

    let Some(etape) = tournee.prochaine(&reglages.adresses, bruit) else {
        // `Reglages::nouveaux` a déjà refusé la liste vide ; on ne peut arriver
        // ici qu'en ayant contourné le constructeur.
        return Pas::Impossible(Faute::SansAnnuaire);
    };

    if etape.attendre_ms > 0 {
        tokio::time::sleep(Duration::from_millis(etape.attendre_ms)).await;
        if parti() {
            return Pas::Arret;
        }
    }

    let Some(cible) = reglages.annuaires.get(etape.place) else {
        return Pas::Ratee;
    };
    match Connexion::ouvrir(cible.adresse, &cible.nom, &reglages.racines, alea).await {
        Ok(connexion) => Pas::Ouverte(Box::new(connexion)),
        // **UNE RACINE ILLISIBLE NE DEVIENT PAS LISIBLE EN RÉESSAYANT.** Une
        // faute de configuration réessayée à l'infini est une panne muette : le
        // porteur voit un daemon qui « cherche », alors qu'il ne trouvera jamais.
        Err(Faute::Tls(quoi)) => Pas::Impossible(Faute::Tls(quoi)),
        Err(_) => Pas::Ratee,
    }
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
/// Seulement ce que réessayer ne réparerait pas : [`Faute::Tls`] pour une racine
/// qu'on ne sait pas lire, [`Faute::SansAnnuaire`] pour une liste vide.
pub async fn joindre(
    reglages: &Reglages,
    alea: &(dyn Fn() -> [u8; 16] + Sync),
) -> Result<Connexion, Faute> {
    let mut tournee = Tournee::nouvelle(reglages.reprise);
    loop {
        match un_pas(reglages, alea, &mut tournee, None).await {
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
/// dans `asl diagnostic` — et [`Etat::abandonnee`] est le seul état dont un
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
    /// **ELLE NE RENONCE QUE SUR UNE FAUTE DE CONFIGURATION** — une racine
    /// illisible, une liste vide. Jamais sur une panne de réseau, quelle qu'en
    /// soit la durée.
    pub abandonnee: bool,
    /// Combien de poussées de verdict sont arrivées depuis le départ.
    ///
    /// **ZÉRO N'EST PAS UNE ANOMALIE** : l'annuaire ne pousse que ce qui a
    /// CHANGÉ, et un service dont les sondes confirment ce qu'il disait déjà n'en
    /// produit aucune.
    pub poussees: u64,
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
        }
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
    let mut tournee = Tournee::nouvelle(reglages.reprise);
    loop {
        let connexion = match un_pas(&reglages, &*alea, &mut tournee, Some(&partage.retrait)).await
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
        let attachee = tenir(&mut connexion, &identite, &annonces, &partage).await;

        // **LE RECUL NE REPART DE ZÉRO QU'ICI** : une connexion ouverte ne
        // prouve rien, une annonce acceptée prouve tout.
        if attachee {
            tournee.reussite();
            partage.attachee.store(false, Ordering::Release);
            partage.ruptures.fetch_add(1, Ordering::Relaxed);
        }

        if partage.retrait.load(Ordering::Acquire) {
            let _ = connexion.fermer().await;
            return;
        }
    }
}

/// S'authentifier, réannoncer, puis ne plus disparaître.
///
/// Rend `true` si l'attache a bien été établie — c'est ce qui distingue une
/// rupture d'un refus, et le recul en dépend.
async fn tenir(
    connexion: &mut Connexion,
    identite: &Identite,
    annonces: &[Vec<u8>],
    partage: &Partage,
) -> bool {
    if connexion.authentifier(identite).await.is_err() {
        return false;
    }
    for annonce in annonces {
        if connexion.annoncer_encodee(annonce).await.is_err() {
            return false;
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
    // tenir l'une tient l'autre, et le keepalive est celui de QUIC.
    while connexion.vivante() && !partage.retrait.load(Ordering::Acquire) {
        if connexion.entretenir(ENTRETIEN_MS).await.is_err() {
            break;
        }
        recueillir_les_poussees(connexion, partage);
    }
    true
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
