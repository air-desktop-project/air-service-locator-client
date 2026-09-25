//! La voie des applications mobiles (`protocole.md` §2), sur une connexion
//! tenue.
//!
//! # CE QUE LE TRANSPORT FAIT POUR UN APPAREIL, ET CE QU'IL NE FAIT PAS
//!
//! Il ouvre la connexion, exporte la liaison de canal, tire le défi, porte la
//! preuve et tient la connexion vivante. **Il ne signe rien** : la clé d'un
//! téléphone vit dans son matériel, et `asl_client::appareil` compose ce qu'il y
//! a à signer. Ce qui arrive ici est une signature déjà rendue.
//!
//! # UNE CONNEXION TENUE, MÊME POUR UN TÉLÉPHONE
//!
//! L'authentification est portée par la connexion (`protocole.md` §3) : la clé
//! est prouvée une fois, et toutes les requêtes en héritent. Pour un téléphone,
//! prouver coûte un geste biométrique — **et un geste par requête serait
//! intenable**. [`Tenue`] garde donc la connexion dans une tâche de fond, la
//! maintient au keepalive, et sert les requêtes de l'écran une à une, sans
//! redemander quoi que ce soit au porteur tant qu'elle vit.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, PoisonError};

use asl_id::Identifiant;
use tokio::sync::{Notify, mpsc, oneshot};

use crate::{Connexion, Faute, Pont, REPONSE_MS, Reponse, maintenant};

/// La plus longue ligne de `GET /v1/nouvelles` qu'on rend, en octets.
///
/// **UNE LIGNE D'AUJOURD'HUI EN FAIT VINGT-QUATRE** — `{"quoi":"autorisation"}`
/// —, et elle ne dit rien d'autre par construction (`protocole.md`, « une ligne
/// dit qu'il y a du neuf, et de quel genre »). Un kibioctet laisse la place aux
/// genres à venir sans laisser un annuaire faire grandir la mémoire d'un
/// téléphone : une ligne plus longue est SAUTÉE, comme un genre inconnu.
pub const NOUVELLE_MAX: usize = 1_024;

/// Combien de nouvelles la tenue garde pour l'application, au plus.
///
/// **AU-DELÀ, LA PLUS ANCIENNE PART**, et rien n'est perdu : une ligne ne porte
/// que « relis », et la relecture de `GET /v1/autorisations` rattrape tout ce
/// qu'on aurait jeté. Seul le compteur de [`Tenue::nouvelles_recues`] dit
/// combien il en est arrivé.
const FILE_MAX: usize = 64;

/// Le découpage en lignes de ce qui arrive sur `GET /v1/nouvelles`.
///
/// # DES LIGNES, ET NON `asl_proto::cadrage::objets`
///
/// Le flux des verdicts porte des objets encodés par ce dépôt, que le cadrage
/// sait sauter. Celui-ci porte « un objet par ligne » (`protocole.md`), qu'**on
/// ne lit pas** : c'est l'application qui le lit, avec l'analyseur JSON de sa
/// plate-forme, et elle saute les genres qu'elle ne connaît pas. La fin de
/// ligne est donc la seule frontière qu'il faille connaître ici.
#[derive(Debug, Default)]
pub(crate) struct Lignes {
    /// La ligne en cours, sans sa fin.
    reste: Vec<u8>,
    /// La ligne en cours a dépassé [`NOUVELLE_MAX`] : on la saute jusqu'à sa
    /// fin.
    a_sauter: bool,
}

impl Lignes {
    /// Les lignes que ces octets achèvent, sans leur fin ni leurs blancs.
    ///
    /// **UNE LIGNE COUPÉE PAR UN DATAGRAMME EST LE CAS ORDINAIRE** : elle attend
    /// la suite. Une ligne vide n'est rien, et n'est pas rendue.
    pub(crate) fn couper(&mut self, arrives: &[u8]) -> Vec<Vec<u8>> {
        let mut rendues = Vec::new();
        for &octet in arrives {
            if octet == b'\n' {
                let ligne = core::mem::take(&mut self.reste);
                let sautee = core::mem::replace(&mut self.a_sauter, false);
                let ligne = ligne.trim_ascii();
                if !sautee && !ligne.is_empty() {
                    rendues.push(ligne.to_vec());
                }
            } else if self.a_sauter {
                // On attend la fin de la ligne trop longue.
            } else if self.reste.len() == NOUVELLE_MAX {
                self.reste.clear();
                self.a_sauter = true;
            } else {
                self.reste.push(octet);
            }
        }
        rendues
    }
}

/// Ce que `POST /v1/comptes` rend : le compte créé, et cet appareil nommé.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompteCree {
    /// Le compte, `u-…` — l'identifiant public qu'on donne pour être autorisé.
    pub compte: Identifiant,
    /// Cet appareil, `a-…` — ce qu'il signera désormais à chaque connexion.
    pub appareil: Identifiant,
}

impl Connexion {
    /// Prouve la clé de cet appareil sur CETTE connexion.
    ///
    /// La signature couvre `asl_client::appareil::message_d_authentification`,
    /// composé sur le défi de cette connexion et sa liaison. **Elle a été faite
    /// ailleurs** — par l'enclave du téléphone — et n'est ici que des octets.
    ///
    /// # Errors
    ///
    /// Celles de [`Connexion::requete`], plus [`Faute::Statut`] (`401` : la
    /// preuve ne vérifie pas, et l'annuaire ne dit pas pourquoi) et
    /// [`Faute::Illisible`] si l'identifiant n'est pas celui d'un appareil.
    pub async fn prouver_appareil(
        &mut self,
        appareil: Identifiant,
        signature: &[u8; asl_cle::SIGNATURE_APPAREIL_OCTETS],
    ) -> Result<(), Faute> {
        let corps = asl_client::appareil::preuve_d_authentification(appareil, signature)
            .map_err(|_| Faute::Illisible)?;
        let reponse = self
            .requete(
                b"POST",
                b"/v1/defi",
                &[(b"content-type", b"application/octet-stream")],
                &corps,
            )
            .await?;
        reponse.exige(204)
    }

    /// Prouve la clé de cet appareil — qui vient de REJOINDRE un compte — et
    /// présente sa chaîne d'attestation, en un verbe, sur CETTE connexion.
    ///
    /// # LA CONNEXION EST CELLE OÙ LE DÉFI A ÉTÉ TIRÉ AVANT LA CLÉ
    ///
    /// `protocole.md` §2.2, « Attester un appareil qui rejoint » : le nouvel
    /// appareil se connecte nu, tire son défi, GÉNÈRE sa clé avec le condensat
    /// de `asl_client::appareil::message_pour_attestation_de_cle`, la montre à
    /// l'ancien appareil, attend son `a-…`, puis prouve ici — la signature
    /// couvre `message_d_authentification`, comme pour [`Self::prouver_appareil`],
    /// et la chaîne suit. **Le défi vit ce que vit la connexion** : si elle est
    /// tombée entre le code montré et cet appel, la clé ne s'attestera plus, et
    /// c'est l'application qui recommence — nouvelle connexion, nouvelle clé.
    ///
    /// Après `204`, la connexion est celle de cet appareil. Sous
    /// [`asl_client::appareil::Plateforme::Aucune`], sans chaîne, ce verbe vaut
    /// `POST /v1/defi`.
    ///
    /// # Errors
    ///
    /// Celles de [`Connexion::requete`], plus [`Faute::Statut`] — `401` : la
    /// preuve ne tient pas, il n'y a pas de défi, l'appareil est révoqué ou son
    /// compte effacé, et l'annuaire ne dit pas lequel ; `403` : la preuve
    /// tient, la chaîne est refusée et la posture l'exige ; `400` : le corps —
    /// et [`Faute::Illisible`] si le corps ne se compose pas.
    pub async fn attester(
        &mut self,
        appareil: Identifiant,
        signature: &[u8; asl_cle::SIGNATURE_APPAREIL_OCTETS],
        plateforme: asl_client::appareil::Plateforme,
        attestation: &[u8],
    ) -> Result<(), Faute> {
        let mut corps = vec![0_u8; asl_client::appareil::ATTESTATION_CORPS_MAX];
        let combien = asl_client::appareil::corps_d_attestation(
            appareil,
            signature,
            plateforme,
            attestation,
            &mut corps,
        )
        .map_err(|_| Faute::Illisible)?;
        corps.truncate(combien);
        let reponse = self
            .requete(
                b"POST",
                b"/v1/attestation",
                &[(b"content-type", b"application/octet-stream")],
                &corps,
            )
            .await?;
        reponse.exige(204)
    }

    /// Crée le compte et enrôle cet appareil, avec un corps déjà composé par
    /// `asl_client::appareil::corps_de_compte`.
    ///
    /// **La connexion est désormais celle de cet appareil** : la preuve de
    /// possession portée par ce corps l'authentifie, et il n'y a pas de second
    /// tour par `/v1/defi` à faire.
    ///
    /// # Errors
    ///
    /// Celles de [`Connexion::requete`], plus [`Faute::Statut`] et
    /// [`Faute::Illisible`].
    pub async fn creer_compte(&mut self, corps: &[u8]) -> Result<CompteCree, Faute> {
        let reponse = self
            .requete(
                b"POST",
                b"/v1/comptes",
                &[(b"content-type", b"application/octet-stream")],
                corps,
            )
            .await?;
        reponse.exige(201)?;
        Ok(CompteCree {
            compte: reponse.identifiant("compte")?,
            appareil: reponse.identifiant("appareil")?,
        })
    }

    /// Une requête de la voie mobile, telle que l'écran la formule.
    ///
    /// # POURQUOI UN VERBE GÉNÉRIQUE, ET NON UN PAR RESSOURCE
    ///
    /// La voie mobile compte une vingtaine de verbes dont les corps sont du
    /// JSON lisible, et **c'est l'application qui les lit** — un téléphone a
    /// un analyseur JSON, et ce dépôt refuse d'en tirer un pour le compte des
    /// tiers (voir `Reponse::identifiant`). Le transport porte donc des octets
    /// et un code d'état, et l'application fait le reste. Un verbe par
    /// ressource serait vingt fois la même fonction, à tenir d'accord avec un
    /// protocole qui bouge.
    ///
    /// **Le code d'état est rendu, jamais jugé** : un `404` ou un `409` sont
    /// des réponses de l'annuaire, et c'est l'écran qui sait quoi en dire.
    ///
    /// # Errors
    ///
    /// Celles de [`Connexion::requete`] — le réseau, pas l'annuaire.
    pub async fn requete_mobile(
        &mut self,
        methode: &str,
        chemin: &str,
        corps: &[u8],
    ) -> Result<Reponse, Faute> {
        let champs: &[(&[u8], &[u8])] = if corps.is_empty() {
            &[]
        } else {
            &[(b"content-type", b"application/json")]
        };
        self.requete(methode.as_bytes(), chemin.as_bytes(), champs, corps)
            .await
    }

    /// Ouvre `GET /v1/nouvelles` sur CETTE connexion, et attend son statut.
    ///
    /// # LE STATUT, ET NON LA RÉPONSE
    ///
    /// La réponse ne se termine jamais : [`Connexion::requete`] l'attendrait
    /// pour toujours. On attend donc la section d'en-têtes seule — c'est là que
    /// l'annuaire dit `200`, `409` (un flux est déjà ouvert sur cette connexion)
    /// ou `401` (l'appareil a été révoqué depuis sa preuve) —, puis on garde le
    /// flux, et [`Connexion::nouvelles`] lit ce qui y arrive.
    ///
    /// **UN REFUS NE TOUCHE PAS AU FLUX DÉJÀ OUVERT** : un `409` dit justement
    /// qu'il vit. Un `200` le remplace — ce qui n'arrive que si le précédent
    /// s'était fermé.
    ///
    /// # Errors
    ///
    /// [`Faute::Statut`] pour tout autre code que `200` ; [`Faute::Delai`] si
    /// l'annuaire ne répond pas ; [`Faute::Http3`], [`Faute::Socket`],
    /// [`Faute::Quic`].
    pub async fn ouvrir_les_nouvelles(&mut self) -> Result<(), Faute> {
        let flux = {
            let mut pont = Pont(&mut self.quic);
            self.h3
                .request(
                    &mut pont,
                    b"GET",
                    b"/v1/nouvelles",
                    self.autorite.as_bytes(),
                    &[],
                    b"",
                )
                .map_err(Faute::Http3)?
        };
        self.emettre().await?;

        let echeance = maintenant().saturating_add(REPONSE_MS.saturating_mul(1_000));
        let statut = loop {
            if let Some(statut) = self.h3.statut(flux) {
                break statut.value();
            }
            if maintenant() >= echeance {
                return Err(Faute::Delai);
            }
            self.recevoir(REPONSE_MS.min(500)).await?;
            self.lire_les_flux(flux)?;
            self.emettre().await?;
        };
        if statut != 200 {
            // Un refus finit son flux : son suivi part avec lui.
            let _ = self.h3.take_response(flux);
            return Err(Faute::Statut(statut));
        }
        if let Some(ancien) = self.nouvelles.replace(flux) {
            let _ = self.h3.take_response(ancien);
        }
        self.lignes = Lignes::default();
        Ok(())
    }

    /// Les lignes arrivées sur `GET /v1/nouvelles` depuis le dernier appel.
    ///
    /// **RIEN EST LA RÉPONSE LA PLUS FRÉQUENTE**, comme pour
    /// [`Connexion::poussees`] : une autorisation se donne rarement.
    pub fn nouvelles(&mut self) -> Vec<Vec<u8>> {
        let Some(flux) = self.nouvelles else {
            return Vec::new();
        };
        let arrives = self.h3.prendre_ce_qui_est_arrive(flux).unwrap_or_default();
        self.lignes.couper(&arrives)
    }

    /// Le flux des nouvelles est-il ouvert, et le reste-t-il ?
    #[must_use]
    pub fn ecoute_les_nouvelles(&self) -> bool {
        self.nouvelles.is_some_and(|flux| !self.h3.est_fini(flux))
    }
}

/// Ce que la tâche de fond sait faire.
enum Ordre {
    Requete {
        methode: String,
        chemin: String,
        corps: Vec<u8>,
        reponse: oneshot::Sender<Result<Reponse, Faute>>,
    },
    Nouvelles(oneshot::Sender<Result<(), Faute>>),
    Fermer(oneshot::Sender<()>),
}

/// Ce que la tâche de fond a reçu sur `GET /v1/nouvelles`, et que l'application
/// n'a pas encore pris.
#[derive(Debug, Default)]
struct Recu {
    /// Les lignes, de la plus ancienne à la plus récente.
    lignes: VecDeque<Vec<u8>>,
    /// Combien il en est arrivé depuis que la tenue existe, jetées comprises.
    recues: u64,
    /// Le flux est-il ouvert — et la connexion vivante ?
    ouvert: bool,
}

/// Ce que la tâche de fond partage avec les attentes de l'application.
///
/// # UN VERROU, ET NON UN ORDRE À LA TÂCHE
///
/// Attendre une nouvelle ne doit pas occuper la tâche : elle sert les requêtes
/// de l'écran une à une, et une attente de trente secondes dans sa file
/// retiendrait d'autant la suivante. La tâche DÉPOSE donc ici, et
/// l'application PREND ici — c'est le modèle des verdicts poussés
/// (`attache.rs`), où la tâche tient la connexion et le handle lit ce qu'elle a
/// recueilli.
#[derive(Debug, Default)]
struct Boite {
    recu: Mutex<Recu>,
    /// Sonne à chaque dépôt, et quand le flux se ferme.
    sonnette: Notify,
}

impl Boite {
    /// Le verrou, même empoisonné : ce qu'il garde reste cohérent à chaque
    /// instruction, et une tâche qui a paniqué n'a rien laissé à moitié.
    fn recu(&self) -> std::sync::MutexGuard<'_, Recu> {
        self.recu.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Dépose ce que la connexion a reçu, et sonne si quelque chose a changé.
    fn deposer(&self, lignes: Vec<Vec<u8>>, ouvert: bool) {
        let mut recu = self.recu();
        let change = !lignes.is_empty() || recu.ouvert != ouvert;
        for ligne in lignes {
            if recu.lignes.len() == FILE_MAX {
                recu.lignes.pop_front();
            }
            recu.lignes.push_back(ligne);
            recu.recues = recu.recues.saturating_add(1);
        }
        recu.ouvert = ouvert;
        drop(recu);
        if change {
            self.sonnette.notify_one();
        }
    }
}

/// Ce qu'une attente de nouvelle rend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Nouvelle {
    /// Une ligne — un objet JSON, que l'application lit.
    Ligne(Vec<u8>),
    /// Rien n'est arrivé avant l'échéance. **Le cas ordinaire.**
    Rien,
    /// Le flux n'est pas ouvert, ou il s'est fermé avec la connexion : rien
    /// n'arrivera plus sans le rouvrir.
    Ferme,
    /// Une ligne attend, mais elle fait ce nombre d'octets, plus que la place
    /// offerte : **elle reste en tête**, pour un appel avec plus de place.
    TropLongue(usize),
}

/// Combien de temps la tâche dort entre deux ordres, en millisecondes.
///
/// **CE N'EST PAS LA CADENCE DU KEEPALIVE** — celle-là est posée sur la
/// connexion par [`Connexion::maintenir`]. C'est seulement le grain auquel un
/// datagramme entrant est lu, et un ordre servi.
const ENTRETIEN_MS: u64 = 250;

/// Combien de temps [`Tenue::fermer`] laisse à la tâche pour partir proprement.
const RETRAIT_MS: u64 = 2_000;

/// Une connexion d'appareil, tenue dans une tâche de fond.
///
/// # ELLE SE PARTAGE, ET C'EST VOULU
///
/// À la différence d'une [`Connexion`] nue, une tenue se clone : c'est un canal
/// vers la tâche, et les requêtes qu'on y pousse sont servies une à une, dans
/// l'ordre. Les droits sont ceux d'UN appareil — le seul qui ait prouvé sa clé
/// sur cette connexion —, et c'est exactement ce qu'une application mobile
/// veut : plusieurs écrans, une connexion, un porteur.
///
/// # ELLE NE SE RECONNECTE PAS TOUTE SEULE
///
/// Se reconnecter, c'est reprouver la clé, donc redemander un geste au porteur.
/// Ce n'est pas à une tâche de fond de décider quand un visage doit se
/// présenter : quand la connexion tombe, les requêtes rendent une faute, et
/// c'est l'application qui rouvre — au moment qu'elle choisit.
#[derive(Debug, Clone)]
pub struct Tenue {
    ordres: mpsc::Sender<Ordre>,
    liaison: asl_cle::LiaisonDeCanal,
    boite: Arc<Boite>,
}

impl Tenue {
    /// Prend cette connexion en charge, et la tient jusqu'à [`Tenue::fermer`].
    ///
    /// **Elle doit déjà être authentifiée**, ou nue pour créer un compte : la
    /// tenue ne prouve rien, elle porte.
    #[must_use]
    pub fn tenir(connexion: Connexion) -> Self {
        let liaison = connexion.liaison();
        let (ordres, boite_aux_ordres) = mpsc::channel::<Ordre>(16);
        let boite = Arc::new(Boite::default());
        let partagee = Arc::clone(&boite);
        tokio::spawn(async move {
            servir(connexion, boite_aux_ordres, &partagee).await;
            // **QUOI QUI AIT FINI LA TÂCHE, UNE ATTENTE LE SAIT** : sans ce
            // dépôt, elle dormirait jusqu'à son échéance sur une connexion
            // morte.
            partagee.deposer(Vec::new(), false);
        });
        Self {
            ordres,
            liaison,
            boite,
        }
    }

    /// La liaison de canal de la connexion tenue.
    #[must_use]
    pub const fn liaison(&self) -> asl_cle::LiaisonDeCanal {
        self.liaison
    }

    /// Envoie cette requête, et attend sa réponse.
    ///
    /// # Errors
    ///
    /// Celles de [`Connexion::requete_mobile`] ; [`Faute::Delai`] si la tâche a
    /// disparu — la connexion est tombée, et il faut en rouvrir une.
    pub async fn requete(
        &self,
        methode: &str,
        chemin: &str,
        corps: &[u8],
    ) -> Result<Reponse, Faute> {
        let (reponse, attente) = oneshot::channel();
        self.ordres
            .send(Ordre::Requete {
                methode: methode.to_owned(),
                chemin: chemin.to_owned(),
                corps: corps.to_vec(),
                reponse,
            })
            .await
            .map_err(|_| Faute::Delai)?;
        attente.await.map_err(|_| Faute::Delai)?
    }

    /// Ouvre `GET /v1/nouvelles` sur la connexion tenue.
    ///
    /// **PASSE PAR LA FILE DES REQUÊTES**, comme une requête d'écran : c'est
    /// une requête, et c'est son statut qu'on attend. Ce qui arrive ensuite est
    /// recueilli par la tâche entre deux ordres, et se prend par
    /// [`Tenue::nouvelle`].
    ///
    /// # Errors
    ///
    /// Celles de [`Connexion::ouvrir_les_nouvelles`] — `409` si un flux est
    /// déjà ouvert sur cette connexion, `401` si l'appareil est révoqué ;
    /// [`Faute::Delai`] si la tâche a disparu.
    pub async fn ecouter_les_nouvelles(&self) -> Result<(), Faute> {
        let (reponse, attente) = oneshot::channel();
        self.ordres
            .send(Ordre::Nouvelles(reponse))
            .await
            .map_err(|_| Faute::Delai)?;
        attente.await.map_err(|_| Faute::Delai)?
    }

    /// La plus ancienne nouvelle que l'application n'a pas prise, en attendant
    /// au plus `attente` qu'il en arrive une.
    ///
    /// **ELLE N'OCCUPE PAS LA TÂCHE** : une requête d'écran passe pendant qu'on
    /// attend ici. Une attente nulle ne fait que regarder.
    ///
    /// **UNE SEULE ATTENTE À LA FOIS** a un sens : deux se partageraient les
    /// lignes, et chacune n'en verrait qu'une partie.
    pub async fn nouvelle(&self, attente: tokio::time::Duration) -> Nouvelle {
        self.nouvelle_dans(attente, usize::MAX).await
    }

    /// La même, pour qui n'a que `place` octets où la recevoir : une ligne plus
    /// longue n'est PAS prise, et [`Nouvelle::TropLongue`] dit sa taille.
    ///
    /// **C'EST LE TAMPON EN DEUX TEMPS DE L'ABI C**, sans perte : une ligne
    /// prise puis refusée faute de place serait une ligne perdue.
    pub async fn nouvelle_dans(&self, attente: tokio::time::Duration, place: usize) -> Nouvelle {
        // **BORNÉE À UN JOUR**, pour que l'addition ne puisse pas déborder ;
        // une application qui attend plus longtemps rappelle.
        let maintenant = tokio::time::Instant::now();
        let echeance = maintenant
            .checked_add(attente.min(tokio::time::Duration::from_secs(86_400)))
            .unwrap_or(maintenant);
        loop {
            // La sonnette est prise AVANT de regarder : un dépôt qui tomberait
            // entre les deux ne serait sinon entendu par personne.
            let sonne = self.boite.sonnette.notified();
            {
                let mut recu = self.boite.recu();
                if let Some(taille) = recu.lignes.front().map(Vec::len) {
                    if taille > place {
                        return Nouvelle::TropLongue(taille);
                    }
                    return recu
                        .lignes
                        .pop_front()
                        .map_or(Nouvelle::Rien, Nouvelle::Ligne);
                }
                if !recu.ouvert {
                    return Nouvelle::Ferme;
                }
            }
            if tokio::time::timeout_at(echeance, sonne).await.is_err() {
                return Nouvelle::Rien;
            }
        }
    }

    /// Combien de nouvelles sont arrivées depuis que cette tenue existe —
    /// celles que la file a dû jeter comprises.
    #[must_use]
    pub fn nouvelles_recues(&self) -> u64 {
        self.boite.recu().recues
    }

    /// La tâche tient-elle encore une connexion ?
    #[must_use]
    pub fn vivante(&self) -> bool {
        !self.ordres.is_closed()
    }

    /// Ferme la connexion, proprement, et attend que ce soit fait.
    pub async fn fermer(self) {
        let (fini, attente) = oneshot::channel();
        if self.ordres.send(Ordre::Fermer(fini)).await.is_ok() {
            let _ =
                tokio::time::timeout(tokio::time::Duration::from_millis(RETRAIT_MS), attente).await;
        }
    }
}

/// La boucle de la tâche de fond : un ordre à la fois, l'entretien entre deux,
/// et après chaque tour, le dépôt de ce que `GET /v1/nouvelles` a apporté.
async fn servir(
    mut connexion: Connexion,
    mut boite_aux_ordres: mpsc::Receiver<Ordre>,
    boite: &Boite,
) {
    loop {
        let attente = tokio::time::Duration::from_millis(ENTRETIEN_MS);
        match tokio::time::timeout(attente, boite_aux_ordres.recv()).await {
            Ok(Some(Ordre::Requete {
                methode,
                chemin,
                corps,
                reponse,
            })) => {
                let issue = connexion.requete_mobile(&methode, &chemin, &corps).await;
                // Personne n'attend plus : l'écran a été fermé. Ce n'est
                // pas une faute.
                let _ = reponse.send(issue);
            }
            Ok(Some(Ordre::Nouvelles(reponse))) => {
                let issue = connexion.ouvrir_les_nouvelles().await;
                // Déposé AVANT de répondre : une attente lancée dès le retour
                // doit trouver le flux ouvert.
                boite.deposer(connexion.nouvelles(), connexion.ecoute_les_nouvelles());
                let _ = reponse.send(issue);
            }
            Ok(Some(Ordre::Fermer(fini))) => {
                let _ = connexion.fermer().await;
                let _ = fini.send(());
                return;
            }
            // Tous les émetteurs ont disparu : la tenue a été lâchée
            // sans être fermée. On ferme quand même — proprement.
            Ok(None) => {
                let _ = connexion.fermer().await;
                return;
            }
            // Rien à faire : on entretient, et l'on relit.
            Err(_) => {
                if connexion.entretenir(1).await.is_err() || !connexion.vivante() {
                    return;
                }
            }
        }
        boite.deposer(connexion.nouvelles(), connexion.ecoute_les_nouvelles());
    }
}
