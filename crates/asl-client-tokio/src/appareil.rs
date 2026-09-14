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

use asl_id::Identifiant;
use tokio::sync::{mpsc, oneshot};

use crate::{Connexion, Faute, Reponse};

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
}

/// Ce que la tâche de fond sait faire.
enum Ordre {
    Requete {
        methode: String,
        chemin: String,
        corps: Vec<u8>,
        reponse: oneshot::Sender<Result<Reponse, Faute>>,
    },
    Fermer(oneshot::Sender<()>),
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
}

impl Tenue {
    /// Prend cette connexion en charge, et la tient jusqu'à [`Tenue::fermer`].
    ///
    /// **Elle doit déjà être authentifiée**, ou nue pour créer un compte : la
    /// tenue ne prouve rien, elle porte.
    #[must_use]
    pub fn tenir(mut connexion: Connexion) -> Self {
        let liaison = connexion.liaison();
        let (ordres, mut boite) = mpsc::channel::<Ordre>(16);
        tokio::spawn(async move {
            loop {
                let attente = tokio::time::Duration::from_millis(ENTRETIEN_MS);
                match tokio::time::timeout(attente, boite.recv()).await {
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
            }
        });
        Self { ordres, liaison }
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
