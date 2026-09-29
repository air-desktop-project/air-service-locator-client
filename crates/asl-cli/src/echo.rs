//! `asl echo` — l'écho de cette machine (`protocole.md` §3 quater, décisions
//! 89 à 93).
//!
//! # CE QU'IL FAIT
//!
//! Il lie **une** socket UDP à un port tiré au hasard dans
//! [`PREMIER_PORT`]–[`DERNIER_PORT`], annonce `asl-echo`
//! avec un seul point `udp:<port>`, et **tient le bail sur cette même
//! socket** (décision 90 ; E2) : derrière un NAT, le mapping que le bail ouvre
//! et que son keepalive tient est celui de la socket où l'écho écoute. Puis il
//! répond aux sondes autorisées — celle de l'annuaire qui tient son bail ou
//! d'une racine, celle d'`asl ping` munie d'un jeton — et se tait devant tout
//! le reste. Comme `asl announce`, il ne rend pas la main : la connexion EST
//! le bail.
//!
//! # CE QU'IL NE DÉCIDE PAS ICI
//!
//! Qui croire, le débit, l'anti-rejeu, la signature : `asl_client::echo`, sans
//! une entrée-sortie, éprouvé à part. Le tri de la socket au premier octet :
//! `asl-client-tokio`. Ce fichier-ci ne fait qu'obéir et dire.
//!
//! # LA PASSERELLE (décisions 94 à 97)
//!
//! **Active par défaut** (décision 95 ; E15) : une tâche à côté
//! ([`crate::passerelle`]) demande à la box la redirection du port de l'écho,
//! et de lui seul. L'annonce est faite deux fois (§3 quater, « Comment
//! l'annuaire l'apprend ») : **sans** `passerelle` d'abord, pour apprendre
//! `vu_depuis` ; **avec** (`Annonce::avec_passerelle`, `asl-proto` 0.44.0),
//! sur la même connexion, une fois la box interrogée —
//! et seulement vers un annuaire qui connaît le champ (`GET /v1/version`,
//! 0.44.0 ou plus), faute de quoi il refuserait l'annonce entière.
//! `--no-upnp`, ou `ASL_ECHO_UPNP=0` dans l'environnement d'une unité, la
//! coupe.
//!
//! # LE BAIL EN IPv4, QUAND LA BOX NE PERCE PAS SON PARE-FEU IPv6 (décision 106)
//!
//! Le bail part en IPv6 d'abord. Mais derrière une box qui refuse le trou
//! IPv6 et redirige en IPv4 — la Livebox, en vrai —, l'annuaire voit l'IPv6
//! que la box ferme, et la redirection ne peut pas s'annoncer. Quand la
//! passerelle le dit ([`passerelle::Voeu::Ipv4`]), l'écho **ferme le bail
//! IPv6 et le rouvre en IPv4, sur la même socket**, vers les seules adresses
//! IPv4 des annuaires ; la passerelle vérifie alors que `vu_depuis` est
//! l'adresse externe de la box. Le bail reste en IPv4 d'une reconnexion à
//! l'autre, et n'en revient que sur un trou obtenu, une redirection perdue,
//! un double NAT révélé — ou un annuaire muet en IPv4.
//!
//! # CHEZ UN ANNUAIRE LOCAL : L'ADRESSE DE LA BOX, CONFIRMÉE (décision 107)
//!
//! Quand le bail va à un annuaire local — un renvoi —, la bascule ne sert à
//! rien : le membre est sur le réseau de la maison, et ne verrait jamais
//! l'adresse de la box. L'écho reste en IPv6, et **confirme** l'adresse
//! externe que la box lui a dite (`passerelle.externe`, `GetExternalIPAddress`
//! — celle que le double NAT lit déjà), avec le port redirigé ; les racines,
//! qui voient l'adresse IPv4 de la box du membre, sondent la redirection du
//! dehors si les deux concordent. Seulement vers un membre en 0.45.0 au
//! moins : un plus ancien refuserait le champ, et l'annonce avec lui.
//!
//! **Le même PORT, et c'est ce qui compte** : c'est lui que la box redirige,
//! lui que le pare-feu de la machine laisse entrer (décision 105). Une
//! seconde socket liée au même port aurait demandé `SO_REUSEPORT`, et le
//! noyau aurait réparti les datagrammes entrants entre les deux — l'écho
//! n'aurait plus su lesquels étaient à lui. La socket est donc **reliée**, et
//! jamais doublée ([`Socket::relier_pour`]).
//!
//! # L'ADRESSE IPv6 STABLE (décision 108)
//!
//! Liée à `[::]`, la socket laisse **le système** choisir son adresse
//! source : là où les adresses temporaires tournent (RFC 8981 ; macOS par
//! défaut, Linux souvent), c'est une adresse qui aura disparu demain, et une
//! règle posée à la main dans une box qui refuse UPnP meurt avec elle.
//! L'écho se lie donc à **l'adresse IPv6 stable et globale** de l'interface
//! qui sert le bail, quand la machine en a une et que le système la dit
//! ([`crate::stable`]) ; à défaut, il garde le choix du système et le dit.
//! **Le revers est assumé** (Thierry, 2026-09-30) : une adresse stable suit
//! la machine sur l'Internet. **Et une socket liée à une adresse IPv6 ne
//! parle pas IPv4** : la bascule de la décision 106 relie donc la socket à
//! `[::]` en double pile, **au même port**, et le retour en IPv6 la relie à
//! l'adresse stable.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use asl_client::Identite;
use asl_client::echo::{NOM_SERVICE, Repondeur, Silence};
use asl_client_tokio::{Connexion, Faute as FauteReseau, Reglages, joindre_sur};
use asl_echo::RefusSonde;
use asl_id::Genre;
use asl_proto::{NomService, Passerelle, PointEcoute, Port, Protocole, ViaPasserelle};
use tokio::net::UdpSocket;

use crate::arguments::Invocation;
use crate::commandes::{PLAFOND_MS, patience, refus_de_l_annuaire, reglages, reglages_du_renvoi};
use crate::passerelle::{self, Passerelle as TacheDePasserelle, Retour, Voeu};
use crate::{Issue, Sortie, etat, rendu};

/// Ce que la ligne de commande et l'environnement disent de la passerelle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OptionsEcho {
    /// `--no-upnp` n'a pas été donné.
    pub upnp: bool,
    /// `--verbose` : dire aussi ce que la passerelle tait d'habitude.
    pub bavard: bool,
}

/// Lit `ASL_ECHO_UPNP` — `0` coupe la passerelle, `1` la laisse ; toute
/// autre valeur est refusée plutôt que devinée — et `ASL_ECHO_SSDP`.
///
/// # Erreurs
///
/// [`Issue::Configuration`] sur une valeur qui ne se lit pas.
fn reglage_de_la_passerelle(options: OptionsEcho) -> Result<Option<passerelle::Reglage>, Issue> {
    let par_l_environnement = match std::env::var("ASL_ECHO_UPNP").as_deref() {
        Err(_) | Ok("1") => true,
        Ok("0") => false,
        Ok(autre) => {
            return Err(Issue::Configuration(format!(
                "ASL_ECHO_UPNP vaut 0 (couper UPnP) ou 1, et non « {autre} »"
            )));
        }
    };
    if !options.upnp || !par_l_environnement {
        return Ok(None);
    }
    let ssdp = match std::env::var("ASL_ECHO_SSDP") {
        Ok(texte) => Some(passerelle::adresses_ssdp(&texte).map_err(Issue::Configuration)?),
        Err(_) => None,
    };
    Ok(Some(passerelle::Reglage {
        bavard: options.bavard,
        ssdp,
    }))
}

/// Combien de temps la boucle dort entre deux réveils, au plus : une sonde
/// réveille la boucle dès qu'elle arrive, et ceci ne borne que le temps qu'un
/// arrêt met à être vu.
const ENTRETIEN_MS: u64 = 500;

/// Ce qu'on attend avant de recommencer après une panne à la preuve ou à
/// l'annonce : sans cela, un annuaire qui accepte la connexion puis échoue
/// serait rejoint en boucle serrée.
const REPRISE: std::time::Duration = std::time::Duration::from_secs(1);

/// Combien de temps une bascule en IPv4 n'est pas retentée après un annuaire
/// muet en IPv4 : **la moitié d'un tour de passerelle** — assez pour que les
/// accords redits à chaque reconnexion ne la relancent pas, assez peu pour
/// que le tour suivant ([`passerelle::CADENCE`]) la retente.
const SUSPENSION: std::time::Duration = std::time::Duration::from_secs(15 * 60);

const _: () = assert!(
    SUSPENSION.as_secs() * 2 == passerelle::CADENCE.as_secs(),
    "la moitié d'un tour de passerelle"
);

/// Une ligne de bilan par minute, au plus — le débit dépassé, les sondes
/// refusées, une horloge qui dérive (`protocole.md` §3 quater : « une ligne
/// de journal par minute au plus »).
const BILAN_MS: u64 = 60_000;

/// L'heure murale, en millisecondes : c'est elle que les sondes et les jetons
/// datent.
fn maintenant_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |ecoule| {
            u64::try_from(ecoule.as_millis()).unwrap_or(u64::MAX)
        })
}

/// L'écho de cette machine. Ne rend la main que sur un arrêt demandé, ou sur
/// une faute de configuration.
pub async fn echo(
    invocation: &Invocation,
    identite: &Identite,
    dossier: &Path,
    options: OptionsEcho,
) -> Sortie {
    refuser_root()?;
    let reglage_upnp = reglage_de_la_passerelle(options)?;
    let reglages = reglages(invocation)?;
    let tirage = etat::hasard::<8>()
        .map(u64::from_le_bytes)
        .map_err(|quoi| Issue::Configuration(quoi.to_string()))?;
    // **L'ADRESSE IPv6 STABLE, AVANT DE LIER** (décision 108) : elle se
    // choisit sur l'interface que le système prendrait pour l'annuaire.
    let stable = adresse_stable(&reglages).await;
    let (socket, liee_a_la_stable) = lier_dans(&ordre_de_la_plage(tirage), stable).await?;
    let socket = Arc::new(socket);
    let ici = socket
        .local_addr()
        .map_err(|quoi| Issue::Configuration(format!("la socket ne dit pas son port : {quoi}")))?;
    let port = ici.port();
    // **CE QUE LA BASCULE EN IPv4 DEMANDE** (décision 106) : non que CETTE
    // socket soit double pile — on la relie —, mais que la machine sache
    // l'IPv4 sur une socket liée à `[::]` (ce que `net.ipv6.bindv6only`
    // retire à toutes ses sockets), et qu'on ait une IPv6 (sinon le bail y
    // est déjà).
    let double_pile = ici.is_ipv6() && machine_a_double_pile().await;
    let points = [PointEcoute::nouveau(
        Protocole::Udp,
        Port::depuis_u16(port)
            .map_err(|_| Issue::Configuration("le noyau a rendu le port zéro".to_owned()))?,
    )];
    let nom = NomService::analyser(NOM_SERVICE)
        .map_err(|quoi| Issue::Configuration(format!("`{NOM_SERVICE}` : {quoi:?}")))?;
    let graine = etat::hasard::<8>()
        .map(u64::from_le_bytes)
        .map_err(|quoi| Issue::Configuration(quoi.to_string()))?;
    let mut repondeur = Repondeur::nouveau(identite, graine);

    println!(
        "écho           {} — udp {port}, tiré dans {PREMIER_PORT}–{DERNIER_PORT}",
        identite.machine().texte().as_str()
    );
    println!("               il ne répond qu'aux sondes signées ; aux autres, le silence.");
    dire_la_liaison(stable, liee_a_la_stable);

    // **LA PASSERELLE, À CÔTÉ** : elle ne bloque jamais une réponse. Elle
    // retire d'abord ce qu'un arrêt brutal a laissé sur la box.
    let mut passerelle = match reglage_upnp {
        Some(reglage) => Some(TacheDePasserelle::lancer(port, dossier.to_owned(), reglage)),
        None => {
            println!("passerelle     UPnP coupé : la box n'est pas interrogée");
            None
        }
    };
    let mut socket = Socket {
        socket,
        double_pile,
        stable,
        liee_a_la_stable,
    };
    let sortie = tenir_l_echo(
        &reglages,
        identite,
        &mut socket,
        &points,
        nom,
        &mut repondeur,
        &mut passerelle,
    )
    .await;
    // Ce qui n'a pas déjà été retiré avant la fermeture du bail — une
    // faute, un arrêt pendant qu'on cherchait l'annuaire — l'est ici.
    if let Some(passerelle) = passerelle.take() {
        passerelle.arreter().await;
    }
    sortie
}

/// La socket de l'écho, et ce qu'elle sait.
#[derive(Debug)]
struct Socket {
    /// Celle où l'écho écoute, et par où le bail part — **elle est remplacée
    /// quand la famille du bail change** ([`Socket::relier_pour`]).
    socket: Arc<UdpSocket>,
    /// **La machine sait-elle l'IPv4** sur une socket liée à `[::]` en double
    /// pile, et avons-nous une IPv6 ? C'est ce que la bascule de la
    /// décision 106 demande.
    double_pile: bool,
    /// L'adresse IPv6 stable retenue (décision 108), s'il y en a une :
    /// c'est à elle que la socket est liée quand le bail est en IPv6.
    stable: Option<Ipv6Addr>,
    /// La socket est-elle liée à cette adresse **en ce moment** ? Non quand
    /// il n'y en a pas, et non pendant un bail IPv4.
    liee_a_la_stable: bool,
}

impl Socket {
    /// L'adresse IPv6 stable **à laquelle la socket est liée en ce moment** —
    /// celle que l'annonce doit porter (décision 108).
    const fn liee(&self) -> Option<Ipv6Addr> {
        if self.liee_a_la_stable {
            self.stable
        } else {
            None
        }
    }

    /// **RELIE LA SOCKET À LA FAMILLE DU BAIL**, au même port (décisions 106
    /// et 108) : à l'adresse IPv6 stable en IPv6, à `[::]` en double pile
    /// quand le bail passe en IPv4 — une socket liée à une adresse IPv6 ne
    /// parle pas IPv4. Ne fait rien quand la liaison est déjà la bonne, ce
    /// qui est le cas ordinaire (aucune adresse stable, ou pas de bascule).
    ///
    /// # ON LÂCHE L'ANCIENNE AVANT DE LIER LA NOUVELLE
    ///
    /// Le port ne change pas, et deux sockets ne le partagent pas : l'ancienne
    /// doit tomber d'abord. Une socket au port éphémère prend sa place le
    /// temps d'une ligne — rien ne s'en sert, et la nouvelle la remplace. Si
    /// la nouvelle liaison échoue, le port vient pourtant d'être libéré :
    /// c'est une faute de la machine, et l'écho s'arrête en le disant plutôt
    /// que de tourner sourd.
    async fn relier_pour(&mut self, port: u16, en_ipv4: bool) -> Result<(), Issue> {
        let voulue = if en_ipv4 { None } else { self.stable };
        if voulue.is_some() == self.liee_a_la_stable {
            return Ok(());
        }
        let ephemere = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0))
            .await
            .or(UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await);
        match ephemere {
            Ok(rien) => self.socket = Arc::new(rien),
            Err(quoi) => {
                return Err(Issue::Configuration(format!(
                    "la socket de l'écho ne se relie pas (aucune socket éphémère) : {quoi}"
                )));
            }
        }
        let (neuve, liee) = lier(port, voulue).await.map_err(|quoi| {
            Issue::Configuration(format!(
                "la socket de l'écho ne se relie pas à udp {port} : {quoi}"
            ))
        })?;
        self.socket = Arc::new(neuve);
        self.liee_a_la_stable = liee;
        match self.liee() {
            Some(adresse) => println!(
                "écho           socket reliée à l'adresse IPv6 stable {adresse}, udp {port}"
            ),
            None => println!(
                "écho           socket reliée en double pile, udp {port} : le bail passe en IPv4"
            ),
        }
        Ok(())
    }
}

/// **LA BASCULE EN IPv4** (décision 106), tenue d'un bail à l'autre.
#[derive(Debug, Default)]
struct Famille {
    /// Le bail est en IPv4 parce que l'écho l'y a mis : l'adresse externe et
    /// le port que la box redirige. `None` : IPv6 d'abord, comme partout.
    ipv4: Option<(Ipv4Addr, u16)>,
    /// Jusqu'à quand la bascule n'est pas retentée, après un annuaire muet en
    /// IPv4 : la moitié d'un tour de passerelle, pour que le tour suivant la
    /// retente, et que les accords redits à chaque reconnexion ne la
    /// relancent pas en boucle.
    pas_avant: Option<std::time::Instant>,
    /// Ce qu'on a dit la dernière fois qu'une bascule voulue n'a pas pu se
    /// faire : on ne le redit pas à chaque accord.
    empechement: Option<Empechement>,
    /// L'adresse externe et le port qu'on a dit confirmer à un annuaire
    /// local (décision 107) : on ne le redit qu'au changement.
    confirmee: Option<(Ipv4Addr, u16)>,
}

/// Ce qui empêche une bascule en IPv4 que la passerelle demande.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Empechement {
    /// La socket de l'écho ne sait pas l'IPv4.
    PasDeDoublePile,
    /// Aucun annuaire de la liste n'a d'adresse IPv4.
    PasDAnnuaireIpv4,
    /// Un annuaire muet en IPv4 tout à l'heure : on attend le tour suivant.
    Suspendue,
}

impl std::fmt::Display for Empechement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::PasDeDoublePile => {
                "la socket de l'écho n'est pas à double pile (IPV6_V6ONLY refusé à zéro)"
            }
            Self::PasDAnnuaireIpv4 => "aucun annuaire n'a d'adresse IPv4",
            Self::Suspendue => {
                "aucun annuaire n'a répondu en IPv4 tout à l'heure — nouvel essai au prochain \
                 tour de la passerelle"
            }
        })
    }
}

/// Ce que l'écho fait d'un [`Voeu`] de la passerelle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Jugement {
    /// Garder le bail où il est.
    Rester,
    /// Fermer le bail IPv6, le rouvrir en IPv4.
    VersIpv4 { externe: Ipv4Addr, port: u16 },
    /// Fermer le bail IPv4, le rouvrir en IPv6.
    VersIpv6(Retour),
    /// La passerelle voudrait l'IPv4, et c'est impossible d'ici.
    Empeche(Empechement),
    /// **Chez un annuaire local** (décision 107) : rester en IPv6, et
    /// confirmer l'adresse externe de la box avec le port redirigé.
    Confirmer { externe: Ipv4Addr, port: u16 },
}

/// **CE QUE L'ÉCHO FAIT D'UN VŒU** — une fonction, éprouvée à part.
///
/// - `Ipv4` : basculer, si le bail n'y est pas déjà et que rien ne l'empêche
///   — **sauf chez un annuaire local** (`local`), où l'on reste en IPv6 et
///   l'on confirme l'adresse externe de la box (décision 107) ;
/// - `Ipv6` : revenir, **seulement d'une bascule que l'écho a faite** — un
///   bail IPv4 subi (une machine sans IPv6, un annuaire injoignable en IPv6)
///   n'a nulle part où revenir, et la passerelle ne sait pas la différence ;
/// - `Rester` : rien.
fn juger(voeu: Voeu, en_ipv4: bool, local: bool, empechement: Option<Empechement>) -> Jugement {
    match voeu {
        Voeu::Ipv4 { .. } if en_ipv4 => Jugement::Rester,
        Voeu::Ipv4 { externe, port } if local => Jugement::Confirmer { externe, port },
        Voeu::Ipv4 { externe, port } => match empechement {
            Some(empeche) => Jugement::Empeche(empeche),
            None => Jugement::VersIpv4 { externe, port },
        },
        Voeu::Ipv6(retour) if en_ipv4 => Jugement::VersIpv6(retour),
        Voeu::Ipv6(_) | Voeu::Rester => Jugement::Rester,
    }
}

/// **LES SEULS ANNUAIRES IPv4** de ces réglages, pour un bail tenu en IPv4 —
/// ou rien, s'il n'y en a pas. Une adresse IPv4 enfouie dans l'IPv6
/// (`::ffff:a.b.c.d`) compte : c'est une IPv4 sur le fil.
fn en_ipv4_seulement(reglages: &Reglages) -> Option<Reglages> {
    let annuaires: Vec<_> = reglages
        .annuaires()
        .iter()
        .filter(|annuaire| annuaire.adresse.ip().to_canonical().is_ipv4())
        .cloned()
        .collect();
    Reglages::nouveaux(annuaires, PLAFOND_MS).ok()
}

/// La boucle de l'écho : joindre, annoncer, tenir, recommencer.
#[expect(
    clippy::too_many_lines,
    reason = "la boucle se lit d'un trait : joindre, annoncer, tenir, basculer ou recommencer"
)]
async fn tenir_l_echo(
    reglages: &Reglages,
    identite: &Identite,
    socket: &mut Socket,
    points: &[PointEcoute; 1],
    nom: NomService<'_>,
    repondeur: &mut Repondeur,
    passerelle: &mut Option<TacheDePasserelle>,
) -> Sortie {
    let arret = ecouter_l_arret();
    let mut journal = Journal::default();
    let mut famille = Famille::default();
    let port_local = points[0].port.valeur();

    // L'annuaire local vers lequel une racine nous a renvoyés, s'il y en a un
    // — la même règle qu'`asl announce` : un seul saut, et l'on revient aux
    // racines quand il se tait.
    let mut local: Option<Reglages> = None;
    loop {
        if arret.load(Ordering::Acquire) {
            println!("écho arrêté.");
            return Ok(());
        }
        let (tous, racine) = match &local {
            Some(chez_lui) => (chez_lui, false),
            None => (reglages, true),
        };
        // **EN IPv4, LES SEULES ADRESSES IPv4** : c'est la famille qui fait
        // la bascule, et la tournée mettrait l'IPv6 en tête.
        let filtres = match famille.ipv4 {
            Some(_) => {
                let filtres = en_ipv4_seulement(tous);
                if filtres.is_none() {
                    println!(
                        "bail           le bail revient en IPv6 : aucun annuaire n'a d'adresse IPv4"
                    );
                    famille.ipv4 = None;
                }
                filtres
            }
            None => None,
        };
        let courants = filtres.as_ref().unwrap_or(tous);
        let borne = !racine || famille.ipv4.is_some();
        // **LA LIAISON SUIT LA FAMILLE DU BAIL** (décisions 106 et 108) : la
        // socket de l'itération précédente est tombée avec sa connexion, et
        // c'est ici, avant d'en ouvrir une autre, qu'on la relie.
        socket
            .relier_pour(port_local, famille.ipv4.is_some())
            .await?;
        let mut connexion = match joindre(courants, &socket.socket, borne, &arret).await {
            Ok(connexion) => connexion,
            Err(Joindre::Arret) => {
                println!("écho arrêté.");
                return Ok(());
            }
            Err(Joindre::Configuration(quoi)) => return Err(quoi),
            // **UN ANNUAIRE MUET EN IPv4 FAIT REVENIR EN IPv6**, et la bascule
            // attend le tour suivant de la passerelle.
            Err(Joindre::Muet) if famille.ipv4.is_some() => {
                println!(
                    "bail           le bail revient en IPv6 : aucun annuaire ne répond en IPv4"
                );
                famille.ipv4 = None;
                famille.pas_avant = std::time::Instant::now().checked_add(SUSPENSION);
                continue;
            }
            Err(Joindre::Muet) => {
                println!("l'annuaire local ne répond pas — retour aux racines.");
                local = None;
                continue;
            }
        };

        // **QUI TIENT LE BAIL, SOUS QUELLE CLÉ** : celle que la poignée de
        // main a jugée. C'est le seul annuaire hors du binaire que l'écho
        // croira, et il ne délivre de jeton que s'il est une racine de cette
        // invocation — jamais un annuaire local joint par un renvoi.
        let distante = connexion.distante().ok();
        let annuaire = distante.and_then(|ou| {
            courants
                .annuaires()
                .iter()
                .find(|quoi| quoi.adresse == ou)
                .map(|quoi| quoi.identite)
        });
        if let (Some(annuaire), Some(cle)) = (annuaire, connexion.cle_distante()) {
            repondeur.tenir_le_bail(annuaire, cle, racine);
        }

        // **TOUTES LES FAMILLES, MÊME EN IPv4** : l'annonce porte l'IPv6 de la
        // machine pour les sondeurs du même réseau, et la passerelle en a
        // besoin pour redemander le trou — c'est lui qui fera revenir le bail.
        let locales = adresses_locales(tous, &socket.socket, socket.liee()).await;
        let annonce = identite
            .annoncer(nom, points, &locales)
            .map_err(|quoi| Issue::Configuration(format!("l'annonce est refusée : {quoi:?}")))
            .and_then(|annonce| {
                // L'encodage est une validation : une annonce qui ne tient
                // pas dans un message est une faute rendue ici, pas une panne
                // qu'on recommencerait sans fin.
                asl_client_tokio::encoder(&annonce)
                    .map(|_| annonce)
                    .map_err(|quoi| {
                        Issue::Configuration(format!("l'annonce ne s'encode pas : {quoi}"))
                    })
            })?;
        match connexion.authentifier(identite).await {
            Ok(()) => {}
            // **UN REFUS DE LA CLÉ S'ARRÊTE ICI** : réessayer ne la rendrait
            // pas meilleure, et un écho qui boucle contre l'annuaire qui vient
            // de le refuser serait pire qu'un écho arrêté.
            Err(quoi @ FauteReseau::Statut(_)) => {
                let _ = connexion.fermer().await;
                return Err(refus_de_l_annuaire(quoi));
            }
            // Une panne n'est pas un refus : on recommence, après un temps.
            Err(quoi) => {
                println!("bail perdu à la preuve ({quoi}) — on recommence.");
                repondeur.lacher_le_bail();
                tokio::time::sleep(REPRISE).await;
                continue;
            }
        }
        let corps = match connexion.annoncer(&annonce).await {
            Ok(corps) => corps,
            Err(FauteReseau::Renvoye(corps)) if local.is_none() => {
                let _ = connexion.fermer().await;
                local = Some(reglages_du_renvoi(&corps).await?);
                continue;
            }
            // **UN SEUL SAUT** : un annuaire local qui renvoie à son tour est
            // une faute de configuration du domaine, pas une direction — la
            // même règle que l'attache et qu'`asl announce`.
            Err(FauteReseau::Renvoye(_)) => {
                let _ = connexion.fermer().await;
                return Err(Issue::Configuration(
                    "l'annuaire local renvoie à son tour ailleurs : un renvoi ne se suit qu'une fois"
                        .to_owned(),
                ));
            }
            Err(FauteReseau::Statut(code)) => {
                let _ = connexion.fermer().await;
                return Err(Issue::Refuse(code));
            }
            Err(quoi) => {
                println!("bail perdu à l'annonce ({quoi}) — on recommence.");
                repondeur.lacher_le_bail();
                tokio::time::sleep(REPRISE).await;
                continue;
            }
        };
        if let Ok(bail) = asl_client_tokio::cadence_du_bail(&corps) {
            connexion.maintenir(bail);
        }
        dire_le_bail(annuaire, distante, &corps);
        let mut annonce_tenue = AnnonceTenue {
            sans: annonce,
            annoncee: None,
            accepte: false,
            accepte_externe: false,
            externe_tue: false,
        };
        apres_l_annonce(
            &mut connexion,
            &corps,
            &locales,
            passerelle,
            &mut annonce_tenue,
        )
        .await;
        let _ = connexion.ecouter_les_poussees().await;

        let empechement = if !socket.double_pile {
            Some(Empechement::PasDeDoublePile)
        } else if en_ipv4_seulement(tous).is_none() {
            Some(Empechement::PasDAnnuaireIpv4)
        } else {
            famille
                .pas_avant
                .filter(|quand| std::time::Instant::now() < *quand)
                .map(|_| Empechement::Suspendue)
        };
        let fin = tenir(
            &mut connexion,
            identite,
            repondeur,
            &mut journal,
            &arret,
            passerelle,
            &mut annonce_tenue,
            &mut famille,
            !racine,
            empechement,
        )
        .await;
        repondeur.lacher_le_bail();

        match fin {
            Jugement::VersIpv4 { externe, port } => {
                println!(
                    "bail           le bail passe en IPv4 : la box ne perce pas son pare-feu IPv6, \
                     mais redirige udp {port_local} (box {externe}:{port})"
                );
                famille.ipv4 = Some((externe, port));
                famille.pas_avant = None;
                let _ = connexion.fermer().await;
                continue;
            }
            Jugement::VersIpv6(retour) => {
                println!("bail           le bail revient en IPv6 : {retour}");
                famille.ipv4 = None;
                let _ = connexion.fermer().await;
                continue;
            }
            Jugement::Rester | Jugement::Empeche(_) | Jugement::Confirmer { .. } => {}
        }

        if arret.load(Ordering::Acquire) {
            // **LA BOX D'ABORD, LE BAIL ENSUITE** (§3 quater, « La durée ») :
            // la redirection est retirée avant que l'annonce tombe.
            if let Some(passerelle) = passerelle.take() {
                passerelle.arreter().await;
            }
            let _ = connexion.fermer().await;
            println!("écho retiré : le bail est fermé, l'annonce avec lui.");
            return Ok(());
        }
        if famille.ipv4.is_some() {
            println!("bail perdu — on recommence en IPv4, et l'on réannonce sur le même port.");
        } else {
            println!("bail perdu — on recommence, et l'on réannonce sur le même port.");
        }
    }
}

/// Ce que [`joindre`] rend quand elle ne rend pas de connexion.
enum Joindre {
    /// Une faute de configuration : réessayer n'y changerait rien.
    Configuration(Issue),
    /// L'annuaire — local, ou joint en IPv4 après une bascule — ne répond
    /// pas dans le temps d'une personne.
    Muet,
    /// On a demandé l'arrêt pendant qu'on cherchait.
    Arret,
}

/// Joint un annuaire sur la socket de l'écho.
///
/// **AUX RACINES, SANS BORNE** : l'écho est un daemon, et un annuaire
/// injoignable doit le faire attendre, pas tomber (`protocole.md` §1.4).
/// **Chez un annuaire local, ou en IPv4 après une bascule, la patience
/// d'`asl announce`** (`borne`) : au-delà, on retourne aux racines, qui diront
/// peut-être que le domaine a changé d'hébergeur — ou en IPv6, où le bail
/// tenait.
///
/// **L'ARRÊT SE REGARDE PENDANT QU'ON CHERCHE** : Ctrl-C ne tue plus le
/// processus une fois qu'on l'écoute, et une tournée sans fin l'ignorerait.
/// La recherche n'est pas abandonnée entre deux regards — son recul continue
/// là où il en était.
async fn joindre(
    reglages: &Reglages,
    socket: &Arc<UdpSocket>,
    borne: bool,
    arret: &AtomicBool,
) -> Result<Connexion, Joindre> {
    let alea = || etat::hasard::<16>().unwrap_or([0; 16]);
    let mut recherche = Box::pin(joindre_sur(reglages, socket, &alea));
    let echeance = borne.then(|| {
        let depuis = std::time::Instant::now();
        depuis
            .checked_add(std::time::Duration::from_secs(patience()))
            .unwrap_or(depuis)
    });
    loop {
        let regard = tokio::time::Duration::from_millis(ENTRETIEN_MS);
        if let Ok(jointe) = tokio::time::timeout(regard, &mut recherche).await {
            return jointe
                .map_err(|quoi| Joindre::Configuration(Issue::Configuration(quoi.to_string())));
        }
        if arret.load(Ordering::Acquire) {
            return Err(Joindre::Arret);
        }
        if echeance.is_some_and(|fin| std::time::Instant::now() >= fin) {
            return Err(Joindre::Muet);
        }
    }
}

/// Tient le bail, et répond. Rend quand la connexion tombe, qu'on demande
/// l'arrêt ([`Jugement::Rester`]) — ou que la passerelle dit de changer de
/// famille ([`Jugement::VersIpv4`], [`Jugement::VersIpv6`]).
#[expect(
    clippy::too_many_arguments,
    reason = "l'état de la boucle de l'écho, que `tenir` lit et ne garde pas"
)]
async fn tenir(
    connexion: &mut Connexion,
    identite: &Identite,
    repondeur: &mut Repondeur,
    journal: &mut Journal,
    arret: &AtomicBool,
    passerelle: &mut Option<TacheDePasserelle>,
    annonce: &mut AnnonceTenue<'_>,
    famille: &mut Famille,
    local: bool,
    empechement: Option<Empechement>,
) -> Jugement {
    while connexion.vivante() && !arret.load(Ordering::Acquire) {
        if connexion.entretenir(ENTRETIEN_MS).await.is_err() {
            break;
        }
        if let Some(accord) = passerelle.as_mut().and_then(TacheDePasserelle::accord) {
            let a_annoncer = match juger(accord.voeu, famille.ipv4.is_some(), local, empechement) {
                Jugement::Rester => accord.port.map(|port| (port, None)),
                Jugement::Empeche(empeche) => {
                    if famille.empechement != Some(empeche) {
                        println!(
                            "bail           la box ne perce pas son pare-feu IPv6 et redirige en IPv4, \
                             mais le bail reste en IPv6 : {empeche}"
                        );
                        famille.empechement = Some(empeche);
                    }
                    accord.port.map(|port| (port, None))
                }
                Jugement::Confirmer { externe, port } => {
                    if famille.confirmee != Some((externe, port)) {
                        println!(
                            "passerelle     la box ne perce pas son pare-feu IPv6 et redirige udp \
                             {port} de {externe} :\n\
                             \x20              le bail reste chez l'annuaire local, en IPv6 ; \
                             l'adresse de la box est confirmée,\n\
                             \x20              et les racines sonderont {externe}:{port} si elles \
                             voient l'annuaire local depuis elle"
                        );
                        famille.confirmee = Some((externe, port));
                    }
                    Some((port, Some(externe)))
                }
                bascule => return bascule,
            };
            reannoncer(connexion, annonce, a_annoncer).await;
        }
        for (datagramme, source) in connexion.echos() {
            let maintenant = maintenant_ms();
            match repondeur.recevoir(identite, &datagramme, source, maintenant) {
                Ok(repondue) => {
                    // **LA RÉPONSE PART D'OÙ LA SONDE EST ARRIVÉE** : la
                    // socket du bail, le port annoncé.
                    let envoi = connexion.envoyer_a(&repondue.reponse, source).await;
                    journal.repondu(repondue.sondeur, source, envoi.is_ok());
                }
                Err(silence) => journal.silence(silence),
            }
        }
        journal.bilan(maintenant_ms());
        if let Ok(poussees) = connexion.poussees()
            && let Some(derniere) = poussees.last()
        {
            journal.poussee(derniere);
        }
    }
    Jugement::Rester
}

/// Ce que l'écho dit de ce qu'il fait — **sobrement** : une ligne par preuve
/// rendue, un bilan par minute au plus pour ce qu'il a tu, une ligne quand le
/// verdict de l'annuaire change.
#[derive(Debug, Default)]
struct Journal {
    /// Depuis le dernier bilan : refusées, au-delà du débit, illisibles.
    refusees: u64,
    debit: u64,
    illisibles: u64,
    rejeux: u64,
    /// Une sonde d'annuaire authentique, hors de la fenêtre : l'horloge dérive.
    horloge: u64,
    /// Quand le dernier bilan a été dit.
    dernier_bilan: u64,
    /// Le dernier verdict poussé, tel qu'on l'a dit.
    verdict: Option<String>,
}

impl Journal {
    fn repondu(&self, sondeur: asl_id::Identifiant, source: SocketAddr, parti: bool) {
        let qui = if sondeur.genre() == Genre::Annuaire {
            "annuaire"
        } else {
            "jeton   "
        };
        let issue = if parti {
            "preuve rendue"
        } else {
            "preuve signée, NON ENVOYÉE (la socket a refusé)"
        };
        println!(
            "sonde          {qui} {} depuis {} — {issue}",
            sondeur.texte().as_str(),
            vue(source)
        );
    }

    const fn silence(&mut self, silence: Silence) {
        match silence {
            Silence::DebitSource | Silence::DebitTotal => self.debit = self.debit.saturating_add(1),
            Silence::Illisible(_) => self.illisibles = self.illisibles.saturating_add(1),
            Silence::Rejeu => self.rejeux = self.rejeux.saturating_add(1),
            Silence::Refusee(RefusSonde::HorsFenetre) => {
                self.horloge = self.horloge.saturating_add(1);
            }
            Silence::Refusee(_) => self.refusees = self.refusees.saturating_add(1),
        }
    }

    /// Le bilan de la minute écoulée, s'il y a quelque chose à dire.
    fn bilan(&mut self, maintenant: u64) {
        if maintenant.saturating_sub(self.dernier_bilan) < BILAN_MS {
            return;
        }
        if self.horloge > 0 {
            println!(
                "HORLOGE        {} sonde(s) d'annuaire authentique(s) datée(s) à plus de deux\n\
                 \x20              minutes de l'heure de cette machine : son horloge dérive, et l'écho\n\
                 \x20              ne répondra à aucune sonde tant qu'elle dérivera. Réglez NTP.",
                self.horloge
            );
        }
        let tues = self
            .refusees
            .saturating_add(self.debit)
            .saturating_add(self.illisibles)
            .saturating_add(self.rejeux);
        if tues > 0 {
            println!(
                "silence        dans la minute : {} non autorisée(s), {} au-delà du débit, \
                 {} illisible(s), {} rejouée(s)",
                self.refusees, self.debit, self.illisibles, self.rejeux
            );
        }
        *self = Self {
            dernier_bilan: maintenant,
            verdict: self.verdict.take(),
            ..Self::default()
        };
    }

    /// Le verdict que l'annuaire pousse sur le point de l'écho, quand il
    /// change.
    fn poussee(&mut self, octets: &[u8]) {
        let dit = match rendu::poussee(octets) {
            Ok(dit) => dit,
            Err(quoi) => format!("ILLISIBLE — {quoi}"),
        };
        if self.verdict.as_deref() != Some(dit.as_str()) {
            println!("verdict        {dit}");
            self.verdict = Some(dit);
        }
    }
}

/// Une source, telle qu'on la lit : une IPv4 enfouie redevient une IPv4.
fn vue(source: SocketAddr) -> String {
    SocketAddr::new(source.ip().to_canonical(), source.port()).to_string()
}

/// Dit qui tient le bail, et sous quelle adresse l'annuaire nous voit.
fn dire_le_bail(annuaire: Option<asl_id::Identifiant>, distante: Option<SocketAddr>, corps: &[u8]) {
    let qui = annuaire.map_or_else(|| "?".to_owned(), |id| id.texte().as_str().to_owned());
    let ou = distante.map_or_else(|| "?".to_owned(), vue);
    let mut tampons = asl_proto::cadrage::TamponsReponse::nouveaux();
    match asl_proto::Reponse::decoder(corps, &mut tampons) {
        Ok(lue) => {
            let vu = SocketAddr::new(lue.vu_depuis.adresse, lue.vu_depuis.port.valeur());
            println!(
                "bail           tenu par {qui} ({ou}) — {} annoncé, vu depuis {}",
                lue.service.texte().as_str(),
                vue(vu)
            );
            for entree in lue.joignabilite {
                println!("verdict        {}", rendu::verdict(entree));
            }
        }
        Err(quoi) => {
            println!("bail           tenu par {qui} ({ou}) — réponse illisible ({quoi:?})")
        }
    }
}

/// L'annonce de l'écho sur UNE connexion : l'annonce sans `passerelle`, ce
/// qu'on y a annoncé depuis, et si l'annuaire connaît le champ.
#[derive(Debug)]
struct AnnonceTenue<'a> {
    /// L'annonce, sans `passerelle`.
    sans: asl_proto::Annonce<'a>,
    /// Le port de `passerelle` que cette connexion a annoncé, et l'adresse
    /// externe qu'il confirmait, s'il y en a un.
    annoncee: Option<(u16, Option<Ipv4Addr>)>,
    /// L'annuaire de cette connexion connaît `passerelle` (0.44.0 ou plus).
    accepte: bool,
    /// Il connaît aussi `passerelle.externe` (0.45.0 ou plus, décision 107).
    accepte_externe: bool,
    /// On a déjà dit qu'il ne la connaît pas.
    externe_tue: bool,
}

/// **CE QUI SUIT LA PREMIÈRE ANNONCE** (décision 97 ; E21) : lire la
/// version de l'annuaire — il faut 0.44.0 pour `passerelle` —, puis dire à la
/// passerelle d'où l'annuaire nous voit. Elle répondra par un accord, que
/// [`tenir`] réannonce sur cette même connexion.
async fn apres_l_annonce(
    connexion: &mut Connexion,
    reponse: &[u8],
    locales: &[IpAddr],
    passerelle: &Option<TacheDePasserelle>,
    annonce: &mut AnnonceTenue<'_>,
) {
    let Some(passerelle) = passerelle else {
        return;
    };
    let mut tampons = asl_proto::cadrage::TamponsReponse::nouveaux();
    let Ok(lue) = asl_proto::Reponse::decoder(reponse, &mut tampons) else {
        return;
    };
    let vu = lue.vu_depuis.adresse;
    let version = match connexion.version().await {
        Ok(corps) => rendu::version_seule(&corps).ok(),
        Err(_) => None,
    };
    annonce.accepte = version
        .as_deref()
        .is_some_and(passerelle::connait_la_passerelle);
    annonce.accepte_externe = version
        .as_deref()
        .is_some_and(passerelle::connait_l_externe);
    if !annonce.accepte {
        let (a, b, c) = passerelle::VERSION_PASSERELLE;
        println!(
            "passerelle     l'annuaire ({}) ne connaît pas encore le champ `passerelle` ({a}.{b}.{c}) :\n\
             \x20              ce que la box accordera ne lui sera pas annoncé",
            version.as_deref().unwrap_or("version inconnue")
        );
    }
    passerelle.vu(vu, locales.to_vec());
}

/// Réannonce sur la connexion tenue, avec ou sans `passerelle`, selon
/// l'accord de la box — et seulement vers un annuaire qui connaît le champ.
///
/// **LE CHAMP EST ÉCRIT PAR `asl-proto`** (`Annonce::avec_passerelle`,
/// serveur 0.44.0) : la même grammaire que celle que l'annuaire lit, et qui
/// refuse le champ sur toute autre annonce que `asl-echo`.
///
/// **Une adresse externe ne part que vers un annuaire en 0.45.0 au moins**
/// (décision 107) : sinon rien ne part — un port redirigé en IPv4 annoncé
/// sans elle, sur un bail IPv6, ferait sonder l'IPv6 à ce port.
async fn reannoncer(
    connexion: &mut Connexion,
    annonce: &mut AnnonceTenue<'_>,
    accord: Option<(u16, Option<Ipv4Addr>)>,
) {
    if accord == annonce.annoncee || !annonce.accepte {
        return;
    }
    if accord.is_some_and(|(_, externe)| externe.is_some()) && !annonce.accepte_externe {
        if !annonce.externe_tue {
            let (a, b, c) = passerelle::VERSION_EXTERNE;
            println!(
                "passerelle     l'annuaire local ne connaît pas encore `passerelle.externe` \
                 ({a}.{b}.{c}) :\n\
                 \x20              l'adresse de la box ne lui sera pas confirmée"
            );
            annonce.externe_tue = true;
        }
        return;
    }
    let corps = match accord {
        Some((port, externe)) => {
            let passerelle = Port::depuis_u16(port).map(|port| Passerelle {
                port,
                via: ViaPasserelle::Upnp,
                externe,
            });
            match passerelle.and_then(|passerelle| annonce.sans.avec_passerelle(passerelle)) {
                Ok(avec) => avec,
                Err(quoi) => {
                    println!(
                        "annonce        la passerelle ne s'écrit pas ({quoi}) : l'annonce reste sans"
                    );
                    return;
                }
            }
        }
        None => annonce.sans,
    };
    match connexion.annoncer(&corps).await {
        Ok(_) => {
            annonce.annoncee = accord;
            match accord {
                Some((port, None)) => println!(
                    "annonce        réannoncée avec la passerelle : port externe {port} (upnp)"
                ),
                Some((port, Some(externe))) => println!(
                    "annonce        réannoncée avec la passerelle : {externe}:{port} (upnp), \
                     adresse confirmée"
                ),
                None => println!("annonce        réannoncée sans passerelle"),
            }
        }
        // Un refus du champ : on n'insiste pas sur cette connexion.
        Err(FauteReseau::Statut(code)) => {
            annonce.accepte = false;
            println!(
                "annonce        l'annuaire refuse la passerelle ({code}) : l'annonce reste sans"
            );
        }
        // Une panne : la connexion le dira, et l'on recommencera.
        Err(_) => {}
    }
}

/// Le premier port de la plage de l'écho.
///
/// # UNE PLAGE, ET NON UN PORT ÉPHÉMÈRE (décision du 2026-09-29)
///
/// La spécification disait « un port aléatoire » ; l'essai réel a montré que
/// c'est le pare-feu de la machine (nft, ufw en politique `drop`) qui
/// décidait alors, et qu'aucun exploitant ne peut ouvrir d'avance un port
/// qu'il ne connaît pas. **Neuf ports, 6631 à 6639**, juste au-dessus de
/// celui de l'annuaire : l'exploitant les ouvre une fois —
/// `udp dport 6631-6639 accept` (nft), `ufw allow proto udp from any to any
/// port 6631:6639` —, et l'écho en prend un **au hasard**, le suivant dans
/// son ordre tiré si celui-là est pris. Il reste sans port fixe (décision
/// 89) : neuf échos peuvent tourner sur une même machine, et qui balaie ne
/// sait pas lequel des neuf répondrait — ni qu'il ne répond qu'aux sondes
/// signées.
pub const PREMIER_PORT: u16 = 6631;

/// Le dernier port de la plage de l'écho — voir [`PREMIER_PORT`].
pub const DERNIER_PORT: u16 = 6639;

/// Le nombre de ports de la plage.
const PORTS: usize = 9;

const _: () = assert!(
    DERNIER_PORT - PREMIER_PORT + 1 == 9,
    "PORTS doit compter la plage"
);

/// Les ports de la plage, **dans un ordre tiré de `graine`** : un mélange de
/// Fisher-Yates, sur un générateur `xorshift` que la graine amorce. L'ordre
/// n'a rien de secret — ce qui protège l'écho, ce sont les signatures ; il
/// étale seulement les échos d'une machine sur la plage.
fn ordre_de_la_plage(graine: u64) -> [u16; PORTS] {
    let mut ports = [0_u16; PORTS];
    for (place, port) in ports.iter_mut().zip(PREMIER_PORT..=DERNIER_PORT) {
        *place = port;
    }
    // Une graine nulle figerait `xorshift` à zéro.
    let mut etat = graine | 1;
    for haut in (1..PORTS).rev() {
        etat ^= etat << 13;
        etat ^= etat >> 7;
        etat ^= etat << 17;
        let borne = u64::try_from(haut).unwrap_or(0).saturating_add(1);
        let tire = usize::try_from(etat.checked_rem(borne).unwrap_or(0)).unwrap_or(0);
        ports.swap(haut, tire);
    }
    ports
}

/// Lie la socket de l'écho au premier de ces ports qui soit libre :
/// **`[::]:<port>`, à double pile**, et `0.0.0.0:<port>` si la machine n'a
/// pas d'IPv6 (`protocole.md` §3 quater, « IPv6 d'abord ») ; rend aussi si
/// elle est à double pile.
///
/// Un port pris — par un autre écho, par n'importe qui — fait passer au
/// suivant ; une autre faute du noyau aussi, dite à la fin si aucun ne se
/// lie.
///
/// # LA DOUBLE PILE, POSÉE ET NON SUPPOSÉE (décision 106)
///
/// Linux et macOS donnent la double pile par défaut à une socket liée sur
/// `[::]` — **par défaut** : `net.ipv6.bindv6only = 1` la retire à toutes
/// les sockets d'une machine Linux. Le bail de l'écho doit pouvoir passer en
/// IPv4 sur CETTE socket, celle dont la box redirige le port ; on pose donc
/// `IPV6_V6ONLY` à zéro avant de lier (`socket2`, déjà tiré pour
/// `IPV6_MULTICAST_IF`), et l'on relit l'option : un système qui la refuse
/// laisse une socket IPv6 seule, et l'écho le dira s'il doit basculer.
///
/// # Erreurs
///
/// [`Issue::Configuration`] — « aucun port libre » — quand toute la plage
/// est occupée : c'est la machine qu'il faut regarder, pas le réseau.
async fn lier_dans(ports: &[u16], stable: Option<Ipv6Addr>) -> Result<(UdpSocket, bool), Issue> {
    let mut derniere: Option<std::io::Error> = None;
    for port in ports {
        match lier(*port, stable).await {
            Ok(liee) => return Ok(liee),
            Err(quoi) => derniere = Some(quoi),
        }
    }
    let premier = ports.iter().min().copied().unwrap_or(PREMIER_PORT);
    let dernier = ports.iter().max().copied().unwrap_or(DERNIER_PORT);
    Err(Issue::Configuration(format!(
        "aucun port libre dans {premier}–{dernier} : chacun est déjà pris sur cette\n\
         machine{} — un autre écho, ou un autre service. `ss -ulpn` dit lequel.",
        derniere.map_or_else(String::new, |quoi| format!(" (dernier refus : {quoi})"))
    )))
}

/// **Lie la socket de l'écho à ce port** : à `stable` si l'on en a une
/// (décision 108), sinon à `[::]` en double pile, sinon — pas d'IPv6 sur
/// cette machine — à `0.0.0.0`. Rend la socket, et **si elle est liée à
/// l'adresse stable**.
async fn lier(port: u16, stable: Option<Ipv6Addr>) -> std::io::Result<(UdpSocket, bool)> {
    if let Some(adresse) = stable {
        // Une adresse précise : rien à dire de la double pile, c'est une
        // socket IPv6 et elle le reste (la bascule la reliera).
        match UdpSocket::bind((adresse, port)).await {
            Ok(socket) => return Ok((socket, true)),
            // L'adresse a disparu entre le choix et la liaison, ou le port est
            // pris : on essaie comme si l'on n'en avait pas, et la ligne de
            // journal de `lier_dans` dira le port retenu.
            Err(quoi) if quoi.kind() == std::io::ErrorKind::AddrInUse => return Err(quoi),
            Err(_) => {}
        }
    }
    match lier_en_double_pile(port) {
        Ok(socket) => return UdpSocket::from_std(socket).map(|socket| (socket, false)),
        Err(quoi) if quoi.kind() == std::io::ErrorKind::AddrInUse => return Err(quoi),
        // Pas d'IPv6 sur cette machine : l'IPv4 seule, sur le même port.
        Err(_) => {}
    }
    UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port))
        .await
        .map(|socket| (socket, false))
}

/// Une socket UDP liée à `[::]:<port>`, **`IPV6_V6ONLY` posé à zéro**, non
/// bloquante. Voir [`lier`].
fn lier_en_double_pile(port: u16) -> std::io::Result<std::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    // **POSÉE, ET NON SUPPOSÉE** : `net.ipv6.bindv6only = 1` retire la double
    // pile à toutes les sockets d'une machine Linux.
    let _ = socket.set_only_v6(false);
    socket.set_nonblocking(true)?;
    socket.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)).into())?;
    Ok(socket.into())
}

/// **LA MACHINE SAIT-ELLE L'IPv4 SUR UNE SOCKET DOUBLE PILE ?** — ce que la
/// bascule de la décision 106 demande, lu une fois, sur un port éphémère :
/// la socket de l'écho, elle, peut être liée à une adresse IPv6 précise
/// (décision 108), et n'apprendrait rien de son propre `IPV6_V6ONLY`.
async fn machine_a_double_pile() -> bool {
    use socket2::{Domain, Protocol, Socket, Type};
    let Ok(socket) = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)) else {
        return false;
    };
    let posee = socket.set_only_v6(false).is_ok();
    posee && socket.only_v6().is_ok_and(|seule| !seule)
}

/// **L'ADRESSE IPv6 STABLE À LAQUELLE SE LIER** (décision 108), ou rien.
///
/// L'interface est celle que le système prendrait pour joindre un annuaire :
/// on la lui demande comme [`adresses_locales`] le fait — une socket qu'on
/// connecte, sans rien envoyer —, puis [`crate::stable::choisir`] tranche.
async fn adresse_stable(reglages: &Reglages) -> Option<Ipv6Addr> {
    let cible = reglages
        .annuaires()
        .iter()
        .map(|annuaire| annuaire.adresse)
        .find(SocketAddr::is_ipv6)?;
    let sonde = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)).await.ok()?;
    sonde.connect(cible).await.ok()?;
    let source = match sonde.local_addr().ok()?.ip() {
        IpAddr::V6(six) if !six.is_unspecified() => six,
        _ => return None,
    };
    crate::stable::choisir(crate::stable::table().as_deref(), source)
}

/// **POURQUOI LA LIAISON N'EST PAS CELLE QU'ON VOULAIT** (décision 108), ou
/// `None` quand elle l'est : c'est ce qui dit à l'exploitant si une règle
/// posée à la main dans sa box tiendra.
const fn raison_de_liaison(stable: bool, liee: bool, sans_table: bool) -> Option<&'static str> {
    match (stable, liee) {
        (true, true) => None,
        // Choisie, mais la liaison n'a pas tenu : l'adresse a disparu entre
        // le choix et le `bind`, ou tous les ports de la plage étaient pris
        // sur elle.
        (true, false) => {
            Some("l'adresse IPv6 stable n'a pas pu être liée (disparue, ou son port était pris)")
        }
        (false, _) if sans_table => {
            Some("ce système ne dit pas les drapeaux de ses adresses (pas de /proc/net/if_inet6)")
        }
        (false, _) => Some("aucune adresse IPv6 stable et globale sur l'interface du bail"),
    }
}

/// Ce que l'écho dit de sa liaison, une fois, au démarrage (décision 108).
fn dire_la_liaison(stable: Option<Ipv6Addr>, liee: bool) {
    let Some(pourquoi) =
        raison_de_liaison(stable.is_some(), liee, crate::stable::table().is_none())
    else {
        let adresse = stable.map_or_else(String::new, |adresse| adresse.to_string());
        println!(
            "écho           lié à l'adresse IPv6 stable {adresse} : elle ne tourne pas, et une \
             règle"
        );
        println!("               posée à la main dans la box y tiendra.");
        return;
    };
    println!("écho           {pourquoi} :");
    println!(
        "               le système choisit son adresse — une règle posée à la main dans la box"
    );
    println!("               ne tiendra pas (le trou UPnP, lui, est redemandé à chaque tour).");
}

/// Les adresses de cette machine à annoncer : **une par famille**, celle par
/// laquelle elle sort vers l'annuaire de cette famille — IPv6 d'abord, puis
/// IPv4.
///
/// # POURQUOI PAS TOUTES
///
/// La spécification les voudrait toutes, jusqu'à `ADRESSES_MAX`. Les
/// énumérer demande `getifaddrs`, c'est-à-dire du C (C4). Ce que le noyau dit
/// sans C, c'est l'adresse qu'il choisirait pour joindre une destination : on
/// le lui demande, sans rien envoyer, pour une destination de chaque famille —
/// les annuaires qu'on joint. Une machine à plusieurs adresses globales n'en
/// annonce donc qu'une par famille, **celle qui sort** : c'est aussi celle
/// qu'un sondeur du même réseau a le plus de chances de joindre.
async fn adresses_locales(
    reglages: &Reglages,
    socket: &UdpSocket,
    liee: Option<Ipv6Addr>,
) -> Vec<IpAddr> {
    let double_pile = socket.local_addr().is_ok_and(|ici| ici.is_ipv6());
    let mut trouvees: Vec<IpAddr> = Vec::new();
    // **L'ADRESSE LIÉE EST CELLE QU'ON ANNONCE** (décision 108) : une socket
    // liée ne reçoit que ce qui lui est destiné, et c'est sur cette
    // comparaison que l'annuaire prend son verdict de NAT — annoncer
    // l'adresse que le système aurait choisie ferait dire `nat` là où il faut
    // dire `direct`.
    if let Some(stable) = liee {
        trouvees.push(IpAddr::V6(stable));
    }
    for six in [true, false] {
        if six && (!double_pile || liee.is_some()) {
            continue;
        }
        let Some(cible) = reglages
            .annuaires()
            .iter()
            .map(|annuaire| annuaire.adresse)
            .find(|adresse| adresse.is_ipv6() == six)
        else {
            continue;
        };
        let lien = if six { "[::]:0" } else { "0.0.0.0:0" };
        let Ok(sonde) = UdpSocket::bind(lien).await else {
            continue;
        };
        if sonde.connect(cible).await.is_err() {
            continue;
        }
        if let Ok(ici) = sonde.local_addr()
            && !ici.ip().is_unspecified()
            && !trouvees.contains(&ici.ip())
        {
            trouvees.push(ici.ip());
        }
    }
    trouvees
}

/// **L'ÉCHO NE TOURNE PAS EN ROOT** (C8) : l'identité vit chez
/// l'utilisateur qui la détient, et c'est sous son compte qu'il répond.
///
/// L'`euid` se lit sans `libc` : le propriétaire de `/proc/self` sous Linux,
/// celui d'un fichier qu'on vient de créer ailleurs. Si rien ne le dit, on ne
/// refuse pas — on ne sait pas.
fn refuser_root() -> Result<(), Issue> {
    if euid() == Some(0) {
        return Err(Issue::Configuration(
            "asl echo refuse de tourner en root : l'identité de cette machine vit chez\n\
             l'utilisateur qui la détient, et c'est sous son compte que l'écho répond\n\
             (systemctl --user, pas le gestionnaire du système)."
                .to_owned(),
        ));
    }
    Ok(())
}

/// L'`euid` de ce processus, lu sans `unsafe`.
fn euid() -> Option<u32> {
    use std::os::unix::fs::MetadataExt as _;
    if let Ok(meta) = std::fs::metadata("/proc/self") {
        return Some(meta.uid());
    }
    let temoin = std::env::temp_dir().join(format!(
        "asl-echo-euid-{}-{}",
        std::process::id(),
        maintenant_ms()
    ));
    let fichier = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temoin)
        .ok()?;
    let uid = fichier.metadata().ok().map(|meta| meta.uid());
    drop(fichier);
    let _ = std::fs::remove_file(&temoin);
    uid
}

/// Un drapeau que Ctrl-C **ou `SIGTERM`** lève — ce que systemd et launchd
/// envoient pour arrêter l'unité : le bail se ferme alors proprement, et
/// l'annuaire ne donne pas une adresse morte une minute durant.
fn ecouter_l_arret() -> Arc<AtomicBool> {
    let arret = crate::commandes::ecouter_ctrl_c();
    let sien = Arc::clone(&arret);
    tokio::spawn(async move {
        if let Ok(mut terme) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            && terme.recv().await.is_some()
        {
            sien.store(true, Ordering::Release);
        }
    });
    arret
}

#[cfg(test)]
mod tests {
    use super::{
        DERNIER_PORT, Empechement, Jugement, PREMIER_PORT, Socket, adresses_locales,
        en_ipv4_seulement, juger, lier, lier_dans, machine_a_double_pile, ordre_de_la_plage,
        raison_de_liaison,
    };
    use crate::Issue;
    use crate::passerelle::{Retour, Voeu};
    use asl_client_tokio::{Annuaire, Reglages};
    use asl_id::{Genre, Identifiant};
    use std::net::{IpAddr, SocketAddr};
    use tokio::net::UdpSocket;

    #[test]
    fn l_echo_ne_revient_que_d_une_bascule_qu_il_a_faite() {
        let externe = "203.0.113.7".parse().unwrap();
        let ipv4 = Voeu::Ipv4 {
            externe,
            port: 6634,
        };
        let retour = Voeu::Ipv6(Retour::RedirectionPerdue);
        // En IPv6 : basculer, sauf empêchement ; un retour ne veut rien dire.
        assert_eq!(
            juger(ipv4, false, false, None),
            Jugement::VersIpv4 {
                externe,
                port: 6634
            }
        );
        for empeche in [
            Empechement::PasDeDoublePile,
            Empechement::PasDAnnuaireIpv4,
            Empechement::Suspendue,
        ] {
            assert_eq!(
                juger(ipv4, false, false, Some(empeche)),
                Jugement::Empeche(empeche)
            );
        }
        assert_eq!(juger(retour, false, false, None), Jugement::Rester);
        assert_eq!(juger(Voeu::Rester, false, false, None), Jugement::Rester);
        // En IPv4 par bascule : rester, ou revenir.
        assert_eq!(juger(ipv4, true, false, None), Jugement::Rester);
        assert_eq!(juger(Voeu::Rester, true, false, None), Jugement::Rester);
        assert_eq!(
            juger(retour, true, false, Some(Empechement::Suspendue)),
            Jugement::VersIpv6(Retour::RedirectionPerdue)
        );
    }

    #[test]
    fn chez_un_annuaire_local_l_echo_confirme_l_adresse_de_la_box_sans_basculer() {
        let externe = "193.250.159.198".parse().unwrap();
        let ipv4 = Voeu::Ipv4 {
            externe,
            port: 6633,
        };
        // Décision 107 : ni bascule ni empêchement — une confirmation.
        for empechement in [None, Some(Empechement::PasDAnnuaireIpv4)] {
            assert_eq!(
                juger(ipv4, false, true, empechement),
                Jugement::Confirmer {
                    externe,
                    port: 6633
                }
            );
        }
        // Le reste ne change pas chez lui.
        assert_eq!(juger(Voeu::Rester, false, true, None), Jugement::Rester);
        assert_eq!(juger(ipv4, true, true, None), Jugement::Rester);
    }

    #[test]
    fn les_empechements_se_disent() {
        assert!(
            Empechement::PasDeDoublePile
                .to_string()
                .contains("pas à double pile")
        );
        assert_eq!(
            Empechement::PasDAnnuaireIpv4.to_string(),
            "aucun annuaire n'a d'adresse IPv4"
        );
        assert!(
            Empechement::Suspendue
                .to_string()
                .contains("prochain tour de la passerelle")
        );
    }

    #[test]
    fn en_ipv4_seulement_les_adresses_ipv4() {
        let identite = Identifiant::depuis_entropie(Genre::Annuaire, [0x11; 16]);
        let annuaire = |adresse: &str| Annuaire {
            adresse: adresse.parse().unwrap(),
            nom: "racine".to_owned(),
            identite,
        };
        let deux = Reglages::nouveaux(
            vec![
                annuaire("[2001:db8::1]:6630"),
                annuaire("203.0.113.1:6630"),
                annuaire("[::ffff:203.0.113.2]:6630"),
            ],
            15_000,
        )
        .unwrap();
        let quatre: Vec<String> = en_ipv4_seulement(&deux)
            .unwrap()
            .annuaires()
            .iter()
            .map(|annuaire| annuaire.adresse.to_string())
            .collect();
        assert_eq!(quatre, ["203.0.113.1:6630", "[::ffff:203.0.113.2]:6630"]);
        let six = Reglages::nouveaux(vec![annuaire("[2001:db8::1]:6630")], 15_000).unwrap();
        assert!(en_ipv4_seulement(&six).is_none());
    }

    /// **LA DOUBLE PILE, SUR LE VRAI NOYAU** : la socket de l'écho, liée à
    /// `[::]`, reçoit d'une socket IPv4 — c'est ce qui laisse le bail passer
    /// en IPv4 sans changer de port (décision 106).
    #[tokio::test]
    async fn la_socket_de_l_echo_recoit_aussi_l_ipv4() {
        let (_tenu, _, libre) = un_pris_un_libre().await;
        let (socket, liee) = lier_dans(&[libre], None).await.expect("un port libre");
        assert!(!liee, "sans adresse stable, on ne s'y lie pas");
        let ici = socket.local_addr().unwrap();
        if !ici.is_ipv6() {
            // Une machine sans IPv6 : la socket est IPv4, rien à éprouver.
            return;
        }
        assert!(machine_a_double_pile().await, "IPV6_V6ONLY posé à zéro");
        let quatre = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        quatre
            .send_to(b"\x04asl", ("127.0.0.1", ici.port()))
            .await
            .unwrap();
        let mut recu = [0_u8; 16];
        let (lus, source) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            socket.recv_from(&mut recu),
        )
        .await
        .expect("reçu dans les deux secondes")
        .unwrap();
        assert_eq!(&recu[..lus], b"\x04asl");
        assert_eq!(source.ip().to_canonical().to_string(), "127.0.0.1");
    }

    #[test]
    fn l_ordre_est_un_melange_de_toute_la_plage() {
        let mut vus = std::collections::BTreeSet::new();
        for graine in 0..64_u64 {
            let ordre = ordre_de_la_plage(graine.wrapping_mul(0x9E37_79B9_7F4A_7C15));
            let mut trie = ordre;
            trie.sort_unstable();
            assert_eq!(
                trie.to_vec(),
                (PREMIER_PORT..=DERNIER_PORT).collect::<Vec<_>>(),
                "chaque port une fois"
            );
            vus.insert(ordre[0]);
        }
        assert!(
            vus.len() > 4,
            "le premier port varie avec la graine : {vus:?}"
        );
    }

    /// Deux ports que le noyau vient de donner : le premier reste tenu, le
    /// second est rendu.
    async fn un_pris_un_libre() -> (UdpSocket, u16, u16) {
        let tenu = UdpSocket::bind("[::]:0").await.expect("une socket");
        let pris = tenu.local_addr().unwrap().port();
        let libre = UdpSocket::bind("[::]:0")
            .await
            .expect("une socket")
            .local_addr()
            .unwrap()
            .port();
        (tenu, pris, libre)
    }

    #[tokio::test]
    async fn un_port_pris_fait_passer_au_suivant() {
        let (_tenu, pris, libre) = un_pris_un_libre().await;
        let (socket, _) = lier_dans(&[pris, libre], None)
            .await
            .expect("le suivant est libre");
        assert_eq!(socket.local_addr().unwrap().port(), libre);
    }

    #[tokio::test]
    async fn une_plage_pleine_est_une_faute_de_configuration_dite_clairement() {
        let (_tenu, pris, _) = un_pris_un_libre().await;
        match lier_dans(&[pris], None).await {
            Err(Issue::Configuration(quoi)) => {
                assert!(
                    quoi.contains(&format!("aucun port libre dans {pris}–{pris}")),
                    "{quoi}"
                );
            }
            autre => panic!("une faute de configuration : {autre:?}"),
        }
        // Sur la vraie plage, le message nomme la vraie plage.
        let tenus: Vec<_> = {
            let mut tenus = Vec::new();
            for port in PREMIER_PORT..=DERNIER_PORT {
                if let Ok(socket) = UdpSocket::bind(("::", port)).await {
                    tenus.push(socket);
                }
            }
            tenus
        };
        if tenus.len() == 9 {
            match lier_dans(&ordre_de_la_plage(7), None).await {
                Err(Issue::Configuration(quoi)) => {
                    assert!(quoi.contains("aucun port libre dans 6631–6639"), "{quoi}");
                }
                autre => panic!("une faute de configuration : {autre:?}"),
            }
        }
    }

    /// **LA LIAISON À UNE ADRESSE IPv6 PRÉCISE, SUR LE VRAI NOYAU** : la
    /// boucle locale `::1` tient le rôle de l'adresse stable — ce qui est
    /// éprouvé est que l'on se lie bien à elle, et à ce port (décision 108).
    #[tokio::test]
    async fn la_socket_se_lie_a_l_adresse_qu_on_lui_donne() {
        let sonde = UdpSocket::bind("[::1]:0").await;
        let Ok(sonde) = sonde else {
            // Une machine sans IPv6 du tout : rien à éprouver.
            return;
        };
        let libre = sonde.local_addr().unwrap().port();
        drop(sonde);
        let (socket, liee) = lier(libre, Some(std::net::Ipv6Addr::LOCALHOST))
            .await
            .expect("la boucle locale se lie");
        assert!(liee, "on est bien lié à l'adresse demandée");
        assert_eq!(
            socket.local_addr().unwrap(),
            SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, libre))
        );
    }

    /// **LA BASCULE RELIE LA SOCKET, AU MÊME PORT** (décisions 106 et 108) :
    /// liée à l'adresse stable en IPv6, à `[::]` pour l'IPv4, et de nouveau à
    /// la stable au retour. Le port ne change jamais : c'est lui que la box
    /// redirige.
    #[tokio::test]
    async fn la_bascule_relie_la_socket_au_meme_port() {
        let sonde = UdpSocket::bind("[::1]:0").await;
        let Ok(sonde) = sonde else {
            return;
        };
        let port = sonde.local_addr().unwrap().port();
        drop(sonde);
        let stable = std::net::Ipv6Addr::LOCALHOST;
        let (socket, liee) = lier(port, Some(stable)).await.expect("liée");
        let mut tenue = Socket {
            socket: std::sync::Arc::new(socket),
            double_pile: true,
            stable: Some(stable),
            liee_a_la_stable: liee,
        };
        assert_eq!(tenue.liee(), Some(stable));

        // Le bail passe en IPv4 : `[::]`, le même port.
        tenue.relier_pour(port, true).await.expect("reliée");
        assert_eq!(tenue.liee(), None, "plus liée à la stable");
        let ici = tenue.socket.local_addr().unwrap();
        assert_eq!(ici.port(), port, "le port ne change pas");
        assert!(ici.ip().is_unspecified(), "{ici}");

        // Deux fois de suite : rien à faire, et rien ne casse.
        tenue.relier_pour(port, true).await.expect("rien à faire");
        assert_eq!(tenue.socket.local_addr().unwrap().port(), port);

        // Le retour en IPv6 : de nouveau la stable, le même port.
        tenue.relier_pour(port, false).await.expect("reliée");
        assert_eq!(tenue.liee(), Some(stable));
        assert_eq!(
            tenue.socket.local_addr().unwrap(),
            SocketAddr::from((stable, port))
        );
    }

    /// **SANS ADRESSE STABLE, LA BASCULE NE RELIE RIEN** : la socket est déjà
    /// liée à `[::]`, et une bascule ne doit pas la remplacer pour rien.
    #[tokio::test]
    async fn sans_adresse_stable_la_bascule_ne_touche_pas_la_socket() {
        let (_tenu, _, libre) = un_pris_un_libre().await;
        let (socket, _) = lier_dans(&[libre], None).await.expect("un port libre");
        let avant = socket.local_addr().unwrap();
        let mut tenue = Socket {
            socket: std::sync::Arc::new(socket),
            double_pile: true,
            stable: None,
            liee_a_la_stable: false,
        };
        for en_ipv4 in [true, false, true] {
            tenue.relier_pour(libre, en_ipv4).await.expect("rien");
            assert_eq!(tenue.socket.local_addr().unwrap(), avant);
            assert_eq!(tenue.liee(), None);
        }
    }

    /// **L'ANNONCE PORTE L'ADRESSE LIÉE**, et ne sonde pas le système pour
    /// l'IPv6 (décision 108) : sans cela, l'annuaire dirait `nat` là où il
    /// faut dire `direct`.
    #[tokio::test]
    async fn l_annonce_porte_l_adresse_a_laquelle_la_socket_est_liee() {
        let identite = Identifiant::depuis_entropie(Genre::Annuaire, [0x11; 16]);
        let reglages = Reglages::nouveaux(
            vec![Annuaire {
                adresse: "[2001:db8::1]:6630".parse().unwrap(),
                nom: "racine".to_owned(),
                identite,
            }],
            crate::commandes::PLAFOND_MS,
        )
        .expect("des réglages");
        let socket = UdpSocket::bind("[::]:0").await;
        let Ok(socket) = socket else {
            return;
        };
        let stable = "2001:db8::7".parse().unwrap();
        assert_eq!(
            adresses_locales(&reglages, &socket, Some(stable)).await,
            vec![IpAddr::V6(stable)],
            "l'adresse liée, et elle seule — aucune sonde IPv6"
        );
    }

    #[test]
    fn la_raison_de_la_liaison_se_dit() {
        assert_eq!(raison_de_liaison(true, true, false), None, "rien à dire");
        assert!(
            raison_de_liaison(true, false, false)
                .expect("une raison")
                .contains("n'a pas pu être liée")
        );
        assert!(
            raison_de_liaison(false, false, true)
                .expect("une raison")
                .contains("pas de /proc/net/if_inet6")
        );
        assert!(
            raison_de_liaison(false, false, false)
                .expect("une raison")
                .contains("aucune adresse IPv6 stable")
        );
    }
}
