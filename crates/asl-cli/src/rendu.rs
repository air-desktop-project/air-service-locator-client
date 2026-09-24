//! Ce que l'annuaire a répondu, mis en français sur un terminal.
//!
//! # POURQUOI CE MODULE NE SE CONTENTE PAS D'AFFICHER LE JSON
//!
//! Parce que la question qu'on se pose en tapant `asl` n'est presque jamais
//! « quel est le port » — c'est « pourquoi ça ne marche pas ». Un corps brut
//! répond à la première et laisse la seconde entière.
//!
//! # C6 EST RENDUE VISIBLE, ET NON APLATIE
//!
//! Les trois états qui ne sont pas « joignable » ne veulent pas dire la même
//! chose, et les afficher pareil serait mentir :
//!
//! - **`en_cours`** — l'annuaire n'a pas fini de mesurer. Il n'affirme rien.
//! - **`non_sonde`** — il ne mesurera pas : UDP n'a pas de poignée de main, donc
//!   une sonde n'y distinguerait pas « écoute et ignore » de « rien n'écoute ».
//! - **`injoignable`** — il a essayé, et cela n'a pas abouti.
//!
//! Il en va de même du verdict de NAT, qui a **trois** valeurs : un
//! `indetermine` affiché comme un « non » enverrait chercher la panne partout
//! sauf là où elle est.

use asl_proto::{
    Candidat, Joignabilite, Origine, PointEcoute, Reponse, Verdict, VerdictNat, VuDepuis,
    cadrage::TamponsReponse, ordonner,
};

/// Met en français ce que l'annuaire a répondu à une annonce ou à une résolution.
///
/// # ELLE REND UNE CHAÎNE, ET N'IMPRIME RIEN
///
/// **C'est ce qui la rend éprouvable.** Une fonction qui écrit sur la sortie
/// standard ne se vérifie qu'en détournant un descripteur de fichier, ce qui
/// mesure le détournement. Celle-ci se vérifie en lisant ce qu'elle rend —
/// et le rendu d'une réponse est précisément l'endroit où une confusion entre
/// `en_cours` et `injoignable` passerait inaperçue.
///
/// **LES DEUX RENDENT LE MÊME MESSAGE**, et c'est délibéré côté serveur :
/// `/v1/ou` rend la réponse d'annonce telle qu'elle a été composée. Une seule
/// lecture ici, donc, et pas deux qui divergeraient.
///
/// # Erreurs
///
/// Rend `Err` avec ce qui n'a pas pu être lu.
pub fn reponse(corps: &[u8]) -> Result<String, String> {
    let mut tampons = TamponsReponse::nouveaux();
    let lue = Reponse::decoder(corps, &mut tampons)
        .map_err(|quoi| format!("la réponse de l'annuaire ne se lit pas : {quoi:?}"))?;

    let mut texte = String::new();
    let mut dire = |ligne: &str| {
        texte.push_str(ligne);
        texte.push('\n');
    };

    dire(&format!("service        {}", lue.service.texte().as_str()));
    dire(&format!(
        "bail           keepalive {} s, inactivité {} s",
        lue.bail.keepalive_secondes(),
        lue.bail.inactivite_secondes()
    ));
    dire(&format!(
        "vu depuis      {} ({})",
        adresse(&lue.vu_depuis),
        if lue.vu_depuis.est_ipv6() {
            "IPv6"
        } else {
            "IPv4"
        }
    ));
    dire(&format!("derrière NAT   {}", nat(lue.derriere_nat)));

    dire("");
    dire("points d'écoute");
    for entree in lue.joignabilite {
        dire(&format!("  {}", verdict(entree)));
    }

    let mut candidats = candidats(&lue);
    ordonner(&mut candidats);
    dire("");
    dire("candidats, dans l'ordre où un client les essaierait");
    for (rang, quoi) in candidats.iter().enumerate() {
        dire(&format!(
            "  {}. {:<4} {:<40} {}",
            rang.saturating_add(1),
            quoi.protocole.texte(),
            point_ecrit(quoi),
            match quoi.origine {
                Origine::Reflexif => "réflexif",
                Origine::Annonce => "annoncé",
            }
        ));
    }

    // **CE QUI MANQUE EST DIT, ET NON TU.** Un `en_cours` que rien ne complète
    // ressemble à un outil qui n'a pas fini d'afficher.
    if lue
        .joignabilite
        .iter()
        .any(|entree| matches!(entree.verdict, Verdict::EnCours))
    {
        dire("");
        dire(
            "Au moins un verdict est `en_cours`. L'annuaire répond avant d'avoir\n\
             sondé — c'est ce qui évite de faire attendre un démarrage de daemon.\n\
             Le verdict doit revenir par la connexion tenue ; cette poussée n'est\n\
             pas encore câblée côté serveur, donc `asl` ne peut pas l'attendre.",
        );
    }
    Ok(texte)
}

/// Les candidats qu'un client tirerait de cette réponse.
///
/// **CELUI QU'UNE SONDE A MESURÉ PASSE AVANT CELUI QU'ON DÉDUIT** : quand
/// l'annuaire a constaté qu'un point était joignable, il dit PAR OÙ, et cette
/// adresse-là vaut mieux que celle qu'on recomposerait.
fn candidats(lue: &Reponse<'_>) -> Vec<Candidat> {
    lue.joignabilite
        .iter()
        .map(|entree| match entree.verdict {
            Verdict::Joignable { candidat, .. } => candidat,
            _ => Candidat {
                protocole: entree.point.protocole,
                adresse: lue.vu_depuis.adresse,
                port: entree.point.port,
                // **RÉFLEXIF, ET NON ANNONCÉ** : cette adresse est celle sous
                // laquelle l'annuaire nous a VU, pas celle que nous avons dite.
                origine: Origine::Reflexif,
            },
        })
        .collect()
}

/// Un verdict, avec ce qu'il implique.
fn verdict(entree: &Joignabilite) -> String {
    let ou = point(entree.point);
    match entree.verdict {
        Verdict::Joignable { a, .. } => format!("{ou:<12} joignable      constaté à {a}"),
        Verdict::Injoignable { a } => {
            format!("{ou:<12} INJOIGNABLE    essayé à {a}, sans aboutir")
        }
        Verdict::NonSonde { raison } => {
            format!("{ou:<12} non sondé      {raison} — rien n'a été mesuré, et rien n'est affirmé")
        }
        Verdict::EnCours => format!("{ou:<12} en cours       la sonde n'a pas encore répondu"),
    }
}

/// `protocole:port`.
fn point(quoi: PointEcoute) -> String {
    format!("{}:{}", quoi.protocole.texte(), quoi.port.valeur())
}

/// Une adresse et un port, avec les crochets qu'IPv6 demande.
fn point_ecrit(quoi: &Candidat) -> String {
    match quoi.adresse {
        core::net::IpAddr::V6(adresse) => format!("[{adresse}]:{}", quoi.port.valeur()),
        core::net::IpAddr::V4(adresse) => format!("{adresse}:{}", quoi.port.valeur()),
    }
}

/// L'adresse observée, avec ses crochets.
fn adresse(quoi: &VuDepuis) -> String {
    match quoi.adresse {
        core::net::IpAddr::V6(adresse) => format!("[{adresse}]:{}", quoi.port.valeur()),
        core::net::IpAddr::V4(adresse) => format!("{adresse}:{}", quoi.port.valeur()),
    }
}

/// Le verdict de NAT, en toutes lettres — **et ses trois valeurs**.
fn nat(quoi: VerdictNat) -> &'static str {
    match quoi {
        VerdictNat::Non => "non — l'adresse observée est bien l'une des vôtres",
        VerdictNat::Oui => "OUI — l'annuaire vous voit sous une autre adresse que la vôtre",
        VerdictNat::Indetermine => {
            "indéterminé — aucune adresse locale n'a été annoncée, il n'y avait rien à comparer"
        }
    }
}

#[cfg(test)]
mod essais {
    use super::*;
    use asl_id::{Genre, Identifiant};
    use asl_proto::{Bail, Horodatage, Port, Protocole};
    use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    /// Compose une réponse d'annuaire, telle qu'elle arrive sur le fil.
    fn sur_le_fil(vu_depuis: VuDepuis, nat: VerdictNat, verdicts: &[Joignabilite]) -> Vec<u8> {
        let service = Identifiant::depuis_entropie(Genre::Service, [0x11; 16]);
        let bail = Bail::nouveau(15, 45).expect("un bail juste");
        let reponse =
            Reponse::nouvelle(service, bail, vu_depuis, nat, verdicts).expect("une réponse juste");
        let mut sortie = vec![0_u8; asl_proto::cadrage::MESSAGE_MAX];
        let combien = reponse.encoder(&mut sortie).expect("elle s'encode");
        sortie.truncate(combien);
        sortie
    }

    fn point(protocole: Protocole, port: u16) -> PointEcoute {
        PointEcoute::nouveau(protocole, Port::depuis_u16(port).expect("un port"))
    }

    fn vu(adresse: IpAddr) -> VuDepuis {
        VuDepuis {
            adresse,
            port: Port::depuis_u16(41_234).expect("un port"),
        }
    }

    #[test]
    fn les_quatre_verdicts_se_disent_differemment() {
        // **C6, RENDUE VISIBLE.** Les afficher pareil serait mentir : trois de
        // ces quatre états ne veulent pas dire « ça ne marche pas ».
        let tcp = point(Protocole::Tcp, 8080);
        let autre = point(Protocole::Tcp, 8081);
        let encore = point(Protocole::Tcp, 8082);
        let udp = point(Protocole::Udp, 9000);
        let adresse = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));

        let verdicts = [
            Joignabilite {
                point: tcp,
                verdict: Verdict::Joignable {
                    candidat: Candidat {
                        protocole: Protocole::Tcp,
                        adresse,
                        port: tcp.port,
                        origine: Origine::Reflexif,
                    },
                    a: Horodatage::depuis_millisecondes(1_700_000_000),
                },
            },
            Joignabilite {
                point: autre,
                verdict: Verdict::Injoignable {
                    a: Horodatage::depuis_millisecondes(1_700_000_001),
                },
            },
            Joignabilite {
                point: encore,
                verdict: Verdict::EnCours,
            },
            Joignabilite {
                point: udp,
                verdict: Verdict::NonSonde {
                    raison: asl_proto::RaisonNonSonde::ProtocoleNonSondable,
                },
            },
        ];

        let texte =
            reponse(&sur_le_fil(vu(adresse), VerdictNat::Non, &verdicts)).expect("elle se lit");

        assert!(texte.contains("tcp:8080"), "{texte}");
        assert!(texte.contains("joignable"), "{texte}");
        assert!(texte.contains("INJOIGNABLE"), "{texte}");
        assert!(texte.contains("en cours"), "{texte}");
        assert!(texte.contains("non sondé"), "{texte}");
        assert!(
            texte.contains("protocole_non_sondable"),
            "un `non_sonde` sans sa raison ressemble à une panne : {texte}"
        );
        // Et l'on dit pourquoi un `en_cours` ne se complétera pas tout seul.
        assert!(texte.contains("pas encore câblée"), "{texte}");
    }

    #[test]
    fn les_trois_verdicts_de_nat_sont_trois_phrases() {
        // **`indetermine` AFFICHÉ COMME UN « NON » ENVERRAIT CHERCHER LA PANNE
        // PARTOUT SAUF LÀ OÙ ELLE EST.** C'est exactement ce que C6 refuse.
        let tcp = point(Protocole::Tcp, 8080);
        let verdicts = [Joignabilite {
            point: tcp,
            verdict: Verdict::EnCours,
        }];
        let adresse = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));

        let non = reponse(&sur_le_fil(vu(adresse), VerdictNat::Non, &verdicts)).unwrap();
        let oui = reponse(&sur_le_fil(vu(adresse), VerdictNat::Oui, &verdicts)).unwrap();
        let sais_pas =
            reponse(&sur_le_fil(vu(adresse), VerdictNat::Indetermine, &verdicts)).unwrap();

        assert!(non.contains("non — l'adresse observée"), "{non}");
        assert!(oui.contains("OUI —"), "{oui}");
        assert!(sais_pas.contains("indéterminé"), "{sais_pas}");
        assert!(
            !sais_pas.contains("derrière NAT   non"),
            "un `indetermine` ne doit jamais se lire « non » : {sais_pas}"
        );
    }

    #[test]
    fn une_adresse_v6_porte_ses_crochets() {
        // Sans eux, `2001:db8::1:8080` est ambigu, et ce qu'on affiche ne se
        // recopie pas dans une commande.
        let tcp = point(Protocole::Tcp, 8080);
        let verdicts = [Joignabilite {
            point: tcp,
            verdict: Verdict::EnCours,
        }];
        let adresse = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

        let texte = reponse(&sur_le_fil(vu(adresse), VerdictNat::Indetermine, &verdicts)).unwrap();
        assert!(texte.contains("[2001:db8::1]:41234"), "{texte}");
        assert!(texte.contains("[2001:db8::1]:8080"), "{texte}");
        assert!(texte.contains("(IPv6)"), "{texte}");
    }

    #[test]
    fn le_candidat_mesure_passe_avant_celui_qu_on_deduit() {
        // **QUAND L'ANNUAIRE A CONSTATÉ, IL DIT PAR OÙ** — et cette adresse-là
        // vaut mieux que celle qu'on recomposerait à partir de `vu_depuis`.
        let tcp = point(Protocole::Tcp, 8080);
        let mesure = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9));
        let observe = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));

        let verdicts = [Joignabilite {
            point: tcp,
            verdict: Verdict::Joignable {
                candidat: Candidat {
                    protocole: Protocole::Tcp,
                    adresse: mesure,
                    port: tcp.port,
                    origine: Origine::Annonce,
                },
                a: Horodatage::depuis_millisecondes(1_700_000_000),
            },
        }];

        let texte = reponse(&sur_le_fil(vu(observe), VerdictNat::Oui, &verdicts)).unwrap();
        assert!(
            texte.contains("198.51.100.9:8080"),
            "le candidat mesuré doit être celui qu'on propose : {texte}"
        );
        assert!(texte.contains("annoncé"), "et son origine avec : {texte}");
    }

    #[test]
    fn un_corps_qui_n_est_pas_une_reponse_est_refuse_et_non_devine() {
        assert!(reponse(b"").is_err());
        assert!(reponse(b"{}").is_err());
        assert!(reponse(b"ce n'est pas une reponse d'annuaire").is_err());
    }
}

/// Ce que `GET /v1/vu` rend, en une ligne.
///
/// # UNE RECHERCHE, ET NON UN ANALYSEUR
///
/// Ce corps est écrit par `asl-session`, à champs fixes et sans échappement :
/// `{"adresse":"…","port":N,"famille":N}`. Tirer un analyseur JSON pour lire
/// trois champs qu'on a écrits soi-même serait payer cher une généralité dont
/// personne n'a besoin — c'est le même choix qu'`asl_client_tokio::Reponse`.
///
/// # Erreurs
///
/// Rend `Err` avec ce qui n'a pas pu être lu.
pub fn vu(corps: &[u8]) -> Result<String, String> {
    let texte = core::str::from_utf8(corps)
        .map_err(|_| "la réponse n'est pas de l'UTF-8".to_owned())?
        .to_owned();

    let entre_guillemets = |apres: &str| -> Option<String> {
        let reste = texte.split(apres).nth(1)?;
        Some(reste.split('"').next()?.to_owned())
    };
    let nombre = |apres: &str| -> Option<String> {
        let reste = texte.split(apres).nth(1)?;
        Some(
            reste
                .chars()
                .take_while(char::is_ascii_digit)
                .collect::<String>(),
        )
    };

    let adresse =
        entre_guillemets(r#""adresse":""#).ok_or_else(|| format!("pas d'adresse dans {texte}"))?;
    let port = nombre(r#""port":"#).ok_or_else(|| format!("pas de port dans {texte}"))?;
    let famille = nombre(r#""famille":"#).unwrap_or_default();

    // **LES CROCHETS EN IPv6**, comme partout ailleurs : sans eux,
    // `2001:db8::1:6630` est ambigu, et ce qu'on affiche ne se recopie pas.
    let ou = if famille == "6" {
        format!("[{adresse}]:{port}")
    } else {
        format!("{adresse}:{port}")
    };
    Ok(format!("{ou}   (IPv{famille})"))
}

/// Une LISTE de réponses de résolution — `GET /v1/ou?service=` —, chacune
/// rendue comme [`reponse`], séparées par une ligne.
///
/// **UNE LISTE VIDE LE DIT** : « aucune instance » n'est pas une panne, c'est
/// ce que l'annuaire a répondu — rien de ce nom chez vous ni chez ceux qui vous
/// ont accordé quelque chose.
///
/// # Erreurs
///
/// Rend `Err` avec ce qui n'a pas pu être lu.
pub fn reponses(corps: &[u8]) -> Result<String, String> {
    let elements = asl_proto::cadrage::elements(corps)
        .map_err(|quoi| format!("la liste de l'annuaire ne se lit pas : {quoi:?}"))?;
    let mut texte = String::new();
    let mut combien = 0_usize;
    for element in elements {
        if combien > 0 {
            texte.push_str("──────────────────────────────────────────────────────────\n");
        }
        texte.push_str(&reponse(element)?);
        combien = combien.saturating_add(1);
    }
    if combien == 0 {
        texte.push_str(
            "aucune instance de ce service — ni chez vous, ni chez ceux qui vous\n\
             ont accordé quelque chose.\n",
        );
    }
    Ok(texte)
}

/// Les machines d'un utilisateur — `GET /v1/utilisateurs/{u}/machines` —,
/// une par ligne : l'identifiant, puis le nom.
///
/// **UNE LISTE VIDE LE DIT, ET DIT CE QU'ELLE VEUT DIRE** : rien n'a été
/// accordé — ou l'utilisateur n'a aucune machine, et l'annuaire ne distingue
/// pas les deux (C9).
///
/// # Erreurs
///
/// Rend `Err` avec ce qui n'a pas pu être lu.
pub fn machines(corps: &[u8]) -> Result<String, String> {
    let elements = asl_proto::cadrage::elements(corps)
        .map_err(|quoi| format!("la liste de l'annuaire ne se lit pas : {quoi:?}"))?;
    let mut texte = String::new();
    let mut combien = 0_usize;
    for element in elements {
        let (machine, nom) = machine_vue(element)?;
        texte.push_str(&format!("{}   {nom}\n", machine.texte().as_str()));
        combien = combien.saturating_add(1);
    }
    if combien == 0 {
        texte.push_str(
            "aucune machine visible : cet utilisateur ne vous a rien accordé qui en\n\
             nomme une — ou n'en a aucune ; l'annuaire ne dit pas lequel.\n",
        );
    }
    Ok(texte)
}

/// Lit `{"machine":"m-…","nom":"…"}`.
///
/// **LE MÊME LECTEUR QUE LE SERVEUR** (`asl_proto::cadrage`), et non une
/// recherche de sous-chaîne : le nom est du texte libre, avec ses accents et
/// ses émoji, et c'est `texte_libre` qui sait le lire.
fn machine_vue(octets: &[u8]) -> Result<(asl_id::Identifiant, String), String> {
    let mut lecteur = asl_proto::cadrage::Lecteur::nouveau(octets);
    let faute = |quoi: asl_proto::Erreur| format!("une machine ne se lit pas : {quoi:?}");
    lecteur.attendre(b'{', "un objet").map_err(faute)?;
    let mut machine = None;
    let mut nom = None;
    loop {
        lecteur.sauter_blancs();
        let champ = lecteur.chaine().map_err(faute)?;
        lecteur.attendre(b':', "deux-points").map_err(faute)?;
        match champ {
            "machine" => {
                let texte = lecteur.chaine().map_err(faute)?;
                machine = Some(
                    asl_id::Identifiant::analyser_genre(asl_id::Genre::Machine, texte)
                        .map_err(|quoi| format!("`{texte}` n'est pas une machine : {quoi:?}"))?,
                );
            }
            "nom" => nom = Some(lecteur.texte_libre().map_err(faute)?.to_owned()),
            // **UN CHAMP INCONNU SE SAUTE** : un annuaire plus récent peut en
            // ajouter, et un `asl` d'hier doit encore lire ce qu'il comprend.
            _ => {
                lecteur.chaine().map_err(faute)?;
            }
        }
        lecteur.sauter_blancs();
        match lecteur.regarder() {
            Some(b',') => lecteur.avancer(),
            _ => break,
        }
    }
    lecteur.attendre(b'}', "la fin de l'objet").map_err(faute)?;
    Ok((
        machine.ok_or_else(|| "il manque `machine`".to_owned())?,
        nom.ok_or_else(|| "il manque `nom`".to_owned())?,
    ))
}

/// Les appareils d'un compte — `GET /v1/moi/appareils` —, un par ligne :
/// l'identifiant, le modèle (ou « ? » s'il ne s'est pas décrit), la
/// plate-forme, l'attestation sous laquelle il est entré, et « révoqué » quand
/// il l'est.
///
/// **UN RÉVOQUÉ RESTE SUR SA LIGNE** (`modele.md` §2.2 : « marqué, non
/// effacé ») — c'est ce qu'on regarde après avoir perdu un téléphone. Et
/// **l'identifiant est en tête**, parce que le modèle est une étiquette que
/// l'appareil s'est posée lui-même, pas une preuve : ce qui identifie est
/// l'`a-…`.
///
/// # Erreurs
///
/// Rend `Err` avec ce qui n'a pas pu être lu.
pub fn appareils(corps: &[u8]) -> Result<String, String> {
    let elements = asl_proto::cadrage::elements(corps)
        .map_err(|quoi| format!("la liste de l'annuaire ne se lit pas : {quoi:?}"))?;
    let vus = elements
        .map(appareil_vu)
        .collect::<Result<Vec<AppareilVu>, String>>()?;
    // **LA COLONNE DU MODÈLE SE MESURE SUR LA LISTE**, et non sur une largeur
    // fixe : un modèle est du texte libre jusqu'à soixante-quatre octets, et
    // une largeur devinée décalait tout ce qui suit dès qu'un seul la passait.
    let largeur = vus
        .iter()
        .map(|vu| vu.modele.as_deref().unwrap_or("?").chars().count())
        .max()
        .unwrap_or(1);
    let mut texte = String::new();
    for vu in &vus {
        // **`attendue` SE DIT EN CLAIR** (`protocole.md` §2.2, 2026-09-21) :
        // une clé apportée par un autre appareil du compte, que son porteur
        // n'a pas encore prouvée ni attestée sous une posture exigée — il
        // n'est pas entré. C'est le seul mot de la colonne qui décrit un état
        // et non une caution ; les autres s'affichent tels quels.
        let attestation = if vu.attestation == "attendue" {
            "en attente d'attestation"
        } else {
            vu.attestation.as_str()
        };
        texte.push_str(&format!(
            "{}   {:<largeur$}   {:<8}   {}{}\n",
            vu.appareil.texte().as_str(),
            vu.modele.as_deref().unwrap_or("?"),
            vu.plateforme.as_deref().unwrap_or("?"),
            attestation,
            if vu.revoque { "   révoqué" } else { "" }
        ));
    }
    if vus.is_empty() {
        // Un compte a toujours l'appareil qui l'a ouvert : une liste vide est
        // une réponse qu'on n'attend pas, et le dire vaut mieux qu'un silence.
        texte.push_str("aucun appareil : l'annuaire n'en rend aucun pour ce compte.\n");
    }
    Ok(texte)
}

/// Un appareil tel que la liste le rend, une fois lu.
struct AppareilVu {
    appareil: asl_id::Identifiant,
    attestation: String,
    revoque: bool,
    plateforme: Option<String>,
    modele: Option<String>,
}

/// Lit `{"appareil":"a-…","attestation":"…","revoque":bool[,"plateforme":"…","modele":"…"]}`.
///
/// **LE MÊME LECTEUR QUE [`machine_vue`]**, et la même tolérance : un champ
/// inconnu se saute, et une attestation d'un mot nouveau s'affiche telle
/// quelle — un `asl` d'hier doit encore rendre ce qu'un annuaire de demain lui
/// dit, et le mot que l'annuaire emploie est déjà celui qu'on veut lire.
fn appareil_vu(octets: &[u8]) -> Result<AppareilVu, String> {
    let mut lecteur = asl_proto::cadrage::Lecteur::nouveau(octets);
    let faute = |quoi: asl_proto::Erreur| format!("un appareil ne se lit pas : {quoi:?}");
    lecteur.attendre(b'{', "un objet").map_err(faute)?;
    let mut appareil = None;
    let mut attestation = None;
    let mut revoque = None;
    let mut plateforme = None;
    let mut modele = None;
    loop {
        lecteur.sauter_blancs();
        let champ = lecteur.chaine().map_err(faute)?;
        lecteur.attendre(b':', "deux-points").map_err(faute)?;
        match champ {
            "appareil" => {
                let texte = lecteur.chaine().map_err(faute)?;
                appareil = Some(
                    asl_id::Identifiant::analyser_genre(asl_id::Genre::Appareil, texte)
                        .map_err(|quoi| format!("`{texte}` n'est pas un appareil : {quoi:?}"))?,
                );
            }
            "attestation" => attestation = Some(lecteur.chaine().map_err(faute)?.to_owned()),
            "revoque" => {
                lecteur.sauter_blancs();
                revoque = Some(if lecteur.mot("true") {
                    true
                } else if lecteur.mot("false") {
                    false
                } else {
                    return Err("`revoque` n'est ni `true` ni `false`".to_owned());
                });
            }
            "plateforme" => plateforme = Some(lecteur.chaine().map_err(faute)?.to_owned()),
            "modele" => modele = Some(lecteur.texte_libre().map_err(faute)?.to_owned()),
            // **UN CHAMP INCONNU SE SAUTE** — voir [`machine_vue`].
            _ => {
                lecteur.chaine().map_err(faute)?;
            }
        }
        lecteur.sauter_blancs();
        match lecteur.regarder() {
            Some(b',') => lecteur.avancer(),
            _ => break,
        }
    }
    lecteur.attendre(b'}', "la fin de l'objet").map_err(faute)?;
    Ok(AppareilVu {
        appareil: appareil.ok_or_else(|| "il manque `appareil`".to_owned())?,
        attestation: attestation.ok_or_else(|| "il manque `attestation`".to_owned())?,
        revoque: revoque.ok_or_else(|| "il manque `revoque`".to_owned())?,
        plateforme,
        modele,
    })
}

/// L'état de la voie entre les deux racines — `GET /v1/replication` —, sur
/// une ligne, comme une machine d'`asl machines` : le pair, la voie, et les
/// trois nombres. **L'écart, lui, ne se tire pas d'ici** : il faut les deux
/// racines, et c'est [`conclusion`] qui les rapproche.
///
/// # POURQUOI UNE SEULE RACINE NE CONCLUT RIEN, MÊME MAINTENANT
///
/// `compteur` est l'horloge de Lamport de la racine jointe ; `applique` est le
/// curseur qu'elle tient pour le pair — l'estampille de la dernière opération
/// du pair qu'elle a appliquée (`replication.md` §4, §5.3). **L'horloge compte
/// aussi les écritures de la racine elle-même**, et le curseur ne compte que
/// celles du pair : soustraire l'un de l'autre revient à compter les écritures
/// de la racine jointe comme un retard de l'autre. Vérifié sur les racines le
/// 2026-09-21 : `compteur 35, applique 23`, voie ouverte, rien à rattraper —
/// les douze d'écart étaient les propres écritures de la racine jointe,
/// l'autre n'ayant rien écrit depuis l'amorçage. Un « en retard de 12 » aurait
/// menti, et c'est précisément le genre de mensonge qu'un outil de diagnostic
/// ne peut pas se permettre (voir l'en-tête de ce module).
///
/// **Ce qui a changé le 2026-09-24** : l'annuaire rend `ecrit`, la dernière
/// estampille que CETTE racine a écrite elle-même (`replication.md` §8, servi
/// depuis 0.17.0). Le même exemple se lit alors sans ambiguïté — l'`applique`
/// d'une racine se compare à l'`ecrit` de l'AUTRE, jamais à son `compteur` :
/// `23` contre l'`ecrit` d'argon, qui vaut `23`, et tout est appliqué. C'est
/// exactement ce que le compteur ne pouvait pas dire.
///
/// La ligne rend donc les trois nombres, et rien de plus. Un annuaire d'avant
/// 0.17.0 n'en rend que deux : la ligne le dit en ne montrant pas `écrit`,
/// plutôt qu'en affichant un zéro qui se confondrait avec une racine qui n'a
/// jamais rien écrit.
///
/// **UNE RACINE SEULE LE DIT**, et dit ce que cela veut dire : sans pair réglé,
/// il n'y a rien à répliquer — c'est un banc, pas une panne. Elle rend
/// néanmoins son `ecrit` : elle écrit comme une autre, et c'est ce qu'un futur
/// pair devra rattraper.
///
/// # Erreurs
///
/// Rend `Err` avec ce qui n'a pas pu être lu.
pub fn replication(corps: &[u8]) -> Result<String, String> {
    let etat = replication_vue(corps)?;
    let ecrit = match etat.ecrit {
        Some(ecrit) => format!("   écrit {ecrit}"),
        None => String::new(),
    };
    let mut texte = String::new();
    match etat.pair {
        Some((pair, applique)) => {
            texte.push_str(&format!(
                "{}   {:<8}   compteur {}   appliqué {}{}\n",
                pair.texte().as_str(),
                etat.voie,
                etat.compteur,
                applique,
                ecrit
            ));
        }
        None => {
            texte.push_str(&format!(
                "{:<8}   compteur {}{}\n",
                etat.voie, etat.compteur, ecrit
            ));
            texte.push_str(
                "aucun pair réglé : cette racine tourne seule, et rien n'y est à\n\
                 répliquer — un banc, pas une panne.\n",
            );
        }
    }
    Ok(texte)
}

/// Ce que les DEUX racines, rapprochées, permettent de conclure.
///
/// # L'`APPLIQUE` DE L'UNE SE COMPARE À L'`ECRIT` DE L'AUTRE
///
/// Et jamais à son `compteur` : c'est toute la leçon du 2026-09-21, et
/// [`replication`] la raconte. `applique` chez A est l'estampille de la
/// dernière opération de B que A a appliquée ; `ecrit` chez B est l'estampille
/// de la dernière opération que B a écrite. Les deux nombres parlent donc de
/// la même suite — ce que B a écrit —, et se comparent. Égaux, A a tout
/// appliqué de B ; en deçà, il manque ce que B a écrit depuis.
///
/// # CE QUI N'EST PAS DIT : « IL MANQUE N OPÉRATIONS »
///
/// La différence de deux estampilles n'est pas un nombre d'opérations.
/// L'horloge de Lamport de B se hisse aussi sur ce que B REÇOIT (§4) : entre
/// deux écritures de B, son compteur a pu grimper de dix sans que B écrive une
/// ligne. Annoncer « douze opérations en retard » referait, sous une autre
/// forme, l'erreur que ce module a déjà commise une fois. On nomme donc les
/// deux estampilles, et on laisse l'exploitant lire.
///
/// # POURQUOI ON VÉRIFIE QU'IL S'AGIT BIEN DE DEUX RACINES
///
/// L'alias rend QUATRE adresses — l'A et l'AAAA de chacun des deux bancs — et
/// rien dans une réponse ne dit de quelle racine elle vient
/// (`replication.md` §6). Joindre « une autre adresse » ne garantit donc pas
/// d'avoir joint l'autre racine : on peut retomber sur la même par sa seconde
/// famille. Mais **chaque racine nomme son pair**, et c'est ce qui sauve : si
/// les deux réponses nomment le MÊME pair, c'est la même racine deux fois, et
/// l'on ne conclut pas. Si elles nomment des pairs différents, chacune nomme
/// l'autre — la première est celle que la seconde appelle son pair, et
/// réciproquement. C'est ainsi qu'on peut dire QUI est à jour sans qu'aucune
/// racine ait eu à décliner son propre nom.
///
/// # Erreurs
///
/// Rend `Err` avec ce qui n'a pas pu être lu.
pub fn conclusion(premier: &[u8], second: &[u8]) -> Result<String, String> {
    let ici = replication_vue(premier)?;
    let la_bas = replication_vue(second)?;
    let (Some((pair_ici, applique_ici)), Some((pair_la_bas, applique_la_bas))) =
        (ici.pair, la_bas.pair)
    else {
        return Ok(
            "sans conclusion   l'une des deux tourne seule : il n'y a pas de voie
                   à juger.
"
            .to_owned(),
        );
    };
    if pair_ici == pair_la_bas {
        return Ok(format!(
            "sans conclusion   les deux réponses nomment le même pair ({}) : c'est la
             même racine jointe deux fois, et l'alias en rend quatre adresses.
",
            pair_ici.texte().as_str()
        ));
    }
    // Chacune nomme l'autre : celle qu'on a jointe d'abord est le pair de la
    // seconde, et inversement.
    let nom_ici = pair_la_bas.texte();
    let nom_la_bas = pair_ici.texte();
    let mut texte = String::new();
    for (qui, applique, chez_qui, ecrit) in [
        (
            nom_ici.as_str(),
            applique_ici,
            nom_la_bas.as_str(),
            la_bas.ecrit,
        ),
        (
            nom_la_bas.as_str(),
            applique_la_bas,
            nom_ici.as_str(),
            ici.ecrit,
        ),
    ] {
        match ecrit {
            None => texte.push_str(&format!(
                "sans conclusion   {chez_qui} ne rend pas `ecrit` : un annuaire d'avant 0.17.0,
                 et ce que {qui} a appliqué ne se compare à rien.
"
            )),
            Some(ecrit) if applique >= ecrit => texte.push_str(&format!(
                "à jour            {qui} a appliqué tout ce que {chez_qui} a écrit ({ecrit}).
"
            )),
            Some(ecrit) => texte.push_str(&format!(
                "en retard         {qui} s'est arrêtée à {applique} ; {chez_qui} a écrit
                 jusqu'à {ecrit}.
"
            )),
        }
    }
    Ok(texte)
}

/// L'état de la réplication tel que l'annuaire le rend, une fois lu.
struct ReplicationVue {
    /// Le pair et le curseur qu'on tient pour lui — ensemble, ou ni l'un ni
    /// l'autre : c'est la cohérence que le lecteur vérifie.
    pair: Option<(asl_id::Identifiant, u64)>,
    voie: String,
    compteur: u64,
    /// La dernière estampille que CETTE racine a écrite (`replication.md` §8,
    /// servi depuis 0.17.0). **`None` est un annuaire d'avant**, pas un zéro :
    /// une racine qui n'a jamais rien écrit rend `0`, et les deux ne se
    /// concluent pas de la même façon.
    ecrit: Option<u64>,
}

/// Lit `{"pair":"n-…","voie":"…","compteur":N,"applique":M}` — ou, seule,
/// `{"voie":"seule","compteur":N}`.
///
/// **LE MÊME LECTEUR QUE [`machine_vue`]**, et la même tolérance pour un champ
/// de demain, à ceci près qu'un champ inconnu peut ici porter un nombre : on
/// regarde ce qui vient, et l'on saute ce qu'on trouve. **Le mot `voie` est
/// rendu tel quel**, même s'il n'est pas l'un des trois qu'on connaît — un
/// annuaire de demain peut en dire un quatrième, et le mot qu'il emploie est
/// déjà celui qu'on veut lire. Ce qui est vérifié est la COHÉRENCE : un pair
/// sans curseur, ou un curseur sans pair, n'est pas un état, c'est une réponse
/// qu'on ne comprend pas.
fn replication_vue(octets: &[u8]) -> Result<ReplicationVue, String> {
    let mut lecteur = asl_proto::cadrage::Lecteur::nouveau(octets);
    let faute =
        |quoi: asl_proto::Erreur| format!("l'état de la réplication ne se lit pas : {quoi:?}");
    lecteur.attendre(b'{', "un objet").map_err(faute)?;
    let mut pair = None;
    let mut voie = None;
    let mut compteur = None;
    let mut applique = None;
    let mut ecrit = None;
    loop {
        lecteur.sauter_blancs();
        let champ = lecteur.chaine().map_err(faute)?;
        lecteur.attendre(b':', "deux-points").map_err(faute)?;
        match champ {
            "pair" => {
                let texte = lecteur.chaine().map_err(faute)?;
                pair = Some(
                    asl_id::Identifiant::analyser_genre(asl_id::Genre::Annuaire, texte)
                        .map_err(|quoi| format!("`{texte}` n'est pas une racine : {quoi:?}"))?,
                );
            }
            // `coupée` porte un accent : c'est `texte_libre` qui sait le lire.
            "voie" => voie = Some(lecteur.texte_libre().map_err(faute)?.to_owned()),
            "compteur" => compteur = Some(lecteur.entier().map_err(faute)?),
            "applique" => applique = Some(lecteur.entier().map_err(faute)?),
            "ecrit" => ecrit = Some(lecteur.entier().map_err(faute)?),
            // **UN CHAMP INCONNU SE SAUTE**, qu'il porte un mot ou un nombre.
            _ => {
                lecteur.sauter_blancs();
                if lecteur.regarder() == Some(b'"') {
                    lecteur.texte_libre().map_err(faute)?;
                } else {
                    lecteur.entier().map_err(faute)?;
                }
            }
        }
        lecteur.sauter_blancs();
        match lecteur.regarder() {
            Some(b',') => lecteur.avancer(),
            _ => break,
        }
    }
    lecteur.attendre(b'}', "la fin de l'objet").map_err(faute)?;
    lecteur.fin().map_err(faute)?;
    let voie = voie.ok_or_else(|| "il manque `voie`".to_owned())?;
    let compteur = compteur.ok_or_else(|| "il manque `compteur`".to_owned())?;
    let pair = match (pair, applique) {
        (Some(pair), Some(applique)) => Some((pair, applique)),
        (None, None) => None,
        (Some(_), None) => return Err("un pair est nommé, sans `applique`".to_owned()),
        (None, Some(_)) => return Err("`applique` est rendu, sans pair".to_owned()),
    };
    Ok(ReplicationVue {
        pair,
        voie,
        compteur,
        ecrit,
    })
}

#[cfg(test)]
mod tests {
    use super::{appareils, conclusion, machines, replication, reponses, vu};

    #[test]
    fn la_replication_se_rend_sur_une_ligne_sans_inventer_un_retard() {
        let pair = asl_id::Identifiant::depuis_entropie(asl_id::Genre::Annuaire, [0x4E; 16]);
        // Voie ouverte, curseur égal à l'horloge.
        let corps = format!(
            r#"{{"pair":"{}","voie":"ouverte","compteur":4812,"applique":4812}}"#,
            pair.texte().as_str()
        );
        let dit = replication(corps.as_bytes()).expect("lisible");
        assert_eq!(dit.lines().count(), 1, "{dit}");
        assert!(dit.starts_with(pair.texte().as_str()), "{dit}");
        assert!(dit.contains("ouverte"), "{dit}");
        assert!(dit.contains("compteur 4812"), "{dit}");
        assert!(dit.contains("appliqué 4812"), "{dit}");
        // Voie coupée, et un curseur en deçà de l'horloge : les deux nombres
        // sont rendus tels quels, **et rien n'est dit d'un retard** — l'écart
        // peut n'être que les écritures de la racine jointe.
        let corps = format!(
            r#"{{"pair":"{}","voie":"coupée","compteur":4812,"applique":4790}}"#,
            pair.texte().as_str()
        );
        let dit = replication(corps.as_bytes()).expect("lisible");
        assert!(dit.contains("coupée"), "{dit}");
        assert!(dit.contains("appliqué 4790"), "{dit}");
        assert!(!dit.contains("retard"), "{dit}");
        assert!(!dit.contains("22"), "{dit}");
    }

    /// **LE CAS RÉEL DU 2026-09-21, ENFIN CONCLU.** Sur les vraies racines :
    /// `compteur 35, applique 23` des deux côtés, voie ouverte, et rien en
    /// retard — nitrogen avait écrit douze fois depuis l'amorçage, argon rien.
    /// Le `compteur` ne pouvait pas le dire ; l'`ecrit` de l'autre le dit.
    #[test]
    fn deux_racines_a_jour_se_concluent_meme_quand_les_compteurs_different() {
        let (r1, r2) = deux_racines();
        // Vue de nitrogen : elle a écrit jusqu'à 35, et a appliqué 23 d'argon.
        let ici = format!(
            r#"{{"pair":"{}","voie":"ouverte","compteur":35,"applique":23,"ecrit":35}}"#,
            r2.texte().as_str()
        );
        // Vue d'argon : elle n'a écrit que jusqu'à 23, et a tout appliqué.
        let la_bas = format!(
            r#"{{"pair":"{}","voie":"ouverte","compteur":35,"applique":35,"ecrit":23}}"#,
            r1.texte().as_str()
        );
        let dit = conclusion(ici.as_bytes(), la_bas.as_bytes()).expect("lisible");
        assert_eq!(dit.lines().count(), 2, "{dit}");
        assert!(!dit.contains("en retard"), "{dit}");
        assert!(!dit.contains("sans conclusion"), "{dit}");
        // Chacune est nommée par le pair de l'autre, et dite à jour.
        assert!(dit.contains(r1.texte().as_str()), "{dit}");
        assert!(dit.contains(r2.texte().as_str()), "{dit}");
        // **L'ÉCART DE DOUZE N'EST JAMAIS NOMMÉ** : il n'a jamais existé.
        assert!(!dit.contains("12"), "{dit}");
    }

    #[test]
    fn une_racine_en_retard_est_nommee_sans_compter_des_operations() {
        let (r1, r2) = deux_racines();
        let ici = format!(
            r#"{{"pair":"{}","voie":"coupée","compteur":40,"applique":23,"ecrit":40}}"#,
            r2.texte().as_str()
        );
        let la_bas = format!(
            r#"{{"pair":"{}","voie":"coupée","compteur":40,"applique":40,"ecrit":30}}"#,
            r1.texte().as_str()
        );
        let dit = conclusion(ici.as_bytes(), la_bas.as_bytes()).expect("lisible");
        assert!(dit.contains("en retard"), "{dit}");
        // Les deux estampilles sont dites, telles quelles.
        assert!(dit.contains("23"), "{dit}");
        assert!(dit.contains("30"), "{dit}");
        // **PAS DE « 7 OPÉRATIONS »** : une différence d'estampilles n'est pas
        // un compte d'écritures (`replication.md` §4).
        assert!(!dit.contains("opération"), "{dit}");
        assert!(!dit.contains(" 7 "), "{dit}");
        // L'autre sens, lui, est à jour : 40 ≥ 40.
        assert!(dit.contains("à jour"), "{dit}");
    }

    #[test]
    fn un_annuaire_d_avant_ne_conclut_pas_et_ne_ment_pas() {
        let (r1, r2) = deux_racines();
        // La seconde ne rend pas `ecrit` : 0.16.1 ou avant.
        let ici = format!(
            r#"{{"pair":"{}","voie":"ouverte","compteur":35,"applique":23,"ecrit":35}}"#,
            r2.texte().as_str()
        );
        let la_bas = format!(
            r#"{{"pair":"{}","voie":"ouverte","compteur":35,"applique":35}}"#,
            r1.texte().as_str()
        );
        let dit = conclusion(ici.as_bytes(), la_bas.as_bytes()).expect("lisible");
        assert!(dit.contains("sans conclusion"), "{dit}");
        assert!(dit.contains("0.17.0"), "{dit}");
        // L'autre sens se conclut quand même : ce qu'on sait, on le dit.
        assert!(dit.contains("à jour"), "{dit}");
        // Et la ligne d'une telle racine ne montre pas d'`écrit` inventé.
        let ligne = replication(la_bas.as_bytes()).expect("lisible");
        assert!(!ligne.contains("écrit"), "{ligne}");
    }

    #[test]
    fn la_meme_racine_jointe_deux_fois_ne_conclut_rien() {
        let (r1, r2) = deux_racines();
        // Les deux réponses nomment le MÊME pair : l'alias a rendu deux
        // adresses du même banc.
        let corps = format!(
            r#"{{"pair":"{}","voie":"ouverte","compteur":35,"applique":23,"ecrit":35}}"#,
            r2.texte().as_str()
        );
        let dit = conclusion(corps.as_bytes(), corps.as_bytes()).expect("lisible");
        assert!(dit.contains("sans conclusion"), "{dit}");
        assert!(dit.contains("même racine"), "{dit}");
        assert!(!dit.contains("à jour"), "{dit}");
        let _ = r1;
    }

    #[test]
    fn une_racine_seule_ne_se_conclut_pas() {
        let (_, r2) = deux_racines();
        let seule = br#"{"voie":"seule","compteur":35,"ecrit":35}"#;
        let avec_pair = format!(
            r#"{{"pair":"{}","voie":"ouverte","compteur":35,"applique":35,"ecrit":35}}"#,
            r2.texte().as_str()
        );
        let dit = conclusion(seule, avec_pair.as_bytes()).expect("lisible");
        assert!(dit.contains("sans conclusion"), "{dit}");
        assert!(dit.contains("tourne seule"), "{dit}");
        // Dans l'autre ordre aussi.
        let dit = conclusion(avec_pair.as_bytes(), seule).expect("lisible");
        assert!(dit.contains("sans conclusion"), "{dit}");
        // **UNE RACINE SEULE REND SON `ecrit`** : elle écrit comme une autre.
        let ligne = replication(seule).expect("lisible");
        assert!(ligne.contains("écrit 35"), "{ligne}");
        assert!(ligne.contains("tourne seule"), "{ligne}");
    }

    #[test]
    fn une_conclusion_illisible_est_refusee() {
        let (_, r2) = deux_racines();
        let bon = format!(
            r#"{{"pair":"{}","voie":"ouverte","compteur":35,"applique":35,"ecrit":35}}"#,
            r2.texte().as_str()
        );
        assert!(conclusion(b"{", bon.as_bytes()).is_err());
        assert!(conclusion(bon.as_bytes(), b"{").is_err());
    }

    /// Deux racines distinctes, pour les essais de conclusion.
    fn deux_racines() -> (asl_id::Identifiant, asl_id::Identifiant) {
        (
            asl_id::Identifiant::depuis_entropie(asl_id::Genre::Annuaire, [0x4E; 16]),
            asl_id::Identifiant::depuis_entropie(asl_id::Genre::Annuaire, [0x41; 16]),
        )
    }

    #[test]
    fn une_racine_seule_le_dit() {
        let dit = replication(br#"{"voie":"seule","compteur":4812}"#).expect("lisible");
        assert!(dit.starts_with("seule"), "{dit}");
        assert!(dit.contains("compteur 4812"), "{dit}");
        assert!(dit.contains("tourne seule"), "{dit}");
        assert!(!dit.contains("appliqué"), "{dit}");
    }

    #[test]
    fn un_etat_mal_forme_est_refuse_et_un_champ_neuf_se_saute() {
        let pair = asl_id::Identifiant::depuis_entropie(asl_id::Genre::Annuaire, [0x4E; 16]);
        let machine = asl_id::Identifiant::depuis_entropie(asl_id::Genre::Machine, [0x4E; 16]);
        for corps in [
            &b"{"[..],
            &b"[]"[..],
            &br#"{"voie":"seule"}"#[..],
            &br#"{"compteur":4812}"#[..],
            &br#"{"voie":"seule","compteur":"4812"}"#[..],
            &br#"{"voie":"seule","compteur":4812}{}"#[..],
        ] {
            assert!(
                replication(corps).is_err(),
                "{}",
                String::from_utf8_lossy(corps)
            );
        }
        // Une machine n'est pas une racine.
        let faux = format!(
            r#"{{"pair":"{}","voie":"ouverte","compteur":1,"applique":1}}"#,
            machine.texte().as_str()
        );
        assert!(replication(faux.as_bytes()).is_err());
        // Un pair sans curseur, un curseur sans pair : incohérents.
        let faux = format!(
            r#"{{"pair":"{}","voie":"ouverte","compteur":1}}"#,
            pair.texte().as_str()
        );
        assert!(replication(faux.as_bytes()).is_err());
        assert!(replication(br#"{"voie":"seule","compteur":1,"applique":1}"#).is_err());
        // Un champ de demain — un mot, un nombre — et une voie d'un mot
        // nouveau : lus.
        let neuf = format!(
            r#"{{"depuis":"hier","pair":"{}","voie":"en attente","retard_ms":12,"compteur":7,"applique":7}}"#,
            pair.texte().as_str()
        );
        let dit = replication(neuf.as_bytes()).expect("lisible");
        assert!(dit.contains("en attente"), "{dit}");
    }

    #[test]
    fn une_liste_d_appareils_se_rend_ligne_par_ligne_revoques_compris() {
        let a1 = asl_id::Identifiant::depuis_entropie(asl_id::Genre::Appareil, [0x41; 16]);
        let a2 = asl_id::Identifiant::depuis_entropie(asl_id::Genre::Appareil, [0x42; 16]);
        let a3 = asl_id::Identifiant::depuis_entropie(asl_id::Genre::Appareil, [0x43; 16]);
        let corps = format!(
            concat!(
                r#"[{{"appareil":"{}","attestation":"aucune","revoque":false,"plateforme":"macos","modele":"MacBookPro15,2"}},"#,
                r#"{{"appareil":"{}","attestation":"android","revoque":true,"plateforme":"android","modele":"Fairphone FP5"}},"#,
                r#"{{"appareil":"{}","attestation":"apple","revoque":false}}]"#
            ),
            a1.texte().as_str(),
            a2.texte().as_str(),
            a3.texte().as_str()
        );
        let dit = appareils(corps.as_bytes()).expect("lisible");
        let lignes: Vec<&str> = dit.lines().collect();
        assert_eq!(lignes.len(), 3, "{dit}");
        // Le premier : décrit, vivant.
        assert!(lignes[0].starts_with(a1.texte().as_str()), "{dit}");
        assert!(lignes[0].contains("MacBookPro15,2"), "{dit}");
        assert!(lignes[0].contains("macos"), "{dit}");
        assert!(lignes[0].contains("aucune"), "{dit}");
        assert!(!lignes[0].contains("révoqué"), "{dit}");
        // Le second : révoqué, ET TOUJOURS LÀ, avec sa description.
        assert!(lignes[1].starts_with(a2.texte().as_str()), "{dit}");
        assert!(lignes[1].contains("Fairphone FP5"), "{dit}");
        assert!(lignes[1].ends_with("révoqué"), "{dit}");
        // Le troisième : jamais décrit — un « ? » à la place du modèle et de
        // la plate-forme, jamais une valeur inventée.
        assert!(lignes[2].starts_with(a3.texte().as_str()), "{dit}");
        assert!(lignes[2].contains("?"), "{dit}");
        assert!(lignes[2].contains("apple"), "{dit}");
    }

    #[test]
    fn une_liste_vide_d_appareils_le_dit() {
        let dit = appareils(b"[]").expect("lisible");
        assert!(dit.contains("aucun appareil"), "{dit}");
    }

    #[test]
    fn les_colonnes_des_appareils_s_alignent_sur_le_modele_le_plus_long() {
        // Un modèle plus long que la largeur qu'on aurait devinée ne décale
        // pas les colonnes des autres : la plate-forme commence au même rang
        // sur chaque ligne, accents comptés en caractères et non en octets.
        let a1 = asl_id::Identifiant::depuis_entropie(asl_id::Genre::Appareil, [0x41; 16]);
        let a2 = asl_id::Identifiant::depuis_entropie(asl_id::Genre::Appareil, [0x42; 16]);
        let corps = format!(
            concat!(
                r#"[{{"appareil":"{}","attestation":"aucune","revoque":false,"plateforme":"macos","modele":"MacBook Pro 16 pouces, 2019, éprouvé"}},"#,
                r#"{{"appareil":"{}","attestation":"android","revoque":false,"plateforme":"android","modele":"FP5"}}]"#
            ),
            a1.texte().as_str(),
            a2.texte().as_str()
        );
        let dit = appareils(corps.as_bytes()).expect("lisible");
        // La colonne « attestation » est la dernière de ces deux lignes ; elle
        // commence au même rang de caractères sur l'une et l'autre.
        let rang_du_dernier_mot = |ligne: &str| {
            let dernier = ligne.split(' ').next_back().unwrap_or_default();
            ligne
                .chars()
                .count()
                .saturating_sub(dernier.chars().count())
        };
        let rangs: Vec<usize> = dit.lines().map(rang_du_dernier_mot).collect();
        assert_eq!(rangs.len(), 2, "{dit}");
        assert_eq!(rangs[0], rangs[1], "{dit}");
    }

    #[test]
    fn un_appareil_mal_forme_est_refuse_et_un_champ_neuf_se_saute() {
        let a = asl_id::Identifiant::depuis_entropie(asl_id::Genre::Appareil, [0x41; 16]);
        let m = asl_id::Identifiant::depuis_entropie(asl_id::Genre::Machine, [0x41; 16]);
        for corps in [
            &b"{"[..],
            &br#"[{"attestation":"aucune","revoque":false}]"#[..],
            &br#"[{"appareil":"pas-un-appareil","attestation":"aucune","revoque":false}]"#[..],
        ] {
            assert!(
                appareils(corps).is_err(),
                "{}",
                String::from_utf8_lossy(corps)
            );
        }
        // Une machine n'est pas un appareil.
        let faux = format!(
            r#"[{{"appareil":"{}","attestation":"aucune","revoque":false}}]"#,
            m.texte().as_str()
        );
        assert!(appareils(faux.as_bytes()).is_err());
        // `revoque` qui n'est pas un booléen, ou qui manque.
        let faux = format!(
            r#"[{{"appareil":"{}","attestation":"aucune","revoque":"oui"}}]"#,
            a.texte().as_str()
        );
        assert!(appareils(faux.as_bytes()).is_err());
        let faux = format!(
            r#"[{{"appareil":"{}","attestation":"aucune"}}]"#,
            a.texte().as_str()
        );
        assert!(appareils(faux.as_bytes()).is_err());
        let faux = format!(
            r#"[{{"appareil":"{}","revoque":true}}]"#,
            a.texte().as_str()
        );
        assert!(appareils(faux.as_bytes()).is_err());
        // Un champ de demain, et une attestation d'un mot nouveau : lus.
        let neuf = format!(
            r#"[{{"appareil":"{}","enrole_a":"hier","attestation":"invitation","revoque":false}}]"#,
            a.texte().as_str()
        );
        let dit = appareils(neuf.as_bytes()).expect("lisible");
        assert!(dit.contains("invitation"), "{dit}");
        // Un appareil apporté, pas encore prouvé : « en attente », en clair.
        let attendu = format!(
            r#"[{{"appareil":"{}","attestation":"attendue","revoque":false,"plateforme":"android","modele":"FP5"}}]"#,
            a.texte().as_str()
        );
        let dit = appareils(attendu.as_bytes()).expect("lisible");
        assert!(dit.contains("en attente d'attestation"), "{dit}");
        assert!(!dit.contains("attendue"), "{dit}");
    }

    #[test]
    fn une_liste_de_machines_se_rend_ligne_par_ligne() {
        let m1 = asl_id::Identifiant::depuis_entropie(asl_id::Genre::Machine, [0x31; 16]);
        let m2 = asl_id::Identifiant::depuis_entropie(asl_id::Genre::Machine, [0x32; 16]);
        let corps = format!(
            r#"[{{"machine":"{}","nom":"grenier"}},{{"machine":"{}","nom":"Mac « été » 🖥"}}]"#,
            m1.texte().as_str(),
            m2.texte().as_str()
        );
        let dit = machines(corps.as_bytes()).expect("lisible");
        assert_eq!(
            dit,
            format!(
                "{}   grenier\n{}   Mac « été » 🖥\n",
                m1.texte().as_str(),
                m2.texte().as_str()
            )
        );
    }

    #[test]
    fn une_liste_vide_de_machines_dit_ce_qu_elle_veut_dire() {
        let dit = machines(b"[]").expect("lisible");
        assert!(dit.contains("aucune machine visible"), "{dit}");
        assert!(dit.contains("ne dit pas lequel"), "{dit}");
    }

    #[test]
    fn une_machine_mal_formee_est_refusee_et_un_champ_neuf_se_saute() {
        let m = asl_id::Identifiant::depuis_entropie(asl_id::Genre::Machine, [0x31; 16]);
        for corps in [
            &b"{"[..],
            &br#"[{"nom":"grenier"}]"#[..],
            &br#"[{"machine":"pas-une-machine","nom":"grenier"}]"#[..],
        ] {
            assert!(
                machines(corps).is_err(),
                "{}",
                String::from_utf8_lossy(corps)
            );
        }
        let neuf = format!(
            r#"[{{"machine":"{}","etat":"neuf","nom":"nas"}}]"#,
            m.texte().as_str()
        );
        assert!(
            machines(neuf.as_bytes())
                .expect("lisible")
                .ends_with("   nas\n")
        );
    }

    #[test]
    fn une_liste_vide_de_reponses_dit_aucune_instance() {
        let dit = reponses(b"[]").expect("lisible");
        assert!(dit.contains("aucune instance"), "{dit}");
        assert!(reponses(b"{").is_err());
    }

    #[test]
    fn une_adresse_v6_porte_ses_crochets() {
        // Sans eux, `2001:db8::1:6630` est ambigu : le dernier `:` sépare-t-il
        // un port ou un groupe d'adresse ? Ce qu'on affiche doit se recopier.
        let dit = vu(br#"{"adresse":"2001:db8::1","port":49152,"famille":6}"#).expect("lisible");
        assert!(dit.starts_with("[2001:db8::1]:49152"), "{dit}");
        assert!(dit.contains("IPv6"), "{dit}");
    }

    #[test]
    fn une_adresse_v4_n_en_porte_pas() {
        let dit = vu(br#"{"adresse":"203.0.113.7","port":1,"famille":4}"#).expect("lisible");
        assert!(dit.starts_with("203.0.113.7:1"), "{dit}");
        assert!(dit.contains("IPv4"), "{dit}");
    }

    #[test]
    fn un_corps_qui_ne_dit_pas_ce_qu_on_attend_est_refuse() {
        // **ET NON RENDU À MOITIÉ** : une ligne de diagnostic à demi remplie est
        // pire qu'une ligne qui dit qu'elle n'a pas pu lire.
        assert!(vu(b"{}").is_err());
        assert!(vu(br#"{"port":1,"famille":4}"#).is_err());
        assert!(vu(br#"{"adresse":"203.0.113.7","famille":4}"#).is_err());
        assert!(vu(&[0xff, 0xfe]).is_err());
    }

    #[test]
    fn une_famille_absente_ne_fait_pas_echouer_la_lecture() {
        // **UN ANNUAIRE PLUS RÉCENT POURRAIT AJOUTER DES CHAMPS**, et un
        // diagnostic qui refuserait de lire ce qu'il comprend pour un champ
        // qu'il ne connaît pas ne rendrait service à personne.
        let dit = vu(br#"{"adresse":"203.0.113.7","port":80,"quoi":"neuf"}"#).expect("lisible");
        assert!(dit.starts_with("203.0.113.7:80"), "{dit}");
    }
}
