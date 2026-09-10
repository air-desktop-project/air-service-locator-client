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

#[cfg(test)]
mod tests {
    use super::vu;

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
