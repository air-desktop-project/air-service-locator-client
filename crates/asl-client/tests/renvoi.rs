//! Le renvoi vers un annuaire local, lu puis suivi — sans une socket.
//!
//! **Ce qu'on éprouve ici, c'est qu'un `421` ne devient jamais une boucle** :
//! un seul saut, un retour aux racines qui se paie, et un recul qui ne repart
//! de zéro que sur une annonce acceptée. Le transport qui obéit est éprouvé
//! à part, sur de vraies sockets (`asl-client-tokio/tests/federation.rs`).

use core::net::SocketAddr;

use asl_client::Reprise;
use asl_client::renvoi::{
    ADRESSES_MAX, Aiguillage, Cote, EtapeAiguillee, FauteDeRenvoi, Renvoi, separer_l_adresse,
};
use asl_id::{Genre, Identifiant};

fn annuaire() -> Identifiant {
    Identifiant::depuis_entropie(Genre::Annuaire, [0x4E; 16])
}

fn corps(adresses: &str) -> String {
    format!(
        r#"{{"annuaire":"{}","adresses":[{adresses}]}}"#,
        annuaire().texte().as_str()
    )
}

// ── La lecture ──────────────────────────────────────────────────────────────

#[test]
fn le_corps_du_serveur_se_lit_tel_qu_il_est_emis() {
    let texte = corps(r#""speedy.example:6630","[2001:db8::7]:6630""#);
    let lu = Renvoi::lire(texte.as_bytes()).expect("la forme que la racine émet");
    assert_eq!(lu.annuaire(), annuaire());
    assert_eq!(lu.adresses(), ["speedy.example:6630", "[2001:db8::7]:6630"]);
}

fn membre(octet: u8) -> Identifiant {
    Identifiant::depuis_entropie(Genre::Annuaire, [octet; 16])
}

/// Le corps de 0.31.0 (décision 59), avec `identites` à la lettre.
fn corps_nommant(adresses: &str, identites: &str) -> String {
    format!(
        r#"{{"annuaire":"{}","adresses":[{adresses}],"identites":"{identites}"}}"#,
        annuaire().texte().as_str()
    )
}

#[test]
fn un_corps_d_avant_attend_le_titulaire_au_bout_de_chaque_adresse() {
    let texte = corps(r#""192.0.2.7:6630","192.0.2.8:6630""#);
    let lu = Renvoi::lire(texte.as_bytes()).expect("lisible");
    assert!(!lu.nomme_chaque_membre());
    let membres: Vec<(&str, Identifiant)> = lu.membres().collect();
    assert_eq!(
        membres,
        [
            ("192.0.2.7:6630", annuaire()),
            ("192.0.2.8:6630", annuaire())
        ]
    );
}

#[test]
fn chaque_adresse_porte_l_identite_que_le_421_met_a_cote() {
    // Le titulaire aux deux adresses de speedy, helium à la sienne : le corps
    // tel que la racine l'émet depuis 0.31.0.
    let (titulaire, helium) = (annuaire(), membre(0x48));
    let texte = corps_nommant(
        r#""[2001:db8::1]:6630","192.0.2.1:6630","192.0.2.2:6630""#,
        &format!(
            "{t} {t} {h}",
            t = titulaire.texte().as_str(),
            h = helium.texte().as_str()
        ),
    );
    let lu = Renvoi::lire(texte.as_bytes()).expect("la forme de 0.31.0");
    assert!(lu.nomme_chaque_membre());
    assert_eq!(lu.annuaire(), titulaire);
    let membres: Vec<(&str, Identifiant)> = lu.membres().collect();
    assert_eq!(
        membres,
        [
            ("[2001:db8::1]:6630", titulaire),
            ("192.0.2.1:6630", titulaire),
            ("192.0.2.2:6630", helium),
        ]
    );
    // L'ordre des clés ne change rien : `identites` peut venir d'abord.
    let avant = format!(
        r#"{{"identites":"{} {}","annuaire":"{}","adresses":["192.0.2.1:6630","192.0.2.2:6630"]}}"#,
        titulaire.texte().as_str(),
        helium.texte().as_str(),
        titulaire.texte().as_str()
    );
    let lu = Renvoi::lire(avant.as_bytes()).expect("dans n'importe quel ordre");
    assert_eq!(lu.membres().nth(1), Some(("192.0.2.2:6630", helium)));
}

#[test]
fn des_identites_qui_ne_tombent_pas_juste_refusent_le_renvoi() {
    let (t, h) = (annuaire(), membre(0x48));
    let (t, h) = (t.texte().as_str().to_owned(), h.texte().as_str().to_owned());
    let deux = r#""192.0.2.1:6630","192.0.2.2:6630""#;
    let formes = [
        // Une de moins, une de trop.
        (corps_nommant(deux, &t), FauteDeRenvoi::Forme),
        (
            corps_nommant(deux, &format!("{t} {h} {h}")),
            FauteDeRenvoi::Forme,
        ),
        // Une case vide : deux espaces, une espace en tête ou en queue, rien.
        (
            corps_nommant(deux, &format!("{t}  {h}")),
            FauteDeRenvoi::Annuaire,
        ),
        (
            corps_nommant(deux, &format!(" {t} {h}")),
            FauteDeRenvoi::Annuaire,
        ),
        (
            corps_nommant(deux, &format!("{t} {h} ")),
            FauteDeRenvoi::Forme,
        ),
        (corps_nommant(deux, ""), FauteDeRenvoi::Annuaire),
        // Un identifiant qui n'est pas celui d'un annuaire.
        (
            corps_nommant(
                deux,
                &format!(
                    "{t} {}",
                    Identifiant::depuis_entropie(Genre::Machine, [1; 16])
                        .texte()
                        .as_str()
                ),
            ),
            FauteDeRenvoi::Annuaire,
        ),
        // Deux fois la clé.
        (
            format!(
                r#"{{"annuaire":"{t}","adresses":[{deux}],"identites":"{t} {h}","identites":"{t} {h}"}}"#
            ),
            FauteDeRenvoi::Forme,
        ),
        // Une liste d'objets n'est pas la forme émise.
        (
            format!(r#"{{"annuaire":"{t}","adresses":[{deux}],"identites":["{t}","{h}"]}}"#),
            FauteDeRenvoi::Forme,
        ),
    ];
    for (texte, faute) in formes {
        assert_eq!(Renvoi::lire(texte.as_bytes()).err(), Some(faute), "{texte}");
    }
}

#[test]
fn l_ordre_des_cles_les_blancs_et_une_cle_inconnue_ne_changent_rien() {
    let texte = format!(
        " {{ \"adresses\" : [ \"192.0.2.7:6630\" ] ,\n \"neuf\" : \"plus tard\" , \"annuaire\" : \"{}\" }} \n",
        annuaire().texte().as_str()
    );
    let lu = Renvoi::lire(texte.as_bytes()).expect("lisible");
    assert_eq!(lu.adresses(), ["192.0.2.7:6630"]);
}

#[test]
fn un_renvoi_mal_forme_est_refuse_en_entier() {
    let n = annuaire().texte().as_str().to_owned();
    let formes = [
        // Pas de l'UTF-8, pas un objet, objet ouvert.
        vec![0xFF_u8],
        b"[]".to_vec(),
        b"{".to_vec(),
        b"".to_vec(),
        // Clé sans deux-points, valeur qui n'est pas une chaîne.
        br#"{"annuaire" "n"}"#.to_vec(),
        format!(r#"{{"annuaire":"{n}","adresses":["a:1"],"neuf":1}}"#).into_bytes(),
        // Un échappement, une chaîne non fermée.
        format!(r#"{{"annuaire":"{n}","adresses":["a\"b:1"]}}"#).into_bytes(),
        format!(r#"{{"annuaire":"{n}","adresses":["a:1"#).into_bytes(),
        // Séparateur faux entre membres, puis dans la liste.
        format!(r#"{{"annuaire":"{n}";"adresses":["a:1"]}}"#).into_bytes(),
        format!(r#"{{"annuaire":"{n}","adresses":["a:1";"b:1"]}}"#).into_bytes(),
        format!(r#"{{"annuaire":"{n}","adresses":"a:1"}}"#).into_bytes(),
        // Clé en double, clé manquante.
        format!(r#"{{"annuaire":"{n}","annuaire":"{n}","adresses":["a:1"]}}"#).into_bytes(),
        format!(r#"{{"adresses":["a:1"],"adresses":["a:1"],"annuaire":"{n}"}}"#).into_bytes(),
        br#"{"adresses":["a:1"]}"#.to_vec(),
        format!(r#"{{"annuaire":"{n}"}}"#).into_bytes(),
        // Un corps coupé net : après une valeur, après `[`, après une adresse ;
        // et une valeur d'`annuaire` qui n'est pas une chaîne.
        format!(r#"{{"annuaire":"{n}""#).into_bytes(),
        format!(r#"{{"annuaire":"{n}","adresses":["#).into_bytes(),
        format!(r#"{{"annuaire":"{n}","adresses":["a:1""#).into_bytes(),
        br#"{"annuaire":1,"adresses":["a:1"]}"#.to_vec(),
        // Quelque chose après la fin.
        format!(r#"{{"annuaire":"{n}","adresses":["a:1"]}} x"#).into_bytes(),
    ];
    for forme in &formes {
        assert_eq!(
            Renvoi::lire(forme),
            Err(FauteDeRenvoi::Forme),
            "{}",
            String::from_utf8_lossy(forme)
        );
    }
}

#[test]
fn un_renvoi_sans_annuaire_ni_adresse_n_emmene_nulle_part() {
    let machine = Identifiant::depuis_entropie(Genre::Machine, [0x4D; 16]);
    let pas_un_annuaire = format!(
        r#"{{"annuaire":"{}","adresses":["a:1"]}}"#,
        machine.texte().as_str()
    );
    assert_eq!(
        Renvoi::lire(pas_un_annuaire.as_bytes()),
        Err(FauteDeRenvoi::Annuaire)
    );
    assert_eq!(
        Renvoi::lire(corps("").as_bytes()),
        Err(FauteDeRenvoi::SansAdresse)
    );
    assert_eq!(
        Renvoi::lire(corps(" ").as_bytes()),
        Err(FauteDeRenvoi::SansAdresse)
    );
}

#[test]
fn trop_d_adresses_ou_une_adresse_fausse_refusent_tout() {
    let beaucoup: Vec<String> = (0..=ADRESSES_MAX).map(|i| format!("\"h{i}:1\"")).collect();
    assert_eq!(
        Renvoi::lire(corps(&beaucoup.join(",")).as_bytes()),
        Err(FauteDeRenvoi::TropDAdresses)
    );
    let juste: Vec<String> = (0..ADRESSES_MAX).map(|i| format!("\"h{i}:1\"")).collect();
    assert_eq!(
        Renvoi::lire(corps(&juste.join(",")).as_bytes())
            .expect("la borne est permise")
            .adresses()
            .len(),
        ADRESSES_MAX
    );
    assert_eq!(
        Renvoi::lire(corps(r#""bon:1","sans-port""#).as_bytes()),
        Err(FauteDeRenvoi::Adresse)
    );
}

#[test]
fn une_adresse_est_un_hote_puis_un_port_non_nul() {
    assert_eq!(
        separer_l_adresse("speedy.example:6630"),
        Ok(("speedy.example", 6630))
    );
    assert_eq!(separer_l_adresse("192.0.2.7:1"), Ok(("192.0.2.7", 1)));
    assert_eq!(
        separer_l_adresse("[2001:db8::7]:6630"),
        Ok(("2001:db8::7", 6630))
    );
    for faux in [
        "sans-port",
        ":6630",
        "a b:6630",
        "é.example:6630",
        "a:b:6630",
        "hote:0",
        "hote:99999",
        "hote:",
        "[2001:db8::7]",
        "[pas-une-ipv6]:6630",
        "[2001:db8::7]:0",
    ] {
        assert_eq!(
            separer_l_adresse(faux),
            Err(FauteDeRenvoi::Adresse),
            "{faux}"
        );
    }
}

// ── L'aiguillage ────────────────────────────────────────────────────────────

fn racines() -> Vec<SocketAddr> {
    vec![
        "192.0.2.1:6630".parse().unwrap(),
        "[2001:db8::1]:6630".parse().unwrap(),
    ]
}

fn locaux() -> Vec<SocketAddr> {
    vec![
        "198.51.100.1:6630".parse().unwrap(),
        "[2001:db8::a]:6630".parse().unwrap(),
    ]
}

fn aiguillage() -> Aiguillage {
    Aiguillage::nouveau(Reprise::nouvelle(15_000).unwrap())
}

fn etape(cote: Cote, place: usize, attendre_ms: u64) -> Option<EtapeAiguillee> {
    Some(EtapeAiguillee {
        cote,
        place,
        attendre_ms,
    })
}

#[test]
fn sans_racine_il_n_y_a_rien_a_essayer() {
    let mut a = aiguillage();
    assert_eq!(a.prochaine(&[], &locaux(), 0), None);
    assert!(a.renvoye());
    assert_eq!(a.prochaine(&[], &locaux(), 0), None);
}

#[test]
fn sans_renvoi_c_est_la_tournee_des_racines() {
    // IPv6 d'abord, tout le tour sans attendre, puis le recul.
    let mut a = aiguillage();
    assert_eq!(a.cote(), Cote::Racines);
    assert_eq!(a.prochaine(&racines(), &[], 0), etape(Cote::Racines, 1, 0));
    assert_eq!(a.prochaine(&racines(), &[], 0), etape(Cote::Racines, 0, 0));
    let boucle = a.prochaine(&racines(), &[], 0).unwrap();
    assert_eq!((boucle.cote, boucle.place), (Cote::Racines, 1));
    assert!(boucle.attendre_ms > 0, "le tour boucle se paie");
    assert_eq!(a.tours_perdus(), 1);
}

#[test]
fn un_renvoi_se_suit_sans_attendre_membre_apres_membre() {
    let mut a = aiguillage();
    let _ = a.prochaine(&racines(), &[], 0);
    assert!(a.renvoye(), "une racine renvoie");
    assert_eq!(a.cote(), Cote::Local);
    assert_eq!(a.renvois(), 1);
    // Les deux membres de la paire, IPv6 d'abord, sans attendre : un membre
    // mort ne retarde pas l'autre.
    assert_eq!(
        a.prochaine(&racines(), &locaux(), 0),
        etape(Cote::Local, 1, 0)
    );
    assert_eq!(
        a.prochaine(&racines(), &locaux(), 0),
        etape(Cote::Local, 0, 0)
    );
    assert_eq!(a.tours_perdus(), 0);
}

#[test]
fn un_seul_saut_un_421_de_l_annuaire_local_n_est_pas_un_renvoi() {
    let mut a = aiguillage();
    assert!(a.renvoye());
    assert!(!a.renvoye(), "un annuaire local ne renvoie pas plus loin");
    assert_eq!(a.renvois(), 1);
    assert_eq!(a.cote(), Cote::Local);
}

#[test]
fn un_local_muet_ramene_aux_racines_et_le_retour_se_paie() {
    let mut a = aiguillage();
    assert!(a.renvoye());
    let _ = a.prochaine(&racines(), &locaux(), 0);
    let _ = a.prochaine(&racines(), &locaux(), 0);
    // Les deux membres ont échoué : retour aux racines, APRÈS un recul.
    let retour = a.prochaine(&racines(), &locaux(), 0).unwrap();
    assert_eq!((retour.cote, retour.place), (Cote::Racines, 1));
    assert!(
        retour.attendre_ms > 0,
        "le va-et-vient ne tourne pas plus vite que la reprise"
    );
    assert_eq!(a.cote(), Cote::Racines);
    assert_eq!(a.tours_perdus(), 1);
}

#[test]
fn racine_421_local_muet_en_boucle_recule_de_plus_en_plus() {
    // **LE CAS QUE CE MODULE EXISTE POUR BORNER** : chaque racine renvoie,
    // l'annuaire local ne répond jamais. Chaque cycle perd un tour, et le recul
    // grandit jusqu'à son plafond — jamais une boucle serrée.
    let mut a = aiguillage();
    let mut attentes = Vec::new();
    for _ in 0..6 {
        let racine = a.prochaine(&racines(), &locaux(), 0x8000).unwrap();
        assert_eq!(racine.cote, Cote::Racines);
        attentes.push(racine.attendre_ms);
        assert!(a.renvoye());
        let _ = a.prochaine(&racines(), &locaux(), 0x8000);
        let _ = a.prochaine(&racines(), &locaux(), 0x8000);
    }
    assert_eq!(attentes[0], 0, "le premier essai part tout de suite");
    for paire in attentes.windows(2).skip(1) {
        assert!(
            paire[1] >= paire[0],
            "le recul ne décroît pas : {attentes:?}"
        );
    }
    assert!(attentes[5] > attentes[1], "il grandit : {attentes:?}");
    assert_eq!(a.renvois(), 6);
}

#[test]
fn un_renvoi_sans_adresse_locale_ramene_aussitot_aux_racines() {
    let mut a = aiguillage();
    assert!(a.renvoye());
    let retour = a.prochaine(&racines(), &[], 0).unwrap();
    assert_eq!(retour.cote, Cote::Racines);
    assert!(retour.attendre_ms > 0);
}

#[test]
fn apres_une_attache_locale_rompue_on_recommence_par_l_annuaire_local() {
    let mut a = aiguillage();
    assert!(a.renvoye());
    let _ = a.prochaine(&racines(), &locaux(), 0);
    let _ = a.prochaine(&racines(), &locaux(), 0);
    a.reussite();
    assert_eq!(a.cote(), Cote::Local);
    assert_eq!(
        a.prochaine(&racines(), &locaux(), 0),
        etape(Cote::Local, 1, 0)
    );
    assert_eq!(a.tours_perdus(), 0);
}
