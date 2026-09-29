//! Le lecteur XML : ce qu'il lit, et tout ce qu'il refuse.

use asl_upnp::xml::{ATTRIBUTS_MAX, Evenement, FauteXml, Lecteur, PROFONDEUR_MAX};

/// Tous les événements d'un document, ou la première faute.
fn evenements(texte: &str) -> Result<Vec<Evenement<'_>>, FauteXml> {
    let mut lecteur = Lecteur::nouveau(texte.as_bytes())?;
    let mut tous = Vec::new();
    while let Some(evenement) = lecteur.suivant()? {
        tous.push(evenement);
    }
    Ok(tous)
}

fn faute(texte: &str) -> FauteXml {
    evenements(texte).expect_err(texte)
}

#[test]
fn un_document_se_lit_par_noms_locaux() {
    let texte = "\u{feff}<?xml version=\"1.0\"?>\n<!-- une box -->\n\
                 <s:Envelope xmlns:s='x' a = \"1>2\">\
                 <s:Body><u:Rep>  <v>&lt;&gt;&amp;&quot;&apos;&#65;&#x42;&#X43;</v><vide/>\
                 <![CDATA[<brut>]]><![CDATA[  ]]><?pi ?></u:Rep ></s:Body></s:Envelope>\n<!-- fin -->\n";
    assert_eq!(
        evenements(texte),
        Ok(vec![
            Evenement::Ouvre("Envelope"),
            Evenement::Ouvre("Body"),
            Evenement::Ouvre("Rep"),
            Evenement::Ouvre("v"),
            Evenement::Texte("<>&\"'ABC".to_owned()),
            Evenement::Ferme("v"),
            Evenement::Ouvre("vide"),
            Evenement::Ferme("vide"),
            Evenement::Texte("<brut>".to_owned()),
            Evenement::Ferme("Rep"),
            Evenement::Ferme("Body"),
            Evenement::Ferme("Envelope"),
        ])
    );
    assert_eq!(
        evenements("<racine/>"),
        Ok(vec![Evenement::Ouvre("racine"), Evenement::Ferme("racine")])
    );
}

#[test]
fn ce_qui_n_est_pas_un_document_se_refuse() {
    assert_eq!(Lecteur::nouveau(&[0xff]).unwrap_err(), FauteXml::PasDuTexte);
    assert_eq!(faute(""), FauteXml::Fin);
    assert_eq!(faute("  \n"), FauteXml::Fin);
    assert_eq!(faute("<a>"), FauteXml::Fin);
    assert_eq!(faute("<a"), FauteXml::Fin);
    assert_eq!(faute("<?xml"), FauteXml::Fin);
    assert_eq!(faute("<!-- sans fin"), FauteXml::Fin);
    assert_eq!(faute("<a><![CDATA[ sans fin</a>"), FauteXml::Fin);
    assert_eq!(faute("<a b=\"sans fin></a>"), FauteXml::Fin);
}

#[test]
fn rien_hors_de_la_racine() {
    assert_eq!(faute("avant<a/>"), FauteXml::HorsRacine);
    assert_eq!(faute("<a/>apres"), FauteXml::HorsRacine);
    assert_eq!(faute("<a/><b/>"), FauteXml::HorsRacine);
    assert_eq!(faute("<![CDATA[x]]><a/>"), FauteXml::HorsRacine);
}

#[test]
fn aucune_dtd_n_entre() {
    assert_eq!(
        faute("<!DOCTYPE a [<!ENTITY x \"xx\">]><a>&x;</a>"),
        FauteXml::Doctype
    );
}

#[test]
fn les_balises_se_ferment_dans_l_ordre() {
    assert_eq!(faute("<a><b></a></b>"), FauteXml::Desequilibre);
    assert_eq!(faute("</a>"), FauteXml::Desequilibre);
    assert_eq!(faute("<a></ >"), FauteXml::Balise);
    assert_eq!(faute("<a></a x>"), FauteXml::Balise);
    assert!(evenements("<a></a  >").is_ok(), "des blancs avant `>`");
}

#[test]
fn une_balise_mal_formee_se_refuse() {
    assert_eq!(faute("<>"), FauteXml::Balise);
    assert_eq!(faute("<1a/>"), FauteXml::Balise);
    assert_eq!(faute("<a\"x\"/>"), FauteXml::Balise);
    assert_eq!(faute("<a =\"x\"/>"), FauteXml::Balise);
    assert_eq!(faute("<a b/>"), FauteXml::Balise);
    assert_eq!(faute("<a b=x/>"), FauteXml::Balise);
    assert_eq!(faute("<a b=\"<\"/>"), FauteXml::Balise);
}

#[test]
fn les_bornes_tiennent() {
    let profond = format!(
        "{}{}",
        "<a>".repeat(PROFONDEUR_MAX),
        "</a>".repeat(PROFONDEUR_MAX)
    );
    assert!(evenements(&profond).is_ok(), "exactement la borne");
    let trop = format!(
        "{}<a/>{}",
        "<a>".repeat(PROFONDEUR_MAX),
        "</a>".repeat(PROFONDEUR_MAX)
    );
    assert_eq!(faute(&trop), FauteXml::Profondeur);
    let attributs: String = (0..ATTRIBUTS_MAX)
        .map(|rang| format!(" x{rang}='1'"))
        .collect();
    assert!(evenements(&format!("<a{attributs}/>")).is_ok());
    assert_eq!(
        faute(&format!("<a{attributs} y='1'/>")),
        FauteXml::TropDAttributs
    );
}

#[test]
fn une_entite_inconnue_se_refuse() {
    for texte in [
        "<a>&</a>",
        "<a>&lt</a>",
        "<a>&foo;</a>",
        "<a>&#;</a>",
        "<a>&#+65;</a>",
        "<a>&#123456789;</a>",
        "<a>&#x110000;</a>",
        "<a>&#0;</a>",
        "<a>&#xZZ;</a>",
    ] {
        assert_eq!(faute(texte), FauteXml::Entite, "{texte}");
    }
}

#[test]
fn chaque_faute_se_dit() {
    for faute in [
        FauteXml::PasDuTexte,
        FauteXml::Balise,
        FauteXml::Profondeur,
        FauteXml::TropDAttributs,
        FauteXml::Desequilibre,
        FauteXml::Entite,
        FauteXml::Doctype,
        FauteXml::HorsRacine,
        FauteXml::Fin,
    ] {
        assert!(!faute.to_string().is_empty(), "{faute:?}");
    }
    let evenement = Evenement::Ouvre("a");
    assert_eq!(evenement.clone(), evenement);
    let lecteur = Lecteur::nouveau(b"<a/>").unwrap();
    assert!(format!("{lecteur:?}").contains("Lecteur"));
}
