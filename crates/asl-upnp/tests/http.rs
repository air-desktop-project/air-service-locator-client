//! HTTP/1.1 : deux requêtes, et une réponse lue par morceaux, bornée.

use asl_upnp::http::{FauteHttp, Lu, REPONSE_MAX, Reponse, TETE_MAX, get, lire, soap};
use asl_upnp::url;

fn complete(octets: &[u8]) -> Reponse {
    match lire(octets, false) {
        Ok(Lu::Complet(reponse)) => reponse,
        autre => panic!("une réponse complète : {autre:?}"),
    }
}

#[test]
fn les_requetes_disent_l_hote_et_ferment() {
    let url = url::lire("http://192.168.1.1:5000/rootDesc.xml").unwrap();
    assert_eq!(
        String::from_utf8(get(&url)).unwrap(),
        "GET /rootDesc.xml HTTP/1.1\r\nHost: 192.168.1.1:5000\r\nUser-Agent: asl-echo UPnP/2.0\r\n\
         Connection: close\r\n\r\n"
    );
    let controle = url::lire("http://[fe80::1%252]:5000/ctl").unwrap();
    let requete = String::from_utf8(soap(
        &controle,
        "urn:schemas-upnp-org:service:WANIPConnection:1",
        "GetExternalIPAddress",
        "<x/>",
    ))
    .unwrap();
    assert!(
        requete.starts_with("POST /ctl HTTP/1.1\r\nHost: [fe80::1]:5000\r\n"),
        "{requete}"
    );
    assert!(requete.contains(
        "SOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#GetExternalIPAddress\"\r\n"
    ));
    assert!(
        requete.ends_with("Content-Length: 4\r\n\r\n<x/>"),
        "{requete}"
    );
}

#[test]
fn une_longueur_dite_se_lit_jusqu_a_elle() {
    let reponse = complete(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nbonjour");
    assert_eq!(
        (reponse.statut, reponse.corps.as_slice()),
        (200, &b"bonjo"[..])
    );
    assert_eq!(
        lire(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nbon", false),
        Ok(Lu::Incomplet)
    );
    assert_eq!(
        lire(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nbon", true),
        Err(FauteHttp::Tronquee)
    );
}

#[test]
fn sans_longueur_le_corps_va_jusqu_a_la_fermeture() {
    assert_eq!(
        lire(b"HTTP/1.1 500 Erreur\r\n\r\n<a/>", false),
        Ok(Lu::Incomplet)
    );
    assert_eq!(
        lire(b"HTTP/1.1 500 Erreur\r\n\r\n<a/>", true),
        Ok(Lu::Complet(Reponse {
            statut: 500,
            corps: b"<a/>".to_vec(),
        }))
    );
}

#[test]
fn une_tete_inachevee_attend_ou_se_dit_tronquee() {
    assert_eq!(lire(b"HTTP/1.1 200 OK\r\n", false), Ok(Lu::Incomplet));
    assert_eq!(lire(b"HTTP/1.1 200 OK\r\n", true), Err(FauteHttp::Tronquee));
    let sans_fin = vec![b'a'; TETE_MAX.saturating_add(1)];
    assert_eq!(lire(&sans_fin, false), Err(FauteHttp::TropLong));
    let mut longue = b"HTTP/1.1 200 OK\r\nX: ".to_vec();
    longue.extend(vec![b'a'; TETE_MAX]);
    longue.extend_from_slice(b"\r\n\r\n");
    assert_eq!(lire(&longue, true), Err(FauteHttp::TropLong));
    let enorme = vec![b'a'; REPONSE_MAX.saturating_add(1)];
    assert_eq!(lire(&enorme, true), Err(FauteHttp::TropLong));
}

#[test]
fn une_tete_fautive_se_refuse() {
    assert_eq!(
        lire(b"HTTP/1.1 200 \xff\r\n\r\n", true),
        Err(FauteHttp::PasDuTexte)
    );
    assert!(matches!(
        lire(b"HTTP/9 200\r\n\r\n", true),
        Err(FauteHttp::Tete(_))
    ));
    assert!(matches!(
        lire(
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\ncontent-length: 1\r\n\r\na",
            true
        ),
        Err(FauteHttp::Tete(_))
    ));
    assert!(matches!(
        lire(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n",
            true
        ),
        Err(FauteHttp::Tete(_))
    ));
}

#[test]
fn longueur_et_decoupage_ensemble_c_est_une_contrebande() {
    assert_eq!(
        lire(
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            true
        ),
        Err(FauteHttp::Longueur)
    );
    for longueur in ["", "abc", "+3", "12345678", "9999999"] {
        let texte = format!("HTTP/1.1 200 OK\r\nContent-Length: {longueur}\r\n\r\n");
        assert_eq!(
            lire(texte.as_bytes(), true),
            Err(FauteHttp::Longueur),
            "{longueur}"
        );
    }
    assert_eq!(
        lire(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n", true),
        Err(FauteHttp::Codage)
    );
}

#[test]
fn un_corps_decoupe_se_recolle() {
    let decoupe = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\n\r\n\
                    4\r\nbonj\r\n3;ext=1\r\nour\r\n 0 \r\nX-Queue: y\r\n\r\n";
    assert_eq!(complete(decoupe).corps, b"bonjour");
    let tete = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    // Chaque coupure possible attend la suite — ou se dit tronquée.
    for partiel in [
        &b""[..],
        b"4",
        b"4\r\nbo",
        b"4\r\nbonj",
        b"4\r\nbonj\r",
        b"4\r\nbonj\r\n0\r\n",
        b"4\r\nbonj\r\n0\r\nX: y\r\n",
    ] {
        let mut octets = tete.clone();
        octets.extend_from_slice(partiel);
        assert_eq!(lire(&octets, false), Ok(Lu::Incomplet), "{partiel:?}");
        assert_eq!(lire(&octets, true), Err(FauteHttp::Tronquee), "{partiel:?}");
    }
}

#[test]
fn un_morceau_fautif_se_refuse() {
    let tete = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    for (morceau, faute) in [
        (&b"\r\n"[..], FauteHttp::Morceau),
        (b"1234567\r\n", FauteHttp::Morceau),
        (b"+4\r\nbonj\r\n0\r\n\r\n", FauteHttp::Morceau),
        (b"\xff\r\n", FauteHttp::Morceau),
        (b"zz\r\n", FauteHttp::Morceau),
        (b"4\r\nbonjXX", FauteHttp::Morceau),
        (b"fffff\r\n", FauteHttp::TropLong),
    ] {
        let mut octets = tete.clone();
        octets.extend_from_slice(morceau);
        assert_eq!(lire(&octets, true), Err(faute), "{morceau:?}");
    }
}

#[test]
fn les_fautes_se_comparent_et_se_montrent() {
    let faute = FauteHttp::Codage;
    assert_eq!(faute, faute.clone());
    assert!(format!("{faute:?}").contains("Codage"));
    let lu = Lu::Incomplet;
    assert_eq!(lu.clone(), Lu::Incomplet);
}
