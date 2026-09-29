//! L'écho vu de la machine sondée, et vu du sondeur — sans une socket.
//!
//! **Ce qu'on éprouve ici, c'est l'ordre et les bornes** : qu'un inconnu ne
//! fasse rien signer, qu'une rafale se paie avant toute vérification, qu'un
//! défi ne serve qu'une fois, et que le sondeur distingue « c'est elle » de
//! « quelqu'un d'autre répond à cette adresse ». Le codec lui-même (les
//! octets, les signatures) est éprouvé dans le dépôt serveur, contre des
//! vecteurs figés ; le transport qui trie la socket, dans
//! `asl-client-tokio/tests/echo.rs`.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use asl_cle::{ClePublique, CleSecrete, identifiant_de_racine};
use asl_client::Identite;
use asl_client::echo::{
    Constat, DEBIT_TOTAL, DEFIS_RETENUS, Debit, MemoireDesDefis, RAFALE_PAR_SOURCE, Repondeur,
    Silence, constater, prefixe_de_source,
};
use asl_echo::{
    Adresse, DefiEcho, FENETRE_HORLOGE_MS, Jeton, REPONSE_OCTETS, REQUETE_OCTETS, Refus,
    RefusJeton, RefusSonde, Reponse, SondeAnnuaire,
};
use asl_id::{Genre, Identifiant};

const MAINTENANT: u64 = 1_789_217_751_000;

fn cle(graine: u8) -> CleSecrete {
    CleSecrete::depuis_entropie([graine; 32])
}

/// L'annuaire du bail — une racine de banc.
fn annuaire() -> CleSecrete {
    cle(0x11)
}

fn annuaire_id() -> Identifiant {
    identifiant_de_racine(&annuaire().publique())
}

/// L'écho : cette machine.
fn moi() -> Identite {
    Identite::nouvelle(
        Identifiant::depuis_entropie(Genre::Machine, [0x70; 16]),
        [0x33; 32],
    )
    .expect("une machine")
}

/// La machine qui sonde, avec `asl ping`.
fn lui() -> Identite {
    Identite::nouvelle(
        Identifiant::depuis_entropie(Genre::Machine, [0x80; 16]),
        [0x44; 32],
    )
    .expect("une machine")
}

fn defi(marque: u8) -> DefiEcho {
    DefiEcho::depuis_octets([marque; 16])
}

fn source(dernier: u8) -> SocketAddr {
    SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(
            0x2001,
            0xdb8,
            0,
            u16::from(dernier),
            0,
            0,
            0,
            1,
        )),
        53_211,
    )
}

/// Un répondeur dont le bail est tenu par [`annuaire`], racine ou non.
fn au_bail(racine: bool) -> Repondeur {
    let mut repondeur = Repondeur::nouveau(&moi(), 0x5EED);
    repondeur.tenir_le_bail(annuaire_id(), annuaire().publique(), racine);
    repondeur
}

fn sonde_d_annuaire(
    signe: &CleSecrete,
    nomme: Identifiant,
    marque: u8,
    emise_a: u64,
) -> [u8; REQUETE_OCTETS] {
    SondeAnnuaire::signer(defi(marque), nomme, moi().machine(), emise_a, signe)
        .expect("les bons genres")
        .octets()
}

fn jeton(signe: &CleSecrete, emis_a: u64) -> Jeton {
    Jeton::emettre(
        signe,
        moi().machine(),
        moi().publique(),
        lui().machine(),
        lui().publique(),
        emis_a,
    )
    .expect("les bons genres")
}

fn sonde_munie(signe: &CleSecrete, marque: u8) -> [u8; REQUETE_OCTETS] {
    lui()
        .sonder(defi(marque), jeton(signe, MAINTENANT))
        .octets()
}

// ── Le débit ────────────────────────────────────────────────────────────────

#[test]
fn une_source_est_une_64_en_ipv6_et_une_adresse_en_ipv4() {
    let a = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 3, 4, 5, 6));
    let b = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 9, 9, 9, 9));
    let c = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 3, 3, 4, 5, 6));
    assert_eq!(prefixe_de_source(a), prefixe_de_source(b), "même /64");
    assert_ne!(prefixe_de_source(a), prefixe_de_source(c));

    let v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
    let enfouie = IpAddr::V6(Ipv4Addr::new(192, 0, 2, 7).to_ipv6_mapped());
    assert_eq!(
        prefixe_de_source(v4),
        prefixe_de_source(enfouie),
        "une IPv4 enfouie est une IPv4"
    );
    assert_ne!(
        prefixe_de_source(v4),
        prefixe_de_source(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 8))),
        "une adresse IPv4 par source"
    );
    assert_eq!(prefixe_de_source(v4)[0], 4);
    assert_eq!(prefixe_de_source(a)[0], 6);
}

#[test]
fn une_source_a_dix_d_avance_puis_cinq_par_seconde() {
    let mut debit = Debit::nouveau(7);
    let ip = source(1).ip();
    for _ in 0..RAFALE_PAR_SOURCE {
        assert_eq!(debit.admettre(ip, MAINTENANT), Ok(()));
    }
    assert_eq!(debit.admettre(ip, MAINTENANT), Err(Silence::DebitSource));
    // Un cinquième de seconde rend un jeton, et un seul.
    assert_eq!(
        debit.admettre(ip, MAINTENANT + 199),
        Err(Silence::DebitSource)
    );
    assert_eq!(debit.admettre(ip, MAINTENANT + 200), Ok(()));
    assert_eq!(
        debit.admettre(ip, MAINTENANT + 200),
        Err(Silence::DebitSource)
    );
    // **UNE HORLOGE QUI RECULE NE REMPLIT RIEN.**
    assert_eq!(debit.admettre(ip, MAINTENANT), Err(Silence::DebitSource));
    assert_eq!(
        debit.admettre(ip, MAINTENANT + 200),
        Err(Silence::DebitSource)
    );
    assert_eq!(debit.admettre(ip, MAINTENANT + 400), Ok(()));
}

#[test]
fn cinquante_en_tout_et_un_bavard_seul_n_entame_pas_le_commun() {
    let mut debit = Debit::nouveau(7);
    // Un bavard épuise son seau ; ses refus n'entament pas le commun.
    let bavard = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
    for _ in 0..RAFALE_PAR_SOURCE {
        assert_eq!(debit.admettre(bavard, MAINTENANT), Ok(()));
    }
    for _ in 0..1_000 {
        assert_eq!(
            debit.admettre(bavard, MAINTENANT),
            Err(Silence::DebitSource)
        );
    }
    // Il reste quarante réponses au commun, pour autant de sources.
    let mut admises = 0_u64;
    let mut n = 0_u16;
    while admises < DEBIT_TOTAL - RAFALE_PAR_SOURCE {
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, n, 0, 0, 0, 0, 1));
        n += 1;
        if debit.admettre(ip, MAINTENANT) == Ok(()) {
            admises += 1;
        }
    }
    let neuve = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0xFFFF, 0, 0, 0, 0, 1));
    assert_eq!(debit.admettre(neuve, MAINTENANT), Err(Silence::DebitTotal));
    // Le commun se remplit d'un jeton toutes les vingt millisecondes.
    assert_eq!(debit.admettre(neuve, MAINTENANT + 20), Ok(()));
    assert_eq!(
        debit.admettre(neuve, MAINTENANT + 20),
        Err(Silence::DebitTotal)
    );
}

// ── La mémoire des défis ────────────────────────────────────────────────────

#[test]
fn un_defi_ne_sert_qu_une_fois_en_deux_minutes() {
    let mut vus = MemoireDesDefis::default();
    assert!(vus.retenir(&defi(1), MAINTENANT));
    assert!(!vus.retenir(&defi(1), MAINTENANT + FENETRE_HORLOGE_MS));
    assert!(vus.retenir(&defi(2), MAINTENANT));
    // Au-delà de la fenêtre, le défi est oublié.
    assert!(vus.retenir(&defi(1), MAINTENANT + FENETRE_HORLOGE_MS + 1));
}

#[test]
fn la_memoire_est_bornee_et_le_plus_vieux_sort_d_abord() {
    let mut vus = MemoireDesDefis::nouvelle();
    let numero = |n: usize| DefiEcho::depuis_octets(u128::try_from(n).unwrap().to_be_bytes());
    for n in 0..DEFIS_RETENUS {
        assert!(vus.retenir(&numero(n), MAINTENANT));
    }
    assert!(!vus.retenir(&numero(0), MAINTENANT), "encore là");
    // Un de plus : le premier sort, le second reste.
    assert!(vus.retenir(&numero(DEFIS_RETENUS), MAINTENANT));
    assert!(
        vus.retenir(&numero(0), MAINTENANT),
        "le plus vieux est sorti"
    );
    assert!(!vus.retenir(&numero(DEFIS_RETENUS - 1), MAINTENANT));
}

// ── Le répondeur ────────────────────────────────────────────────────────────

#[test]
fn l_annuaire_du_bail_obtient_une_preuve_et_une_seule_fois() {
    let mut repondeur = au_bail(false);
    let datagramme = sonde_d_annuaire(&annuaire(), annuaire_id(), 1, MAINTENANT - 1_000);
    let repondue = repondeur
        .recevoir(&moi(), &datagramme, source(1), MAINTENANT)
        .expect("l'annuaire du bail est cru");
    assert_eq!(repondue.sondeur, annuaire_id());
    assert_eq!(repondue.reponse.len(), REPONSE_OCTETS);
    const { assert!(REPONSE_OCTETS < REQUETE_OCTETS, "aucune amplification") };

    // Ce que l'annuaire conclut : la preuve, pour lui, vue de la source.
    let lue = Reponse::lire(&repondue.reponse).expect("elle se lit");
    assert_eq!(lue.adresse(), Adresse::depuis_source(source(1)));
    assert_eq!(
        lue.verifier(&defi(1), moi().machine(), annuaire_id(), &moi().publique()),
        Ok(())
    );

    // Rejouée : le silence.
    assert_eq!(
        repondeur.recevoir(&moi(), &datagramme, source(2), MAINTENANT),
        Err(Silence::Rejeu)
    );
}

#[test]
fn un_annuaire_inconnu_une_mauvaise_signature_ou_une_autre_cible_se_taisent() {
    let mut repondeur = au_bail(false);
    let intrus = cle(0x99);
    let intrus_id = identifiant_de_racine(&intrus.publique());
    assert_eq!(
        repondeur.recevoir(
            &moi(),
            &sonde_d_annuaire(&intrus, intrus_id, 1, MAINTENANT),
            source(1),
            MAINTENANT
        ),
        Err(Silence::Refusee(RefusSonde::AnnuaireInconnu))
    );
    // Un intrus qui se dit l'annuaire du bail : sa signature ne tient pas.
    assert_eq!(
        repondeur.recevoir(
            &moi(),
            &sonde_d_annuaire(&intrus, annuaire_id(), 2, MAINTENANT),
            source(1),
            MAINTENANT
        ),
        Err(Silence::Refusee(RefusSonde::Signature))
    );
    // Un intrus qui se dit une racine EMBARQUÉE : il est reconnu, et sa
    // signature ne tient pas sous la clé que ce binaire porte.
    let embarquee = asl_client::racines::RACINES[0]
        .identite()
        .expect("une racine embarquée");
    assert_eq!(
        repondeur.recevoir(
            &moi(),
            &sonde_d_annuaire(&intrus, embarquee, 3, MAINTENANT),
            source(1),
            MAINTENANT
        ),
        Err(Silence::Refusee(RefusSonde::Signature))
    );
    // Une sonde qui vise une autre machine.
    let ailleurs = SondeAnnuaire::signer(
        defi(4),
        annuaire_id(),
        lui().machine(),
        MAINTENANT,
        &annuaire(),
    )
    .unwrap()
    .octets();
    assert_eq!(
        repondeur.recevoir(&moi(), &ailleurs, source(1), MAINTENANT),
        Err(Silence::Refusee(RefusSonde::AutreCible))
    );
}

#[test]
fn une_horloge_qui_derive_se_dit_et_se_tait() {
    let mut repondeur = au_bail(false);
    let datee = sonde_d_annuaire(
        &annuaire(),
        annuaire_id(),
        1,
        MAINTENANT - FENETRE_HORLOGE_MS - 1,
    );
    assert_eq!(
        repondeur.recevoir(&moi(), &datee, source(1), MAINTENANT),
        Err(Silence::Refusee(RefusSonde::HorsFenetre))
    );
}

#[test]
fn le_bail_lache_l_annuaire_n_est_plus_cru() {
    let mut repondeur = au_bail(false);
    repondeur.lacher_le_bail();
    assert_eq!(
        repondeur.recevoir(
            &moi(),
            &sonde_d_annuaire(&annuaire(), annuaire_id(), 1, MAINTENANT),
            source(1),
            MAINTENANT
        ),
        Err(Silence::Refusee(RefusSonde::AnnuaireInconnu))
    );
    // Sans bail du tout, dès le départ : de même.
    let mut neuf = Repondeur::nouveau(&moi(), 1);
    assert_eq!(
        neuf.recevoir(
            &moi(),
            &sonde_d_annuaire(&annuaire(), annuaire_id(), 2, MAINTENANT),
            source(1),
            MAINTENANT
        ),
        Err(Silence::Refusee(RefusSonde::AnnuaireInconnu))
    );
}

#[test]
fn un_jeton_ne_vaut_que_d_une_racine_et_pour_la_cle_qu_il_nomme() {
    // Le bail est une racine : son jeton est cru.
    let mut repondeur = au_bail(true);
    let repondue = repondeur
        .recevoir(&moi(), &sonde_munie(&annuaire(), 1), source(1), MAINTENANT)
        .expect("un jeton de la racine du bail");
    assert_eq!(repondue.sondeur, lui().machine());
    assert!(matches!(
        constater(&repondue.reponse, &[defi(9), defi(1)], moi().machine(), lui().machine(), &moi().publique()),
        Constat::Prouvee { rang: 1, vu_comme } if vu_comme == source(1)
    ));

    // **UN ANNUAIRE LOCAL NE DÉLIVRE PAS DE JETON** : le même bail, non racine.
    let mut local = au_bail(false);
    assert_eq!(
        local.recevoir(&moi(), &sonde_munie(&annuaire(), 2), source(1), MAINTENANT),
        Err(Silence::Refusee(RefusSonde::Jeton(
            RefusJeton::RacineInconnue
        )))
    );

    // Un jeton qui se dit d'une racine EMBARQUÉE, signé d'une autre clé.
    let faussaire = cle(0x99);
    let mut octets = jeton(&faussaire, MAINTENANT).octets();
    let embarquee = asl_client::racines::RACINES[0]
        .identite()
        .expect("une racine embarquée");
    octets[1..17].copy_from_slice(embarquee.octets());
    let usurpe = Jeton::depuis_octets(&octets).expect("bien formé");
    assert_eq!(
        repondeur.recevoir(
            &moi(),
            &lui().sonder(defi(3), usurpe).octets(),
            source(1),
            MAINTENANT
        ),
        Err(Silence::Refusee(RefusSonde::Jeton(RefusJeton::Signature)))
    );

    // **LE JETON N'EST PAS PORTEUR** : présenté par un tiers qui signe de sa
    // propre clé, il est refusé.
    let tiers = Identite::nouvelle(
        Identifiant::depuis_entropie(Genre::Machine, [0x90; 16]),
        [0x55; 32],
    )
    .unwrap();
    assert_eq!(
        repondeur.recevoir(
            &moi(),
            &tiers
                .sonder(defi(4), jeton(&annuaire(), MAINTENANT))
                .octets(),
            source(1),
            MAINTENANT
        ),
        Err(Silence::Refusee(RefusSonde::SignatureDuSondeur))
    );
}

#[test]
fn ce_qui_ne_se_lit_pas_se_tait_et_la_longueur_se_juge_d_abord() {
    let mut repondeur = au_bail(true);
    assert_eq!(
        repondeur.recevoir(&moi(), &[0x0A, 0x01], source(1), MAINTENANT),
        Err(Silence::Illisible(Refus::Longueur {
            attendue: REQUETE_OCTETS,
            obtenue: 2
        }))
    );
    // La bonne longueur, et du QUIC : ce n'est pas de l'écho.
    let mut quic = [0_u8; REQUETE_OCTETS];
    quic[0] = 0xC3;
    assert_eq!(
        repondeur.recevoir(&moi(), &quic, source(1), MAINTENANT),
        Err(Silence::Illisible(Refus::PasDeLEcho { premier: 0xC3 }))
    );
    // Une sonde au bourrage non nul.
    let mut bourree = sonde_d_annuaire(&annuaire(), annuaire_id(), 1, MAINTENANT);
    bourree[REQUETE_OCTETS - 1] = 1;
    assert_eq!(
        repondeur.recevoir(&moi(), &bourree, source(1), MAINTENANT),
        Err(Silence::Illisible(Refus::Bourrage))
    );
}

#[test]
fn le_debit_se_paie_avant_toute_verification() {
    let mut repondeur = au_bail(false);
    let intrus = cle(0x99);
    let intrus_id = identifiant_de_racine(&intrus.publique());
    // Dix sondes d'un inconnu, refusées pour ce qu'elles sont…
    for marque in 0..10 {
        assert!(matches!(
            repondeur.recevoir(
                &moi(),
                &sonde_d_annuaire(&intrus, intrus_id, marque, MAINTENANT),
                source(1),
                MAINTENANT
            ),
            Err(Silence::Refusee(_))
        ));
    }
    // … et la onzième, même authentique, n'est plus vérifiée : le débit
    // de cette source est épuisé.
    assert_eq!(
        repondeur.recevoir(
            &moi(),
            &sonde_d_annuaire(&annuaire(), annuaire_id(), 42, MAINTENANT),
            source(1),
            MAINTENANT
        ),
        Err(Silence::DebitSource)
    );
    // D'une autre /64, elle passe.
    assert!(
        repondeur
            .recevoir(
                &moi(),
                &sonde_d_annuaire(&annuaire(), annuaire_id(), 42, MAINTENANT),
                source(2),
                MAINTENANT
            )
            .is_ok()
    );
}

// ── Le sondeur ──────────────────────────────────────────────────────────────

/// Une réponse composée à la main — ce qu'un autre que l'écho enverrait.
fn reponse(
    signe: &CleSecrete,
    marque: u8,
    machine: Identifiant,
    sondeur: Identifiant,
) -> [u8; REPONSE_OCTETS] {
    Reponse::signer(
        defi(marque),
        machine,
        Adresse::depuis_source(source(1)),
        sondeur,
        signe,
    )
    .expect("les bons genres")
    .octets()
}

#[test]
fn le_sondeur_distingue_la_preuve_d_un_autre_qui_repond() {
    let machine = cle(0x33);
    let cible = moi().machine();
    let sondeur = lui().machine();
    let defis = [defi(1), defi(2)];
    let cle_cible: ClePublique = moi().publique();

    assert_eq!(
        constater(
            &reponse(&machine, 2, cible, sondeur),
            &defis,
            cible,
            sondeur,
            &cle_cible
        ),
        Constat::Prouvee {
            rang: 1,
            vu_comme: source(1)
        }
    );
    // **QUELQU'UN D'AUTRE RÉPOND** : une autre clé, ou une autre machine.
    let autre = cle(0x77);
    assert_eq!(
        constater(
            &reponse(&autre, 1, cible, sondeur),
            &defis,
            cible,
            sondeur,
            &cle_cible
        ),
        Constat::AutreCle
    );
    let ailleurs = Identifiant::depuis_entropie(Genre::Machine, [0x71; 16]);
    assert_eq!(
        constater(
            &reponse(&autre, 1, ailleurs, sondeur),
            &defis,
            cible,
            sondeur,
            &cle_cible
        ),
        Constat::AutreCle
    );
    // Pas pour nous : un autre défi, un autre sondeur.
    assert_eq!(
        constater(
            &reponse(&machine, 3, cible, sondeur),
            &defis,
            cible,
            sondeur,
            &cle_cible
        ),
        Constat::PasPourMoi
    );
    assert_eq!(
        constater(
            &reponse(&machine, 1, cible, annuaire_id()),
            &defis,
            cible,
            sondeur,
            &cle_cible
        ),
        Constat::PasPourMoi
    );
    // Illisible : une autre longueur.
    assert_eq!(
        constater(&[0x0A, 0x81, 0], &defis, cible, sondeur, &cle_cible),
        Constat::Illisible(Refus::Longueur {
            attendue: REPONSE_OCTETS,
            obtenue: 3
        })
    );
}
