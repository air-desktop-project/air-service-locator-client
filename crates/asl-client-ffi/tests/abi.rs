//! La frontière, appelée comme C l'appelle.
//!
//! # CE QUE CES ESSAIS ÉPROUVENT, ET QU'AUCUN AUTRE N'ÉPROUVE
//!
//! Ce qui est derrière la frontière est déjà couvert : la politique de reprise à
//! 100 %, le transport de bout en bout, la tournée sur de vraies sockets. **Ce
//! qui n'est couvert nulle part est la frontière elle-même** — un pointeur nul,
//! une chaîne qui n'est pas de l'UTF-8, un tampon trop petit, un ordonnanceur qui
//! ne tourne pas.
//!
//! Ce sont exactement les fautes qu'un appelant Python déclencherait le premier
//! jour, et qui, du côté Rust, compilent toutes.
//!
//! # POURQUOI IL N'Y A PAS UNE LIGNE DE C ICI NON PLUS
//!
//! Un essai en C prouverait que l'en-tête compile — ce qui vaut. Il faudrait
//! pour cela un compilateur C dans la CI, sur un dépôt dont une contrainte
//! entière (C4) tient à ce qu'aucun C n'entre. Le contrat est donc tenu
//! autrement : `check-abi.sh` compare les symboles du binaire, le registre et
//! les déclarations de l'en-tête, et l'essai ci-dessous compare les CONSTANTES
//! de l'en-tête à celles de Rust.

use core::ffi::CStr;
use std::ptr;

use asl_client_ffi::{
    ASL_ANNONCE, ASL_ARGUMENT, ASL_CONFIGURATION, ASL_DEJA, ASL_EN_COURS, ASL_GRAINE_OCTETS,
    ASL_IDENTIFIANT_OCTETS, ASL_INJOIGNABLE, ASL_INJOIGNABLE_POINT, ASL_INTERNE, ASL_JOIGNABLE,
    ASL_NON_SONDE, ASL_OK, ASL_PAS_D_IDENTITE, ASL_REFLEXIF, ASL_REFUSE, ASL_TAMPON_TROP_PETIT,
    ASL_TCP, ASL_UDP, AslCandidat, AslClient, AslEtat, AslPoint, asl_annoncer, asl_client_annuaire,
    asl_client_identite, asl_client_libere, asl_client_neuf, asl_client_racines, asl_enroler,
    asl_etat, asl_faute_texte, asl_ou, asl_version,
};
use asl_id::{Genre, Identifiant};

/// Une machine d'essai, en texte terminé par NUL.
fn machine_texte() -> std::ffi::CString {
    let machine = Identifiant::depuis_entropie(Genre::Machine, [0x11; 16]);
    std::ffi::CString::new(machine.texte().as_str()).expect("un identifiant sans NUL")
}

/// Un client neuf, ou l'essai s'arrête.
fn client() -> *mut AslClient {
    let mut brut: *mut AslClient = ptr::null_mut();
    assert_eq!(unsafe { asl_client_neuf(&raw mut brut) }, ASL_OK);
    assert!(!brut.is_null());
    brut
}

/// Un état rempli de valeurs qu'aucun appel ne rendrait.
fn etat_sali() -> AslEtat {
    AslEtat {
        attaches: 7,
        ruptures: 7,
        attachee: 7,
        abandonnee: 7,
        reserve: [7; 6],
    }
}

// ── CE QUI NE TOUCHE À RIEN ─────────────────────────────────────────────────

#[test]
fn la_version_se_lit_et_tolere_les_pointeurs_nuls() {
    let (mut ma, mut mi, mut co) = (99_u32, 99, 99);
    unsafe { asl_version(&raw mut ma, &raw mut mi, &raw mut co) };
    assert_eq!((ma, mi, co), (0, 1, 0));

    // Un appelant qui ne veut qu'un des trois ne doit pas avoir à en fournir
    // trois — et surtout ne doit pas y perdre son processus.
    unsafe { asl_version(ptr::null_mut(), &raw mut mi, ptr::null_mut()) };
    assert_eq!(mi, 1);
    unsafe { asl_version(ptr::null_mut(), ptr::null_mut(), ptr::null_mut()) };
}

#[test]
fn chaque_code_a_sa_phrase_et_aucune_n_est_partagee() {
    // **UNE PHRASE PARTAGÉE EST UN CODE PERDU** : deux causes différentes que
    // l'appelant lirait pareil.
    let codes = [
        ASL_OK,
        ASL_ARGUMENT,
        ASL_CONFIGURATION,
        ASL_INJOIGNABLE,
        ASL_REFUSE,
        ASL_TAMPON_TROP_PETIT,
        ASL_INTERNE,
        ASL_PAS_D_IDENTITE,
        ASL_DEJA,
    ];
    let mut vues = std::collections::BTreeSet::new();
    for code in codes {
        let brut = asl_faute_texte(code);
        assert!(!brut.is_null(), "{code}");
        let texte = unsafe { CStr::from_ptr(brut) }
            .to_str()
            .expect("les phrases sont en ASCII");
        assert!(!texte.is_empty(), "{code}");
        assert!(vues.insert(texte), "`{texte}` sert déjà à un autre code");
    }
    // Un code qu'on n'a jamais rendu ne doit pas rendre un pointeur nul.
    let inconnu = unsafe { CStr::from_ptr(asl_faute_texte(-424_242)) };
    assert_eq!(inconnu.to_str().unwrap(), "code inconnu");
}

// ── LES POINTEURS NULS ──────────────────────────────────────────────────────

#[test]
fn un_pointeur_nul_rend_un_code_et_n_emporte_pas_le_processus() {
    // **C'EST LA PREMIÈRE FAUTE QU'UN APPELANT COMMET**, et la seule dont la
    // sanction naturelle serait de tuer son application.
    let vide = c"";
    assert_eq!(unsafe { asl_client_neuf(ptr::null_mut()) }, ASL_ARGUMENT);
    assert_eq!(
        unsafe { asl_client_annuaire(ptr::null_mut(), vide.as_ptr(), vide.as_ptr()) },
        ASL_ARGUMENT
    );
    assert_eq!(
        unsafe { asl_client_racines(ptr::null_mut(), ptr::null(), 0) },
        ASL_ARGUMENT
    );
    assert_eq!(
        unsafe { asl_client_identite(ptr::null_mut(), vide.as_ptr(), ptr::null()) },
        ASL_ARGUMENT
    );
    assert_eq!(
        unsafe {
            asl_enroler(
                ptr::null_mut(),
                vide.as_ptr(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        },
        ASL_ARGUMENT
    );
    assert_eq!(
        unsafe { asl_annoncer(ptr::null_mut(), vide.as_ptr(), ptr::null(), 0) },
        ASL_ARGUMENT
    );
    assert_eq!(
        unsafe { asl_etat(ptr::null(), ptr::null_mut()) },
        ASL_ARGUMENT
    );
    assert_eq!(
        unsafe {
            asl_ou(
                ptr::null_mut(),
                vide.as_ptr(),
                vide.as_ptr(),
                ptr::null_mut(),
                0,
                ptr::null_mut(),
            )
        },
        ASL_ARGUMENT
    );

    // Et libérer le néant est un non-événement, comme `free(NULL)`.
    unsafe { asl_client_libere(ptr::null_mut()) };
}

// ── LA CONSTRUCTION ─────────────────────────────────────────────────────────

#[test]
fn un_annuaire_se_pose_par_une_adresse_litterale_et_jamais_par_un_nom() {
    // **LA RÉSOLUTION APPARTIENT À L'APPELANT** : un daemon chargé dans un
    // interpréteur a déjà son résolveur, sa politique de cache et ses fils.
    let client = client();
    let nom = c"nitrogen.example";

    for bonne in [c"203.0.113.7:6630", c"[2001:db8::1]:6630"] {
        assert_eq!(
            unsafe { asl_client_annuaire(client, bonne.as_ptr(), nom.as_ptr()) },
            ASL_OK,
            "{bonne:?}"
        );
    }
    for mauvaise in [
        c"nitrogen.example:6630", // un NOM : ce n'est pas à nous de le résoudre
        c"203.0.113.7",           // pas de port
        c"2001:db8::1:6630",      // sans crochets, c'est ambigu
        c"",
    ] {
        assert_eq!(
            unsafe { asl_client_annuaire(client, mauvaise.as_ptr(), nom.as_ptr()) },
            ASL_ARGUMENT,
            "{mauvaise:?}"
        );
    }
    // Un nom vide ne vérifie aucun certificat.
    assert_eq!(
        unsafe { asl_client_annuaire(client, c"203.0.113.7:6630".as_ptr(), c"".as_ptr()) },
        ASL_ARGUMENT
    );
    unsafe { asl_client_libere(client) };
}

#[test]
fn une_identite_exige_une_machine_et_trente_deux_octets() {
    let client = client();
    let graine = [0x42_u8; ASL_GRAINE_OCTETS];

    let service = Identifiant::depuis_entropie(Genre::Service, [7; 16]);
    let pas_une_machine = std::ffi::CString::new(service.texte().as_str()).unwrap();
    assert_eq!(
        unsafe { asl_client_identite(client, pas_une_machine.as_ptr(), graine.as_ptr()) },
        ASL_ARGUMENT,
        "un service n'est pas une machine"
    );
    assert_eq!(
        unsafe { asl_client_identite(client, c"n'importe quoi".as_ptr(), graine.as_ptr()) },
        ASL_ARGUMENT
    );

    let machine = machine_texte();
    assert_eq!(
        unsafe { asl_client_identite(client, machine.as_ptr(), graine.as_ptr()) },
        ASL_OK
    );
    unsafe { asl_client_libere(client) };
}

// ── L'ANNONCE ───────────────────────────────────────────────────────────────

/// Un client configuré, avec une racine que `rustls` REFUSERA.
///
/// C'est ce qu'il faut pour éprouver le seul cas où l'attache renonce.
fn client_a_racine_illisible() -> *mut AslClient {
    let client = client();
    let racines = b"pas un PEM";
    assert_eq!(
        unsafe { asl_client_annuaire(client, c"127.0.0.1:1".as_ptr(), c"localhost".as_ptr()) },
        ASL_OK
    );
    assert_eq!(
        unsafe { asl_client_racines(client, racines.as_ptr(), racines.len()) },
        ASL_OK
    );
    let machine = machine_texte();
    let graine = [0x42_u8; ASL_GRAINE_OCTETS];
    assert_eq!(
        unsafe { asl_client_identite(client, machine.as_ptr(), graine.as_ptr()) },
        ASL_OK
    );
    client
}

#[test]
fn une_annonce_exige_une_identite_et_des_points_qui_se_lisent() {
    let client = client();
    let tcp = AslPoint {
        port: 8080,
        protocole: ASL_TCP,
        reserve: 0,
    };

    // Sans identité, on ne peut rien signer.
    assert_eq!(
        unsafe { asl_annoncer(client, c"depot".as_ptr(), &raw const tcp, 1) },
        ASL_PAS_D_IDENTITE
    );

    let machine = machine_texte();
    let graine = [0x42_u8; ASL_GRAINE_OCTETS];
    assert_eq!(
        unsafe { asl_client_identite(client, machine.as_ptr(), graine.as_ptr()) },
        ASL_OK
    );

    // **L'ANNONCE EST VALIDÉE ICI**, dans la main de l'appelant, et non dans un
    // fil que personne ne regarde.
    assert_eq!(
        unsafe { asl_annoncer(client, c"depot".as_ptr(), &raw const tcp, 0) },
        ASL_ARGUMENT,
        "aucun point"
    );
    assert_eq!(
        unsafe { asl_annoncer(client, c"".as_ptr(), &raw const tcp, 1) },
        ASL_ARGUMENT,
        "un nom de service vide"
    );
    let sans_protocole = AslPoint {
        port: 8080,
        protocole: 99,
        reserve: 0,
    };
    assert_eq!(
        unsafe { asl_annoncer(client, c"depot".as_ptr(), &raw const sans_protocole, 1) },
        ASL_ARGUMENT
    );
    let port_nul = AslPoint {
        port: 0,
        protocole: ASL_TCP,
        reserve: 0,
    };
    assert_eq!(
        unsafe { asl_annoncer(client, c"depot".as_ptr(), &raw const port_nul, 1) },
        ASL_ARGUMENT
    );

    // Et l'identité a survécu à tous ces refus.
    assert_eq!(
        unsafe { asl_annoncer(client, c"depot".as_ptr(), &raw const tcp, 1) },
        ASL_CONFIGURATION,
        "il manque un annuaire, et non l'identité"
    );
    unsafe { asl_client_libere(client) };
}

#[test]
fn l_ordonnanceur_tourne_sans_que_personne_l_attende() {
    // **C'EST L'ESSAI QUI COMPTE LE PLUS DE TOUT CE FICHIER.**
    //
    // L'annonce est tenue par une tâche de fond, et une tâche de fond ne
    // progresse, sur un ordonnanceur à un seul fil, que lorsque quelqu'un
    // l'attend. Ici personne ne l'attend : `asl_annoncer` a rendu la main, et
    // l'appelant est parti faire autre chose — c'est précisément ce que
    // `protocole.md` §1.4 exige.
    //
    // Si le moteur n'avait pas son propre fil, `abandonnee` ne passerait JAMAIS
    // à 1, et tout compilerait.
    let client = client_a_racine_illisible();
    let tcp = AslPoint {
        port: 8080,
        protocole: ASL_TCP,
        reserve: 0,
    };
    assert_eq!(
        unsafe { asl_annoncer(client, c"depot".as_ptr(), &raw const tcp, 1) },
        ASL_OK
    );

    // Un second appel ne remplace pas la première annonce en silence.
    assert_eq!(
        unsafe { asl_annoncer(client, c"depot".as_ptr(), &raw const tcp, 1) },
        ASL_DEJA
    );

    let depart = std::time::Instant::now();
    let mut etat = etat_sali();
    while depart.elapsed() < std::time::Duration::from_secs(5) {
        assert_eq!(unsafe { asl_etat(client, &raw mut etat) }, ASL_OK);
        if etat.abandonnee == 1 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert_eq!(
        etat.abandonnee, 1,
        "la tâche n'a pas tourné : le moteur n'a pas de fil à lui"
    );
    assert_eq!(etat.attachee, 0);
    assert_eq!(etat.attaches, 0, "une racine illisible n'attache rien");

    unsafe { asl_client_libere(client) };
}

#[test]
fn un_client_qui_n_a_jamais_annonce_rend_un_etat_a_zero() {
    let client = client();
    let mut etat = etat_sali();
    assert_eq!(unsafe { asl_etat(client, &raw mut etat) }, ASL_OK);
    assert_eq!(etat.attaches, 0);
    assert_eq!(etat.ruptures, 0);
    assert_eq!(etat.attachee, 0);
    assert_eq!(
        etat.abandonnee, 0,
        "n'avoir rien tenté n'est pas avoir renoncé"
    );
    unsafe { asl_client_libere(client) };
}

// ── LE CONTRAT, TROIS FOIS ÉCRIT ────────────────────────────────────────────

#[test]
fn les_constantes_de_l_en_tete_sont_celles_de_rust() {
    // **L'EN-TÊTE EST CE QUE LES CINQ LIAISONS COMPILENT.** Une constante qui y
    // dériverait ne casserait rien à la compilation, ni ici ni chez elles : elle
    // ferait seulement lire `ASL_REFUSE` là où le code dit `ASL_INJOIGNABLE`.
    let entete = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/include/asl.h"))
        .expect("l'en-tête est dans le dépôt");

    let mut declarees = std::collections::BTreeMap::new();
    for ligne in entete.lines() {
        let Some(reste) = ligne.trim().strip_prefix("#define ASL_") else {
            continue;
        };
        let mut mots = reste.split_whitespace();
        let (Some(nom), Some(valeur)) = (mots.next(), mots.next()) else {
            continue;
        };
        let Ok(valeur) = valeur.parse::<i64>() else {
            continue;
        };
        declarees.insert(format!("ASL_{nom}"), valeur);
    }

    let attendues: [(&str, i64); 19] = [
        ("ASL_OK", ASL_OK.into()),
        ("ASL_ARGUMENT", ASL_ARGUMENT.into()),
        ("ASL_CONFIGURATION", ASL_CONFIGURATION.into()),
        ("ASL_INJOIGNABLE", ASL_INJOIGNABLE.into()),
        ("ASL_REFUSE", ASL_REFUSE.into()),
        ("ASL_TAMPON_TROP_PETIT", ASL_TAMPON_TROP_PETIT.into()),
        ("ASL_INTERNE", ASL_INTERNE.into()),
        ("ASL_PAS_D_IDENTITE", ASL_PAS_D_IDENTITE.into()),
        ("ASL_DEJA", ASL_DEJA.into()),
        (
            "ASL_IDENTIFIANT_OCTETS",
            i64::try_from(ASL_IDENTIFIANT_OCTETS).expect("il tient"),
        ),
        (
            "ASL_GRAINE_OCTETS",
            i64::try_from(ASL_GRAINE_OCTETS).expect("il tient"),
        ),
        ("ASL_TCP", ASL_TCP.into()),
        ("ASL_UDP", ASL_UDP.into()),
        ("ASL_REFLEXIF", ASL_REFLEXIF.into()),
        ("ASL_ANNONCE", ASL_ANNONCE.into()),
        ("ASL_JOIGNABLE", ASL_JOIGNABLE.into()),
        ("ASL_INJOIGNABLE_POINT", ASL_INJOIGNABLE_POINT.into()),
        ("ASL_NON_SONDE", ASL_NON_SONDE.into()),
        ("ASL_EN_COURS", ASL_EN_COURS.into()),
    ];

    for (nom, valeur) in attendues {
        assert_eq!(
            declarees.get(nom),
            Some(&valeur),
            "`{nom}` diverge entre `asl.h` et Rust"
        );
    }
    assert_eq!(
        declarees.len(),
        attendues.len(),
        "l'en-tête déclare une constante que cet essai ne compare pas : {declarees:?}"
    );
}

#[test]
fn les_tailles_de_structure_sont_celles_que_l_en_tete_annonce() {
    // Elles sont déjà vérifiées à la compilation ; ce qui l'est ici est
    // l'accord avec les nombres ÉCRITS dans les commentaires de l'en-tête, que
    // les cinq liaisons recopient.
    assert_eq!(core::mem::size_of::<AslPoint>(), 4);
    assert_eq!(core::mem::size_of::<AslCandidat>(), 24);
    assert_eq!(core::mem::size_of::<AslEtat>(), 24);
    assert_eq!(ASL_IDENTIFIANT_OCTETS, 29);
}

#[test]
fn l_identite_survit_a_l_annonce() {
    // **UNE IDENTITÉ NE SE DUPLIQUE PAS, ET L'ANNONCE EN CONSOMME UNE.** Rangée
    // telle quelle dans le client, elle disparaissait au premier `asl_annoncer`
    // — et le `asl_ou` suivant répondait « aucune identité » à un daemon qui
    // venait précisément de s'annoncer. Rien ne le disait à la compilation.
    let client = client_a_racine_illisible();
    let tcp = AslPoint {
        port: 8080,
        protocole: ASL_TCP,
        reserve: 0,
    };
    assert_eq!(
        unsafe { asl_annoncer(client, c"depot".as_ptr(), &raw const tcp, 1) },
        ASL_OK
    );

    let cible = machine_texte();
    let mut combien = 0_usize;
    let code = unsafe {
        asl_ou(
            client,
            cible.as_ptr(),
            c"depot".as_ptr(),
            ptr::null_mut(),
            0,
            &raw mut combien,
        )
    };
    assert_ne!(
        code, ASL_PAS_D_IDENTITE,
        "l'annonce a emporté l'identité du client"
    );
    // La racine reste illisible : ce qu'on obtient est une configuration, et
    // c'est bien le chemin qu'on voulait atteindre.
    assert_eq!(code, ASL_CONFIGURATION, "{code}");

    unsafe { asl_client_libere(client) };
}
