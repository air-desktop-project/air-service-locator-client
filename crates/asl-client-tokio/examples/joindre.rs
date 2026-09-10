//! Ouvre UNE connexion vers un annuaire, et dit ce qui s'est passé.
//!
//! # POURQUOI CET EXEMPLE EXISTE
//!
//! `asl joindre` n'abandonne jamais : c'est ce qu'un daemon doit faire, et c'est
//! ce que `asl_client::Reprise` garantit. **Mais un humain qui diagnostique a
//! besoin de la CAUSE**, et une reprise qui réessaie pour toujours la remplace
//! par « aucun annuaire n'a répondu en vingt secondes ».
//!
//! Celui-ci essaie UNE FOIS, et rend la faute telle quelle.
//!
//! ```sh
//! cargo run -p asl-client-tokio --example joindre -- \
//!     '[::1]:6630' localhost racine.crt
//! ```

use std::net::ToSocketAddrs as _;

fn main() -> std::process::ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let (cible, nom, racines, tenir) = match arguments.as_slice() {
        [a, b, c] => (a.clone(), b.clone(), c.clone(), 0_u64),
        [a, b, c, d] => (
            a.clone(),
            b.clone(),
            c.clone(),
            d.parse().unwrap_or_default(),
        ),
        _ => {
            eprintln!("usage : joindre <hôte:port> <nom exigé> <racines.pem> [secondes]");
            return std::process::ExitCode::from(1);
        }
    };

    let Ok(mut adresses) = cible.to_socket_addrs() else {
        eprintln!("« {cible} » ne se résout pas");
        return std::process::ExitCode::from(2);
    };
    let Some(adresse) = adresses.next() else {
        eprintln!("« {cible} » ne rend aucune adresse");
        return std::process::ExitCode::from(2);
    };
    let pem = match std::fs::read(&racines) {
        Ok(quoi) => quoi,
        Err(quoi) => {
            eprintln!("{racines} : {quoi}");
            return std::process::ExitCode::from(2);
        }
    };

    let execution = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("une exécution");

    execution.block_on(async move {
        println!("→ {adresse}, nom exigé « {nom} »");
        // **L'ALÉA EST VRAI, MÊME DANS UN EXEMPLE.** §7.2 : l'identifiant de
        // destination du premier paquet doit être imprévisible, parce que §5.2
        // en dérive les clés `Initial`. Un exemple qui figerait une graine
        // apprendrait à qui le recopie que ce détail n'en est pas un.
        let alea = || {
            let mut octets = [0_u8; 16];
            std::fs::File::open("/dev/urandom")
                .and_then(|mut source| std::io::Read::read_exact(&mut source, &mut octets))
                .expect("le noyau doit savoir tirer seize octets");
            octets
        };
        match asl_client_tokio::Connexion::ouvrir(adresse, &nom, &pem, &alea).await {
            Ok(mut connexion) => {
                println!(
                    "✓ poignée de main faite, socket locale {:?}",
                    connexion.locale()
                );
                for seconde in 1..=tenir {
                    // `entretenir` est ce que la boucle d'attache appelle : elle
                    // lit ce qui arrive, puis émet ce que QUIC a à dire. Si rien
                    // n'émet de keepalive, elle n'émet rien.
                    let issue = connexion.entretenir(1_000).await;
                    println!(
                        "  {seconde:>3} s : vivante={} {}",
                        connexion.vivante(),
                        match issue {
                            Ok(()) => String::new(),
                            Err(quoi) => format!("— {quoi}"),
                        }
                    );
                    if !connexion.vivante() {
                        println!("✗ la connexion est tombée au bout de {seconde} s de silence");
                        return std::process::ExitCode::from(4);
                    }
                }
                std::process::ExitCode::SUCCESS
            }
            Err(quoi) => {
                println!("✗ {quoi}");
                println!("  ({quoi:?})");
                std::process::ExitCode::from(3)
            }
        }
    })
}
