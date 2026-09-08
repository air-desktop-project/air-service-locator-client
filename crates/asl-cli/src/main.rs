//! `asl` — faire à la main ce que la bibliothèque fait dans un programme.
//!
//! # À quoi il sert vraiment
//!
//! Pas à remplacer la bibliothèque : à **diagnostiquer**. Quand un daemon ne
//! s'annonce pas, la question est de savoir si le tort est au daemon, au réseau
//! ou à l'annuaire — et un utilitaire qui refait le même chemin, seul, tranche
//! en une commande.
//!
//! Ce qu'il devra savoir faire, et qui découle des spécifications :
//!
//! | Commande | Ce qu'elle répond |
//! |---|---|
//! | `asl annonce` | Annoncer un service à la main, et afficher `vu_depuis`, `derriere_nat` et le verdict de joignabilité. |
//! | `asl ou <service>` | Résoudre, et montrer les candidats DANS L'ORDRE où le client les essaierait. |
//! | `asl diagnostic` | Est-ce que je joins l'annuaire ? en IPv6 ? sous quelle adresse me voit-il ? suis-je derrière un NAT ? |
//!
//! **`asl diagnostic` est la commande qui compte le plus**, et c'est la moins
//! évidente. La question qu'un administrateur se pose n'est presque jamais
//! « quel est le port » — c'est « pourquoi ça ne marche pas ». Un annuaire qui
//! mesure la joignabilité sans donner le moyen de lire cette mesure à la main
//! garderait sa réponse pour lui.
//!
//! # État
//!
//! Il ne fait rien, et il le dit — plutôt que d'afficher une aide qui
//! promettrait des commandes qui n'existent pas.

fn main() {
    println!("asl : rien à faire — `asl-client` n'est pas écrit (voir le README).");
}
