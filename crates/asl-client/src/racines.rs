//! Les racines embarquées, et la liste qu'une racine rend — l'ancre
//! (`annuaires.md` §2 quater, décisions 53 à 59, C20).
//!
//! # CE QUI EST ÉPINGLÉ, C'EST LA CLÉ
//!
//! Pour chaque racine : son identifiant `n-…`, **sa clé d'identité**, et des
//! locateurs. Un locateur ne fait rien croire : il dit où joindre ; la clé dit
//! qui l'on doit trouver au bout (`protocole.md` §0, « Qui l'on croit »).
//!
//! # UNE SEULE ÉCRITURE, CELLE DU SERVEUR
//!
//! La 0.17.0 avait recopié la liste et la règle ici, faute de pouvoir tirer
//! `asl-loop-tokio`, un étage 3 qui aurait porté sa boucle et son entrepôt
//! dans un client. Le serveur les a sorties dans `asl-racines` (0.31.0), une
//! crate pure qui ne dépend que d'`asl-id`, `asl-cle` et `asl-api` — déjà
//! tirées. Ce module n'en est plus que la porte : **deux listes finiraient
//! par diverger, et la première divergence serait une racine qu'un client
//! croit et que l'autre refuse.**
//!
//! # AUCUN NOM PAR DÉFAUT (C20)
//!
//! La liste embarquée porte, après les adresses de chaque racine, son nom —
//! une commodité qu'un porteur peut écrire. Ce qui se joint sans rien dire
//! n'en garde que les **adresses littérales**, IPv6 d'abord : c'est
//! `asl-client-tokio::racines_embarquees` qui trie, et il ne résout rien.

pub use asl_racines::{
    ALIAS_DES_RACINES, FauteDeListe, RACINES, RacineEmbarquee, identite_attendue,
    identite_du_certificat, racines_du_locateur, verifier_la_liste,
};
