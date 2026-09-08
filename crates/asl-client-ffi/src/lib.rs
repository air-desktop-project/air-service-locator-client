//! L'ABI C d'`asl-client` — le seul passage par lequel les liaisons entrent.
//!
//! # Pourquoi une ABI C, et pas cinq liaisons natives
//!
//! Python, Ruby, C++, Kotlin et Swift savent tous appeler du C. Aucun ne sait
//! appeler du Rust. Écrire cinq passages natifs, ce serait maintenir cinq fois
//! la même logique de conversion — et c'est la copie qu'on oublie qui finit par
//! diverger.
//!
//! # Les deux règles, et ce qu'elles interdisent (contrainte C12)
//!
//! **AUCUN TYPE RUST NE TRAVERSE LA FRONTIÈRE.** Ni `String`, ni `Result`, ni
//! générique, ni trait. Des entiers, des pointeurs opaques, des tampons fournis
//! par l'appelant, et des codes d'erreur. Un `String` rendu à Python serait un
//! bloc alloué par l'allocateur de Rust que l'appelant tenterait de libérer avec
//! le sien.
//!
//! **LE RETRAIT D'UNE SIGNATURE EST UNE RUPTURE MAJEURE**, pour les cinq
//! liaisons à la fois — qui ne se mettent pas à jour au même rythme. Un ajout est
//! libre ; c'est le retrait qui casse. `scripts/check-abi.sh` devra comparer
//! l'en-tête généré à celui du dernier commit et exiger une justification écrite
//! pour toute suppression.
//!
//! # La forme que prendra chaque fonction
//!
//! - Elle rend un `int32_t` : zéro, ou un code d'erreur négatif. **Jamais une
//!   valeur utile** — celle-ci sort par un pointeur fourni par l'appelant.
//! - Elle ne panique pas. Une panique qui traverse une frontière FFI est un
//!   comportement indéfini, et non une erreur qu'on rattrape plus haut.
//! - Tout ce qu'elle alloue se libère par une fonction de cette même
//!   bibliothèque, nommée à côté de celle qui a alloué.
//!
//! # État
//!
//! Vide. `asl-client` n'a rien à exposer encore.
