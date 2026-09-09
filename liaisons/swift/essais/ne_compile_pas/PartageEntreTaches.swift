// **CE FICHIER NE DOIT PAS COMPILER**, et c'est tout son objet.
//
// L'ABI dit qu'un client ne se partage pas entre fils : deux appels concurrents
// aliaseraient un `&mut` du côté Rust, ce qui est un comportement indéfini et non
// un ralentissement.
//
// Python, Ruby et Kotlin posent un verrou pour faire respecter cette phrase.
// C++ se contente de l'écrire. **Swift la fait vérifier** : `Client` ne conforme
// pas à `Sendable`, donc il ne peut pas être PARTAGÉ entre domaines d'isolement.
//
// ── CE QUE `Sendable` REFUSE, ET CE QU'IL LAISSE PASSER ────────────────────
//
// Il a fallu le constater plutôt que le supposer. Un `Task.detached` qui capture
// un `Client` COMPILE : l'isolement par régions (SE-0414) sait prouver qu'un
// paramètre dont plus rien ne se sert est détaché, et le laisse donc PARTIR.
// C'est un déplacement, pas un partage, et c'est correct.
//
// Ce qui reste interdit est le partage lui-même — ranger un `Client` dans un
// acteur, dans un `@Sendable` que d'autres tiennent, dans une variable globale.
// Tout cela passe par la même exigence, et c'est elle que ce fichier épingle.
//
// Sans essai, ce refus disparaîtrait le jour où quelqu'un ajouterait
// `: @unchecked Sendable` pour faire taire un avertissement — et rien ne
// casserait, sinon en production, une fois.
//
// `scripts/check-swift.sh` compile ce fichier et exige un ÉCHEC.

import Asl

/// Ce qu'exige tout ce qui PARTAGE : un acteur, une variable globale, une
/// fermeture `@Sendable` que plusieurs tiennent.
func exigeSendable<T: Sendable>(_ quoi: T) {}

func rangerLaOuPlusieursFilsLeVerront(_ client: Client) {
  exigeSendable(client)
}
