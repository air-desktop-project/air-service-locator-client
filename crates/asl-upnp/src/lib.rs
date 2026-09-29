//! Le client UPnP-IGD d'`asl echo` — **son codec, sans une entrée-sortie**
//! (`protocole.md` §3 quater, « La passerelle », décisions 94 à 97).
//!
//! # POURQUOI UNE CRATE, ET POURQUOI LA NÔTRE
//!
//! Pour mettre toutes les chances de son côté, l'écho demande à la box de lui
//! rediriger son port (décision 94). Ce qu'il lit alors — une réponse SSDP, une
//! description d'appareil en XML, des réponses SOAP, le tout sur du HTTP/1.1 —
//! **vient d'un appareil du réseau local que personne n'authentifie** : UPnP
//! n'a aucune authentification, et n'importe quelle machine du réseau peut se
//! faire passer pour la box. C'est donc un décodeur exposé, et C3 veut qu'il
//! soit fuzzé, C1 qu'il ne fasse aucune entrée-sortie, C2 qu'il soit couvert.
//!
//! `igd-next` sait l'essentiel, mais ses décodeurs ne sont pas les nôtres, il
//! tire une trentaine de crates, et il ne sait pas le trou IPv6. **Décidé
//! (décision 96 ; E17) : notre client**, lu contre `igd-next` comme référence
//! et jamais ajouté au graphe. Cette crate n'a **aucune dépendance** : la
//! bibliothèque standard, et rien d'autre.
//!
//! # CE QUI EST ICI, ET CE QUI N'Y EST PAS
//!
//! Ici, des octets entrent et des valeurs sortent — ou une faute :
//!
//! | Module | Ce qu'il lit ou écrit |
//! |---|---|
//! | [`url`] | Une URL `http://` à **adresse littérale** (C20 : aucun nom), et la règle « hôte local » |
//! | [`ssdp`] | Le `M-SEARCH`, et la réponse qui donne `LOCATION` — suivie seulement vers l'adresse qui a répondu |
//! | [`http`] | Une requête `GET` ou `POST` SOAP, et une réponse bornée : `Content-Length`, `chunked`, ou jusqu'à la fermeture |
//! | [`xml`] | Un lecteur XML réduit à ce que la description et SOAP portent : pas de DTD, pas d'entité inventée, profondeur bornée |
//! | [`description`] | Les services de la box, et le choix : `WANIPConnection:2`, `:1`, `WANPPPConnection:1` ; `WANIPv6FirewallControl:1` |
//! | [`soap`] | Les huit actions que l'écho sait demander — pas une de plus —, et leurs réponses ou leurs fautes |
//! | [`memoire`] | Ce que l'écho a ouvert, écrit dans son répertoire d'état pour être retiré après un arrêt brutal |
//!
//! La socket, le délai, le tirage des ports, le journal : `asl-cli`, qui seul
//! parle UPnP. **UPnP reste hors d'`asl-client`** (§3 quater) : la
//! bibliothèque que les daemons des autres chargent n'ouvre rien sur la box.
//!
//! # UN SEUL PORT, LE SIEN
//!
//! Les constructeurs de [`soap`] ne savent redemander que `(UDP, un port, une
//! adresse)`, avec la description `asl-echo` : il n'existe pas d'action pour
//! ouvrir TCP, ni pour nommer un autre protocole. C'est l'appelant qui passe
//! le port de l'écho ; la crate, elle, ne sait pas en ouvrir d'autre sorte.

#![forbid(unsafe_code)]

pub mod description;
pub mod http;
pub mod memoire;
pub mod soap;
pub mod ssdp;
pub mod url;
pub mod xml;

mod tete;
