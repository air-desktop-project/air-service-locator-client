//! La bibliothèque des DEUX bouts : ce qu'un daemon lie pour s'annoncer, et ce
//! qu'un de ses clients lie pour retrouver le port où le joindre.
//!
//! # Le problème que tout ceci existe pour résoudre
//!
//! Un daemon qui n'a pas de numéro de port fixe est un daemon qu'on ne peut pas
//! joindre — sauf si quelque chose sait où il est. Cette crate est ce quelque
//! chose, vu des deux côtés :
//!
//! - au démarrage, le daemon obtient un port du système, puis l'ANNONCE ;
//! - plus tard, son client DEMANDE ce port et ouvre la connexion.
//!
//! # Ce qui contraint cette crate plus que les autres
//!
//! **Elle est liée par du code qui n'est pas le nôtre.** Sa surface publique est
//! donc un engagement, et son graphe de dépendances aussi : ce qu'elle tire, un
//! daemon tiers l'embarque. Elle ne doit jamais dépendre d'`asl-store` ni
//! d'`asl-annuaire` — s'annoncer ne doit pas coûter d'embarquer la base de
//! données du service.
//!
//! **Et elle doit survivre à l'annuaire.** Un service de découverte injoignable
//! ne doit pas empêcher un daemon de démarrer. La règle est arrêtée
//! (`protocole.md` §1.4) : rendre la main immédiatement, se connecter en
//! arrière-plan, essayer les annuaires dans l'ordre — IPv6 avant IPv4 —,
//! réessayer avec un recul exponentiel et un bruit de ±20 %, et **ne jamais
//! abandonner**.
//!
//! **Ce mécanisme EST aussi la bascule entre les deux annuaires racines**, et il
//! n'y en a pas d'autre : l'état vivant n'est délibérément pas répliqué, parce
//! qu'il se reconstruit ici, tout seul, en un keepalive (`annuaires.md` §3). Ce
//! qui ressemble à du code de reprise est en réalité le mécanisme de haute
//! disponibilité du produit entier.
//!
//! # Le transport
//!
//! **HTTP/3 sur QUIC, connexion TENUE, IPv6 d'abord.** Le daemon ouvre une
//! connexion et la maintient par un keepalive : la connexion *est* le bail. Il
//! n'y a pas de réannonce périodique à écrire.
//!
//! Les valeurs de temps — keepalive, délai d'inactivité — **viennent du
//! serveur** et ne sont jamais figées ici. Le bon delta se mesure sur des NAT
//! réels et n'est pas encore mesuré ; le figer dans cette crate exigerait de
//! mettre à jour tous les daemons installés chez des tiers, ce qui ne se
//! produira jamais.
//!
//! # Ce que le porteur doit poser sur la machine
//!
//! **Un secret de machine, `sm-…`, et rien d'autre** (`docs/modele.md` §2.3).
//! Le même objet des deux côtés : la machine qui héberge le daemon le porte avec
//! la capacité `annonce`, celle qui consomme le porte avec la capacité
//! `lecture`. Une machine n'est pas « une machine à daemon » — c'est n'importe
//! quelle machine d'un utilisateur.
//!
//! **Il n'y a aucun mode anonyme à implémenter** (contrainte C10) : une
//! résolution sans secret valide n'existe pas, et un client qui prévoirait un
//! chemin de repli « sans authentification » coderait une porte que le serveur
//! n'ouvre pas.
//!
//! # État
//!
//! Vide. Spécifié, pas écrit.
