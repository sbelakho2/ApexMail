+++
title = "Sous-traitants"
description = "Registre des sous-traitants d'ApexMail — la liste des prestataires autorisés qui traitent des données en notre nom."
template = "prose.html"

[extra]
last_updated = "2026-07-29"
+++
## Registre des sous-traitants

Cette page énumère les prestataires tiers engagés par Bel Consulting OÜ (exerçant sous le nom d'ApexMail) susceptibles de traiter des données personnelles de clients dans le cadre de la fourniture du service ApexMail. Ce registre est tenu conformément à l'article 28 du RGPD et à la section 5 de l'accord de traitement des données ApexMail.

### Sous-traitants d'infrastructure

Les entités tierces suivantes traitent des données personnelles de clients pour le compte d'ApexMail.

| Entité juridique | Marque | Service | Finalité | Catégories de données | Pays de traitement | Pays de stockage | Pays de l'entreprise | Mécanisme de transfert | Obligatoire |
|---|---|---|---|---|---|---|---|---|---|
| Hetzner Online GmbH | Hetzner | Hébergement cloud | Calcul, stockage, réseau | Données du service principal dans le déploiement partagé par défaut | Région UE/EEE configurée | Région UE/EEE configurée | Allemagne | Traitement intra-EEE ; les règles de transfert du chapitre V du RGPD ne s'appliquent pas | Oui |
| Amazon Web Services, Inc. | AWS S3 | Stockage d'objets de télémétrie | Stockage de télémétrie lorsqu'il est activé | Les journaux Loki et les traces Tempo peuvent contenir des métadonnées opérationnelles | Région S3 configurée (par défaut : `eu-central-1`) | Région S3 configurée (par défaut : `eu-central-1`) | États-Unis | Clauses contractuelles types de l'UE (DPA AWS) | Non — uniquement lorsque le déploiement actif utilise le stockage S3 |
| Amazon Web Services, Inc. | AWS SES | Transport de livraison d'emails | Livraison d'emails lorsqu'elle est activée | Contenu des emails et adresses des destinataires | Région SES configurée | Région SES configurée | États-Unis | Clauses contractuelles types de l'UE (DPA AWS) | Non — uniquement lorsque le déploiement actif utilise SES |
| Google LLC | Google | Authentification OAuth | Connexion via Google OAuth | Jetons OAuth, adresse email, nom | Mondial (données UE) | Utilisateurs établis dans l'EEE : EEE | États-Unis | Clauses contractuelles types (CCT) | Non — uniquement si le client active Google OAuth |
| GitHub, Inc. | GitHub | Authentification OAuth | Connexion via GitHub OAuth | Jetons OAuth, nom d'utilisateur, adresse email | Mondial (données UE) | Utilisateurs établis dans l'EEE : EEE | États-Unis | Clauses contractuelles types (CCT) | Non — uniquement si le client active GitHub OAuth |
| Stripe, Inc. | Stripe | Traitement des paiements | Facturation par abonnement, facturation, stockage des moyens de paiement | Jetons de moyens de paiement, métadonnées de transaction, données de facturation | États-Unis (principal) ; Inde (assistance) | États-Unis | États-Unis | Clauses contractuelles types (CCT) selon le DPA Stripe | Oui — requis pour les forfaits payants |

### Infrastructure auto-hébergée (pas des sous-traitants tiers)

Les logiciels suivants sont déployés et gérés par ApexMail sur l'infrastructure Hetzner. Leurs éditeurs ne traitent pas de données clients.

| Logiciel | Finalité | Catégories de données | Pays de traitement | Pays de stockage | Notes |
|---|---|---|---|---|---|
| ClickHouse (open source) | Base de données analytique | Événements de livraison, événements d'ouverture et de clic, données de rebond et de plainte | Région de déploiement configurée | Région de déploiement configurée | Auto-hébergé par ApexMail. ClickHouse, Inc. ne traite pas de données clients. |
| Redis (open source) | Cache en mémoire | Jetons de session, compteurs de limitation de débit | Région de déploiement configurée | Région de déploiement configurée | Auto-hébergé par ApexMail. Redis Ltd. ne traite pas de données clients. |

### Notification

Les clients sont informés au moins **30 jours** avant l'engagement d'un nouveau sous-traitant. Pour recevoir les notifications, abonnez-vous à [subprocessor-notifications@apexmail.ee](mailto:subprocessor-notifications@apexmail.ee) ou surveillez cette page.

### Opposition

Si vous vous opposez à un nouveau sous-traitant pour des motifs raisonnables de protection des données, contactez [privacy@apexmail.ee](mailto:privacy@apexmail.ee). Si aucune alternative ne peut être trouvée, vous pouvez résilier les services concernés conformément au DPA.

### Historique des modifications

| Date | Modification | Description |
|---|---|---|
| 2026-07-29 | Publication initiale | Registre des sous-traitants publié avec Hetzner (infrastructure), AWS (S3/SES, lorsqu'ils sont activés), Google (OAuth), GitHub (OAuth) et Stripe (paiements). ClickHouse et Redis sont des logiciels auto-hébergés, et non des sous-traitants (voir ci-dessus). |
