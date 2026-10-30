+++
title = "Sous-traitants"
description = "Registre des sous-traitants d'ApexMail, la liste des prestataires autorisés qui traitent des données en notre nom."
template = "prose.html"

[extra]
last_updated = "2026-10-29"
+++
## Registre des sous-traitants

Cette page énumère les prestataires tiers engagés par Bel Consulting OÜ (exerçant sous le nom d'ApexMail) susceptibles de traiter des données personnelles de clients dans le cadre de la fourniture du service ApexMail. Ce registre est tenu conformément à l'article 28 du RGPD et à la section 5 de l'accord de traitement des données ApexMail.

En routage EU-only, l'entrée AWS SES ne transporte le courrier d'aucun locataire : les messages ne sortent que par les MTA propres d'ApexMail sur l'infrastructure UE gérée par ApexMail. Le routage EU-only et ses preuves, y compris la distinction avec le mode global par défaut, qui utilise AWS SES dans sa région UE, sont exposés sur la [page de souveraineté européenne](/fr/eu-sovereign/).

### Sous-traitants d'infrastructure

Les entités tierces suivantes traitent des données personnelles de clients pour le compte d'ApexMail.

| Entité juridique | Marque | Service | Finalité | Catégories de données | Pays de traitement | Pays de stockage | Pays de l'entreprise | Mécanisme de transfert | Obligatoire |
|---|---|---|---|---|---|---|---|---|---|
| Fournisseur d'infrastructure UE (nommé dans l'annexe sous-traitants du DPA client) | Fournisseur d'infrastructure | Hébergement cloud | Calcul, stockage, réseau | Données du service principal dans le déploiement partagé par défaut | UE/EEE | UE/EEE | UE/EEE | Traitement intra-EEE ; les règles de transfert du chapitre V du RGPD ne s'appliquent pas | Oui. |
| Amazon Web Services, Inc. | AWS S3 | Stockage d'objets de télémétrie | Stockage de télémétrie lorsqu'il est activé | Les journaux Loki et les traces Tempo peuvent contenir des métadonnées opérationnelles | Région S3 configurée (par défaut : `eu-central-1`) | Région S3 configurée (par défaut : `eu-central-1`) | États-Unis | Clauses contractuelles types de l'UE (DPA AWS) | Non, uniquement lorsque le déploiement actif utilise le stockage S3 |
| Amazon Web Services, Inc. | AWS SES | Transport de livraison d'emails | Livraison d'emails lorsqu'elle est activée | Contenu des emails et adresses des destinataires | Région SES configurée | Région SES configurée | États-Unis | Clauses contractuelles types de l'UE (DPA AWS) | Non, uniquement lorsque le déploiement actif utilise SES |
| Runtime de modèle d'IA (point de terminaison configuré) | Inférence IA | Triage, rédaction et support assistés par IA lorsqu'ils sont activés (AI_MODEL_ENABLED=true) | Métadonnées de messages et extraits de contenu soumis à l'analyse assistée par IA | UE/EEE (point de terminaison configuré) | UE/EEE (point de terminaison configuré) | UE/EEE | Point de terminaison d'inférence UE/EEE configuré ; traitement intra-EEE | Non, uniquement si AI_MODEL_ENABLED=true et si AI_MODEL_ENDPOINT désigne un runtime UE/EEE. Liste comme processeur possible : inactif tant que AI_MODEL_ENABLED n'est pas true ; le point de terminaison configuré doit être un runtime UE/EEE. |
| Google LLC | Google | Authentification OAuth | Connexion via Google OAuth | Jetons OAuth, adresse email, nom | Mondial (données UE) | Utilisateurs établis dans l'EEE : EEE | États-Unis | Clauses contractuelles types (CCT) | Non, uniquement si le client active Google OAuth |
| GitHub, Inc. | GitHub | Authentification OAuth | Connexion via GitHub OAuth | Jetons OAuth, nom d'utilisateur, adresse email | Mondial (données UE) | Utilisateurs établis dans l'EEE : EEE | États-Unis | Clauses contractuelles types (CCT) | Non, uniquement si le client active GitHub OAuth |
| Mollie B.V. | Mollie | Traitement des paiements | Facturation par abonnement, facturation, stockage des moyens de paiement | Jetons de moyens de paiement, métadonnées de transaction, données de facturation | Pays-Bas | Pays-Bas | Pays-Bas | Entité contractante établie dans l'UE (Mollie B.V., Amsterdam) ; les réseaux de cartes traitent les données à l'échelle mondiale selon le DPA Mollie ; certifié PCI DSS niveau 1 | Oui, requis pour les forfaits payants |

### Infrastructure auto-hébergée (pas des sous-traitants tiers)

Les logiciels suivants sont déployés et gérés par ApexMail sur l'infrastructure UE gérée par ApexMail. Leurs éditeurs ne traitent pas de données clients.

| Logiciel | Finalité | Catégories de données | Pays de traitement | Pays de stockage | Notes |
|---|---|---|---|---|---|
| ClickHouse (open source) | Base de données analytique | Événements de livraison, événements d'ouverture et de clic, données de rebond et de plainte | Région UE ApexMail (EEE) | Région UE ApexMail (EEE) | Auto-hébergé par ApexMail sur l'infrastructure UE gérée par ApexMail. ClickHouse, Inc. ne traite pas de données clients. |
| Redis (open source) | Cache en mémoire | Jetons de session, compteurs de limitation de débit | Région UE ApexMail (EEE) | Région UE ApexMail (EEE) | Auto-hébergé par ApexMail sur l'infrastructure UE gérée par ApexMail. Redis Ltd. ne traite pas de données clients. |

### Prestataire de paiement

Mollie B.V. est un établissement de paiement supervisé par De Nederlandsche Bank (DNB), dont le siège social est situé Keizersgracht 126, 1015 CW Amsterdam, Pays-Bas. Les données de paiement sont traitées aux Pays-Bas (UE) ; les réseaux de cartes peuvent les traiter à l'échelle mondiale dans le cadre de l'accord de traitement des données de Mollie.

### Notification

Les clients sont informés au moins **30 jours** avant l'engagement d'un nouveau sous-traitant. Pour recevoir les notifications, abonnez-vous à [subprocessor-notifications@apexmail.ee](mailto:subprocessor-notifications@apexmail.ee) ou surveillez cette page.

### Opposition

Si vous vous opposez à un nouveau sous-traitant pour des motifs raisonnables de protection des données, contactez [privacy@apexmail.ee](mailto:privacy@apexmail.ee). Si aucune alternative ne peut être trouvée, vous pouvez résilier les services concernés conformément au DPA.

### Historique des modifications

| Date | Modification | Description |
|---|---|---|
| 2026-07-29 | Publication initiale | Registre des sous-traitants publié avec le fournisseur d'infrastructure UE (infrastructure), AWS (S3/SES, lorsqu'ils sont activés), Google (OAuth), GitHub (OAuth) et Mollie (paiements). ClickHouse et Redis sont des logiciels auto-hébergés, et non des sous-traitants (voir ci-dessus). |
| 2026-10-29 | Localisation d'hébergement retirée du registre public ; runtime IA ajouté | Le fournisseur d'infrastructure n'est plus désigné publiquement que comme nommé dans l'annexe DPA client ; son pays et son site ne figurent que dans cette annexe et dans les registres internes. Le registre liste aussi le runtime de modèle d'IA (AI_MODEL_ENDPOINT), couvert par la vérification zéro-US. |
