+++
title = "Accord de traitement des données"
description = "DPA ApexMail — conditions de traitement des données relevant de l'article 28 du RGPD."
template = "prose.html"

[extra]
last_updated = "2026-07-30"
+++

## 1. Champ d'application

Le présent Accord de traitement des données (« DPA ») complète les Conditions d'utilisation et régit le traitement des données personnelles par **Bel Consulting OÜ** (code de registre 16588745, TVA EE102951727, Sakala 7-2, 10141 Tallinn, Estonie), opérant sous le nom d'ApexMail (« **Sous-traitant** ») pour le compte du Client (« **Responsable du traitement** ») en vertu de l'Article 28 du Règlement (UE) 2016/679 (Règlement général sur la protection des données).

## 2. Définitions

Les termes utilisés dans le présent DPA ont la signification donnée dans le RGPD, sauf définition contraire.

## 3. Détails du traitement

| Élément | Description |
|---|---|
| **Objet** | Envoi d'emails, suivi de livraison, analytique |
| **Durée** | Durée du contrat de service |
| **Nature** | Traitement et transmission automatisés de messages électroniques |
| **Finalité** | Fourniture de services d'infrastructure de messagerie |
| **Catégories de données** | Adresses email, contenu des messages, métadonnées de livraison, adresses IP |
| **Personnes concernées** | Utilisateurs finaux du client (destinataires d'emails) |

## 4. Obligations du sous-traitant

Le Sous-traitant s'engage à :
- Traiter les données uniquement sur instructions documentées du Responsable du traitement.
- S'assurer que le personnel est lié par la confidentialité.
- Mettre en œuvre des mesures techniques et organisationnelles appropriées (Article 32).
- Aider le Responsable du traitement à répondre aux demandes des personnes concernées.
- Supprimer ou restituer toutes les données personnelles à la fin du contrat.
- Mettre à disposition toutes les informations nécessaires pour démontrer la conformité avec l'Article 28.
- Permettre et contribuer aux audits et inspections menés par le Responsable du traitement ou un auditeur mandaté.

## 5. Sous-traitants ultérieurs

### 5.1 Sous-traitants autorisés

La liste actuelle des sous-traitants autorisés est tenue dans le [Registre des sous-traitants ApexMail](https://apexmail.ee/subprocessors/), incorporé au présent DPA par référence.

| Sous-traitant | Finalité | Localisation | Garantie de transfert |
|---|---|---|---|
| Hetzner Online GmbH | Infrastructure principale (calcul, stockage) | Région UE/EEE configurée | Confirmer le déploiement actif et la garantie de transfert applicable |
| Amazon Web Services, Inc. | Stockage d'objets de télémétrie lorsqu'il est activé | Région S3 configurée (par défaut : `eu-central-1`) | Confirmer le déploiement actif et la garantie de transfert applicable |
| Amazon Web Services, Inc. | Transport de livraison d'email lorsqu'il est activé | Région SES configurée | Confirmer le déploiement actif et la garantie de transfert applicable |
| Google LLC | Authentification OAuth optionnelle | Mondial (entité américaine, données traitées selon la configuration OAuth) | Clauses contractuelles types |
| GitHub, Inc. | Authentification OAuth optionnelle | Mondial (entité américaine) | Clauses contractuelles types |
| Stripe, Inc. | Traitement des paiements | États-Unis (principal), Inde (support) | Clauses contractuelles types |

L'infrastructure auto-hébergée (ClickHouse, Redis) s'exécute sur des serveurs Hetzner sous le contrôle opérationnel d'ApexMail. Les éditeurs open source en amont ne traitent pas les données des clients.

### 5.2 Notification des changements

Le Sous-traitant notifiera le Responsable du traitement au moins **30 jours** avant l'ajout ou le remplacement de tout sous-traitant, donnant au Responsable du traitement la possibilité de s'y opposer. Si le Responsable du traitement s'y oppose pour des motifs raisonnables de protection des données et qu'aucune alternative ne peut être trouvée, le Responsable du traitement peut résilier les services concernés.

## 6. Transferts internationaux

La configuration fournie cible des régions de l'UE/EEE pour l'infrastructure principale et le stockage d'objets de télémétrie. Les fournisseurs et emplacements actifs dépendent du déploiement ; consultez la page [Emplacements des données](/data-locations/) pour une matrice complète catégorie par catégorie. Aucune donnée personnelle n'est transférée hors de l'EEE sans garanties appropriées (Clauses contractuelles types ou décision d'adéquation en vertu de l'Article 45).

## 7. Mesures de sécurité

- Chiffrement AES-256-GCM au repos
- TLS 1.2+ en transit (TLS 1.3 préféré)
- Hachage de mot de passe Argon2id
- Journalisation d'audit avec intégrité par chaîne de hachage
- Contrôles de sécurité alignés SOC 2 (non certifié actuellement ; cartographie des contrôles et évaluation de préparation en cours)
- Contrôle d'accès avec authentification multi-facteurs
- Analyse continue des vulnérabilités ; programme indépendant de test d'intrusion en cours d'établissement, premier test planifié
- Remédiation selon la gravité conformément à la politique de gestion des vulnérabilités d'ApexMail

## 8. Notification des violations de données

Le Sous-traitant notifiera le Responsable du traitement **sans retard injustifié** après avoir pris connaissance d'une violation de données personnelles impliquant les données du Responsable du traitement. ApexMail vise contractuellement une notification initiale dans les 48 heures, sur la base des informations raisonnablement disponibles à ce moment-là. La notification comprendra :
- La nature de la violation.
- Les catégories et le nombre approximatif de personnes concernées et d'enregistrements.
- Les coordonnées du Responsable de la protection des données.
- Les conséquences probables et les mesures prises ou proposées.

## 9. Restitution et suppression des données

À la fin du contrat, le Sous-traitant, au choix du Responsable du traitement, restituera ou supprimera toutes les données personnelles traitées pour le compte du Responsable du traitement, sauf si le droit de l'UE ou de l'Estonie exige leur conservation (par exemple, les documents de facturation conservés pendant 7 ans conformément à la loi comptable estonienne).

## 10. Droits d'audit

Le Responsable du traitement peut demander un audit de la conformité du Sous-traitant au présent DPA à des intervalles raisonnables. L'audit sera effectué aux frais du Responsable du traitement et sous réserve d'obligations de confidentialité.

## 11. Droit applicable

Le présent DPA est régi par les lois de la République d'Estonie et le RGPD. Tout litige sera résolu par les tribunaux de Tallinn, Estonie.
