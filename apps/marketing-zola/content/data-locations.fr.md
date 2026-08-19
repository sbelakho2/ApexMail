+++
title = "Emplacements des données"
description = "Matrice des emplacements de données ApexMail — où chaque catégorie de données clients est stockée et traitée."
template = "prose.html"

[extra]
last_updated = "2026-07-30"
+++

## Matrice des emplacements de données

Cette matrice décrit la configuration de déploiement fournie, orientée UE/EEE, et non une garantie universelle de localisation. Les paramètres par défaut des données de messagerie principales et de la télémétrie ciblent des régions de l'EEE ; les emplacements actifs, fournisseurs activés et garanties de transfert doivent être confirmés pour l'environnement déployé et l'accord applicable.

Les entrées Dedicated Tenant et BYOC ci-dessous décrivent un modèle uniquement lorsqu'il est approuvé par un accord écrit distinct. Elles ne font pas partie des forfaits publics en libre-service.

| # | Catégorie de données | Emplacement principal par défaut | Sauvegarde / Réplica par défaut | Région de traitement par défaut | Garantie de transfert |
|---|---|---|---|---|---|
| 1 | Données de compte (nom, email, entreprise, adresse) | Hetzner, Allemagne (Falkenstein/Nuremberg) | Hetzner, Finlande (Tuusula) | EEE par défaut | Confirmer le déploiement actif |
| 2 | Clés API (hachées) | Hetzner, Allemagne (Falkenstein/Nuremberg) | Hetzner, Finlande (Tuusula) | EEE par défaut | Confirmer le déploiement actif |
| 3 | Adresses d'expéditeur et de destinataire | Hetzner, Allemagne (Falkenstein/Nuremberg) | Hetzner, Finlande (Tuusula) | EEE par défaut | Confirmer le déploiement actif |
| 4 | Contenu des messages (objet, corps, en-têtes) | Hetzner, Allemagne (Falkenstein/Nuremberg) | Hetzner, Finlande (Tuusula) | EEE par défaut | Confirmer le déploiement actif |
| 5 | Pièces jointes | Hetzner, Allemagne (Falkenstein/Nuremberg) | Hetzner, Finlande (Tuusula) | EEE par défaut | Confirmer le déploiement actif |
| 6 | Événements et journaux (livraison, ouverture, clic, rebond) | Hetzner, Allemagne (Falkenstein/Nuremberg) | Hetzner, Finlande (Tuusula) | EEE par défaut | Confirmer le déploiement actif |
| 7 | Authentification (jetons OAuth, secrets MFA) | Hetzner, Allemagne (Falkenstein/Nuremberg) ; Google LLC / GitHub, Inc. (OAuth) | Géré par le fournisseur | EEE (principal) ; États-Unis pour les fournisseurs OAuth | CCT (fournisseurs OAuth) |
| 8 | Facturation (factures, transactions, jetons de paiement) | Hetzner, Allemagne ; Stripe, Inc. (États-Unis) | Géré par le fournisseur (Inde pour le support Stripe) | EEE (ApexMail) ; États-Unis/Inde (Stripe) | CCT (Stripe) |
| 9 | Tickets de support | Hetzner, Allemagne (Falkenstein/Nuremberg) | Hetzner, Finlande (Tuusula) | EEE par défaut | Confirmer le déploiement actif |
| 10 | Analytique (métriques de livraison agrégées, engagement) | Hetzner, Allemagne (Falkenstein/Nuremberg) | Hetzner, Finlande (Tuusula) | EEE par défaut | Confirmer le déploiement actif |
| 11 | Journaux de sécurité (pistes d'audit, journaux d'accès) | Hetzner, Allemagne (Falkenstein/Nuremberg) | Hetzner, Finlande (Tuusula) | EEE par défaut | Confirmer le déploiement actif |
| 12 | Sauvegardes (base de données, instantanés de stockage de fichiers) | Hetzner, Finlande (Tuusula) | Hetzner, Allemagne (Nuremberg, stockage froid) | EEE par défaut | Confirmer le déploiement actif |

## Emplacements des sous-traitants

| Sous-traitant | Finalité | Emplacement | Garantie de transfert |
|---|---|---|---|
| Hetzner Online GmbH | Infrastructure principale (calcul, stockage, réseau) | Région EEE configurée | Confirmer le déploiement actif et la garantie de transfert |
| Amazon Web Services, Inc. (AWS S3) | Stockage d'objets de télémétrie lorsqu'il est activé | Région S3 configurée (par défaut : `eu-central-1`) | Confirmer le déploiement actif et la garantie de transfert applicable |
| Amazon Web Services, Inc. (AWS SES) | Transport de livraison d'email lorsqu'il est activé | Région SES configurée | Confirmer le déploiement actif et la garantie de transfert applicable |
| Stripe, Inc. | Traitement des paiements | États-Unis (principal), Inde (support) | Clauses contractuelles types de l'UE |
| Google LLC | Authentification OAuth optionnelle | États-Unis | Clauses contractuelles types de l'UE |
| GitHub, Inc. | Authentification OAuth optionnelle | États-Unis | Clauses contractuelles types de l'UE |

## Modèles de déploiement

| Modèle | Région principale | Contrôle client |
|---|---|---|
| Shared EU Cloud | Configuration par défaut orientée UE/EEE ; confirmer les régions actives | Géré par ApexMail |
| Dedicated Tenant | Région convenue avec le client | Single-tenant, géré par ApexMail |
| BYOC (Bring Your Own Cloud) | Fournisseur et région choisis par le client | Infrastructure gérée par le client, couche applicative gérée par ApexMail |

## Contact

Pour les questions relatives à l'emplacement des données : **privacy@apexmail.ee**
