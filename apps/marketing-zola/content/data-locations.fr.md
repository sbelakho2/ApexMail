+++
title = "Emplacements des données"
description = "Matrice des emplacements de données ApexMail — où chaque catégorie de données clients est stockée et traitée."
template = "prose.html"

[extra]
last_updated = "2026-07-30"
+++

## Matrice des emplacements de données

Toutes les données clients sont stockées et traitées dans les centres de données Hetzner en Allemagne et en Finlande, sauf indication contraire ci-dessous. Les transferts hors de l'EEE reposent sur les Clauses contractuelles types de l'UE (CCT) ou une décision d'adéquation en vertu de l'Article 45 du RGPD.

| # | Catégorie de données | Emplacement principal | Sauvegarde / Réplica | Région de traitement | Garantie de transfert |
|---|---|---|---|---|---|
| 1 | Données de compte (nom, email, entreprise, adresse) | Hetzner, Allemagne (Falkenstein/Nuremberg) | Hetzner, Finlande (Tuusula) | EEE uniquement | Non applicable |
| 2 | Clés API (hachées) | Hetzner, Allemagne (Falkenstein/Nuremberg) | Hetzner, Finlande (Tuusula) | EEE uniquement | Non applicable |
| 3 | Adresses d'expéditeur et de destinataire | Hetzner, Allemagne (Falkenstein/Nuremberg) | Hetzner, Finlande (Tuusula) | EEE uniquement | Non applicable |
| 4 | Contenu des messages (objet, corps, en-têtes) | Hetzner, Allemagne (Falkenstein/Nuremberg) | Hetzner, Finlande (Tuusula) | EEE uniquement | Non applicable |
| 5 | Pièces jointes | Hetzner, Allemagne (Falkenstein/Nuremberg) | Hetzner, Finlande (Tuusula) | EEE uniquement | Non applicable |
| 6 | Événements et journaux (livraison, ouverture, clic, rebond) | Hetzner, Allemagne (Falkenstein/Nuremberg) | Hetzner, Finlande (Tuusula) | EEE uniquement | Non applicable |
| 7 | Authentification (jetons OAuth, secrets MFA) | Hetzner, Allemagne (Falkenstein/Nuremberg) ; Google LLC / GitHub, Inc. (OAuth) | Géré par le fournisseur | EEE (principal) ; États-Unis pour les fournisseurs OAuth | CCT (fournisseurs OAuth) |
| 8 | Facturation (factures, transactions, jetons de paiement) | Hetzner, Allemagne ; Stripe, Inc. (États-Unis) | Géré par le fournisseur (Inde pour le support Stripe) | EEE (ApexMail) ; États-Unis/Inde (Stripe) | CCT (Stripe) |
| 9 | Tickets de support | Hetzner, Allemagne (Falkenstein/Nuremberg) | Hetzner, Finlande (Tuusula) | EEE uniquement | Non applicable |
| 10 | Analytique (métriques de livraison agrégées, engagement) | Hetzner, Allemagne (Falkenstein/Nuremberg) | Hetzner, Finlande (Tuusula) | EEE uniquement | Non applicable |
| 11 | Journaux de sécurité (pistes d'audit, journaux d'accès) | Hetzner, Allemagne (Falkenstein/Nuremberg) | Hetzner, Finlande (Tuusula) | EEE uniquement | Non applicable |
| 12 | Sauvegardes (base de données, instantanés de stockage de fichiers) | Hetzner, Finlande (Tuusula) | Hetzner, Allemagne (Nuremberg, stockage froid) | EEE uniquement | Non applicable |

## Emplacements des sous-traitants

| Sous-traitant | Finalité | Emplacement | Garantie de transfert |
|---|---|---|---|
| Hetzner Online GmbH | Infrastructure principale (calcul, stockage, réseau) | Allemagne, Finlande | Non applicable — EEE |
| Stripe, Inc. | Traitement des paiements | États-Unis (principal), Inde (support) | Clauses contractuelles types de l'UE |
| Google LLC | Authentification OAuth optionnelle | États-Unis | Clauses contractuelles types de l'UE |
| GitHub, Inc. | Authentification OAuth optionnelle | États-Unis | Clauses contractuelles types de l'UE |

## Modèles de déploiement

| Modèle | Région principale | Contrôle client |
|---|---|---|
| Shared EU Cloud | Allemagne, Finlande (Hetzner) | Géré par ApexMail |
| Dedicated Tenant | Région UE convenue avec le client (par défaut : Finlande ou Allemagne) | Single-tenant, géré par ApexMail |
| BYOC (Bring Your Own Cloud) | Fournisseur et région choisis par le client | Infrastructure gérée par le client, couche applicative gérée par ApexMail |

## Contact

Pour les questions relatives à l'emplacement des données : **privacy@apexmail.ee**
