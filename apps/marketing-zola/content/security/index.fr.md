+++
title = "Aperçu de la sécurité"
description = "Contrôles de sécurité ApexMail : chiffrement, authentification, défense réseau, réponse aux incidents, gestion des vulnérabilités et preuves de conformité."
template = "prose.html"

[extra]
last_updated = "2026-07-29"
+++

## Chiffrement

### Données en transit

- TLS 1.2+ requis pour toutes les connexions API et SMTP.
- TLS 1.3 préféré lorsque pris en charge par le MTA destinataire.
- Politique MTA-STS avec `mode: enforce` pour le SMTP entrant.
- Validation DANE (enregistrements TLSA) pour les domaines destinataires pris en charge en livraison SMTP sortante.
- WireGuard ou réseau privé pour la communication inter-services.

### Données au repos

- Chiffrement AES-256-GCM pour le contenu des messages et les pièces jointes.
- Argon2id pour le hachage des mots de passe (résistant à la mémoire, aux attaques GPU/ASIC).
- Volumes de base de données chiffrés (LUKS/dm-crypt).
- Sauvegardes chiffrées avec gestion séparée des clés.
- Les exigences de clés de chiffrement gérées par le client ne peuvent être évaluées que dans le cadre d'un déploiement faisant l'objet d'un contrat distinct ; elles ne constituent pas un droit de forfait public.

## Authentification et contrôle d'accès

- Clés API limitées par environnement (live/test) avec permissions configurables.
- Signatures HMAC des webhooks (SHA-256) pour l'intégrité des charges utiles d'événements.
- SAML SSO sur les forfaits Business et Enterprise ; tout engagement de provisionnement est confirmé dans le contrat applicable.
- Contrôle d'accès basé sur les rôles (RBAC) avec rôles personnalisés sur le forfait Enterprise.
- Authentification multi-facteurs (TOTP) pour l'accès au tableau de bord.
- Gestion des sessions avec délai d'expiration configurable et liaison IP.

## Sécurité des applications

### Pare-feu applicatif Web (WAF)

- Détection d'injection SQL (basée sur AST).
- Détection XSS (basée sur AST).
- Règles compatibles OWASP CRS.
- Validation et assainissement des entrées sur tous les points de terminaison API.
- Limitation de débit par point de terminaison et clé API.

### Détection et prévention d'intrusion (IDS/IPS)

- Détection basée sur les signatures.
- Détection d'anomalies de protocole.
- Suivi des connexions et alertes.

### Protection DDoS (défense à 5 couches)

1. Couche 3/4 : Limitation de débit, protection contre les inondations SYN
2. Couche 7 : Analyse de signature des requêtes, défi-réponse
3. Détection d'anomalies basée sur le ML
4. Protection de la machine d'état SMTP
5. Étranglement adaptatif

### Authentification API

- Tous les points de terminaison API nécessitent l'en-tête `X-API-Key` avec une clé API limitée.
- Signatures des webhooks vérifiées via HMAC-SHA256.
- OAuth 2.0 pour les intégrations tierces (connexion Google, GitHub).
- Authentification basée sur les sessions avec cookies sécurisés HTTP-only pour l'accès au tableau de bord.

## Vérification de l'intégrité du système

L'intégrité du système est vérifiée par des contrôles automatisés et récurrents sur l'ensemble de la pile de déploiement et d'exécution :

| Contrôle | Ce qui est vérifié | Fréquence | Preuve |
|---|---|---|---|
| **Artefacts de déploiement signés** | Tous les binaires d'application et images de conteneur sont signés cryptographiquement au moment de la construction. Les déploiements valident les signatures avant le déploiement. | Chaque build | Journaux d'attestation de build (immuables, en ajout seulement) |
| **Contrôles d'intégrité de la base de données** | Validation de somme de contrôle PostgreSQL sur toutes les pages de données ; intégrité par chaîne de hachage dans les tables de journaux d'audit via des résumés SHA-256 chaînés. | Continu (somme de contrôle à la lecture) ; analyse complète nocturne | Alerte en cas de corruption ; point de terminaison de vérification de chaîne de journal d'audit |
| **Journaux de déploiement immuables** | Chaque événement de déploiement (qui, quoi, quand, commit git, hachage d'artefact) est enregistré dans un journal en ajout seulement. | Chaque déploiement | Point de terminaison d'historique de déploiement ; journal inviolable |
| **Surveillance de l'intégrité des fichiers** | Les binaires système, fichiers de configuration et certificats TLS sont surveillés pour détecter les modifications non autorisées. | Continu (basé sur inotify) | Alerte en cas de modification hors des fenêtres de changement approuvées |
| **Restaurations de sauvegarde vérifiées** | Des tests de restauration automatisés valident l'intégrité et la récupérabilité des sauvegardes. | Hebdomadaire | Journal de succès/échec de restauration ; comparaison des données d'échantillon |
| **Intégrité d'exécution** | Les processus d'application sont surveillés pour détecter les modifications binaires inattendues ou les dérives de configuration par rapport à l'état déclaré infrastructure-as-code. | Continu | Alerte de détection de dérive ; rapport de réconciliation |

## Sécurité de l'infrastructure

- Hetzner Online GmbH pour le calcul, le stockage et le réseau dans la région de déploiement configurée.
- Systèmes d'exploitation Debian/Ubuntu renforcés CIS.
- Correctifs de sécurité automatisés avec déploiement progressif.
- Infrastructure immuable via infrastructure-as-code.
- Segmentation réseau entre les plans d'application, de données et de gestion.
- Isolation réseau : serveurs d'application, serveurs de base de données et interfaces de gestion sur des VLAN séparés.
- Gestion des secrets via secrets scellés et isolation d'environnement.

## Gestion des vulnérabilités

- Analyse automatisée des dépendances dans le pipeline CI/CD.
- Analyse automatisée des vulnérabilités de l'infrastructure (cadence hebdomadaire).
- Test d'intrusion annuel par un tiers (prévu — actuellement en cours d'approvisionnement ; les résultats seront publiés après le premier test et la remédiation).
- Programme de divulgation responsable : [security@apexmail.ee](mailto:security@apexmail.ee)
- Objectifs de remédiation des vulnérabilités par gravité :
  - **Critique :** Atténuation immédiate requise ; correction permanente dans les 7 jours.
  - **Élevée :** Objectif dans les 30 jours.
  - **Moyenne :** Objectif dans les 90 jours.
  - **Faible :** Basée sur le risque — traitée dans les cycles de maintenance réguliers.
  - **Activément exploitée :** Processus d'urgence indépendamment de la gravité.

## Réponse aux incidents

- Plan de réponse aux incidents documenté avec exercices sur table semestriels et simulation complète annuelle.
- Classification de la gravité des incidents de sécurité : Critique (SEV-1), Élevé (SEV-2), Moyen (SEV-3), Faible (SEV-4).
- Page de statut mise à jour dans les 15 minutes suivant un incident SEV-1/SEV-2 confirmé. Notification client par e-mail dans l'heure pour les incidents critiques.
- Résumé post-incident dans un délai d'1 jour ouvré pour tous les incidents. Calendrier post-mortem :
  - Dans les 5 jours ouvrés pour les incidents majeurs (tous les modèles de déploiement).
  - L'analyse finale des causes racines est publiée lorsque la validation est terminée.
- Procédures de notification des violations alignées sur le RGPD Art. 33/34 (autorité de contrôle dans les 72 heures).

## Preuves d'audit et de conformité

- Résumé du test d'intrusion : prévu pour publication après la réalisation du premier test d'intrusion externe de l'application et la remédiation des résultats élevés/critiques. Actuellement non disponible.
- Les demandes de questionnaires de sécurité sont évaluées au cas par cas à partir des éléments de revue actuels ; les packs SIG, CAIQ ou HECVAT standardisés ne constituent pas un droit de produit.
- Les journaux d'audit sont disponibles sur Growth, Business et Enterprise ; la conservation dépend du forfait souscrit.
- La facilitation d'audit client est soumise à une revue contractuelle Enterprise.

## Sécurité opérationnelle

- Vérifications des antécédents pour le personnel ayant accès à la production.
- Revues d'accès trimestrielles.
- L'accès à la production nécessite une authentification multi-facteurs et une approbation.
- Gestion des changements avec revue par les pairs et capacité de restauration.
- Séparation des tâches entre le développement et les opérations.

## Liens connexes

- [Centre de conformité](/fr/compliance)
- [Aperçu de l'architecture](/architecture)
- [Politique de confidentialité](/fr/privacy)
- [Accord de traitement des données](/fr/dpa)
- [Politique d'utilisation acceptable](/fr/acceptable-use)
- [Divulgation responsable](/fr/responsible-disclosure)
