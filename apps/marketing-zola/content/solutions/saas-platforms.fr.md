+++
title = "Solution email pour plateformes SaaS"
description = "Infrastructure email multi-tenant pour le SaaS B2B et B2C. Sous-comptes, isolation de domaine, RBAC, SSO et livraison en marque blanche."
template = "prose.html"
+++

## Plateformes SaaS

Offrez à vos clients une infrastructure email fiable et isolée, sans construire ni maintenir votre propre couche email. Le modèle de sous-comptes d'ApexMail donne à chacun de vos tenants des domaines, clés API, listes de suppression et flux d'événements indépendants.

## Audience

Les plateformes SaaS qui envoient des emails pour le compte de leurs clients : CRM envoyant des campagnes, plateformes e-commerce envoyant des reçus, outils d'analytics envoyant des rapports, plateformes de sécurité envoyant des alertes.

## Contexte métier

Les plateformes qui envoient des emails pour leurs clients héritent du risque de réputation de chacun d'eux. Une seule plainte pour spam sur une IP partagée peut dégrader la livraison pour tous les tenants. Sans isolation, les plateformes ne peuvent ni attribuer les problèmes de livraison à des clients précis, ni offrir de contrôles de conformité par tenant.

## Problème central

- Risque de réputation d'IP partagée entre tous les tenants de la plateforme.
- Impossibilité d'isoler la facturation, les quotas d'usage et l'analytique de livraison par client.
- Exigences de conformité variables selon les clients (l'un a besoin de HIPAA, l'autre uniquement du RGPD).
- Les clients exigent des métriques de délivrabilité visibles et l'état d'authentification au niveau du domaine.

## La solution ApexMail

- **Sous-comptes** — Chaque tenant dispose d'un sous-compte indépendant avec ses propres clés API, domaines, webhooks, listes de suppression, IP dédiées et flux d'événements.
- **Isolation de domaine** — Vérification et authentification de domaine par sous-compte (SPF, DKIM, DMARC) pour éviter la contamination croisée des réputations.
- **RBAC personnalisé** — Administrateur au niveau plateforme, administrateur au niveau tenant et rôles en lecture seule. Provisioning SCIM sur Enterprise.
- **SSO** — SAML 2.0 pour les opérateurs de plateforme et les administrateurs de tenants.
- **Quotas d'usage** — Limites strictes et souples par sous-compte pour le volume, le débit et la concurrence.
- **Marque blanche** — Retirez la marque ApexMail des tableaux de bord, des pieds d'email et des modèles de notification.

## Implémentation technique

1. Créez un compte maître pour votre plateforme.
2. Provisionnez des sous-comptes via l'API ou le tableau de bord pour chaque tenant client.
3. Chaque tenant vérifie son ou ses domaines d'envoi indépendamment.
4. Attribuez des IP dédiées aux tenants nécessitant une isolation de réputation.
5. Configurez des points de terminaison webhook par tenant pour les événements de livraison.
6. Surveillez la santé de livraison de l'ensemble de la plateforme via l'analytique agrégée.

## Points de terminaison API pertinents

| Point de terminaison | Description |
|---|---|
| `POST /v1/subaccounts` | Créer un sous-compte |
| `GET /v1/subaccounts` | Lister les sous-comptes |
| `GET /v1/subaccounts/:id` | Récupérer les détails d'un sous-compte |
| `PATCH /v1/subaccounts/:id` | Mettre à jour les paramètres d'un sous-compte |
| `DELETE /v1/subaccounts/:id` | Désactiver un sous-compte |
| `POST /v1/subaccounts/:id/api-keys` | Créer une clé API de sous-compte |

## Forfait requis

Les sous-comptes sont disponibles sur Scale (jusqu'à 10) et Enterprise (jusqu'à 100). Tout arrangement de déploiement non standard requiert une revue d'architecture et de contrat distincte.

## Considérations de sécurité

- Par défaut, les opérateurs de plateforme ne peuvent pas lire le contenu des emails des tenants. L'accès au contenu requiert une autorisation explicite du tenant.
- Les clés API de sous-compte sont limitées à leur sous-compte uniquement. L'accès entre tenants est bloqué au niveau de la couche d'autorisation.
- Les points de terminaison webhook sont configurés par sous-compte. Les signatures HMAC reposent sur un secret propre à chaque sous-compte.
- Les journaux d'audit enregistrent toutes les créations, suppressions de sous-comptes et modifications de permissions.

## Considérations de conformité

- Chaque sous-compte conserve des listes de suppression, une authentification de domaine et une rétention d'événements indépendantes.
- La couverture DPA des sous-comptes requiert la DPA de la plateforme avec ApexMail. L'engagement contractuel dévolu aux tenants relève de la responsabilité de la plateforme.
- Les exigences de localisation des données s'appliquent au niveau de la plateforme et doivent être confirmées pour le déploiement actif et l'accord applicable.
- Les opérateurs de plateforme sont responsables de la conformité d'utilisation acceptable de leurs tenants.

## Limites connues

- L'isolement des sous-comptes est logique sur les forfaits Cloud mutualisé. Un déploiement contractualisé séparément peut définir des exigences d'isolation supplémentaires, mais cela ne constitue pas un droit d'un forfait public.
- L'analytique inter-sous-comptes impose à la plateforme d'agréger les données d'événements des sous-comptes de son côté.
- La marque blanche est disponible sur le forfait Enterprise.

## Prochaine étape recommandée

[Contactez l'équipe commerciale](/fr/contact/sales/) pour une revue d'architecture de sous-comptes et une tarification volume pour un déploiement multi-tenant.
