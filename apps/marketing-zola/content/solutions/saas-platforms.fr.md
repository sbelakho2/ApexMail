+++
title = "Solution email pour plateformes SaaS"
description = "Infrastructure email multi-tenant pour le SaaS B2B et B2C. Isolation des tenants, isolation de domaine, RBAC, SSO et livraison en marque blanche."
template = "prose.html"
+++

## Plateformes SaaS

Offrez à vos clients une infrastructure email fiable et isolée, sans construire ni maintenir votre propre couche email. ApexMail donne à chacun de vos tenants ses propres domaines, clés API, points de terminaison webhook avec un secret HMAC par tenant, listes de suppression, IP dédiées et flux d'événements.

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

- **Isolation des tenants** — Chaque tenant dispose de ses propres domaines, clés API, points de terminaison webhook avec un secret HMAC par tenant, listes de suppression, IP dédiées et flux d'événements.
- **Isolation de domaine** — Vérification et authentification de domaine par tenant (SPF, DKIM, DMARC) pour éviter la contamination croisée des réputations.
- **RBAC personnalisé** — Administrateur au niveau plateforme, administrateur au niveau tenant et rôles en lecture seule. Provisioning SCIM sur Enterprise.
- **SSO** — SAML 2.0 pour les opérateurs de plateforme et les administrateurs de tenants.
- **Quotas d'usage** — Limites strictes et souples par tenant pour le volume, le débit et la concurrence.
- **Marque blanche** — Retirez la marque ApexMail des tableaux de bord, des pieds d'email et des modèles de notification.

## Implémentation technique

1. Créez un compte pour votre plateforme.
2. Provisionnez un tenant distinct pour chaque client.
3. Chaque tenant vérifie son ou ses domaines d'envoi indépendamment.
4. Attribuez des IP dédiées aux tenants nécessitant une isolation de réputation.
5. Configurez des points de terminaison webhook par tenant pour les événements de livraison.
6. Surveillez la santé de livraison de l'ensemble de la plateforme via l'analytique agrégée.

## Forfait requis

Tout arrangement de déploiement non standard requiert une revue d'architecture et de contrat distincte.

## Considérations de sécurité

- Par défaut, les opérateurs de plateforme ne peuvent pas lire le contenu des emails des tenants. L'accès au contenu requiert une autorisation explicite du tenant.
- Les clés API sont limitées à leur tenant uniquement. L'accès entre tenants est bloqué au niveau de la couche d'autorisation.
- Les points de terminaison webhook sont configurés par tenant. Les signatures HMAC reposent sur un secret propre à chaque tenant.
- Les journaux d'audit enregistrent toutes les créations, suppressions de tenants et modifications de permissions.

## Considérations de conformité

- Chaque tenant conserve des listes de suppression, une authentification de domaine et une rétention d'événements indépendantes.
- La couverture DPA des tenants requiert la DPA de la plateforme avec ApexMail. L'engagement contractuel dévolu aux tenants relève de la responsabilité de la plateforme.
- Les exigences de localisation des données s'appliquent au niveau de la plateforme et doivent être confirmées pour le déploiement actif et l'accord applicable.
- Les opérateurs de plateforme sont responsables de la conformité d'utilisation acceptable de leurs tenants.

## Limites connues

- L'isolement des tenants est logique sur les forfaits Cloud mutualisé. Un déploiement contractualisé séparément peut définir des exigences d'isolation supplémentaires, mais cela ne constitue pas un droit d'un forfait public.
- L'analytique inter-tenants impose à la plateforme d'agréger les données d'événements des tenants de son côté.
- La marque blanche est disponible sur le forfait Enterprise.

## Prochaine étape recommandée

[Contactez l'équipe commerciale](/fr/contact/sales/) pour une revue d'architecture multi-tenant et une tarification volume pour votre déploiement.
