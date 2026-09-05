+++
title = "Solution email transactionnel"
description = "Email transactionnel piloté par l'application : réinitialisations de mot de passe, reçus, notifications. API REST et relais SMTP avec webhooks signés et options de déploiement orientées UE/EEE."
template = "prose.html"
+++

## Email transactionnel

Envoyez les emails générés par vos applications via l'API REST ou le relais SMTP d'ApexMail. Chaque message est suivi de l'acceptation à la livraison, avec un historique d'événements par message.

## Audience

Équipes d'ingénierie construisant des applications qui envoient des emails automatisés : réinitialisations de mot de passe, vérification de compte, reçus d'achat, notifications d'expédition, alertes de sécurité et mises à jour de statut système.

## Contexte métier

L'email transactionnel est une infrastructure critique. Des réinitialisations de mot de passe retardées bloquent les utilisateurs. Des reçus manquants génèrent des tickets de support. Des notifications perdues abîment la confiance. La couche email doit être rapide, observable et fiable, sans détourner l'ingénierie du travail produit.

## Problème central

- La délivrabilité varie selon le fournisseur destinataire, la réputation du domaine et la qualité de l'authentification.
- Les bibliothèques SMTP intégrées ajoutent une charge de maintenance et masquent les échecs de livraison.
- Sans événements webhook par message, les équipes ne peuvent pas détecter les échecs de livraison silencieux.
- L'accumulation dans les files pendant les pannes fournisseurs requiert une logique de retry et une gestion des timeouts.

## La solution ApexMail

- **API REST** (`POST /v1/messages`) — Payloads JSON avec clés d'idempotence. Soumettez et n'y pensez plus.
- **Relais SMTP** (`smtp.apexmail.ee:587` avec STARTTLS) — Remplacement direct pour vos clients SMTP existants.
- **Configuration d'envoi isolée** — IP dédiées, domaines personnalisés et listes de suppression peuvent être délimités par type d'email.
- **Webhooks signés** — Événements `delivered`, `bounced`, `complained`, `opened`, `clicked` en temps réel, chacun avec un ID d'événement unique et une signature HMAC.
- **Idempotence** — Dédupliquez les soumissions grâce aux clés fournies par le client. Renvoyez sans risque après une erreur réseau.

## Implémentation technique

1. Créez une clé API dans **Dashboard → Settings → API Keys**.
2. Vérifiez votre domaine d'envoi (SPF, DKIM, return-path personnalisé).
3. Configurez un domaine d'envoi dédié (et, sur les forfaits éligibles, une IP dédiée) pour votre type d'email.
4. Envoyez via REST ou SMTP.
5. Enregistrez un point de terminaison webhook pour recevoir les événements de livraison.
6. Surveillez les métriques de livraison dans le tableau de bord ou via l'API d'analytique.

## Points de terminaison API pertinents

| Point de terminaison | Description |
|---|---|
| `POST /v1/messages` | Envoyer un email |
| `GET /v1/messages/:id` | Récupérer le statut et les événements d'un email |
| `POST /v1/messages/:id/cancel` | Annuler un envoi programmé |
| `POST /v1/messages/batch` | Envoyer jusqu'à 100 messages en une requête |

## Événements webhook pertinents

| Événement | Déclencheur |
|---|---|
| `message.sent` | Message accepté pour livraison |
| `message.delivered` | Le serveur du destinataire a accepté le message |
| `message.bounced` | Rebond dur ou rebond souple |
| `message.complained` | Le destinataire a signalé l'email comme spam |
| `message.opened` | Ouverture détectée (pixel de suivi) |
| `message.clicked` | Clic sur un lien détecté |

## Forfait requis

| Forfait | Volume mensuel | Support |
|---|---|---|
| Free | 30 000 emails | Communauté |
| Starter | 50 000 emails | Support par email |
| Pro | 150 000 emails | Support par email |
| Growth | 500 000 emails | Support par email |
| Scale | 2 000 000 emails | Support prioritaire |
| Enterprise | 5 000 000 emails | Support dédié |

## Considérations de sécurité

- Les clés API sont cloisonnées par environnement (live/test). Les clés de test routent vers des boîtes de test.
- Les webhooks sont signés en HMAC. Validez les signatures avant de traiter les événements.
- TLS 1.2+ requis pour toutes les connexions API et SMTP.
- Contenu des messages chiffré au repos. Rétention du contenu configurable par forfait.

## Considérations de conformité

- Options de déploiement orientées UE/EEE ; confirmez les lieux de données actifs et les garanties de transfert pour le déploiement.
- La DPA est disponible dans le cadre de l'accord ApexMail applicable.
- La disponibilité HIPAA et les BAA ne sont pas proposées actuellement.
- Le client est responsable du consentement des destinataires et de la gestion des désinscriptions.

## Limites connues

- L'historique des événements est conservé 30 jours par défaut (7 jours sur le forfait Free) ; contenu des messages 7 jours par défaut, selon le forfait jusqu'à 730 jours.
- Taille des pièces jointes limitée à 25 MB par message.
- Le suivi des ouvertures et des clics requiert un corps HTML avec pixel de suivi/liens.

## Prochaine étape recommandée

[Créez un compte gratuit](https://app.apexmail.ee/signup) et envoyez votre premier email via l'API REST ou le relais SMTP.
