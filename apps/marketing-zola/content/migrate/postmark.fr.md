+++
title = "Migrer de Postmark vers ApexMail"
description = "Migrez une intégration Postmark vers ApexMail par un changement d'URL de base : POST /email et POST /email/batch acceptent votre clé API ApexMail dans l'en-tête X-Postmark-Server-Token, avec la correspondance MessageStream, les refus nommés, la liste DNS et un plan de bascule 10/50/100."
template = "prose.html"

[extra]
last_updated = "2026-10-15"
og_image = "/images/og-image.png"
+++

ApexMail sert `POST /email` et `POST /email/batch` sur une surface de compatibilité Postmark. Les routes traduisent les charges utiles JSON en requête d'envoi canonique, puis appellent les mêmes gestionnaires que `POST /v1/messages` et `POST /v1/messages/batch` : vérification du domaine expéditeur, filtres de suppression et de consentement, droits du forfait, registre d'idempotence et insertion dans la file s'exécutent donc au même endroit. Votre intégration garde la forme de sa charge utile et son en-tête ; seuls l'hôte et le jeton changent.

## Correspondance des points d'accès

| Point d'accès Postmark | Surface de compatibilité ApexMail | Point d'accès natif ApexMail |
|---|---|---|
| `POST https://api.postmarkapp.com/email` | `POST https://api.apexmail.ee/email` | `POST https://api.apexmail.ee/v1/messages` |
| `POST https://api.postmarkapp.com/email/batch` | `POST https://api.apexmail.ee/email/batch`, jusqu'à 500 messages | `POST https://api.apexmail.ee/v1/messages/batch`, jusqu'à 100 messages par appel |
| `POST /email/bulk` (envoi de masse piloté par modèle) | Non servi | `POST /v1/messages/batch` avec des corps explicites, ou un identifiant de modèle par message |

Un envoi réussi répond `200` avec `{"ErrorCode": 0, "Message": "OK", "MessageID": "<identifiant canonique du message>"}`. La route batch répond un tableau ordonné avec un objet de résultat par message demandé : `ErrorCode` 0 avec le `MessageID`, ou un `ErrorCode` non nul portant le texte du refus pour cette position, de sorte qu'un lot partiel n'est jamais présenté comme un succès complet. L'identifiant est l'identifiant canonique, celui que `GET /v1/messages/{id}` renvoie et celui que les événements webhook portent dans `data.messageId`.

## Bascule de l'authentification

Votre emplacement d'identifiant reste le même. Postmark envoie `X-Postmark-Server-Token` ; remplacez la valeur par la clé API ApexMail (`am_live_…` ou `am_test_…`) et donnez-lui la portée `messages:send`.

| Élément | Postmark aujourd'hui | Surface de compatibilité ApexMail |
|---|---|---|
| En-tête d'identifiant | `X-Postmark-Server-Token: <server token>` | `X-Postmark-Server-Token: am_live_…` |
| Portée | Jeton au niveau du serveur | `messages:send` |
| Idempotence | Non proposée | `Idempotency-Key: <uuid>` sur la même route ; la même clé sous 24 heures rejoue la réponse d'origine, y compris le même `MessageID` |
| Classe d'objet | `MessageStream` sélectionne le flux | `MessageStream` `outbound` devient `transactional`, `broadcast` devient `marketing` ; l'en-tête `X-ApexMail-Category` fonctionne aussi et accepte `transactional`, `service` ou `marketing` |

## Correspondance des champs

Les noms canoniques sont ceux du contrat `POST /v1/messages` : la même compréhension de la charge utile s'applique lors d'un passage ultérieur à l'API native.

| Champ Postmark | Champ canonique | Remarques |
|---|---|---|
| `From` | `from` | Requis |
| `To` | `to` | Chaîne séparée par des virgules ou tableau ; les noms d'affichage entre guillemets gardent leurs virgules |
| `Cc` / `Bcc` | `cc` / `bcc` | |
| `Subject` | `subject` | |
| `HtmlBody` / `TextBody` | `html` / `text` | |
| `ReplyTo` | `reply_to` | |
| `Headers[].Name` / `.Value` | `headers` | `Reply-To` rejoint le champ dédié `reply_to` |
| `Attachments[].Name` / `.Content` / `.ContentType` | `attachments[]` (`filename`, `content`, `contentType`) | `ContentType` vaut `application/octet-stream` par défaut |
| `Tag` | `tags` (un tag) | |
| `Metadata` (valeurs de type chaîne) | `metadata` | Les valeurs non textuelles sont refusées nommément |
| `MessageStream` `outbound` / `broadcast` | `category` `transactional` / `marketing` | |
| `TrackOpens` / `TrackLinks` `true` | Sans effet, accepté | La plateforme suit les ouvertures et les clics à chaque envoi |
| En-tête `X-ApexMail-Category` | `category` | Validé par le normaliseur canonique |

L'envoi planifié ne fait pas partie de cette surface : la charge utile Postmark n'a pas de champ de planification, la route de compatibilité non plus. Utilisez `scheduled_at` (ISO 8601) sur le `POST /v1/messages` natif.

## Champs refusés nommément par la surface

Chacun de ces éléments est refusé dans la forme d'erreur propre à Postmark `{"ErrorCode": <code>, "Message": "…"}`. Les refus de validation répondent `422` ; un jeton absent ou invalide répond `401` avec `ErrorCode` 10.

| Élément Postmark | Refus |
|---|---|
| `TemplateId`, `TemplateAlias` | Un identifiant de modèle Postmark n'est pas un identifiant de modèle ApexMail ; rendez le corps côté client ou envoyez un `template_id` ApexMail via l'API native |
| `TemplateModel` | Le chemin d'envoi canonique n'a pas d'équivalent pour ce champ |
| `InlineImages`, `Attachments[].ContentID` | Le chemin d'envoi canonique n'a pas de notion de partie en ligne ; joignez le fichier au lieu de l'intégrer |
| `TrackOpens: false`, `TrackLinks: false` | La plateforme suit les ouvertures et les clics à chaque envoi ; le suivi par message ne peut pas être désactivé sur cette surface |
| Toute autre valeur `MessageStream` | Seuls `outbound` (transactionnel) et `broadcast` (marketing) correspondent à la catégorie canonique |
| Un tableau batch de plus de 500 messages | Un lot Postmark porte au plus 500 messages |
| Tout autre champ de premier niveau | Aucun équivalent canonique |
| Une valeur non textuelle dans `Metadata` | Les valeurs de Metadata doivent être des chaînes |
| Un `Headers[].Name` envoyé deux fois | L'en-tête en double est refusé plutôt que résolu en choisissant une valeur |

## Ce qui n'est pas encore relayé

La surface de compatibilité ne sert que les deux routes d'envoi. Les API Postmark ci-dessous n'ont pas de route de compatibilité ; utilisez l'API native ApexMail ou le tableau de bord.

- Modèles et mises en page (`/templates`, rendu `TemplateModel`).
- Administration des flux de messages et configuration par serveur.
- Recherche de messages sortants, statistiques et points d'accès de rebond ; les données de rebond arrivent via les événements `message.bounced`.
- Le point d'accès `/email/bulk` (envoi de masse piloté par modèle).
- Configuration des webhooks entrants. Le pipeline entrant d'ApexMail émet l'événement `inbound`, et l'e-mail entrant est disponible sur Business et Enterprise Cloud.
- Gestion des suppressions via l'API Postmark ; les suppressions vivent dans la liste de suppression ApexMail.

## DNS : ce qui change et ce qui reste

Votre domaine d'envoi reste le vôtre, et ApexMail signe DKIM avec un sélecteur généré par domaine sur ce même domaine. Ajoutez les quatre enregistrements de `GET /v1/domains/:id/dns-records` à côté des enregistrements Postmark ; ne retirez ceux de Postmark qu'après la bascule et la fenêtre de conservation.

| Enregistrement Postmark | Équivalent ApexMail |
|---|---|
| Enregistrement DKIM (la paire TXT ou CNAME émise par serveur) | Enregistrement TXT direct sous `<selector>._domainkey.<domain>` avec la clé publique DKIM. Un TXT direct, pas un CNAME |
| CNAME de chemin de retour (le domaine de rebond de l'éditeur) | Enregistrement MX sous `bounce.<domain>`, priorité 10, vers l'hôte de rétroaction de la région, plus un enregistrement TXT sous `bounce.<domain>` avec la valeur SPF de la MAIL FROM personnalisée |
| CNAME de suivi de liens de marque (quand le suivi utilise votre domaine) | Aucun CNAME de liens de marque requis. ApexMail réécrit les liens vers ses propres chemins de suivi ; un domaine de suivi personnalisé (CNAME sur un sous-domaine d'un domaine vérifié) est disponible à partir de Pro |
| Authentification de domaine | Enregistrement TXT sous `_dmarc.<domain>` avec votre politique DMARC |

Liste de contrôle :

1. Ajoutez le domaine d'envoi dans le tableau de bord et récupérez ses enregistrements DNS.
2. Publiez les quatre enregistrements ApexMail ; laissez ceux de Postmark en place.
3. Conservez les enregistrements Postmark tant que Postmark envoie. Le domaine MAIL FROM de Postmark est propre à l'éditeur, ses enregistrements sont donc indépendants de ceux d'ApexMail sur `bounce.<domain>`.
4. Lancez la vérification du domaine et confirmez que le sélecteur DKIM se résout.
5. Gardez la remontée DMARC (rua) active pendant la transition.
6. Après la bascule et la fenêtre de conservation, retirez les enregistrements Postmark et révoquez l'ancien jeton de serveur.

## Modèles

Les modèles, mises en page et alias Postmark ne sont pas relayés, et `TemplateId`, `TemplateAlias` et `TemplateModel` sont refusés nommément. Deux voies de conversion :

- Rendez le corps dans votre application et envoyez `HtmlBody` et `TextBody` via la même route de compatibilité. Aucun travail de migration de modèles, et l'envoi garde la forme de sa charge utile.
- Créez un modèle via `POST /v1/templates` et envoyez-le avec `template_id` plus `template_data` sur le `POST /v1/messages` natif. Les espaces réservés s'écrivent `{{variable}}` ; un espace réservé non résolu est rendu tel quel plutôt que vidé, ce qui rend une variable manquante visible dans l'aperçu.

Les mises en page Postmark (une enveloppe commune autour des modèles de message) correspondent au corps du modèle lui-même : intégrez le HTML de la mise en page dans chaque modèle ApexMail, ou continuez à rendre dans votre application. Les conditions et boucles Mustachio n'ont pas d'équivalent direct dans le moteur d'espaces réservés ; convertissez ces modèles en HTML rendu dans votre application ou découpez-les en modèles par cas.

## Webhooks

Les webhooks Postmark envoient du JSON par flux de messages à votre point de terminaison. Pointez le point de terminaison vers ApexMail, abonnez les événements que vous consommez et vérifiez la signature ApexMail : `X-ApexMail-Signature: sha256=<hex>` sur le corps brut de la requête avec `X-ApexMail-Timestamp`. La livraison est au moins unique, donc dédupliquez sur le champ `id` de l'événement.

| Webhook Postmark | Événement ApexMail | Remarques |
|---|---|---|
| `Delivery` | `message.delivered` | Le serveur destinataire a accepté le message |
| `Bounce` avec `Type: HardBounce` | `message.bounced` | Rejet définitif |
| `Bounce` avec `Type: Transient` | `message.deferred` | Report 4xx ; une nouvelle tentative est planifiée |
| `SpamComplaint` | `message.complained` | |
| `Open` | `message.opened` | |
| `Click` | `message.clicked` | |
| `SubscriptionChange` | `recipient.unsubscribed` | ApexMail émet le sens désabonnement ; les réabonnements sont consignés sur la fiche de préférences |
| `Inbound` | `inbound` | L'e-mail entrant est disponible sur Business et Enterprise Cloud |
| `SMTPAPIError` | Aucun événement équivalent | Les refus à l'acceptation reviennent dans la réponse de l'API |

La forme de la charge utile change selon l'éditeur : les événements ApexMail utilisent l'enveloppe `{id, event, timestamp, data}`, avec `data.messageId` sur les événements de message et `data.email` sur les événements de suppression.

## Plan de bascule

La bascule est un changement d'hôte par route ou par environnement ; un retour arrière est le même changement en sens inverse. Aucune charge utile ni modèle n'est à défaire.

| Étape | Action | Critères de sortie | Retour arrière |
|---|---|---|---|
| 1. Préparer | Créer le compte, ajouter et vérifier le domaine d'envoi, créer une clé API avec `messages:send`, abonner les événements webhook | La vérification passe ; un message de test part d'un environnement de préproduction | Aucun trafic de production |
| 2. Valider en parallèle | Envoyer les mêmes charges utiles vers `https://api.apexmail.ee/email` avec la clé ApexMail dans `X-Postmark-Server-Token` ; comparer réponses, valeurs `MessageID` et événements webhook | `ErrorCode` 0 à chaque test ; les événements arrivent avec des signatures valides | Rebasculer la route de test vers Postmark |
| 3. Basculer 10 % | Router 10 % des envois de production via la route de compatibilité ; surveiller les taux de rejet et de plainte face aux seuils AUP (2 % de rejets, 0,1 % de plaintes) | Les métriques de livraison correspondent à Postmark dans la tolérance convenue pendant la fenêtre d'observation | Rebasculer la route ; Postmark garde les 90 % restants |
| 4. Basculer 50 % | Monter à 50 % une fois la fenêtre terminée proprement ; les deux fournisseurs envoient depuis le même domaine | Parité maintenue à cette part plus élevée | Revenir à 100 % Postmark |
| 5. Basculer à 100 % | Router tous les envois via `POST /email` (et `/email/batch`) sur ApexMail | Volume complet sur ApexMail avec des métriques propres | Rebasculer ; les jetons restent actifs pendant la fenêtre de conservation |
| 6. Retirer l'ancien chemin | Retirer les enregistrements DNS Postmark, révoquer le jeton de serveur, retirer la configuration de modèles et de flux | Les enregistrements ne résolvent plus que vers ApexMail | Restaurer les enregistrements depuis votre journal de changement |

## Étapes suivantes

- Comparez les deux plateformes fonction par fonction sur la [comparaison ApexMail vs Postmark](/fr/compare/postmark/).
- Lisez la [vue d'ensemble de l'API](/docs/api/) et la [spécification OpenAPI](/docs/api/openapi/) pour le contrat natif, envois par lots et modèles compris.
- Lisez [Webhooks](/docs/webhooks/) pour les schémas de charge utile et la vérification des signatures.
- [Contactez le service commercial](/fr/contact/sales/) pour une évaluation de migration si les modèles Postmark ou les webhooks entrants font partie de votre trafic de production.
