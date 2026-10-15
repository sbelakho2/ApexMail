+++
title = "Migrer de Resend vers ApexMail"
description = "Migrez une intégration Resend vers ApexMail par un changement d'URL de base : POST /emails et POST /emails/batch acceptent votre clé API ApexMail dans l'emplacement bearer Authorization que vous envoyez déjà, avec la correspondance exacte des champs, les refus nommés, la liste DNS et un plan de bascule 10/50/100."
template = "prose.html"

[extra]
last_updated = "2026-10-15"
og_image = "/images/og-image.png"
+++

ApexMail sert `POST /emails` et `POST /emails/batch` sur une surface de compatibilité Resend. Les routes traduisent les charges utiles JSON en requête d'envoi canonique, puis appellent les mêmes gestionnaires que `POST /v1/messages` et `POST /v1/messages/batch` : vérification du domaine expéditeur, filtres de suppression et de consentement, droits du forfait, registre d'idempotence durable et insertion dans la file s'exécutent donc au même endroit. Votre intégration garde la forme de sa charge utile et son en-tête bearer ; seuls l'hôte et la clé changent.

## Correspondance des points d'accès

| Point d'accès Resend | Surface de compatibilité ApexMail | Point d'accès natif ApexMail |
|---|---|---|
| `POST https://api.resend.com/emails` | `POST https://api.apexmail.ee/emails` | `POST https://api.apexmail.ee/v1/messages` |
| `POST https://api.resend.com/emails/batch` | `POST https://api.apexmail.ee/emails/batch`, jusqu'à 100 e-mails | `POST https://api.apexmail.ee/v1/messages/batch`, jusqu'à 100 messages par appel |
| `GET /emails/:id` (consultation) | Non servi | `GET /v1/messages/{id}` |

Un envoi réussi répond `200` avec `{"id": "<identifiant canonique du message>"}`. La route batch répond `{"data": […]}` dans l'ordre de la requête : chaque position porte soit `{"id": …}` soit un objet `error` avec le refus, de sorte qu'un lot partiel n'est jamais présenté comme un succès complet. L'identifiant est l'identifiant canonique, celui que `GET /v1/messages/{id}` renvoie et celui que les événements webhook portent dans `data.messageId`.

## Bascule de l'authentification

Votre emplacement d'identifiant reste le même. Resend envoie `Authorization: Bearer` ; remplacez la clé par la clé API ApexMail (`am_live_…` ou `am_test_…`) et donnez-lui la portée `messages:send`.

| Élément | Resend aujourd'hui | Surface de compatibilité ApexMail |
|---|---|---|
| En-tête d'identifiant | `Authorization: Bearer re_…` | `Authorization: Bearer am_live_…` |
| Portée | Accès complet ou clé d'envoi seule | `messages:send` |
| Idempotence | En-tête `Idempotency-Key` | Le même en-tête, contre le registre durable d'ApexMail ; la même clé sous 24 heures rejoue la réponse d'origine, y compris le même identifiant |
| Classe d'objet | Notion absente chez l'éditeur | `X-ApexMail-Category: transactional` (ou `service`) exempte l'envoi du filtre de préférences marketing ; sans cet en-tête, l'envoi compte comme classe `marketing` par défaut et le filtre de consentement s'applique |

## Correspondance des champs

Les noms canoniques sont ceux du contrat `POST /v1/messages` : la même compréhension de la charge utile s'applique lors d'un passage ultérieur à l'API native.

| Champ Resend | Champ canonique | Remarques |
|---|---|---|
| `from` | `from` | Requis |
| `to` | `to` | Une chaîne unique, un tableau, ou des objets `{email, name}` |
| `cc` / `bcc` | `cc` / `bcc` | |
| `subject` | `subject` | |
| `html` / `text` | `html` / `text` | |
| `reply_to` | `reply_to` | |
| `headers` (objet) | `headers` | Valeurs de type chaîne |
| `attachments[].filename` / `.content` / `.content_type` | `attachments[]` (`filename`, `content`, `contentType`) | `content_type` vaut `application/octet-stream` par défaut |
| `tags[].name` / `.value` | `tags` | Chaque paire devient `"name:value"` |
| `scheduled_at` (ISO 8601) | `scheduled_at` | Horodatages RFC 3339 uniquement |
| En-tête `X-ApexMail-Category` | `category` | Validé par le normaliseur canonique |

## Champs refusés nommément par la surface

Chacun de ces éléments est refusé dans la forme d'erreur propre à Resend `{"statusCode": <code>, "name": "<name>", "message": "…"}` : `statusCode` 422 avec `name` `validation_error` pour les refus de validation, `401` `invalid_api_key` ou `missing_api_key` pour les refus d'identifiant, et `403` `restricted_api_key` pour une clé sans la portée `messages:send`.

| Élément Resend | Refus |
|---|---|
| `attachments[].path` | Les URL de pièces jointes distantes ne sont pas récupérées ; envoyez le fichier en `content` base64 |
| `template` | Les modèles n'ont aucun équivalent canonique sur cette surface ; utilisez l'API native ApexMail pour les modèles |
| `topic_id`, `audience_id`, `broadcast_id` | Audiences, topics et broadcasts n'ont aucun équivalent canonique sur cette surface ; utilisez l'API native pour les listes |
| Un `scheduled_at` en langage naturel (`"in 1 min"`) | Un horodatage ISO 8601 (RFC 3339) est requis ; les planifications en langage naturel ne sont pas prises en charge |
| Un tableau batch de plus de 100 e-mails | Un lot Resend porte au plus 100 e-mails |
| Tout autre champ de premier niveau | Aucun équivalent canonique |

## Ce qui n'est pas encore relayé

La surface de compatibilité ne sert que les deux routes d'envoi. Les API Resend ci-dessous n'ont pas de route de compatibilité ; utilisez l'API native ApexMail ou le tableau de bord.

- Modèles (`template`) et le chemin de rendu de modèle.
- Audiences, contacts, topics et broadcasts ; les campagnes, listes et segments ApexMail couvrent ces besoins via l'API native.
- Gestion des domaines (`/domains`) : les domaines s'ajoutent et se vérifient dans le tableau de bord ApexMail ou via `POST /v1/domains`.
- Gestion des clés API, CRUD des abonnements webhook et journal des événements ; les abonnements webhook passent par `POST /v1/webhooks`.
- Pièces jointes récupérées depuis une URL distante, et planification en langage naturel.
- Réception entrante (`email.received`). Le pipeline entrant d'ApexMail émet l'événement `inbound`, et l'e-mail entrant est disponible sur Business et Enterprise Cloud.

## DNS : ce qui change et ce qui reste

Votre domaine d'envoi reste le vôtre, et ApexMail signe DKIM avec un sélecteur généré par domaine sur ce même domaine. Ajoutez les quatre enregistrements de `GET /v1/domains/:id/dns-records` à côté des enregistrements Resend ; ne retirez ceux de Resend qu'après la bascule et la fenêtre de conservation.

| Enregistrement Resend | Équivalent ApexMail |
|---|---|
| Enregistrement DKIM (l'enregistrement TXT de l'éditeur pour le domaine) | Enregistrement TXT direct sous `<selector>._domainkey.<domain>` avec la clé publique DKIM. Un TXT direct, pas un CNAME |
| Enregistrements de chemin de retour (les enregistrements MX et TXT SPF de l'éditeur sur son propre sous-domaine) | Enregistrement MX sous `bounce.<domain>`, priorité 10, vers l'hôte de rétroaction de la région, plus un enregistrement TXT sous `bounce.<domain>` avec la valeur SPF de la MAIL FROM personnalisée |
| CNAME de suivi des clics (quand le suivi utilise votre domaine) | Aucun CNAME de liens de marque requis. ApexMail réécrit les liens vers ses propres chemins de suivi ; un domaine de suivi personnalisé (CNAME sur un sous-domaine d'un domaine vérifié) est disponible à partir de Pro |
| Authentification de domaine | Enregistrement TXT sous `_dmarc.<domain>` avec votre politique DMARC |

Liste de contrôle :

1. Ajoutez le domaine d'envoi dans le tableau de bord et récupérez ses enregistrements DNS.
2. Publiez les quatre enregistrements ApexMail ; laissez ceux de Resend en place.
3. Conservez les enregistrements Resend tant que Resend envoie ; les enregistrements de son sous-domaine de chemin de retour sont indépendants de ceux d'ApexMail sur `bounce.<domain>`.
4. Lancez la vérification du domaine et confirmez que le sélecteur DKIM se résout.
5. Gardez la remontée DMARC (rua) active pendant la transition.
6. Après la bascule et la fenêtre de conservation, retirez les enregistrements Resend et révoquez l'ancienne clé.

## Modèles

Les modèles Resend ne sont pas relayés, et `template` est refusé nommément. Deux voies de conversion :

- Rendez le corps dans votre application et envoyez `html` et `text` via la même route de compatibilité. Aucun travail de migration de modèles, et l'envoi garde la forme de sa charge utile.
- Créez un modèle via `POST /v1/templates` et envoyez-le avec `template_id` plus `template_data` sur le `POST /v1/messages` natif. Les espaces réservés s'écrivent `{{variable}}` ; un espace réservé non résolu est rendu tel quel plutôt que vidé, ce qui rend une variable manquante visible dans l'aperçu.

La forme à triples accolades `{{{variable}}}` de Resend et ses composants React Email se rendent dans votre application ou à l'étape de build ; le moteur d'espaces réservés accepte la substitution `{{variable}}`, donc convertissez ces corps en HTML avant de créer le modèle ApexMail.

## Webhooks

Pointez votre point de terminaison vers ApexMail, abonnez les événements que vous consommez et vérifiez la signature ApexMail : `X-ApexMail-Signature: sha256=<hex>` sur le corps brut de la requête avec `X-ApexMail-Timestamp`. La livraison est au moins unique, donc dédupliquez sur le champ `id` de l'événement.

| Événement Resend | Événement ApexMail | Remarques |
|---|---|---|
| `email.sent` | `message.accepted` | Accepté pour livraison |
| `email.scheduled` | `message.accepted` | L'envoi planifié est accepté à la mise en file |
| `email.delivered` | `message.delivered` | Le serveur destinataire a accepté le message |
| `email.delivery_delayed` | `message.deferred` | Report 4xx ; une nouvelle tentative est planifiée |
| `email.bounced` | `message.bounced` | Rejet définitif |
| `email.complained` | `message.complained` | |
| `email.opened` | `message.opened` | |
| `email.clicked` | `message.clicked` | |
| `email.failed` (correspondance la plus proche) | `message.bounced` | Les refus à l'acceptation reviennent dans la réponse de l'API |
| `email.received` | `inbound` | L'e-mail entrant est disponible sur Business et Enterprise Cloud |

La forme de la charge utile change selon l'éditeur : les événements ApexMail utilisent l'enveloppe `{id, event, timestamp, data}`, avec `data.messageId` sur les événements de message et `data.email` sur les événements de suppression.

## Plan de bascule

La bascule est un changement d'hôte par route ou par environnement ; un retour arrière est le même changement en sens inverse. Aucune charge utile ni modèle n'est à défaire.

| Étape | Action | Critères de sortie | Retour arrière |
|---|---|---|---|
| 1. Préparer | Créer le compte, ajouter et vérifier le domaine d'envoi, créer une clé API avec `messages:send`, abonner les événements webhook | La vérification passe ; un message de test part d'un environnement de préproduction | Aucun trafic de production |
| 2. Valider en parallèle | Envoyer les mêmes charges utiles vers `https://api.apexmail.ee/emails` avec la clé ApexMail dans l'emplacement bearer ; comparer réponses, identifiants et événements webhook | `200` avec un identifiant à chaque test ; les événements arrivent avec des signatures valides | Rebasculer la route de test vers Resend |
| 3. Basculer 10 % | Router 10 % des envois de production via la route de compatibilité ; surveiller les taux de rejet et de plainte face aux seuils AUP (2 % de rejets, 0,1 % de plaintes) | Les métriques de livraison correspondent à Resend dans la tolérance convenue pendant la fenêtre d'observation | Rebasculer la route ; Resend garde les 90 % restants |
| 4. Basculer 50 % | Monter à 50 % une fois la fenêtre terminée proprement ; les deux fournisseurs envoient depuis le même domaine | Parité maintenue à cette part plus élevée | Revenir à 100 % Resend |
| 5. Basculer à 100 % | Router tous les envois via `POST /emails` (et `/emails/batch`) sur ApexMail | Volume complet sur ApexMail avec des métriques propres | Rebasculer ; les clés restent actives pendant la fenêtre de conservation |
| 6. Retirer l'ancien chemin | Retirer les enregistrements DNS Resend, révoquer sa clé, retirer la configuration de modèles et d'audiences | Les enregistrements ne résolvent plus que vers ApexMail | Restaurer les enregistrements depuis votre journal de changement |

## Étapes suivantes

- Comparez les deux plateformes fonction par fonction sur la [comparaison ApexMail vs Resend](/fr/compare/resend/).
- Lisez la [vue d'ensemble de l'API](/docs/api/) et la [spécification OpenAPI](/docs/api/openapi/) pour le contrat natif, envois par lots et modèles compris.
- Lisez [Webhooks](/docs/webhooks/) pour les schémas de charge utile et la vérification des signatures.
- [Contactez le service commercial](/fr/contact/sales/) pour une évaluation de migration si les modèles, audiences ou broadcasts Resend font partie de votre trafic de production.
