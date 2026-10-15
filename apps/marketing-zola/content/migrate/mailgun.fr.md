+++
title = "Migrer de Mailgun vers ApexMail"
description = "Migrez une intégration Mailgun vers ApexMail par un changement d'URL de base : POST /v3/{domain}/messages accepte votre clé API ApexMail dans l'emplacement Basic auth de Mailgun, avec la correspondance exacte des champs, les refus nommés, la réponse messages.mime, la liste DNS et un plan de bascule 10/50/100."
template = "prose.html"

[extra]
last_updated = "2026-10-15"
og_image = "/images/og-image.png"
+++

ApexMail sert `POST /v3/{domain}/messages` sur une surface de compatibilité Mailgun. La route traduit les champs de formulaire en requête d'envoi canonique, puis appelle le même gestionnaire que `POST /v1/messages` : vérification du domaine expéditeur, filtres de suppression et de consentement, droits du forfait, registre d'idempotence et insertion dans la file s'exécutent donc au même endroit. Votre intégration garde ses champs de formulaire et sa forme de point d'accès ; seuls l'hôte et la clé changent.

## Correspondance des points d'accès

| Point d'accès Mailgun | Surface de compatibilité ApexMail | Point d'accès natif ApexMail |
|---|---|---|
| `POST https://api.mailgun.net/v3/{domain}/messages` (UE : `api.eu.mailgun.net`) | `POST https://api.apexmail.ee/v3/{domain}/messages` | `POST https://api.apexmail.ee/v1/messages` |
| `POST /v3/{domain}/messages.mime` (MIME brut) | Câblé et répondu `501` après authentification, avec la raison | `POST /v1/messages` avec des champs structurés, ou un relais MTA via SMTP |
| Aucun point d'accès batch sur cette surface | Une requête par message | `POST /v1/messages/batch`, jusqu'à 100 messages par appel |

Le segment de chemin `{domain}` est le domaine d'envoi Mailgun et doit être identique au domaine de l'adresse `from`. Le chemin d'envoi canonique dérive l'identité DKIM du domaine expéditeur : une divergence est donc refusée nommément plutôt que signée avec une autre autorité.

Un envoi réussi répond `200` avec `{"id": "<identifiant canonique du message>@{domain}", "message": "Queued. Thank you."}`. L'identifiant entre crochets est l'identifiant canonique du message, celui que `GET /v1/messages/{id}` renvoie et celui que les événements webhook portent dans `data.messageId`.

`messages.mime` répond un `501` nommé : `POST /v3/{domain}/messages.mime is not implemented by the ApexMail compatibility surface: raw MIME passthrough would require a second MIME parser in the request path. Use /v3/{domain}/messages with structured fields (from/to/subject/html/text/attachment), or the canonical POST /v1/messages API.`

## Bascule de l'authentification

Votre emplacement d'identifiant reste le même. Mailgun envoie `Authorization: Basic base64("api:<key>")` ; remplacez la clé par la clé API ApexMail (`am_live_…` ou `am_test_…`) et donnez-lui la portée `messages:send`. Le nom d'utilisateur ne porte aucune autorité et est accepté tel qu'envoyé.

| Élément | Mailgun aujourd'hui | Surface de compatibilité ApexMail |
|---|---|---|
| En-tête d'identifiant | `Authorization: Basic base64("api:<key>")` | `Authorization: Basic base64("api:am_live_…")` |
| Type de corps | `application/x-www-form-urlencoded` ou `multipart/form-data` | Les deux mêmes types de corps |
| Portée | Permissions de la clé, éventuellement par domaine | `messages:send` |
| Idempotence | Non proposée | `Idempotency-Key: <uuid>` sur la même route ; la même clé sous 24 heures rejoue la réponse d'origine, y compris le même identifiant de message |
| Classe d'objet | Notion absente chez l'éditeur | `X-ApexMail-Category: transactional` (ou `service`) exempte l'envoi du filtre de préférences marketing ; sans cet en-tête, l'envoi compte comme classe `marketing` par défaut et le filtre de consentement s'applique |

## Correspondance des champs

Les noms canoniques sont ceux du contrat `POST /v1/messages` : la même compréhension de la charge utile s'applique lors d'un passage ultérieur à l'API native.

| Champ Mailgun | Champ canonique | Remarques |
|---|---|---|
| `from` | `from` | Requis ; son domaine doit correspondre au segment de chemin `{domain}` |
| `to` | `to` | Répétable ou séparé par des virgules ; les noms d'affichage entre guillemets gardent leurs virgules |
| `cc` / `bcc` | `cc` / `bcc` | |
| `subject` | `subject` | |
| `html` / `text` | `html` / `text` | |
| `attachment` (partie fichier multipart) | `attachments[]` | Contenu en base64, nom de fichier et Content-Type de la partie ; ce dernier vaut `application/octet-stream` par défaut |
| `o:tag` | `tags` | Doublons supprimés |
| `o:deliverytime` | `scheduled_at` | Horodatage RFC 2822, par exemple `Fri, 15 Oct 2026 12:00:00 -0000` |
| `h:X-Foo` | `headers` | N'importe quel nom d'en-tête ; `h:Reply-To` rejoint le champ dédié `reply_to` |
| `v:my-var` | `metadata` | |
| En-tête `X-ApexMail-Category` | `category` | Validé par le normaliseur canonique |
| `o:tracking=yes`, `o:tracking-clicks=yes`, `o:tracking-opens=yes`, `o:dkim=yes` | Sans effet, accepté | Ces valeurs correspondent aux défauts de la plateforme |
| `o:testmode=no` | Sans effet, accepté | Le mode test est désactivé, ce qui correspond au comportement de la plateforme |

## Champs refusés nommément par la surface

Chacun de ces éléments est refusé dans la forme d'erreur propre à Mailgun `{"message": "…"}` avec le statut `400`, jamais ignoré silencieusement. Plusieurs problèmes dans une même requête sont réunis dans le message unique.

| Élément Mailgun | Refus |
|---|---|
| Partie fichier `inline` | Le chemin d'envoi canonique n'a pas de notion de partie en ligne ; joignez le fichier au lieu de l'intégrer |
| `attachment` envoyé comme valeur de formulaire | Les pièces jointes doivent être envoyées comme parties de fichier multipart (`-F attachment=@file`), pas comme valeurs de formulaire |
| `template` (modèles stockés) | Champ sans équivalent canonique |
| `o:campaign` | Champ sans équivalent canonique |
| `o:require-tls` | Champ sans équivalent canonique |
| `o:skip-verification` | Champ sans équivalent canonique |
| `o:tracking=no`, `o:tracking-clicks=no`, `o:tracking-opens=no`, `o:dkim=no` | Cette surface ne peut pas désactiver le comportement correspondant ; le suivi et la signature DKIM sont des réglages de déploiement |
| `o:testmode=yes` | Le chemin d'envoi canonique n'a pas de mode de livraison supprimée par message ; utilisez la surface de mode test de la plateforme au lieu d'envoyer silencieusement |
| Tout autre champ `o:*` et tout champ de formulaire inconnu | Aucun équivalent canonique sur la surface de compatibilité Mailgun |
| `{domain}` différent du domaine de l'adresse `from` | Le segment de chemin doit être le domaine de l'adresse `from`, car le chemin d'envoi canonique signe avec le domaine expéditeur |
| Nom d'en-tête envoyé deux fois, ou deux valeurs `Reply-To` différentes | Le doublon est refusé plutôt que résolu en choisissant une valeur |

## Ce qui n'est pas encore relayé

La surface de compatibilité ne sert que la route d'envoi. Les API Mailgun ci-dessous n'ont pas de route de compatibilité ; utilisez l'API native ApexMail ou le tableau de bord.

- Envois MIME bruts (`messages.mime`) et champ `template` pour les modèles stockés dans Mailgun.
- Réglages de livraison par message : `o:require-tls`, `o:skip-verification`, `o:dkim=no`, `o:tracking*=no`, `o:testmode=yes`.
- Campagnes (`o:campaign`), listes de diffusion et API d'événements et de statistiques.
- API de routes, domaines, webhooks et suppressions : les suppressions vivent dans la liste de suppression ApexMail ; les abonnements webhook passent par `POST /v1/webhooks`.
- Routage entrant (Mailgun Routes) et récupération des messages stockés.
- Point d'accès batch sur la surface de compatibilité ; l'envoi par lots passe par l'API native (jusqu'à 100 par appel).

## DNS : ce qui change et ce qui reste

Votre domaine d'envoi reste le vôtre, et ApexMail signe DKIM avec un sélecteur généré par domaine sur ce même domaine. Ajoutez les quatre enregistrements de `GET /v1/domains/:id/dns-records` à côté des enregistrements Mailgun ; ne retirez ceux de Mailgun qu'après la bascule et la fenêtre de conservation.

| Enregistrement Mailgun | Équivalent ApexMail |
|---|---|
| Enregistrement DKIM sous `mx._domainkey` ou l'hôte DKIM de l'éditeur | Enregistrement TXT direct sous `<selector>._domainkey.<domain>` avec la clé publique DKIM. Un TXT direct, pas un CNAME |
| Enregistrements de chemin de retour Mailgun (mécanisme SPF `include:mailgun.org`, MX sur le sous-domaine de rebond) | Enregistrement TXT sous `bounce.<domain>` avec la valeur SPF de la MAIL FROM personnalisée, et enregistrement MX sous `bounce.<domain>`, priorité 10, vers l'hôte de rétroaction de la région |
| CNAME de suivi de liens de marque | Aucun CNAME de liens de marque requis. ApexMail réécrit les liens vers ses propres chemins de suivi ; un domaine de suivi personnalisé (CNAME sur un sous-domaine d'un domaine vérifié) est disponible à partir de Pro |
| Authentification de domaine | Enregistrement TXT sous `_dmarc.<domain>` avec votre politique DMARC |

Liste de contrôle :

1. Ajoutez le domaine d'envoi dans le tableau de bord et récupérez ses enregistrements DNS.
2. Publiez les quatre enregistrements ApexMail ; laissez ceux de Mailgun en place.
3. Conservez les enregistrements de chemin de retour Mailgun tant que Mailgun envoie, car le domaine MAIL FROM de Mailgun est son propre sous-domaine.
4. Lancez la vérification du domaine et confirmez que le sélecteur DKIM se résout.
5. Gardez la remontée DMARC (rua) active pendant la transition.
6. Après la bascule et la fenêtre de conservation, retirez les enregistrements Mailgun et révoquez l'ancienne clé.

## Modèles

Les modèles stockés dans Mailgun (`template` plus `t:variables`) ne sont pas relayés, et le champ est refusé nommément. Deux voies de conversion :

- Rendez le corps dans votre application et envoyez `html` et `text` via la même route de compatibilité. Aucun travail de migration de modèles, et l'envoi garde ses champs de formulaire.
- Créez un modèle via `POST /v1/templates` et envoyez-le avec `template_id` plus `template_data` sur le `POST /v1/messages` natif. Les espaces réservés s'écrivent `{{variable}}` ; un espace réservé non résolu est rendu tel quel plutôt que vidé, ce qui rend une variable manquante visible dans l'aperçu.

Les variables de modèle Mailgun voyagent en champs de formulaire `t:name=value` ; sur la route de compatibilité, utilisez les métadonnées `v:` ou rendez les valeurs dans le corps, puis déplacez les variables vers `template_data` lorsque vous adoptez l'API de modèles native.

## Webhooks

Les webhooks Mailgun envoient du JSON à votre point de terminaison (type `http-post`). Pointez le point de terminaison vers ApexMail, abonnez les événements que vous consommez et vérifiez la signature ApexMail : `X-ApexMail-Signature: sha256=<hex>` sur le corps brut de la requête avec `X-ApexMail-Timestamp`. La livraison est au moins unique, donc dédupliquez sur le champ `id` de l'événement.

| Événement Mailgun | Événement ApexMail | Remarques |
|---|---|---|
| `accepted` | `message.accepted` | Accepté pour livraison |
| `stored` | `message.queued` | Le message est entré dans la file de sortie |
| `delivered` | `message.delivered` | Le serveur destinataire a accepté le message |
| `failed` de sévérité permanente | `message.bounced` | Rejet définitif |
| `failed` de sévérité temporaire | `message.deferred` | Report 4xx ; une nouvelle tentative est planifiée |
| `rejected` | `message.suppressed` | Refus par liste de suppression ou politique |
| `opened` | `message.opened` | |
| `clicked` | `message.clicked` | |
| `complained` | `message.complained` | |
| `unsubscribed` | `recipient.unsubscribed` | |

La forme de la charge utile change selon l'éditeur : les événements ApexMail utilisent l'enveloppe `{id, event, timestamp, data}`, avec `data.messageId` sur les événements de message et `data.email` sur les événements de suppression.

## Plan de bascule

La bascule est un changement d'hôte par route ou par environnement ; un retour arrière est le même changement en sens inverse. Aucun champ de formulaire ni modèle n'est à défaire.

| Étape | Action | Critères de sortie | Retour arrière |
|---|---|---|---|
| 1. Préparer | Créer le compte, ajouter et vérifier le domaine d'envoi, créer une clé API avec `messages:send`, abonner les événements webhook | La vérification passe ; un message de test part d'un environnement de préproduction | Aucun trafic de production |
| 2. Valider en parallèle | Envoyer les mêmes charges utiles de formulaire vers `https://api.apexmail.ee/v3/{domain}/messages` avec la clé ApexMail dans l'emplacement Basic ; comparer réponses, identifiants et événements webhook | `200` avec le corps `Queued. Thank you.` à chaque test ; les événements arrivent avec des signatures valides | Rebasculer la route de test vers Mailgun |
| 3. Basculer 10 % | Router 10 % des envois de production via la route de compatibilité ; surveiller les taux de rejet et de plainte face aux seuils AUP (2 % de rejets, 0,1 % de plaintes) | Les métriques de livraison correspondent à Mailgun dans la tolérance convenue pendant la fenêtre d'observation | Rebasculer la route ; Mailgun garde les 90 % restants |
| 4. Basculer 50 % | Monter à 50 % une fois la fenêtre terminée proprement ; les deux fournisseurs envoient depuis le même domaine | Parité maintenue à cette part plus élevée | Revenir à 100 % Mailgun |
| 5. Basculer à 100 % | Router tous les envois via `POST /v3/{domain}/messages` sur ApexMail | Volume complet sur ApexMail avec des métriques propres | Rebasculer ; les clés restent actives pendant la fenêtre de conservation |
| 6. Retirer l'ancien chemin | Retirer les enregistrements DNS Mailgun, révoquer sa clé, retirer la configuration de modèles stockés | Les enregistrements ne résolvent plus que vers ApexMail | Restaurer les enregistrements depuis votre journal de changement |

## Étapes suivantes

- Comparez les deux plateformes fonction par fonction sur la [comparaison ApexMail vs Mailgun](/fr/compare/mailgun/).
- Lisez la [vue d'ensemble de l'API](/docs/api/) et la [spécification OpenAPI](/docs/api/openapi/) pour le contrat natif, envois par lots et modèles compris.
- Lisez [Webhooks](/docs/webhooks/) pour les schémas de charge utile et la vérification des signatures.
- [Contactez le service commercial](/fr/contact/sales/) pour une évaluation de migration si une route MIME brut ou des modèles stockés font partie de votre trafic de production.
