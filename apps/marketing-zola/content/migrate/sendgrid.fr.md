+++
title = "Migrer de SendGrid vers ApexMail"
description = "Migrez une intégration SendGrid vers ApexMail par un changement d'URL de base : la surface de compatibilité sert POST /v3/mail/send avec une clé API ApexMail dans l'en-tête Authorization existant, avec la correspondance des champs, les refus nommés, la liste DNS, les noms d'événements webhook et un plan de bascule 10/50/100."
template = "prose.html"

[extra]
last_updated = "2026-10-15"
og_image = "/images/og-image.png"
+++

ApexMail sert `POST /v3/mail/send` sur une surface de compatibilité SendGrid. La route traduit la charge utile SendGrid en requête d'envoi canonique, puis appelle le même gestionnaire que `POST /v1/messages` : vérification du domaine expéditeur, filtres de suppression et de consentement, droits du forfait, registre d'idempotence et insertion dans la file s'exécutent donc au même endroit. Votre intégration garde la forme de sa requête ; seuls l'URL de base et la clé changent.

## Correspondance des points d'accès

| Point d'accès SendGrid | Surface de compatibilité ApexMail | Point d'accès natif ApexMail |
|---|---|---|
| `POST https://api.sendgrid.com/v3/mail/send` | `POST https://api.apexmail.ee/v3/mail/send` | `POST https://api.apexmail.ee/v1/messages` |
| Aucun point d'accès batch sur cette surface | Une requête par message | `POST https://api.apexmail.ee/v1/messages/batch`, jusqu'à 100 messages par appel |

Un envoi réussi répond `202 Accepted` avec un corps vide et l'identifiant canonique du message dans l'en-tête `X-Message-Id`. Cet identifiant est celui que `GET /v1/messages/{id}` renvoie et celui que les événements webhook portent dans `data.messageId`.

Une entrée `personalizations` par requête : la surface en traite exactement une. Une charge utile avec plusieurs personnalisations est refusée nommément plutôt qu'envoyée avec des objets ou des en-têtes perdus.

## Bascule de l'authentification

Votre emplacement de clé reste le même. Envoyez la clé API ApexMail (`am_live_…` ou `am_test_…`) là où se trouvait la clé SendGrid, et donnez-lui la portée `messages:send` qu'exige aussi `POST /v1/messages`.

| Élément | SendGrid aujourd'hui | Surface de compatibilité ApexMail |
|---|---|---|
| En-tête d'identifiant | `Authorization: Bearer SG.…` | `Authorization: Bearer am_live_…` |
| Portée | Permissions de la clé | `messages:send` |
| Idempotence | Non proposée | `Idempotency-Key: <uuid>` sur la même route ; la même clé sous 24 heures rejoue la réponse d'origine, y compris le même `X-Message-Id` |
| Classe d'objet | Notion absente chez l'éditeur | `X-ApexMail-Category: transactional` (ou `service`) exempte l'envoi du filtre de préférences marketing ; sans cet en-tête, l'envoi compte comme classe `marketing` par défaut et le filtre de consentement s'applique |

## Correspondance des champs

Les noms canoniques sont ceux du contrat `POST /v1/messages` : la même compréhension de la charge utile s'applique lors d'un passage ultérieur à l'API native.

| Champ SendGrid | Champ canonique | Remarques |
|---|---|---|
| `from` (`{email, name}` ou chaîne) | `from` | `"Name <addr>"` lorsqu'un nom est présent |
| `personalizations[0].to[]` | `to` | Requis ; chaînes d'adresse, chaînes `"Name <addr>"` et objets `{email, name}` acceptés |
| `personalizations[0].cc[]` / `.bcc[]` | `cc` / `bcc` | |
| `personalizations[0].subject` (sinon `subject` de premier niveau) | `subject` | La valeur de la personnalisation l'emporte |
| `personalizations[0].headers` fusionnés sous `headers` de premier niveau | `headers` | Un en-tête défini aux deux endroits avec des valeurs différentes est refusé |
| `content[]` avec `type` `text/plain` / `text/html` | `text` / `html` | Une seule partie de chaque type |
| `attachments[].content`, `.filename`, `.type` | `attachments[]` (`filename`, `content`, `contentType`) | `type` vaut `application/octet-stream` par défaut |
| `categories[]` et `X-SMTPAPI` `category`/`categories` | `tags` | Les doublons sont supprimés |
| `custom_args` et `X-SMTPAPI` `unique_args` | `metadata` | Valeurs de type chaîne uniquement ; une clé définie aux deux endroits avec des valeurs différentes est refusée |
| `reply_to` | `reply_to` | |
| `send_at` (secondes Unix) | `scheduled_at` | |
| En-tête `X-ApexMail-Category` | `category` | Validé par le normaliseur canonique |
| `mail_settings.sandbox_mode.enable = false` | Sans effet, accepté | Le comportement par défaut documenté des SDK |

## Champs refusés nommément par la surface

Chacun de ces éléments est refusé dans la forme d'erreur propre à SendGrid `{"errors": [{"message", "field", "help"}]}`, jamais ignoré silencieusement. La paire canonique 400/422 est rendue en `400` SendGrid.

| Élément SendGrid | Refus |
|---|---|
| Plus d'une entrée `personalizations` | `more than one 'personalizations' entry is not supported by the ApexMail compatibility surface: per-personalization subject/headers would be dropped — send one request per personalization` |
| `personalizations[].substitutions`, `.dynamic_template_data` | Champ sans équivalent canonique |
| `template_id`, `dynamic_template_data` | Les identifiants de modèle SendGrid ne sont pas des identifiants de modèle ApexMail |
| `attachments[].content_id`, `disposition: "inline"` | Le chemin d'envoi canonique n'a pas de notion de partie en ligne ; joignez le fichier au lieu de l'intégrer |
| `content[].type` autre que `text/plain` et `text/html` | Seules ces deux parties ont un équivalent canonique |
| `asm`, `batch_id`, `ip_pool_name` | Aucun équivalent canonique |
| `mail_settings.*` autre que le sans-effet sandbox | Aucun équivalent canonique |
| `mail_settings.sandbox_mode.enable = true` | Pas de mode sandbox par message ; utilisez la surface de mode test de la plateforme |
| `tracking_settings.*` | Aucun équivalent canonique |
| Clés `X-SMTPAPI` autres que `category`, `categories`, `unique_args` | Aucun équivalent canonique |
| Tout autre champ de premier niveau | Aucun équivalent canonique |

## Ce qui n'est pas encore relayé

La surface de compatibilité ne sert que la route d'envoi. Les API SendGrid ci-dessous n'ont pas de route de compatibilité ; utilisez l'API native ApexMail ou le tableau de bord.

- Stockage et rendu de modèles (`/v3/templates`, `dynamic_template_data` Handlebars) : voir la section modèles.
- Gestion des suppressions (`/v3/asm/*`, `bypass_list_management`) : les suppressions vivent dans la liste de suppression ApexMail, gérée dans le tableau de bord ou via l'API native.
- API de statistiques, d'activité des messages et de validation d'adresse.
- API de contacts marketing, de listes et de campagnes unitaires.
- Inbound Parse.
- Mode sandbox par message, interrupteurs de suivi par message et personnalisations multiples.

## DNS : ce qui change et ce qui reste

Votre domaine d'envoi reste le vôtre, et ApexMail signe DKIM avec un sélecteur généré par domaine sur ce même domaine. Ajoutez les quatre enregistrements de `GET /v1/domains/:id/dns-records` à côté des enregistrements SendGrid ; ne retirez ceux de SendGrid qu'après la bascule et la fenêtre de conservation.

| Enregistrement SendGrid | Équivalent ApexMail |
|---|---|
| Paire CNAME DKIM (`s1._domainkey`, `s2._domainkey`) | Enregistrement TXT direct sous `<selector>._domainkey.<domain>` avec la clé publique DKIM. Un TXT direct, pas un CNAME |
| CNAME de marque de liens (`url…`) | Aucun CNAME de liens de marque requis. ApexMail réécrit les liens vers ses propres chemins de suivi ; un domaine de suivi personnalisé (CNAME sur un sous-domaine d'un domaine vérifié) est disponible à partir de Pro |
| CNAME du domaine de rebond | Enregistrement MX sous `bounce.<domain>`, priorité 10, vers l'hôte de rétroaction de la région, plus un enregistrement TXT sous `bounce.<domain>` avec la valeur SPF de la MAIL FROM personnalisée |
| Authentification de domaine | Enregistrement TXT sous `_dmarc.<domain>` avec votre politique DMARC |

Liste de contrôle :

1. Ajoutez le domaine d'envoi dans le tableau de bord et récupérez ses enregistrements DNS.
2. Publiez les quatre enregistrements ApexMail ; laissez ceux de SendGrid en place.
3. Conservez l'enregistrement SPF du domaine racine tant que SendGrid envoie. La valeur SPF d'ApexMail vit sur le sous-domaine `bounce.<domain>` (la MAIL FROM personnalisée), elle n'a donc pas besoin d'entrée racine.
4. Lancez la vérification du domaine et confirmez que le sélecteur DKIM se résout.
5. Gardez la remontée DMARC (rua) active pendant la transition.
6. Après la bascule et la fenêtre de conservation, retirez les CNAME SendGrid et tout mécanisme SendGrid de vos enregistrements.

## Modèles

Les identifiants de modèle SendGrid ne sont pas des identifiants de modèle ApexMail, et `template_id` avec `dynamic_template_data` est refusé nommément sur la route de compatibilité. Deux voies de conversion :

- Rendez le corps dans votre application et envoyez-le en `content[]` via la même route de compatibilité. Aucun travail de migration de modèles, et l'envoi garde la forme de sa requête.
- Créez un modèle via `POST /v1/templates` et envoyez-le avec `template_id` plus `template_data` sur le `POST /v1/messages` natif. Les espaces réservés s'écrivent `{{variable}}` ; un espace réservé non résolu est rendu tel quel plutôt que vidé, ce qui rend une variable manquante visible dans l'aperçu.

Les assistants Handlebars (conditions, boucles, `{{#each}}`) n'ont pas d'équivalent direct dans le moteur d'espaces réservés ; convertissez ces modèles en HTML rendu dans votre application ou découpez-les en modèles par cas.

## Webhooks

Pointez votre point de terminaison vers ApexMail, abonnez les événements que vous consommez et vérifiez la signature ApexMail : `X-ApexMail-Signature: sha256=<hex>` sur le corps brut de la requête avec `X-ApexMail-Timestamp`. La livraison est au moins unique, donc dédupliquez sur le champ `id` de l'événement.

| Événement SendGrid | Événement ApexMail | Remarques |
|---|---|---|
| `processed` | `message.accepted` | Accepté pour livraison |
| `delivered` | `message.delivered` | Le serveur destinataire a accepté le message |
| `bounce` | `message.bounced` | Rejet définitif |
| `deferred` | `message.deferred` | Report 4xx ; une nouvelle tentative est planifiée |
| `dropped` | `message.suppressed` | Destinataire sur la liste de suppression |
| `open` | `message.opened` | |
| `click` | `message.clicked` | |
| `spamreport` | `message.complained` | |
| `unsubscribe`, `group_unsubscribe` | `recipient.unsubscribed` | |
| `group_resubscribe` | Aucun événement équivalent | Le réabonnement est consigné sur la fiche de préférences, pas comme événement |

## Plan de bascule

La bascule est un changement d'URL de base par route ou par environnement ; un retour arrière est le même changement en sens inverse. Aucune charge utile ni modèle n'est à défaire.

| Étape | Action | Critères de sortie | Retour arrière |
|---|---|---|---|
| 1. Préparer | Créer le compte, ajouter et vérifier le domaine d'envoi, créer une clé API avec `messages:send`, abonner les événements webhook | La vérification passe ; un message de test part d'un environnement de préproduction | Aucun trafic de production |
| 2. Valider en parallèle | Envoyer les mêmes charges utiles vers `https://api.apexmail.ee/v3/mail/send` avec la clé ApexMail ; comparer réponses, identifiants et événements webhook | `202` avec `X-Message-Id` à chaque test ; les événements arrivent avec des signatures valides | Rebasculer la route de test vers SendGrid |
| 3. Basculer 10 % | Router 10 % des envois de production via la route de compatibilité ; surveiller les taux de rejet et de plainte face aux seuils AUP (2 % de rejets, 0,1 % de plaintes) | Les métriques de livraison correspondent à SendGrid dans la tolérance convenue pendant la fenêtre d'observation | Rebasculer la route ; SendGrid garde les 90 % restants |
| 4. Basculer 50 % | Monter à 50 % une fois la fenêtre terminée proprement ; les deux fournisseurs envoient depuis le même domaine | Parité maintenue à cette part plus élevée | Revenir à 100 % SendGrid |
| 5. Basculer à 100 % | Router tous les envois via `POST /v3/mail/send` sur ApexMail | Volume complet sur ApexMail avec des métriques propres | Rebasculer ; les clés restent actives pendant la fenêtre de conservation |
| 6. Retirer l'ancien chemin | Retirer les CNAME SendGrid et le mécanisme SPF, révoquer sa clé, supprimer la configuration de modèles restante | Les enregistrements ne résolvent plus que vers ApexMail | Restaurer les enregistrements depuis votre journal de changement |

## Étapes suivantes

- Comparez les deux plateformes fonction par fonction sur la [comparaison ApexMail vs SendGrid](/fr/compare/sendgrid/).
- Lisez la [vue d'ensemble de l'API](/docs/api/) et la [spécification OpenAPI](/docs/api/openapi/) pour le contrat natif, envois par lots et modèles compris.
- Lisez [Webhooks](/docs/webhooks/) pour les schémas de charge utile et la vérification des signatures.
- [Contactez le service commercial](/fr/contact/sales/) pour une évaluation de migration si les éléments refusés ci-dessus font partie de votre trafic de production.
