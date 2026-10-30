+++
title = "Souveraineté UE | Conçu en Europe, exploité sous droit de l'UE"
description = "Comment la position de souveraineté européenne d'ApexMail fonctionne réellement : une société estonienne sous droit de l'UE, des centres de données européens, le mode de routage EU-only fail-closed, des reçus de routage signés Ed25519, et la chaîne de sous-traitants que EU-only retire, chaque affirmation liée à sa preuve."
template = "prose.html"

[extra]
last_updated = "2026-10-16"
og_image = "/images/og-image.png"
+++

## La promesse, et la limite honnête

ApexMail est une société de l'UE (Bel Consulting OÜ, Tallinn, Estonie). Le cloud partagé tourne sur des centres de données européens dans l'EEE. Le routage EU-only est un mode réel, activable en un seul réglage : chaque envoi ne part que par les MTA européens d'ApexMail, un envoi sans route MTA propre est retenu plutôt que réacheminé, et chaque message accepté porte un reçu de routage signé Ed25519 que tout tiers peut vérifier avec la clé publique publiée.

La limite honnête appartient au même écran : le routage **par défaut** d'ApexMail est Global, et les envois Global sont livrés via SES d'Amazon Web Services dans sa région UE configurée, une région UE d'une société américaine, couverte par le contrat de sous-traitance AWS et, le cas échéant, par les clauses contractuelles types de l'UE. La phrase « votre courrier ne touche jamais un prestataire contrôlé par les États-Unis » est vraie **en routage EU-only** ; elle ne l'est pas pour un compte Global, et ce site ne la revendique pas à l'échelle de la plateforme. La [matrice des emplacements de données](/fr/data-locations/) énonce pour le stockage la même portée que cette page pour le transport.

## Une société de l'UE sous droit de l'UE

La partie contractante est Bel Consulting OÜ (nom commercial ApexMail), immatriculée en Estonie, code de registre 16588745, TVA EE102951727, Sakala tn 7-2, 10141 Tallinn. Le droit applicable aux contrats d'ApexMail est le droit estonien, et la juridiction judiciaire convenue est le Harju County Court, Tallinn, Estonie. Cette identité juridique est rendue depuis un enregistrement canonique unique sur chaque page de ce site.

Preuves : les [Conditions](/fr/terms/) nomment la partie contractante et le droit applicable ; le [DPA](/fr/dpa/) est l'accord de traitement de l'article 28 ; la [politique de confidentialité](/fr/privacy/) précise les rôles de responsable et de sous-traitant ; la page [À propos](/fr/about/) porte les données d'immatriculation de la société.

## Centres de données européens

Le déploiement partagé par défaut tourne sur l'infrastructure UE gérée par ApexMail. Les données de service essentielles, données de compte, clés d'API hachées, adresses d'expéditeur et de destinataire, contenu des messages, pièces jointes, événements et journaux de livraison, tickets de support, analytique et sauvegardes, sont traitées et répliquées dans l'EEE, sans transfert vers un pays tiers pour ces catégories. Les véritables exceptions sont nommées plutôt que cachées : la connexion OAuth facultative (Google, GitHub) et le traitement des paiements (Mollie B.V.) sont isolés dans la matrice avec leurs propres garanties de transfert.

Preuves : la [matrice des emplacements de données](/fr/data-locations/) liste pour chaque catégorie de données l'emplacement primaire, la sauvegarde et la région de traitement ; le [registre des sous-traitants](/fr/subprocessors/) nomme les entités ainsi que leurs pays de traitement et de stockage.

### Prestataire de paiement

Mollie B.V. est un établissement de paiement supervisé par De Nederlandsche Bank (DNB), dont le siège social est situé Keizersgracht 126, 1015 CW Amsterdam, Pays-Bas. Les données de paiement sont traitées aux Pays-Bas (UE) ; les réseaux de cartes peuvent les traiter à l'échelle mondiale dans le cadre de l'accord de traitement des données de Mollie.

## Routage EU-only : un seul réglage, fail-closed

Le routage EU-only est le mode de routage du locataire (`routingMode`, stocké comme `global` ou `eu_only`). En `eu_only`, chaque envoi doit sortir par les **MTA relais propres** d'ApexMail ; le transport tiers partagé (AWS SES) est interdit pour ce locataire, et le code ne contient aucune entrée qui produise une route tierce en mode EU-only.

Ce qui se passe lorsque la route MTA propre n'est pas disponible est ce qui fait du mode une promesse plutôt qu'une préférence : **le message est retenu**, différé en file d'attente avec un motif nommé, visible et libérable, il n'est jamais basculé vers le transport tiers. La même discipline s'applique quand la configuration de la ligne est illisible : une valeur de routage stockée qui ne peut pas être lue comme `global` est lue comme `eu_only`, car un message retenu est récupérable et un message mal routé ne l'est pas.

Ce qui change par rapport à Global, dit clairement :

| | Global (défaut) | EU-only |
|---|---|---|
| Envois via IP dédiée | MTA relais propres d'ApexMail | MTA relais propres d'ApexMail |
| Tout le reste | Pool partagé, AWS SES dans sa région UE configurée (qui peut inclure l’Allemagne) | MTA européens propres d'ApexMail |
| Route indisponible | Bascule vers le fournisseur | **Retenue avec un motif nommé**, aucun repli tiers |

Disponibilité et prix : inclus sur [Enterprise](/fr/enterprise/) Cloud et sur la ligne contractuelle Compliance ; sur les offres en libre-service, c'est l'add-on **EU-only routing** à **149 €/mois (165 US$/mois)** à partir de Pro, le chiffre exact du catalogue.

Preuves : la [page des tarifs](/fr/pricing/) affiche l'add-on et la ligne Compliance depuis le catalogue de facturation ; la [page conformité](/fr/compliance/) documente le volet workflow ; la [page architecture](/architecture) décrit le chemin de livraison.

## Reçus de routage signés : vérifier, pas faire confiance

Chaque message accepté produit un reçu de routage signé avec Ed25519 (RFC 8032, signature de 64 octets). La signature couvre des octets exacts et recalculables, une charge utile séparée par des LF, sans remplissage :

```text
apexmail-routing-receipt/v1
message_id=<identifiant de message de la plateforme>
tenant_id=<numéro de locataire>
transport=<libellé du transport>
accepted_at=<RFC 3339 UTC>
actual_source_ip=<ip>          ← présent uniquement si le transport en a signalé une
```

N'importe quelle bibliothèque Ed25519 peut recalculer ces octets à partir des champs publiés du reçu et vérifier la signature, sans faire confiance à la base de données, à la surface API ou à la pile TLS d'ApexMail. La clé de vérification est servie sans authentification :

- `GET https://api.apexmail.ee/v1/routing/receipts/public-key`, la clé publique Ed25519, le libellé du schéma et un identifiant de clé (`hex(sha256(public_key))[0:16]`) consigné à côté de chaque signature, de sorte qu'une rotation de clé soit auditable.
- `POST https://api.apexmail.ee/v1/routing/receipts/verify`, `{payload, signature}` ; répond avec le verdict de vérification.

Le schéma est fail-closed dans les deux sens : une écriture de reçu sans clé de signature configurée est refusée (la ligne d'acceptation n'est pas marquée acceptée), et les services qui portent le chemin d'acceptation refusent de démarrer en production sans clé. Un reçu non signé ne peut pas exister silencieusement.

Preuves : les deux endpoints sont des surfaces publiques vivantes et non authentifiées de l'API ; la [documentation API](/docs/api/) couvre le contrat environnant ; la [ligne contractuelle Compliance](/fr/pricing/) liste les reçus de routage signés comme livrable inclus.

## Ce que EU-only retire de la chaîne de sous-traitants

Le [registre des sous-traitants](/fr/subprocessors/) est généré depuis la configuration du déploiement lui-même ; l'ensemble listé ne peut donc pas dériver de ce qui tourne réellement. En routage EU-only, l'entrée Amazon Web Services SES ne transporte pas le courrier d'un locataire : le message ne sort que par les MTA propres d'ApexMail, exploités sur l'infrastructure UE gérée par ApexMail. Les entrées restantes sont les paiements (Mollie B.V., Amsterdam) et la connexion OAuth facultative (Google, GitHub), chacune avec son pays de traitement et son mécanisme de transfert indiqués au registre.

Autrement dit : en EU-only, aucun tiers contrôlé par les États-Unis ne transporte le courrier. En Global, AWS SES le fait, dans des régions UE (qui peuvent inclure l’Allemagne), sous le DPA et les CCT d'AWS, et le registre dit exactement cela.

Preuves : le [registre des sous-traitants](/fr/subprocessors/) (généré, protégé contre la dérive), la section 5 du [DPA](/fr/dpa/) et la [matrice des emplacements de données](/fr/data-locations/).

## Isolation de l'envoi commercial

Le courrier envoyé par l'autopilote commercial d'ApexMail est classé par provenance et routé via un créneau de transport commercial dédié. Il n'est jamais expédié sur le transport SES ou relais d'un client, et lorsque ce créneau n'est pas configuré, le courrier commercial est **retenu**, le transport client n'est pas appelé en repli. Les rebonds et plaintes commerciaux atterrissent dans l'ensemble de suppression du locataire commercial, pas dans la réputation d'envoi des clients.

Preuves : l'isolation est une propriété de la décision de routage du worker de livraison, décrite sur la [page architecture](/architecture) ; l'effet visible pour le client (domaines de réputation séparés) correspond au modèle d'envoi documenté sous les [fonctions de délivrabilité](/fr/features/).

## Le pack de preuves pour les revues

Pour les acheteurs qui ont besoin de l'argument sous forme vérifiable plutôt qu'en prose :

- **Ligne contractuelle Compliance**, 1 M d'emails, routage EU-only inclus, IP dédiée, **pack de preuves DORA/NIS2**, pack de traitement RGPD, reçus de routage signés, journal d'audit d'un an, SSO. Affichée avec son prix exact sur la [page des tarifs](/fr/pricing/).
- **Matériel RGPD/DPA**, le [DPA](/fr/dpa/), la [politique de confidentialité](/fr/privacy/) et la [page des workflows de conformité](/fr/compliance/) ; la documentation de traitement est disponible pour revue.
- **Limites honnêtes, énoncées comme des limites**, HIPAA n'est pas proposé actuellement, la certification ISO 27001 n'est pas proposée actuellement, et aucun pack standardisé SIG/CAIQ/HECVAT n'est un droit produit ; les questionnaires de sécurité sont traités au cas par cas avec le matériel de revue à jour. Ces déclarations proviennent du même enregistrement canonique de revendications qui encadre les textes de ce site.

Preuves : la [page conformité](/fr/compliance/) lie sa documentation ; pour le processus de revue, [contacter le service commercial](/fr/contact/sales/).

## Langues et support

Ce site et les surfaces client du produit sont publiés en anglais, allemand, français et espagnol. Le support fonctionne par email (`support@apexmail.ee`) avec des conditions de support selon l'offre ; Business et Enterprise portent les engagements de disponibilité et de performance du [SLA](/fr/sla/), mesurés par des sondes externes et crédités selon la matrice de l'offre.

Preuves : les quatre éditions linguistiques de chaque page (sélecteur de langue dans l'en-tête), le [SLA](/fr/sla/) et la [page contact](/fr/contact/).

## Pour aller plus loin

- [Matrice des emplacements de données](/fr/data-locations/), où vit chaque catégorie de données.
- [Registre des sous-traitants](/fr/subprocessors/), la liste générée des prestataires.
- [Workflows de conformité](/fr/compliance/) et le [DPA](/fr/dpa/), la couche contractuelle.
- [Tarifs](/fr/pricing/), l'add-on EU-only (149 €/mois, à partir de Pro) et la ligne Compliance.
- [Enterprise](/fr/enterprise/), Enterprise Cloud, où le routage EU-only est inclus.
- [ApexMail vs Amazon SES](/fr/compare/amazon-ses/), la comparaison honnête avec le transport que EU-only retire.
- [Architecture](/architecture), le chemin de livraison en détail technique.
