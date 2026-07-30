+++
title = "Politique d'utilisation acceptable"
description = "Politique d'utilisation acceptable d'ApexMail — règles régissant l'utilisation du service de messagerie, organisées par catégorie de message."
template = "prose.html"

[extra]
last_updated = "2026-07-30"
+++

Cette Politique d'utilisation acceptable (« PUA ») définit les utilisations interdites et acceptables de l'infrastructure de messagerie ApexMail. Toute violation peut entraîner une suspension ou une résiliation. Cette PUA distingue les emails marketing et promotionnels des emails transactionnels et de service — chaque catégorie est soumise à des obligations de consentement, de désabonnement et d'envoi différentes, décrites ci-dessous.

## Emails marketing et promotionnels

Les emails marketing et promotionnels comprennent les newsletters, les annonces de produits, les offres, les invitations à des événements et tout message dont l'objectif principal est la promotion commerciale ou l'engagement client au-delà de l'exécution directe d'un service.

**Exigences pour tous les emails marketing et promotionnels :**

- **Consentement préalable.** Les expéditeurs doivent obtenir et conserver la preuve d'un consentement préalable avant l'envoi. Lorsque la juridiction du destinataire ou les obligations réglementaires de l'expéditeur exigent un consentement exprès (par exemple, RGPD Article 7 pour le marketing direct aux personnes dans l'EEE, CAN-SPAM aux États-Unis), l'expéditeur doit obtenir ce consentement.
- **Base légale.** Les expéditeurs doivent identifier, documenter et conserver la base légale du traitement des données des destinataires en vertu de toutes les lois applicables (par exemple, consentement en vertu du RGPD Article 6(1)(a), intérêt légitime lorsque juridiquement valable). L'expéditeur porte la responsabilité exclusive de garantir l'existence d'une base légale valable pour chaque communication marketing avant l'envoi.
- **Identification de l'expéditeur.** Chaque message doit clairement identifier l'organisation expéditrice et fournir des en-têtes `From`, `Reply-To` et une adresse postale physique exacts.
- **Mécanisme de désabonnement fonctionnel.** Chaque message doit inclure un mécanisme de désabonnement en un clic qui traite les demandes de retrait rapidement et définitivement. Les liens de désabonnement doivent rester fonctionnels pendant au moins 30 jours après l'envoi.
- **Interdiction des listes achetées, aspirées ou collectées.** Les listes acquises par achat, location, aspiration ou collecte ne sont pas autorisées. Toutes les adresses des destinataires doivent être collectées directement par l'expéditeur via un processus de consentement.
- **Surveillance des plaintes.** Les expéditeurs doivent surveiller les plaintes pour abus et maintenir le taux de plainte en dessous de 0,1 % (calculé comme plaintes ÷ messages distribués par domaine d'envoi et par jour).
- **Conformité de la liste de suppression.** Les expéditeurs doivent supprimer les destinataires qui se sont désabonnés ou ont déposé une plainte. ApexMail maintient une liste de suppression au niveau de la plateforme ; les clients ne doivent pas y réintroduire des adresses supprimées.

## Emails transactionnels et de service

Les emails transactionnels et de service comprennent les messages nécessaires à la fourniture d'un service demandé par le destinataire ou que l'expéditeur est légalement tenu d'envoyer. Ces messages ne sont pas principalement promotionnels.

**Exemples d'emails transactionnels et de service :**

- Réinitialisations de mot de passe et liens de récupération de compte
- Codes d'authentification (mots de passe à usage unique, jetons à deux facteurs)
- Alertes de sécurité (connexion non reconnue, changement d'appareil, avis de suspension de compte)
- Reçus d'achat et confirmations de commande
- Factures, reçus de paiement et avis de facturation
- Notifications d'état de compte (expiration d'essai, changement de forfait, fin d'exportation de données)
- Confirmations de service (vérification de domaine, validation de point de terminaison webhook)
- Messages légalement requis (mises à jour de la politique de confidentialité lorsque la notification est obligatoire, notifications de violation de données)

**Exigences pour les emails transactionnels et de service :**

- **Doit être nécessaire au service.** Le message doit être directement lié au compte, à la transaction ou à l'obligation légale du destinataire. Le contenu promotionnel ou marketing ne doit pas être déguisé en message transactionnel.
- **Ne doit pas contenir de marketing déguisé.** Si un message transactionnel contient également du contenu promotionnel (par exemple, une réinitialisation de mot de passe qui fait également la publicité d'un nouveau produit), l'ensemble du message est traité comme du marketing et doit se conformer à la section « Emails marketing et promotionnels ».
- **Identité précise de l'expéditeur.** L'identité de l'expéditeur doit être clairement indiquée avec des informations correctes de domaine et d'en-tête.
- **Responsabilité du client pour la classification.** Le client est responsable de la classification correcte de ses messages (transactionnel vs marketing) et de l'identification de la base légale appropriée. ApexMail fournit des balises de catégorie de message dans l'API ; l'utilisation d'une balise transactionnelle pour un contenu marketing constitue une violation de cette PUA.
- **Conservation appropriée.** Les expéditeurs ne doivent conserver les données des messages transactionnels que le temps nécessaire à l'exécution de la finalité du service ou au respect des obligations légales applicables. Les données transactionnelles courantes (par exemple, accusés de réception, journaux d'authentification) ne doivent pas être conservées au-delà de ce qui est requis pour l'intégrité opérationnelle et la conformité légale.
- **Traitement juridique spécifique à la finalité.** Chaque catégorie de message transactionnel est traitée selon sa finalité juridique spécifique. Les codes d'authentification sont des mesures de sécurité en vertu du RGPD Article 32. Les factures sont des documents financiers soumis à des obligations de conservation. Les confirmations de service sont des communications d'exécution contractuelle. L'expéditeur doit appliquer le cadre juridique approprié pour chaque catégorie de message. L'utilisation d'une catégorie de message inappropriée pour contourner des exigences légales (par exemple, étiqueter un contenu marketing comme transactionnel) constitue une violation de cette PUA.

## Contenu interdit (toutes catégories)

Vous ne pouvez pas utiliser ApexMail pour envoyer :

- **Spam :** Emails de masse non sollicités sans le consentement préalable requis décrit dans la section « Emails marketing et promotionnels ».
- **Hameçonnage :** Emails conçus pour obtenir frauduleusement des informations personnelles ou financières.
- **Logiciels malveillants :** Emails contenant des virus, chevaux de Troie, rançongiciels ou pièces jointes ou liens malveillants.
- **Contenu illégal :** Contenu qui enfreint les lois applicables en Estonie, dans l'UE ou dans la juridiction du destinataire.
- **Harcèlement :** Contenu menaçant, abusif, diffamatoire ou discriminatoire.

## Exigences générales d'envoi

Ces exigences s'appliquent à toutes les catégories de messages :

- L'identité de l'expéditeur doit être clairement indiquée (pas d'usurpation de domaine ou d'en-tête).
- Les taux de rebond doivent rester inférieurs à 2 % par domaine d'envoi et par jour.
- Les plaintes doivent rester inférieures à 0,1 % par domaine d'envoi et par jour.
- Les domaines d'envoi doivent être vérifiés avec des enregistrements SPF, DKIM et DMARC valides.

## Protection de l'infrastructure

- Ne tentez pas de contourner les limites de débit, les quotas ou les plafonds de volume d'envoi.
- N'utilisez pas le service pour des attaques DDoS, des abus de réseau ou des scans de ports.
- Ne partagez pas les clés API ou les identifiants. Chaque utilisateur doit avoir sa propre clé API limitée.
- Ne tentez pas d'accéder ou d'interférer avec les données, les comptes ou les configurations d'envoi d'autres clients.

## Application

Nous surveillons les modèles d'envoi et :

1. Avertirons pour les premières violations mineures (par exemple, taux de rebond élevé).
2. Limiterons l'envoi pour les problèmes répétés ou les violations continues de la politique.
3. Suspendrons l'envoi (avec préavis lorsque cela est possible) pour les violations graves, y compris les plaintes pour spam, l'hameçonnage ou les tentatives de contournement.
4. Résilierons les comptes pour les violations graves, répétées ou pénales.

## Signalement

Signalez les abus ou les violations de la PUA à : **abuse@apexmail.ee**

Tous les signalements sont examinés dans un délai d'1 jour ouvré. Les signalants reçoivent un accusé de réception et, le cas échéant, un résumé des mesures prises.
