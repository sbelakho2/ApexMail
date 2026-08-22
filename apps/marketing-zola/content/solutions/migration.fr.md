+++
title = "Solution de migration"
description = "Migrez de SendGrid, Postmark, Mailgun, SES ou Resend vers ApexMail. Réchauffement IP, transition de domaine, migration des modèles et validation par envoi parallèle."
template = "prose.html"
+++

## Migration

Transférez votre infrastructure d'email transactionnel vers ApexMail sans interruption. Cette solution couvre la transition de domaine, le réchauffement IP, la migration des modèles, la compatibilité webhook et la validation par envoi parallèle.

## Audience

Équipes d'ingénierie migrant depuis SendGrid, Postmark, Mailgun, Amazon SES ou Resend. Équipes d'opérations pilotant la bascule. Équipes de conformité vérifiant les exigences de résidence des données.

## Contexte métier

La migration de fournisseur email est une opération à haut risque. Toute livraison perdue pendant la bascule signifie du chiffre d'affaires perdu. Un réchauffement IP sans automatisation risque le blacklisting. La réputation du domaine doit être préservée d'un fournisseur à l'autre. Sans plan de migration structuré, les équipes s'exposent à une dégradation de livraison prolongée.

## Problème central

- La réputation IP est propre à chaque fournisseur et ne peut pas être transférée.
- Les enregistrements d'authentification de domaine (SPF, DKIM, DMARC) requièrent des modifications DNS coordonnées.
- La syntaxe des modèles diffère d'un fournisseur à l'autre.
- Les payloads de webhook et les types d'événements ne sont pas normalisés.
- L'envoi parallèle pendant la validation requiert un routage bi-fournisseur.

## La solution ApexMail

- **Réchauffement IP géré** — Calendrier de réchauffement automatisé pour les IP dédiées, avec bridage et supervision de la réputation.
- **Guide de transition de domaine** — Configuration DNS pas à pas pour SPF, DKIM, DMARC et return-path personnalisé.
- **Import de modèles** — Mappez vos modèles existants vers le format d'ApexMail en préservant les variables et les layouts.
- **Compatibilité webhook** — Types d'événements normalisés avec documentation de mappage des payloads.
- **Validation par envoi parallèle** — Routez un pourcentage configurable du trafic via ApexMail tout en conservant votre fournisseur actuel.

## Implémentation technique

1. Créez un compte ApexMail et vérifiez votre domaine d'envoi.
2. Copiez l'enregistrement DKIM (ou les enregistrements) propre au domaine, généré dans les paramètres Domains, à côté des sélecteurs de votre fournisseur actuel.
3. Ajoutez le mécanisme SPF ApexMail généré à l'enregistrement SPF existant ; ne retirez pas le fournisseur précédent avant validation de la transition.
4. Définissez la politique DMARC sur `p=none` pendant la transition pour collecter les rapports sans mise en application.
5. Importez les modèles via l'API Template.
6. Configurez les points de terminaison webhook pour la livraison des événements.
7. Démarrez l'envoi parallèle à 10 % du volume, en augmentant progressivement sous supervision des métriques de livraison.
8. Après la période de validation, routez 100 % du trafic via ApexMail et retirez la configuration du fournisseur historique.

## Points de terminaison API pertinents

| Point de terminaison | Description |
|---|---|
| `POST /v1/emails` | Envoyer un email |
| `POST /v1/emails/batch` | Envoi par lots jusqu'à 1 000 emails |
| `POST /v1/templates` | Créer un modèle |
| `GET /v1/templates` | Lister les modèles |
| `PUT /v1/templates/:id` | Mettre à jour un modèle |

## Événements webhook pertinents

| Événement | Déclencheur |
|---|---|
| `email.delivered` | Le serveur du destinataire a accepté le message |
| `email.bounced` | Rebond dur ou rebond souple |
| `email.delayed` | Message différé par le serveur du destinataire |

## Forfait requis

| Forfait | IP dédiée | Support |
|---|---|---|
| Growth | 1 IP dédiée incluse | Support par email |
| Scale | 3 IP dédiées incluses | Support prioritaire |
| Enterprise | 10 IP dédiées incluses | Support dédié |

## Considérations de sécurité

- Les modifications DNS devraient être appliquées pendant une fenêtre de maintenance.
- Surveillez les rapports agrégés DMARC (RUA) pendant toute la période de transition.
- Conservez les clés API des deux fournisseurs actives jusqu'à la validation complète.

## Considérations de conformité

- Confirmez les exigences de localisation des données et de DPA lors de la revue de compte ou Enterprise ; une bascule technique ne crée en soi aucun engagement de résidence ou de conformité.
- Le client reste responsable de la continuité du consentement des destinataires pendant la migration.

## Limites connues

- L'envoi parallèle peut générer des événements de livraison dupliqués pendant la fenêtre de validation.
- Le réchauffement IP requiert 2 à 4 semaines pour les IP dédiées.
- La migration des modèles requiert une revue manuelle pour les logiques conditionnelles complexes.

## Prochaine étape recommandée

[Contactez l'équipe commerciale](/fr/contact/sales/) pour une évaluation de migration et une revue d'éligibilité IP dédiée.
