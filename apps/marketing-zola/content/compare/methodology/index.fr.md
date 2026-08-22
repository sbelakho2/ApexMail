+++
title = "Méthodologie de comparaison"
description = "Comment ApexMail construit et maintient ses comparatifs concurrentiels : standards de preuve, politique de sources, fréquence de mise à jour et processus de correction."
template = "prose.html"

[extra]
last_updated = "2026-07-29"
+++

## Objectif

ApexMail publie des comparaisons factuelles et fondées sur des preuves pour aider les développeurs et les équipes d'achat à évaluer les fournisseurs d'email transactionnel. Chaque affirmation de chaque comparaison est traçable jusqu'à une source publique.

## Standards de divulgation

Chaque page de comparaison divulgue :

| Champ | Description |
|-------|-------------|
| **Date de vérification** | Quand la comparaison a été contrôlée pour la dernière fois contre les sources en ligne |
| **Forfait concurrent comparé** | Nom exact du forfait et palier référencés |
| **Forfait ApexMail comparé** | Forfait ApexMail exact utilisé pour le mapping fonctionnalité par fonctionnalité |
| **Hypothèse de volume mensuel** | Le volume d'emails auquel les tarifs sont calculés |
| **Période de facturation** | Facturation mensuelle ou annuelle utilisée pour la comparaison tarifaire |
| **Devise** | Tous les prix sont affichés en EUR. Les prix ApexMail sont publiés en EUR ; lorsqu'un concurrent publie uniquement en USD, le montant en EUR est converti au taux de référence documenté (1 USD = €0.92, 2026-08-19) et le prix USD publié par le fournisseur est affiché entre parenthèses |
| **Traitement des taxes** | Tous les prix sont hors TVA sauf mention contraire |
| **Définitions des fonctionnalités** | Comment chaque fonctionnalité comparée est définie |
| **Politique de sources** | Uniquement de la documentation publique officielle et des pages tarifs |
| **Fréquence de mise à jour** | Revue ciblée tous les 90 jours ; affirmations critiques revues chaque mois |
| **Processus de correction** | Corrections acceptées à security@apexmail.ee ; vérifiées sous 5 jours ouvrés |

## Champs de preuve par ligne de comparaison

Chaque ligne d'un tableau comparatif est adossée à :

| Champ de preuve | Requis |
|----------------|----------|
| Nom de la fonctionnalité | Oui |
| Implémentation ApexMail | Oui |
| Implémentation du concurrent | Oui |
| Forfait ou palier exact | Oui |
| URL de la source officielle | Oui |
| Date de la source | Oui |
| Date de vérification | Oui |
| Réviseur | Oui |
| Qualification (le cas échéant) | Requise si l'affirmation est qualifiée |
| Capture d'écran ou preuve archivée | Conservée en interne |

## Règles de comparaison tarifaire

- Les comparaisons tarifaires utilisent des **volumes mensuels équivalents** des deux côtés.
- La facturation annuelle n'est comparée que lorsque le catalogue public actuel de chaque fournisseur le prévoit expressément ; aucun rabais supposé n'est appliqué.
- Lorsque les tarifs du concurrent varient par palier de volume, le palier le plus proche de l'hypothèse de volume indiquée est retenu.
- Les devises sont affichées dans leur dénomination d'origine. Lorsqu'un contexte de conversion est utile, le taux de référence de la BCE à la date de vérification est indiqué.

## Règles de comparaison fonctionnelle

- Les fonctionnalités sont comparées selon leur **disponibilité documentée publiquement** au palier de forfait indiqué.
- « Disponible sur les forfaits supérieurs » n'est mentionné que lorsque la fonctionnalité n'est pas disponible sur le forfait comparé.
- « Disponible en option additionnelle » inclut le prix de l'option lorsqu'il est publié.
- Les fonctionnalités listées comme « prévues » ou « bientôt disponibles » sont exclues, sauf si une date de sortie ferme est publiée par l'éditeur.
- Les fonctionnalités ApexMail listées comme « disponibles » doivent être généralement disponibles en production au moment de la vérification.

## Politique d'évaluation subjective

- Les étiquettes subjectives (« meilleur », « supérieur », « basique », « limité ») sont remplacées par des **énoncés mesurables**.
- Lorsqu'une évaluation qualitative est inévitable, elle est explicitement présentée comme une **appréciation éditoriale d'ApexMail**, critères annoncés.
- Les avantages des concurrents sont reconnus explicitement et sans réserve.

## Processus de correction et de contestation

- Les éditeurs et les lecteurs peuvent soumettre des corrections à security@apexmail.ee.
- Les corrections sont vérifiées auprès des sources officielles sous 5 jours ouvrés.
- Les corrections vérifiées sont publiées avec leur date de correction.
- Une section d'errata signalant la correction apparaît en bas de la page concernée.

## Cadence de revue

| Type de contrôle | Fréquence |
|------------|-----------|
| Exactitude des tarifs (tous les concurrents) | Tous les 90 jours |
| Affirmations fonctionnelles (lignes critiques) | Tous les 30 jours |
| Affirmations fonctionnelles (toutes les lignes) | Tous les 90 jours |
| Validité des URL sources | Tous les 90 jours |
| Re-vérification complète | Tous les 180 jours ou lors d'une version majeure d'un éditeur |

## Limites

- Les comparaisons reflètent les informations publiquement disponibles à la date de vérification. Les éditeurs peuvent modifier leurs tarifs et fonctionnalités sans préavis.
- Les tarifs Enterprise (devis personnalisés, remises volume) ne sont pas comparés sauf s'ils sont publiquement affichés.
- Les comparaisons ne constituent ni un conseil juridique, ni une recommandation d'achat, ni une offre contractuelle.
- Les benchmarks de performance (latence, débit) ne sont pas comparés sauf s'ils sont mesurés de manière indépendante par ApexMail dans des conditions de test divulguées.
