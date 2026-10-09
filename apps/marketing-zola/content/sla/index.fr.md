+++
title = "Accord de niveau de service (SLA)"
description = "SLA ApexMail — engagements contractuels de disponibilité pour les clients des forfaits Business et Enterprise."
template = "prose.html"

[extra]
last_updated = "2026-09-09"
+++

## 1. Portée

Le présent Accord de niveau de service (« SLA ») s'applique aux clients des forfaits Business et Enterprise et définit nos engagements de disponibilité et de performance.

## 2. Engagement de disponibilité

| Métrique | Cible |
|---|---|
| Disponibilité de l'API | 99,9 % mensuel |
| Disponibilité du relais SMTP | 99,9 % mensuel |
| Disponibilité du tableau de bord | 99,9 % mensuel |

## 3. Objectifs de performance

| Métrique | Cible |
|---|---|
| Production API P95 (Gateway) | ≤500ms |
| Acceptation de l'email jusqu'à la première tentative d'envoi | ≤30 secondes |
| Livraison webhook (P95) | ≤5 secondes |

### Définitions des métriques

**Production API P95 (Gateway):** Mesuré au niveau de la passerelle API pour toutes les requêtes de production `POST /v1/messages`. Horodatage de début : entrée de la requête à la passerelle. Horodatage de fin : sortie de la réponse de la passerelle. Centile : P95. Requêtes qualifiantes : réponses HTTP 200-299 du point de terminaison messages, hors trafic de clé API sandbox/test. Exclusions : sondes de vérification de santé, OPTIONS préliminaires, clés API sandbox. Période d'échantillonnage : fenêtre glissante de 30 jours, seaux d'agrégation d'1 minute.

## 4. Mesure

La disponibilité est mesurée par notre système de surveillance externe (Blackbox exporter + Prometheus) depuis plusieurs emplacements géographiques. Les fenêtres de maintenance planifiées (annoncées 48 heures à l'avance) sont exclues.

## 5. Crédits de service

Les forfaits éligibles portent un engagement de disponibilité mensuel de 99,9 %. Lorsque la disponibilité mensuelle mesurée descend en dessous de ce seuil, un crédit de service s'applique selon la matrice spécifique au forfait ci-dessous — le pourcentage de crédit correspond aux frais récurrents mensuels du locataire pour le mois concerné.

| Disponibilité mensuelle mesurée | Business | Enterprise Cloud / contractuel |
|---|---:|---:|
| ≥ 99,9 % | 0 % (engagement respecté) | 0 % (engagement respecté) |
| 99,0 % – 99,899 % | 10 % | 10 % |
| 95,0 % – 98,999 % | 20 % | 25 % |
| < 95,0 % | 30 % | 25 % |

**Notes sur les forfaits :**

- **Business** — pourcentages gradués comme indiqué ; pas de plafond forfaitaire en dessous des paliers.
- **Enterprise Cloud et déploiements contractuels** — pourcentages comme indiqué, plafonnés à 25 % (ou le chiffre contractuel lorsqu'un bon de commande en spécifie un).

Les crédits sont calculés à partir de la disponibilité mensuelle mesurée en dessous de l'engagement et plafonnés selon le forfait du client.

## 6. Exclusions

Les crédits ne s'appliquent pas aux : force majeure, problèmes causés par le client, maintenances planifiées, ni fonctionnalités bêta.

## 7. Demande de crédits

Soumettez les demandes de crédit à support@apexmail.ee dans les 30 jours suivant l'incident. Les crédits sont appliqués au cycle de facturation suivant.
