+++
title = "Service Level Agreement (SLA)"
description = "SLA ApexMail — engagements contractuels de disponibilité pour les clients des forfaits Scale et Enterprise."
template = "prose.html"

[extra]
last_updated = "2026-07-29"
+++

## 3. Objectifs de performance

| Métrique | Cible |
|---|---|
| Production API P95 (Gateway) | ≤500ms |
| Acceptation de l'email jusqu'à la première tentative d'envoi | ≤30 secondes |
| Livraison webhook (P95) | ≤5 secondes |

### Définitions des métriques

**Production API P95 (Gateway):** Mesuré au niveau de la passerelle API pour toutes les requêtes de production `POST /v1/messages`. Horodatage de début : entrée de la requête à la passerelle. Horodatage de fin : sortie de la réponse de la passerelle. Centile : P95. Requêtes qualifiantes : réponses HTTP 200-299 du point de terminaison messages, hors trafic de clé API sandbox/test. Exclusions : sondes de vérification de santé, OPTIONS préliminaires, clés API sandbox. Période d'échantillonnage : fenêtre glissante de 30 jours, seaux d'agrégation d'1 minute.
