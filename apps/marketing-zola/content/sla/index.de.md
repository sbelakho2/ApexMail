+++
title = "Servicelevel-Vereinbarung (SLA)"
description = "ApexMail-SLA — vertragliche Betriebszeitverpflichtungen für Scale- und Enterprise-Tarifkunden."
template = "prose.html"

[extra]
last_updated = "2026-07-29"
+++

## 3. Leistungsziele

| Metrik | Ziel |
|---|---|
| Production API P95 (Gateway) | ≤500ms |
| E-Mail-Annahme bis erster Zustellversuch | ≤30 Sekunden |
| Webhook-Zustellung (P95) | ≤5 Sekunden |

### Metrikdefinitionen

**Production API P95 (Gateway):** Gemessen auf der API-Gateway-Ebene für alle produktiven `POST /v1/messages`-Anfragen. Start-Zeitstempel: Anfrageeingang am Gateway. End-Zeitstempel: Antwortausgang vom Gateway. Perzentil: P95. Qualifizierende Anfragen: HTTP 200-299-Antworten vom Messages-Endpunkt, ausschließlich Sandbox/Test-API-Key-Traffic. Ausschlüsse: Health-Check-Probes, Preflight-OPTIONS, Sandbox-API-Keys. Stichprobenzeitraum: gleitendes 30-Tage-Fenster, 1-Minuten-Aggregations-Buckets.
