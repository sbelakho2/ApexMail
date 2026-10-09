+++
title = "Servicelevel-Vereinbarung (SLA)"
description = "ApexMail-SLA — vertragliche Betriebszeitverpflichtungen für Business- und Enterprise-Tarifkunden."
template = "prose.html"

[extra]
last_updated = "2026-09-09"
+++

## 1. Geltungsbereich

Diese Servicelevel-Vereinbarung („SLA") gilt für Kunden der Business- und Enterprise-Tarife und definiert unsere Betriebszeit- und Leistungsverpflichtungen.

## 2. Betriebszeitverpflichtung

| Metrik | Ziel |
|---|---|
| API-Verfügbarkeit | 99,9 % monatlich |
| SMTP-Relay-Verfügbarkeit | 99,9 % monatlich |
| Dashboard-Verfügbarkeit | 99,9 % monatlich |

## 3. Leistungsziele

| Metrik | Ziel |
|---|---|
| Production API P95 (Gateway) | ≤500ms |
| E-Mail-Annahme bis erster Zustellversuch | ≤30 Sekunden |
| Webhook-Zustellung (P95) | ≤5 Sekunden |

### Metrikdefinitionen

**Production API P95 (Gateway):** Gemessen auf der API-Gateway-Ebene für alle produktiven `POST /v1/messages`-Anfragen. Start-Zeitstempel: Anfrageeingang am Gateway. End-Zeitstempel: Antwortausgang vom Gateway. Perzentil: P95. Qualifizierende Anfragen: HTTP 200-299-Antworten vom Messages-Endpunkt, ausschließlich Sandbox/Test-API-Key-Traffic. Ausschlüsse: Health-Check-Probes, Preflight-OPTIONS, Sandbox-API-Keys. Stichprobenzeitraum: gleitendes 30-Tage-Fenster, 1-Minuten-Aggregations-Buckets.

## 4. Messung

Die Betriebszeit wird von unserem externen Überwachungssystem (Blackbox exporter + Prometheus) von mehreren geografischen Standorten gemessen. Geplante Wartungsfenster (48 Stunden im Voraus angekündigt) sind ausgeschlossen.

## 5. Servicegutschriften

Berechtigte Tarife tragen eine monatliche Verfügbarkeitsverpflichtung von 99,9 %. Fällt die gemessene monatliche Betriebszeit darunter, gilt eine Servicegutschrift gemäß der tarifspezifischen Matrix unten — der Gutschriftsprozentsatz entspricht den monatlich wiederkehrenden Gebühren des Mandanten für den betroffenen Monat.

| Gemessene monatliche Verfügbarkeit | Business | Enterprise Cloud / vertraglich |
|---|---:|---:|
| ≥ 99,9 % | 0 % (Verpflichtung erfüllt) | 0 % (Verpflichtung erfüllt) |
| 99,0 % – 99,899 % | 10 % | 10 % |
| 95,0 % – 98,999 % | 20 % | 25 % |
| < 95,0 % | 30 % | 25 % |

**Tarifhinweise:**

- **Business** — gestaffelte Prozentsätze wie angegeben; keine pauschale Obergrenze unterhalb der Stufen.
- **Enterprise Cloud und vertragliche Bereitstellungen** — Prozentsätze wie angegeben, gedeckelt bei 25 % (oder dem vertraglichen Wert, sofern ein Bestellformular einen solchen vorsieht).

Gutschriften werden aus der gemessenen monatlichen Betriebszeit unterhalb der Verpflichtung berechnet und durch den Tarif des Kunden gedeckelt.

## 6. Ausschlüsse

Gutschriften gelten nicht für: höhere Gewalt, kundenverursachte Probleme, geplante Wartung oder Beta-Funktionen.

## 7. Gutschriften beantragen

Reichen Sie Gutschriftenanträge innerhalb von 30 Tagen nach dem Vorfall bei support@apexmail.ee ein. Gutschriften werden im nächsten Abrechnungszyklus angewendet.
