+++
title = "Datenstandorte"
description = "ApexMail-Datenstandort-Matrix — wo jede Kategorie von Kundendaten gespeichert und verarbeitet wird."
template = "prose.html"

[extra]
last_updated = "2026-07-30"
+++

## Datenstandort-Matrix

Alle Kundendaten werden in Hetzner-Rechenzentren in Deutschland und Finnland gespeichert und verarbeitet, sofern unten nicht anders angegeben. Übermittlungen außerhalb des EWR erfolgen auf Grundlage von EU-Standardvertragsklauseln (SCCs) oder eines Angemessenheitsbeschlusses gemäß DSGVO Artikel 45.

| # | Datenkategorie | Primärer Standort | Backup / Replikat | Verarbeitungsregion | Übertragungsgarantie |
|---|---|---|---|---|---|
| 1 | Kontodaten (Name, E-Mail, Unternehmen, Adresse) | Hetzner, Deutschland (Falkenstein/Nürnberg) | Hetzner, Finnland (Tuusula) | Nur EWR | Nicht anwendbar |
| 2 | API-Schlüssel (gehasht) | Hetzner, Deutschland (Falkenstein/Nürnberg) | Hetzner, Finnland (Tuusula) | Nur EWR | Nicht anwendbar |
| 3 | Absender- und Empfängeradressen | Hetzner, Deutschland (Falkenstein/Nürnberg) | Hetzner, Finnland (Tuusula) | Nur EWR | Nicht anwendbar |
| 4 | Nachrichteninhalt (Betreff, Text, Header) | Hetzner, Deutschland (Falkenstein/Nürnberg) | Hetzner, Finnland (Tuusula) | Nur EWR | Nicht anwendbar |
| 5 | Anhänge | Hetzner, Deutschland (Falkenstein/Nürnberg) | Hetzner, Finnland (Tuusula) | Nur EWR | Nicht anwendbar |
| 6 | Ereignisse und Protokolle (Zustellung, Öffnung, Klick, Bounce) | Hetzner, Deutschland (Falkenstein/Nürnberg) | Hetzner, Finnland (Tuusula) | Nur EWR | Nicht anwendbar |
| 7 | Authentifizierung (OAuth-Token, MFA-Geheimnisse) | Hetzner, Deutschland (Falkenstein/Nürnberg); Google LLC / GitHub, Inc. (OAuth) | Anbieter-verwaltet | EWR (Kern); US für OAuth-Anbieter | SCCs (OAuth-Anbieter) |
| 8 | Abrechnung (Rechnungen, Transaktionen, Zahlungstoken) | Hetzner, Deutschland; Stripe, Inc. (US) | Anbieter-verwaltet (Indien für Stripe-Support) | EWR (ApexMail); US/Indien (Stripe) | SCCs (Stripe) |
| 9 | Support-Tickets | Hetzner, Deutschland (Falkenstein/Nürnberg) | Hetzner, Finnland (Tuusula) | Nur EWR | Nicht anwendbar |
| 10 | Analytik (aggregierte Zustellmetriken, Engagement) | Hetzner, Deutschland (Falkenstein/Nürnberg) | Hetzner, Finnland (Tuusula) | Nur EWR | Nicht anwendbar |
| 11 | Sicherheitsprotokolle (Audit-Trails, Zugriffsprotokolle) | Hetzner, Deutschland (Falkenstein/Nürnberg) | Hetzner, Finnland (Tuusula) | Nur EWR | Nicht anwendbar |
| 12 | Backups (Datenbank, Dateispeicher-Snapshots) | Hetzner, Finnland (Tuusula) | Hetzner, Deutschland (Nürnberg, Cold Storage) | Nur EWR | Nicht anwendbar |

## Standorte der Unterauftragsverarbeiter

| Unterauftragsverarbeiter | Zweck | Standort | Übertragungsgarantie |
|---|---|---|---|
| Hetzner Online GmbH | Kerninfrastruktur (Compute, Storage, Netzwerk) | Deutschland, Finnland | Nicht anwendbar — EWR |
| Stripe, Inc. | Zahlungsabwicklung | US (primär), Indien (Support) | EU-Standardvertragsklauseln |
| Google LLC | Optionale OAuth-Authentifizierung | US | EU-Standardvertragsklauseln |
| GitHub, Inc. | Optionale OAuth-Authentifizierung | US | EU-Standardvertragsklauseln |

## Bereitstellungsmodelle

| Modell | Primäre Region | Kundenkontrolle |
|---|---|---|
| Shared EU Cloud | Deutschland, Finnland (Hetzner) | ApexMail-verwaltet |
| Dedicated Tenant | EU-Region nach Vereinbarung mit dem Kunden (Standard: Finnland oder Deutschland) | Single-Tenant, ApexMail-verwaltet |
| BYOC (Bring Your Own Cloud) | Vom Kunden gewählter Anbieter und Region | Kundenverwaltete Infrastruktur, ApexMail-verwaltete Anwendungsschicht |

## Kontakt

Für Anfragen zum Datenstandort: **privacy@apexmail.ee**
