+++
title = "Datenstandorte"
description = "ApexMail-Datenstandort-Matrix — wo jede Kategorie von Kundendaten gespeichert und verarbeitet wird."
template = "prose.html"

[extra]
last_updated = "2026-07-30"
+++

## Datenstandort-Matrix

Diese Matrix beschreibt die mitgelieferte EU/EWR-orientierte Bereitstellungskonfiguration und keine allgemeine Standortgarantie. Die Standardkonfiguration für Kern-E-Mail-Daten und Telemetrie zielt auf EWR-Regionen; aktive Speicherorte, aktivierte Anbieter und Übertragungsgarantien müssen für die bereitgestellte Umgebung und den anwendbaren Vertrag bestätigt werden.

Die unten genannten Einträge zu Dedicated Tenant und BYOC beschreiben ein Modell nur dann, wenn es in einer gesonderten schriftlichen Vereinbarung genehmigt wurde. Sie sind nicht Bestandteil der öffentlichen Self-Service-Tarife.

| # | Datenkategorie | Standardmäßiger primärer Standort | Standard-Backup / Replikat | Standard-Verarbeitungsregion | Übertragungsgarantie |
|---|---|---|---|---|---|
| 1 | Kontodaten (Name, E-Mail, Unternehmen, Adresse) | EU-Rechenzentrum — Deutschland | EU-Rechenzentrum — Finnland | EWR (keine Drittlandübermittlung) | Übermittlung innerhalb der EEA; die Kapitel-V-Regeln der DSGVO finden keine Anwendung |
| 2 | API-Schlüssel (gehasht) | EU-Rechenzentrum — Deutschland | EU-Rechenzentrum — Finnland | EWR (keine Drittlandübermittlung) | Übermittlung innerhalb der EEA; die Kapitel-V-Regeln der DSGVO finden keine Anwendung |
| 3 | Absender- und Empfängeradressen | EU-Rechenzentrum — Deutschland | EU-Rechenzentrum — Finnland | EWR (keine Drittlandübermittlung) | Übermittlung innerhalb der EEA; die Kapitel-V-Regeln der DSGVO finden keine Anwendung |
| 4 | Nachrichteninhalt (Betreff, Text, Header) | EU-Rechenzentrum — Deutschland | EU-Rechenzentrum — Finnland | EWR (keine Drittlandübermittlung) | Übermittlung innerhalb der EEA; die Kapitel-V-Regeln der DSGVO finden keine Anwendung |
| 5 | Anhänge | EU-Rechenzentrum — Deutschland | EU-Rechenzentrum — Finnland | EWR (keine Drittlandübermittlung) | Übermittlung innerhalb der EEA; die Kapitel-V-Regeln der DSGVO finden keine Anwendung |
| 6 | Ereignisse und Protokolle (Zustellung, Öffnung, Klick, Bounce) | EU-Rechenzentrum — Deutschland | EU-Rechenzentrum — Finnland | EWR (keine Drittlandübermittlung) | Übermittlung innerhalb der EEA; die Kapitel-V-Regeln der DSGVO finden keine Anwendung |
| 7 | Authentifizierung (OAuth-Token, MFA-Geheimnisse) | EU-Rechenzentrum — Deutschland; Google LLC / GitHub, Inc. (OAuth) | Anbieter-verwaltet | EWR (Kern); US für OAuth-Anbieter | SCCs (OAuth-Anbieter) |
| 8 | Abrechnung (Rechnungen, Transaktionen, Zahlungstoken) | EU-Rechenzentrum — Deutschland; Stripe, Inc. (US) | Anbieter-verwaltet (Indien für Stripe-Support) | EWR (ApexMail); US/Indien (Stripe) | SCCs (Stripe) |
| 9 | Support-Tickets | EU-Rechenzentrum — Deutschland | EU-Rechenzentrum — Finnland | EWR (keine Drittlandübermittlung) | Übermittlung innerhalb der EEA; die Kapitel-V-Regeln der DSGVO finden keine Anwendung |
| 10 | Analytik (aggregierte Zustellmetriken, Engagement) | EU-Rechenzentrum — Deutschland | EU-Rechenzentrum — Finnland | EWR (keine Drittlandübermittlung) | Übermittlung innerhalb der EEA; die Kapitel-V-Regeln der DSGVO finden keine Anwendung |
| 11 | Sicherheitsprotokolle (Audit-Trails, Zugriffsprotokolle) | EU-Rechenzentrum — Deutschland | EU-Rechenzentrum — Finnland | EWR (keine Drittlandübermittlung) | Übermittlung innerhalb der EEA; die Kapitel-V-Regeln der DSGVO finden keine Anwendung |
| 12 | Backups (Datenbank, Dateispeicher-Snapshots) | EU-Rechenzentrum — Finnland | EU-Rechenzentrum — Deutschland (verschlüsselter Cold Storage) | EWR (keine Drittlandübermittlung) | Übermittlung innerhalb der EEA; die Kapitel-V-Regeln der DSGVO finden keine Anwendung |

## Standorte der Unterauftragsverarbeiter

| Unterauftragsverarbeiter | Zweck | Standort | Übertragungsgarantie |
|---|---|---|---|
| Hetzner Online GmbH | Kerninfrastruktur (Compute, Storage, Netzwerk) | Deutschland und Finnland (EU) | Übermittlung innerhalb der EEA; die Kapitel-V-Regeln der DSGVO finden keine Anwendung |
| Amazon Web Services, Inc. (AWS S3) | Telemetrie-Objektspeicher, wenn aktiviert | Konfigurierte S3-Region (Standard: `eu-central-1`) | EU-Standardvertragsklauseln (AWS-DPA) |
| Amazon Web Services, Inc. (AWS SES) | E-Mail-Zustelltransport, wenn aktiviert | Konfigurierte SES-Region | EU-Standardvertragsklauseln (AWS-DPA) |
| Stripe, Inc. | Zahlungsabwicklung | US (primär), Indien (Support) | EU-Standardvertragsklauseln |
| Google LLC | Optionale OAuth-Authentifizierung | US | EU-Standardvertragsklauseln |
| GitHub, Inc. | Optionale OAuth-Authentifizierung | US | EU-Standardvertragsklauseln |

## Bereitstellungsmodelle

| Modell | Primäre Region | Kundenkontrolle |
|---|---|---|
| Shared EU Cloud | EU/EWR-orientierte Standardkonfiguration; aktive Regionen bestätigen | ApexMail-verwaltet |
| Dedicated Tenant | Mit dem Kunden vereinbarte Region | Single-Tenant, ApexMail-verwaltet |
| BYOC (Bring Your Own Cloud) | Vom Kunden gewählter Anbieter und Region | Kundenverwaltete Infrastruktur, ApexMail-verwaltete Anwendungsschicht |

## Kontakt

Für Anfragen zum Datenstandort: **privacy@apexmail.ee**
