+++
title = "Unterauftragsverarbeiter"
description = "ApexMail-Unterauftragsverarbeiter-Register — die Liste der autorisierten Dienstleister, die Daten in unserem Auftrag verarbeiten."
template = "prose.html"

[extra]
last_updated = "2026-07-29"
+++
## Unterauftragsverarbeiter-Register

Diese Seite listet Drittanbieter auf, die von der Bel Consulting OÜ (handelnd als ApexMail) beauftragt werden und im Rahmen der Erbringung des ApexMail-Dienstes personenbezogene Daten von Kunden verarbeiten können. Dieses Register wird gemäß Artikel 28 der DSGVO und Abschnitt 5 der ApexMail-Auftragsverarbeitungsvereinbarung geführt.

### Infrastruktur-Unterauftragsverarbeiter

Die folgenden Drittunternehmen verarbeiten personenbezogene Daten von Kunden im Auftrag von ApexMail.

| Juristische Person | Marke | Dienst | Zweck | Datenkategorien | Verarbeitungsland | Speicherland | Unternehmenssitz | Übermittlungsmechanismus | Erforderlich |
|---|---|---|---|---|---|---|---|---|---|
| Hetzner Online GmbH | Hetzner | Cloud-Hosting | Compute, Storage, Networking | Kerndienstdaten in der standardmäßigen Shared-Bereitstellung | Konfigurierte EU/EWR-Region | Konfigurierte EU/EWR-Region | Deutschland | Verarbeitung innerhalb des EWR; die Übermittlungsregeln nach Kapitel V DSGVO gelten nicht | Ja |
| Amazon Web Services, Inc. | AWS S3 | Telemetrie-Objektspeicher | Telemetrie-Objektspeicher, wenn aktiviert | Loki-Logs und Tempo-Traces können Betriebsmetadaten enthalten | Konfigurierte S3-Region (Standard: `eu-central-1`) | Konfigurierte S3-Region (Standard: `eu-central-1`) | USA | EU-Standardvertragsklauseln (AWS-DPA) | Nein — nur wenn die aktive Bereitstellung S3-Speicher verwendet |
| Amazon Web Services, Inc. | AWS SES | E-Mail-Zustelltransport | E-Mail-Zustellung, wenn aktiviert | E-Mail-Inhalte und Empfängeradressen | Konfigurierte SES-Region | Konfigurierte SES-Region | USA | EU-Standardvertragsklauseln (AWS-DPA) | Nein — nur wenn die aktive Bereitstellung SES verwendet |
| Google LLC | Google | OAuth-Authentifizierung | Anmeldung über Google OAuth | OAuth-Tokens, E-Mail-Adresse, Name | Global (EU-Daten) | Nutzer mit Sitz im EWR: EWR | USA | Standardvertragsklauseln (SCCs) | Nein — nur wenn der Kunde Google OAuth aktiviert |
| GitHub, Inc. | GitHub | OAuth-Authentifizierung | Anmeldung über GitHub OAuth | OAuth-Tokens, Benutzername, E-Mail-Adresse | Global (EU-Daten) | Nutzer mit Sitz im EWR: EWR | USA | Standardvertragsklauseln (SCCs) | Nein — nur wenn der Kunde GitHub OAuth aktiviert |
| Stripe, Inc. | Stripe | Zahlungsabwicklung | Abonnement-Abrechnung, Rechnungsstellung, Speicherung von Zahlungsmethoden | Tokens für Zahlungsmethoden, Transaktionsmetadaten, Rechnungsdaten | USA (primär); Indien (Support) | USA | USA | Standardvertragsklauseln (SCCs) gemäß Stripe-DPA | Ja — erforderlich für kostenpflichtige Tarife |

### Selbst gehostete Infrastruktur (keine Drittanbieter-Unterauftragsverarbeiter)

Die folgende Software wird von ApexMail auf Hetzner-Infrastruktur bereitgestellt und betrieben. Die Software-Herausgeber verarbeiten keine Kundendaten.

| Software | Zweck | Datenkategorien | Verarbeitungsland | Speicherland | Hinweise |
|---|---|---|---|---|---|
| ClickHouse (Open Source) | Analytik-Datenbank | Zustellereignisse, Öffnungs- und Klickereignisse, Bounce- und Beschwerdedaten | Konfigurierte Bereitstellungsregion | Konfigurierte Bereitstellungsregion | Von ApexMail selbst gehostet. ClickHouse, Inc. verarbeitet keine Kundendaten. |
| Redis (Open Source) | In-Memory-Cache | Sitzungstokens, Zähler für Ratenbegrenzung | Konfigurierte Bereitstellungsregion | Konfigurierte Bereitstellungsregion | Von ApexMail selbst gehostet. Redis Ltd. verarbeitet keine Kundendaten. |

### Benachrichtigung

Kunden werden mindestens **30 Tage** vor der Einbindung eines neuen Unterauftragsverarbeiters benachrichtigt. Um Benachrichtigungen zu erhalten, abonnieren Sie [subprocessor-notifications@apexmail.ee](mailto:subprocessor-notifications@apexmail.ee) oder beobachten Sie diese Seite.

### Widerspruch

Wenn Sie aus berechtigten datenschutzrechtlichen Gründen Widerspruch gegen einen neuen Unterauftragsverarbeiter einlegen, kontaktieren Sie [privacy@apexmail.ee](mailto:privacy@apexmail.ee). Kann keine Alternative gefunden werden, können Sie die betroffenen Dienste gemäß der AVV kündigen.

### Änderungsverlauf

| Datum | Änderung | Beschreibung |
|---|---|---|
| 2026-07-29 | Erstveröffentlichung | Unterauftragsverarbeiter-Register veröffentlicht mit Hetzner (Infrastruktur), AWS (S3/SES, wenn aktiviert), Google (OAuth), GitHub (OAuth) und Stripe (Zahlungen). ClickHouse und Redis sind selbst gehostete Software und keine Unterauftragsverarbeiter (siehe oben). |
