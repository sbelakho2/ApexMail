+++
title = "Vereinbarung zur Auftragsverarbeitung"
description = "ApexMail-Auftragsverarbeitungsvereinbarung — Datenverarbeitungsbedingungen nach Art. 28 DSGVO."
template = "prose.html"

[extra]
last_updated = "2026-07-30"
+++

## 1. Geltungsbereich

Diese Vereinbarung zur Auftragsverarbeitung („AVV") ergänzt die Nutzungsbedingungen und regelt die Verarbeitung personenbezogener Daten durch **Bel Consulting OÜ** (Registernummer 16588745, USt-IdNr. EE102951727, Sakala 7-2, 10141 Tallinn, Estland), handelnd als ApexMail („**Auftragsverarbeiter**") im Auftrag des Kunden („**Verantwortlicher**") gemäß Artikel 28 der Verordnung (EU) 2016/679 (Datenschutz-Grundverordnung).

## 2. Begriffsbestimmungen

Die in dieser AVV verwendeten Begriffe haben die in der DSGVO festgelegten Bedeutungen, sofern nicht anders definiert.

## 3. Verarbeitungsdetails

| Element | Beschreibung |
|---|---|
| **Gegenstand** | E-Mail-Versand, Zustellverfolgung, Analytik |
| **Dauer** | Laufzeit des Dienstleistungsvertrags |
| **Art** | Automatisierte Verarbeitung und Übermittlung von E-Mail-Nachrichten |
| **Zweck** | Bereitstellung von E-Mail-Infrastrukturdiensten |
| **Datenkategorien** | E-Mail-Adressen, Nachrichteninhalte, Zustellmetadaten, IP-Adressen |
| **Betroffene Personen** | Endnutzer des Kunden (E-Mail-Empfänger) |

## 4. Pflichten des Auftragsverarbeiters

Der Auftragsverarbeiter verpflichtet sich:
- Daten nur auf dokumentierte Weisung des Verantwortlichen zu verarbeiten.
- Sicherzustellen, dass das Personal zur Vertraulichkeit verpflichtet ist.
- Geeignete technische und organisatorische Maßnahmen umzusetzen (Artikel 32).
- Den Verantwortlichen bei der Beantwortung von Anträgen betroffener Personen zu unterstützen.
- Alle personenbezogenen Daten nach Beendigung der Vereinbarung zu löschen oder zurückzugeben.
- Alle erforderlichen Informationen zum Nachweis der Einhaltung von Artikel 28 bereitzustellen.
- Audits und Inspektionen durch den Verantwortlichen oder einen beauftragten Prüfer zu ermöglichen.

## 5. Unterauftragsverarbeiter

### 5.1 Autorisierte Unterauftragsverarbeiter

Die aktuelle Liste der autorisierten Unterauftragsverarbeiter wird im [ApexMail-Unterauftragsverarbeiter-Register](https://apexmail.ee/subprocessors/) geführt und durch Verweis in diese AVV einbezogen.

| Unterauftragsverarbeiter | Zweck | Standort | Übertragungsgarantie |
|---|---|---|---|
| Hetzner Online GmbH | Kerninfrastruktur (Compute, Storage) | Konfigurierte EU/EWR-Region | Aktive Bereitstellung und anwendbare Übertragungsgarantie bestätigen |
| Amazon Web Services, Inc. | Telemetrie-Objektspeicher, wenn aktiviert | Konfigurierte S3-Region (Standard: `eu-central-1`) | Aktive Bereitstellung und anwendbare Übertragungsgarantie bestätigen |
| Amazon Web Services, Inc. | E-Mail-Zustelltransport, wenn aktiviert | Konfigurierte SES-Region | Aktive Bereitstellung und anwendbare Übertragungsgarantie bestätigen |
| Google LLC | Optionale OAuth-Authentifizierung | Global (US-Unternehmen, Datenverarbeitung gemäß OAuth-Konfiguration) | Standardvertragsklauseln |
| GitHub, Inc. | Optionale OAuth-Authentifizierung | Global (US-Unternehmen) | Standardvertragsklauseln |
| Stripe, Inc. | Zahlungsabwicklung | US (primär), Indien (Support) | Standardvertragsklauseln |

Self-gehostete Infrastruktur (ClickHouse, Redis) läuft auf Hetzner-Servern unter der operativen Kontrolle von ApexMail. Die Upstream-Open-Source-Herausgeber verarbeiten keine Kundendaten.

### 5.2 Benachrichtigung über Änderungen

Der Auftragsverarbeiter benachrichtigt den Verantwortlichen mindestens **30 Tage** vor Hinzufügung oder Ersetzung eines Unterauftragsverarbeiters und gibt dem Verantwortlichen Gelegenheit zum Widerspruch. Wenn der Verantwortliche aus angemessenen Datenschutzgründen widerspricht und keine Alternative gefunden werden kann, kann der Verantwortliche die betroffenen Dienste kündigen.

## 6. Internationale Übermittlungen

Die bereitgestellte Konfiguration zielt für Kerninfrastruktur und Telemetrie-Objektspeicher auf EU/EWR-Regionen. Aktive Anbieter und Standorte hängen von der Bereitstellung ab; siehe die [Datenstandorte](/data-locations/) Seite für eine vollständige kategorieweise Matrix. Personenbezogene Daten werden nicht ohne angemessene Garantien (Standardvertragsklauseln oder einen Angemessenheitsbeschluss gemäß Artikel 45) außerhalb des EWR übermittelt.

## 7. Sicherheitsmaßnahmen

- AES-256-GCM-Verschlüsselung im Ruhezustand
- TLS 1.2+ bei der Übertragung (TLS 1.3 bevorzugt)
- Argon2id-Passwort-Hashing
- Audit-Protokollierung mit Hash-Ketten-Integrität
- SOC-2-orientierte Sicherheitskontrollen (derzeit nicht zertifiziert; Kontrollkartierung und Bereitschaftsbewertung im Gange)
- Zugriffskontrolle mit Multi-Faktor-Authentifizierung
- Kontinuierliches Schwachstellen-Scanning; unabhängiges Penetrationstestprogramm wird aufgebaut, erster Test geplant
- Behebung nach Schweregrad gemäß der Schwachstellenmanagement-Richtlinie von ApexMail

## 8. Meldung von Datenschutzverletzungen

Der Auftragsverarbeiter benachrichtigt den Verantwortlichen **unverzüglich**, nachdem er von einer Verletzung des Schutzes personenbezogener Daten Kenntnis erlangt hat, die Daten des Verantwortlichen betrifft. ApexMail strebt vertraglich eine erste Benachrichtigung innerhalb von 48 Stunden an, basierend auf den zu diesem Zeitpunkt nach vernünftigem Ermessen verfügbaren Informationen. Die Meldung umfasst:
- Art der Verletzung.
- Kategorien und ungefähre Anzahl der betroffenen Personen und Datensätze.
- Kontaktdaten des Datenschutzbeauftragten.
- Wahrscheinliche Folgen und ergriffene oder vorgeschlagene Maßnahmen.

## 9. Rückgabe und Löschung von Daten

Nach Beendigung der Vereinbarung gibt der Auftragsverarbeiter nach Wahl des Verantwortlichen alle im Auftrag des Verantwortlichen verarbeiteten personenbezogenen Daten zurück oder löscht sie, es sei denn, EU- oder estnisches Recht schreibt eine Aufbewahrung vor (z. B. Aufbewahrung von Abrechnungsunterlagen für 7 Jahre gemäß dem estnischen Rechnungslegungsgesetz).

## 10. Auditrechte

Der Verantwortliche kann in angemessenen Abständen ein Audit der Einhaltung dieser AVV durch den Auftragsverarbeiter verlangen. Das Audit erfolgt auf Kosten des Verantwortlichen und unterliegt der Vertraulichkeit.

## 11. Anwendbares Recht

Diese AVV unterliegt dem Recht der Republik Estland und der DSGVO. Streitigkeiten werden vor den Gerichten von Tallinn, Estland, beigelegt.
