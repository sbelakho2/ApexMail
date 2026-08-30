+++
title = "Datenschutzerklärung"
description = "ApexMail-Datenschutzerklärung — wie wir Ihre Daten erfassen, verwenden und schützen."
template = "prose.html"

[extra]
last_updated = "2026-05-02"
+++

## 1. Einleitung

Bel Consulting OÜ (Handelsname ApexMail) („wir", „uns") verpflichtet sich, Ihre Privatsphäre zu schützen. Diese Richtlinie erläutert, wie wir personenbezogene Daten erfassen, verwenden und schützen, wenn Sie unsere Dienste nutzen, in Übereinstimmung mit der Verordnung (EU) 2016/679 (Datenschutz-Grundverordnung) und dem estnischen Personendatenschutzgesetz (Isikuandmete kaitse seadus).

**Verantwortlicher:** Bel Consulting OÜ, Sakala 7-2, 10141 Tallinn, Estland.
**Registernummer:** 16588745
**USt-IdNr.:** EE102951727

## 2. Von uns erfasste Daten

- **Webseitenbesucher (Marketing-Website):** IP-Adresse, Browsertyp und User-Agent, Geräteinformationen, besuchte Seiten, Referrer-URL und Zeitstempel — automatisch über Server-Zugriffsprotokolle erhoben. Die Marketing-Website setzt keine Analyse-Skripte ein und bettet keine Tracking-Pixel oder Werbe-Cookies ein.
- **Interessenten:** Name, E-Mail-Adresse, Unternehmensname, Telefonnummer (falls angegeben) und Kommunikationsverlauf, bereitgestellt über Kontaktformulare oder E-Mail.
- **Kontodaten:** Name, E-Mail, Unternehmen, Rechnungsadresse, USt-IdNr., Zahlungsdaten-Tokens (Kartendaten werden von Stripe verarbeitet und erreichen niemals unsere Server), API-Schlüssel-Metadaten, Anmeldezeitstempel, IP-Adressen und Audit-Log-Einträge.
- **Nutzungsdaten:** API-Aufrufe, E-Mail-Versandvolumen, Zustellereignisse sowie Engagement-Ereignisse (Öffnungen und Klicks) für Ihre gesendeten Nachrichten.
- **Empfängerdaten (als Auftragsverarbeiter für unsere Kunden):** E-Mail-Adressen und Namen der Empfänger, E-Mail-Inhalte (Betreff, Text, Header, Anhänge) sowie Zustell- und Engagement-Metadaten. Wenn der versendende Kunde das Tracking aktiviert, werden bei Öffnungs- und Klick-Ereignissen zusätzlich IP-Adresse und User-Agent des Empfängers erfasst.
- **Technische Daten:** IP-Adressen (für Authentifizierung, Rate-Limiting sowie Betrugs- und Missbrauchsprävention), Browsertyp, Geräteinformationen.
- **KI-Verarbeitung:** Wenn Sie optionale KI-gestützte Funktionen nutzen, werden die von Ihnen übermittelten Betreffzeilen und Nachrichteninhalte verarbeitet, um die angeforderte Analyse zu erstellen (z. B. Betreffzeilen-Einblicke).

## 3. Rechtsgrundlage

Wir verarbeiten Daten gemäß DSGVO Art. 6 Abs. 1 lit. b) (Vertragserfüllung), Art. 6 Abs. 1 lit. f) (berechtigtes Interesse) und Art. 6 Abs. 1 lit. a) (Einwilligung), soweit anwendbar.

## 4. Datenspeicherung

Die bereitgestellte Konfiguration zielt für Kern-E-Mail-Daten und Telemetriespeicher auf EWR-Regionen. Aktive Standorte, aktivierte Unterauftragsverarbeiter und Übertragungsgarantien hängen von der bereitgestellten Umgebung und dem anwendbaren Vertrag ab. Eine vollständige Aufschlüsselung und den Bestätigungsprozess finden Sie auf unserer Seite [Datenstandorte](/de/data-locations/).

### Zusammenfassende Standort-Matrix

| Datenkategorie | Primärer Standort | Backup / Replikat | Verarbeitung |
|---|---|---|---|
| Kern-E-Mail-Infrastruktur (Nachrichten, Zustellmetadaten, Kontodaten) | EU-Rechenzentrum — Deutschland | EU-Rechenzentrum — Finnland | EWR — keine Drittlandübermittlung |
| OAuth-Authentifizierungstoken | Google LLC / GitHub, Inc. (US-Unternehmen, SCCs) | Anbieter-verwaltet | US (SCCs) |
| Zahlungs- und Abrechnungsdaten | Stripe, Inc. (US, SCCs) | Anbieter-verwaltet (Indien für Support) | US/Indien (SCCs) |
| Support-Tickets | EU-Rechenzentrum — Deutschland | EU-Rechenzentrum — Finnland | EWR — keine Drittlandübermittlung |

Wir übermitteln keine personenbezogenen Daten außerhalb des EWR ohne angemessene Garantien (Standardvertragsklauseln oder einen Angemessenheitsbeschluss gemäß Artikel 45).

## 5. Datenspeicherfristen

Wir bewahren personenbezogene Daten nur so lange auf, wie es für die Zwecke, für die sie erhoben wurden, erforderlich ist:

| Datenkategorie | Aufbewahrungsfrist |
|---|---|
| Kontodaten | Vertragsdauer + 30 Tage |
| Abrechnungsunterlagen | 7 Jahre (estnisches Rechnungslegungsrecht) |
| E-Mail-Inhalte (Text, Betreff, Header, Anhänge) | Standardmäßig 7 Tage; planabhängiges Maximum (von 1 Tag im Free-Plan bis 730 Tage bei Enterprise) |
| Ereignisprotokolle (Zustell-, Öffnungs- und Klick-Ereignisse) | Standardmäßig 30 Tage; planabhängiges Maximum (bis 730 Tage bei Enterprise) |
| Support-Tickets | 2 Jahre nach Lösung |

Vollständige Details finden Sie in unserer [Datenaufbewahrungsrichtlinie](/compliance/#data-retention).

## 6. Ihre Rechte

Gemäß der DSGVO haben Sie folgende Rechte:

- **Auskunftsrecht** (Art. 15) — Bestätigung, ob wir Ihre Daten verarbeiten, und Zugang zu diesen Daten.
- **Recht auf Berichtigung** (Art. 16) — Korrektur unrichtiger Daten.
- **Recht auf Löschung** (Art. 17) — Löschung Ihrer Daten („Recht auf Vergessenwerden").
- **Recht auf Einschränkung der Verarbeitung** (Art. 18) — Einschränkung der Verarbeitung unter bestimmten Bedingungen.
- **Recht auf Datenübertragbarkeit** (Art. 20) — Erhalt Ihrer Daten in einem strukturierten, maschinenlesbaren Format.
- **Widerspruchsrecht** (Art. 21) — Widerspruch gegen die Verarbeitung aufgrund berechtigter Interessen.

Zur Ausübung dieser Rechte kontaktieren Sie uns unter **privacy@apexmail.ee**. Wir antworten innerhalb von 30 Tagen.

## 7. Beschwerden

Wenn Sie der Ansicht sind, dass unsere Verarbeitung Ihrer personenbezogenen Daten gegen die DSGVO verstößt, haben Sie das Recht, Beschwerde bei der **Estnischen Datenschutzinspektion** (Andmekaitse Inspektsioon) einzulegen:

- **Website:** https://www.aki.ee
- **Adresse:** Väike-Ameerika 19, 10129 Tallinn, Estland
- **E-Mail:** info@aki.ee

## 8. Cookies

Siehe unsere [Cookie-Richtlinie](/de/cookies/) für Details zu Cookies und Tracking.

## 9. Kontakt

Für Datenschutzanfragen: **privacy@apexmail.ee**
Datenschutzbeauftragter: Bel Consulting OÜ, Sakala 7-2, 10141 Tallinn, Estland
