+++
title = "Lösung für Transaktions-E-Mails"
description = "Anwendungsgesteuerte Transaktions-E-Mails: Passwort-Resets, Bestellbestätigungen, Benachrichtigungen. REST-API und SMTP-Relay mit signierten Webhooks und EU/EWR-orientierten Bereitstellungsoptionen."
template = "prose.html"
+++

## Transaktions-E-Mails

Senden Sie anwendungsgenerierte E-Mails über die REST-API oder das SMTP-Relay von ApexMail. Jede Nachricht wird von der Annahme bis zur Zustellung mit Ereignisverlauf pro Nachricht verfolgt.

## Zielgruppe

Entwicklungsteams, die Anwendungen mit automatisierten E-Mails bauen: Passwort-Resets, Konto-Verifizierungen, Kaufbestätigungen, Versandbenachrichtigungen, Sicherheitswarnungen und System-Status-Updates.

## Geschäftskontext

Transaktions-E-Mails sind geschäftskritische Infrastruktur. Verzögerte Passwort-Resets blockieren Nutzer. Fehlende Bestellbestätigungen erzeugen Support-Tickets. Verlorene Benachrichtigungen beschädigen Vertrauen. Die E-Mail-Schicht muss schnell, beobachtbar und zuverlässig sein, ohne die Entwicklung vom Produkt abzuziehen.

## Kernproblem

- Die Zustellbarkeit variiert je nach Empfänger-Anbieter, Domain-Reputation und Authentifizierungsqualität.
- Eingebettete SMTP-Bibliotheken verursachen Wartungsaufwand und verdecken Zustellfehler.
- Ohne Webhook-Ereignisse pro Nachricht können Teams stille Zustellfehler nicht erkennen.
- Warteschlangen-Stau bei Anbieter-Ausfällen erfordert Wiederholungslogik und Timeout-Management.

## Die ApexMail-Lösung

- **REST-API** (`POST /v1/messages`) — JSON-Payloads mit Idempotenzschlüsseln. Einreichen und fertig.
- **SMTP-Relay** (`smtp.apexmail.ee:587` mit STARTTLS) — Direkter Ersatz für bestehende SMTP-Clients.
- **Isolierte Sendekonfiguration** — Dedizierte IPs, benutzerdefinierte Domains und Suppressionslisten lassen sich je E-Mail-Typ abgrenzen.
- **Signierte Webhooks** — Echtzeit-Ereignisse `delivered`, `bounced`, `complained`, `opened`, `clicked`, jedes mit eindeutiger Ereignis-ID und HMAC-Signatur.
- **Idempotenz** — Deduplizieren Sie Übermittlungen mit clientseitig bereitgestellten Schlüsseln. Nach Netzwerkfehlern sicher erneut übermitteln.

## Technische Umsetzung

1. Erstellen Sie einen API-Key unter **Dashboard → Einstellungen → API-Keys**.
2. Verifizieren Sie Ihre Sende-Domain (SPF, DKIM, benutzerdefinierter Return-Path).
3. Konfigurieren Sie eine dedizierte Sende-Domain (und auf berechtigten Tarifen eine dedizierte IP) für Ihren E-Mail-Typ.
4. Senden Sie über REST oder SMTP.
5. Registrieren Sie einen Webhook-Endpunkt für den Empfang von Zustellereignissen.
6. Überwachen Sie Zustellmetriken im Dashboard oder über die Analytik-API.

## Relevante API-Endpunkte

| Endpunkt | Beschreibung |
|---|---|
| `POST /v1/messages` | E-Mail senden |
| `GET /v1/messages/:id` | E-Mail-Status und Ereignisse abrufen |
| `POST /v1/messages/:id/cancel` | Geplanten Versand abbrechen |
| `POST /v1/messages/batch` | Bis zu 100 Nachrichten in einer Anfrage senden |

## Relevante Webhook-Ereignisse

| Ereignis | Auslöser |
|---|---|
| `message.sent` | Nachricht zur Zustellung angenommen |
| `message.delivered` | Empfangender Server hat die Nachricht angenommen |
| `message.bounced` | Hard- oder Soft-Bounce |
| `message.complained` | Empfänger hat als Spam gemeldet |
| `message.opened` | Öffnung erkannt (Tracking-Pixel) |
| `message.clicked` | Linkklick erkannt |

## Erforderlicher Tarif

| Tarif | Monatliches Volumen | Support |
|---|---|---|
| Free | 3.000 E-Mails | Community |
| Starter | 50.000 E-Mails | E-Mail-Support |
| Pro | 150.000 E-Mails | E-Mail-Support |
| Growth | 500.000 E-Mails | E-Mail-Support |
| Scale | 2.000.000 E-Mails | Prioritäts-Support |
| Enterprise | 5.000.000 E-Mails | Dedizierter Support |

## Sicherheitshinweise

- API-Keys gelten je Umgebung (live/test). Test-Keys stellen an Test-Postfächer zu.
- Webhooks sind HMAC-signiert. Validieren Sie Signaturen, bevor Sie Ereignisse verarbeiten.
- TLS 1.2+ ist für alle API- und SMTP-Verbindungen erforderlich.
- Nachrichteninhalte werden im Ruhezustand verschlüsselt. Die Inhaltsaufbewahrung ist je Tarif konfigurierbar.

## Compliance-Hinweise

- EU/EWR-orientierte Bereitstellungsoptionen; bestätigen Sie aktive Datenstandorte und Übertragungsgarantien für die Bereitstellung.
- Eine AVV ist im Rahmen der anwendbaren ApexMail-Vereinbarung verfügbar.
- HIPAA-Verfügbarkeit und BAAs werden derzeit nicht angeboten.
- Der Kunde ist für Empfänger-Einwilligungen und das Abmeldemanagement verantwortlich.

## Bekannte Einschränkungen

- Ereignisprotokolle werden standardmäßig 30 Tage aufbewahrt (7 Tage im Free-Tarif); Nachrichteninhalte standardmäßig 7 Tage, tarifabhängig bis zu 730 Tage.
- Die Anhangsgröße ist auf 25 MB pro Nachricht begrenzt.
- Öffnungs- und Klick-Tracking erfordern einen HTML-Body mit Tracking-Pixel bzw. Links.

## Empfohlener nächster Schritt

[Kostenloses Konto erstellen](https://app.apexmail.ee/signup) und Ihre erste E-Mail über die REST-API oder das SMTP-Relay senden.
