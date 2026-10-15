+++
title = "Von Resend zu ApexMail migrieren"
description = "Migrieren Sie eine Resend-Integration zu ApexMail über einen Basis-URL-Wechsel: POST /emails und POST /emails/batch akzeptieren Ihren ApexMail-API-Schlüssel im Authorization-Bearer-Slot, den Sie bereits senden, mit exakter Feldzuordnung, benannten Ablehnungen, der DNS-Checkliste und einem 10/50/100-Umschaltplan."
template = "prose.html"

[extra]
last_updated = "2026-10-15"
og_image = "/images/og-image.png"
+++

ApexMail bedient `POST /emails` und `POST /emails/batch` auf einer Resend-Kompatibilitätsoberfläche. Die Routen übersetzen die JSON-Nutzlasten in die kanonische Sende-Anfrage und rufen dann dieselben Handler auf, die `POST /v1/messages` und `POST /v1/messages/batch` nutzen. Absenderdomain-Prüfung, Unterdrückungs- und Einwilligungsfilter, Tarifberechtigungen, das dauerhafte Idempotenz-Ledger und der Queue-Eintrag laufen damit an einer Stelle. Ihre Integration behält ihre Nutzlastform und ihren Bearer-Header; geändert werden Host und Schlüssel.

## Endpunkt-Zuordnung

| Resend-Endpunkt | ApexMail-Kompatibilitätsoberfläche | Nativer ApexMail-Endpunkt |
|---|---|---|
| `POST https://api.resend.com/emails` | `POST https://api.apexmail.ee/emails` | `POST https://api.apexmail.ee/v1/messages` |
| `POST https://api.resend.com/emails/batch` | `POST https://api.apexmail.ee/emails/batch`, bis zu 100 E-Mails | `POST https://api.apexmail.ee/v1/messages/batch`, bis zu 100 Nachrichten pro Aufruf |
| `GET /emails/:id` (Abruf) | Nicht bedient | `GET /v1/messages/{id}` |

Ein erfolgreicher Versand antwortet mit `200` und `{"id": "<kanonische Nachrichten-ID>"}`. Die Batch-Route antwortet mit `{"data": […]}` in Anfragereihenfolge: Jede Position trägt entweder `{"id": …}` oder ein `error`-Objekt mit der Ablehnung, sodass ein teilweiser Batch nie als voller Erfolg gemeldet wird. Die ID ist die kanonische Nachrichten-ID, dieselbe, die `GET /v1/messages/{id}` liefert und die Webhook-Ereignisse in `data.messageId` tragen.

## Authentifizierung umstellen

Ihr Credential-Slot bleibt bestehen. Resend sendet `Authorization: Bearer`; ersetzen Sie den Schlüssel durch den ApexMail-API-Schlüssel (`am_live_…` oder `am_test_…`) und geben Sie ihm den Scope `messages:send`.

| Element | Resend heute | ApexMail-Kompatibilitätsoberfläche |
|---|---|---|
| Credential-Header | `Authorization: Bearer re_…` | `Authorization: Bearer am_live_…` |
| Scope | Vollzugriff oder Sende-Schlüssel | `messages:send` |
| Idempotenz | Header `Idempotency-Key` | Derselbe Header gegen das dauerhafte Ledger von ApexMail; derselbe Schlüssel innerhalb von 24 Stunden liefert die ursprüngliche Antwort einschließlich derselben ID |
| Betreff-Klasse | Kein Anbieterkonzept | `X-ApexMail-Category: transactional` (oder `service`) befreit den Versand vom Marketing-Präferenzfilter; ohne Header zählt der Versand als Standardklasse `marketing` und der Einwilligungsfilter greift |

## Feldzuordnung

Die kanonischen Feldnamen entsprechen dem Vertrag von `POST /v1/messages`, sodass dasselbe Nutzlastverständnis bei einem späteren Wechsel zur nativen API gilt.

| Resend-Feld | Kanonisches Feld | Hinweise |
|---|---|---|
| `from` | `from` | Erforderlich |
| `to` | `to` | Ein einzelner String, ein Array oder `{email, name}`-Objekte |
| `cc` / `bcc` | `cc` / `bcc` | |
| `subject` | `subject` | |
| `html` / `text` | `html` / `text` | |
| `reply_to` | `reply_to` | |
| `headers` (Objekt) | `headers` | String-Werte |
| `attachments[].filename` / `.content` / `.content_type` | `attachments[]` (`filename`, `content`, `contentType`) | `content_type` hat den Standardwert `application/octet-stream` |
| `tags[].name` / `.value` | `tags` | Jedes Paar wird zu `"name:value"` |
| `scheduled_at` (ISO 8601) | `scheduled_at` | Nur RFC-3339-Zeitstempel |
| `X-ApexMail-Category`-Header | `category` | Wird vom kanonischen Normalisierer validiert |

## Felder, die die Oberfläche benannt ablehnt

Jede dieser Konstruktionen wird in Resends eigener Fehlerform `{"statusCode": <code>, "name": "<name>", "message": "…"}` abgelehnt: `statusCode` 422 mit `name` `validation_error` bei Validierungsablehnungen, `401` `invalid_api_key` oder `missing_api_key` bei Credential-Ablehnungen und `403` `restricted_api_key` bei einem Schlüssel ohne den Scope `messages:send`.

| Resend-Konstrukt | Ablehnung |
|---|---|
| `attachments[].path` | Remote-Anhangs-URLs werden nicht abgerufen; senden Sie die Datei als Base64-`content` |
| `template` | Vorlagen haben kein kanonisches Äquivalent auf dieser Oberfläche; nutzen Sie die native ApexMail-API für Vorlagen |
| `topic_id`, `audience_id`, `broadcast_id` | Audiences, Topics und Broadcasts haben kein kanonisches Äquivalent auf dieser Oberfläche; nutzen Sie die native API für Listen |
| Ein natürlichsprachiges `scheduled_at` (`"in 1 min"`) | Ein ISO-8601-Zeitstempel (RFC 3339) ist erforderlich; natürlichsprachige Planungen werden nicht unterstützt |
| Ein Batch-Array mit mehr als 100 E-Mails | Ein Resend-Batch trägt höchstens 100 E-Mails |
| Jedes weitere Feld auf oberster Ebene | Kein kanonisches Äquivalent |

## Was noch nicht weitergeleitet wird

Die Kompatibilitätsoberfläche bedient die beiden Sende-Routen. Für die folgenden Resend-APIs gibt es keine Kompatibilitätsroute; nutzen Sie die native ApexMail-API oder das Dashboard.

- Vorlagen (`template`) und der Pfad für gerenderte Vorlagen.
- Audiences, Kontakte, Topics und Broadcasts; ApexMail-Kampagnen, Listen und Segmente decken diese über die native API ab.
- Domain-Verwaltung (`/domains`): Domains werden im ApexMail-Dashboard oder über `POST /v1/domains` hinzugefügt und verifiziert.
- API-Schlüsselverwaltung, Webhook-Abonnement-CRUD und das Ereignisprotokoll; Webhook-Abonnements laufen über `POST /v1/webhooks`.
- Anhänge von einer Remote-URL und natürlichsprachige Planung.
- Inbound-Empfang (`email.received`). Die Inbound-Pipeline von ApexMail sendet das Ereignis `inbound`, und Inbound-E-Mail ist auf Business und Enterprise Cloud verfügbar.

## DNS: Was sich ändert und was bleibt

Ihre Sende-Domain bleibt Ihre Domain, und ApexMail signiert DKIM mit einem pro Domain erzeugten Selektor auf derselben Domain. Fügen Sie die vier Records aus `GET /v1/domains/:id/dns-records` neben den Resend-Records hinzu; entfernen Sie die Resend-Records erst nach der Umschaltung und dem Aufbewahrungsfenster.

| Resend-Record | ApexMail-Äquivalent |
|---|---|
| DKIM-Record (der TXT-Record des Anbieters für die Domain) | Direkter TXT-Record unter `<selector>._domainkey.<domain>` mit dem DKIM-Public-Key. Ein direkter TXT-Record, kein CNAME |
| Return-Path-Records (MX- und SPF-TXT-Records des Anbieters auf seiner eigenen Subdomain) | MX-Record unter `bounce.<domain>`, Priorität 10, auf den Feedback-Host der Region, plus TXT-Record unter `bounce.<domain>` mit dem SPF-Wert der benutzerdefinierten MAIL-FROM-Domain |
| Click-Tracking-CNAME (wenn Tracking Ihre Domain nutzt) | Kein Branded-Link-CNAME nötig. ApexMail schreibt Links auf die eigenen Tracking-Pfade um; eine benutzerdefinierte Tracking-Domain (CNAME auf einer Subdomain einer verifizierten Domain) ist ab Pro verfügbar |
| Domain-Authentifizierung | TXT-Record unter `_dmarc.<domain>` mit Ihrer DMARC-Richtlinie |

Checkliste:

1. Fügen Sie die Sende-Domain im Dashboard hinzu und rufen Sie ihre DNS-Records ab.
2. Veröffentlichen Sie die vier ApexMail-Records; lassen Sie die Resend-Records bestehen.
3. Behalten Sie die Resend-Records, solange Resend sendet; die Return-Path-Records seiner Subdomain sind unabhängig von ApexMails `bounce.<domain>`-Records.
4. Führen Sie die Domain-Verifizierung aus und prüfen Sie, dass der DKIM-Selektor auflöst.
5. Lassen Sie DMARC-Reporting (rua) während des Übergangs aktiv.
6. Entfernen Sie nach Umschaltung und Aufbewahrungsfenster die Resend-Records und widerrufen Sie den alten Schlüssel.

## Vorlagen

Resend-Vorlagen werden nicht weitergeleitet, und `template` wird benannt abgelehnt. Zwei Konvertierungspfade:

- Rendern Sie den Body in Ihrer Anwendung und senden Sie `html` und `text` über dieselbe Kompatibilitätsroute. Kein Migrationsaufwand für Vorlagen, und der Versand behält seine Nutzlastform.
- Erstellen Sie eine Vorlage über `POST /v1/templates` und senden Sie sie mit `template_id` plus `template_data` über das native `POST /v1/messages`. Platzhalter werden als `{{variable}}` geschrieben; ein nicht aufgelöster Platzhalter wird unverändert gerendert statt als leerer String, sodass eine fehlende Variable in der Vorschau sichtbar ist.

Die dreifache Klammerform `{{{variable}}}` von Resend und seine React-Email-Komponenten rendern in Ihrer Anwendung oder in Ihrem Build-Schritt; der Platzhalter-Renderer akzeptiert `{{variable}}`-Substitution, daher konvertieren Sie solche Bodies zu HTML, bevor Sie die ApexMail-Vorlage erstellen.

## Webhooks

Richten Sie Ihren Endpunkt auf ApexMail, abonnieren Sie die genutzten Ereignisse und prüfen Sie die ApexMail-Signatur: `X-ApexMail-Signature: sha256=<hex>` über den rohen Request-Body zusammen mit `X-ApexMail-Timestamp`. Die Zustellung erfolgt mindestens einmal, daher deduplizieren Sie über das `id`-Feld des Ereignisses.

| Resend-Ereignis | ApexMail-Ereignis | Hinweise |
|---|---|---|
| `email.sent` | `message.accepted` | Zur Zustellung angenommen |
| `email.scheduled` | `message.accepted` | Der geplante Versand wird beim Einreihen angenommen |
| `email.delivered` | `message.delivered` | Empfangender Server hat die Nachricht angenommen |
| `email.delivery_delayed` | `message.deferred` | 4xx-Aufschub; ein Retry ist geplant |
| `email.bounced` | `message.bounced` | Hard-Bounce |
| `email.complained` | `message.complained` | |
| `email.opened` | `message.opened` | |
| `email.clicked` | `message.clicked` | |
| `email.failed` (nächstliegende Zuordnung) | `message.bounced` | Ablehnungen zum Annahmezeitpunkt kommen stattdessen in der API-Antwort zurück |
| `email.received` | `inbound` | Inbound-E-Mail ist auf Business und Enterprise Cloud verfügbar |

Die Payload-Form ändert sich mit dem Anbieter: ApexMail-Ereignisse nutzen den Umschlag `{id, event, timestamp, data}`, mit `data.messageId` bei Nachrichtenereignissen und `data.email` bei Unterdrückungsereignissen.

## Umschaltplan

Die Umschaltung ist ein Host-Wechsel pro Route oder pro Umgebung; ein Rollback ist derselbe Wechsel rückwärts. Es gibt keine Nutzlast- oder Vorlagenänderung, die zurückgebaut werden müsste.

| Schritt | Aktion | Abbruchkriterien | Rollback |
|---|---|---|---|
| 1. Bereitstellen | Konto erstellen, Sende-Domain hinzufügen und verifizieren, API-Schlüssel mit `messages:send` anlegen, Webhook-Ereignisse abonnieren | Verifizierung besteht; eine Testnachricht wird aus einer Staging-Umgebung versendet | Noch kein Produktionsverkehr |
| 2. Parallel validieren | Dieselben Nutzlasten an `https://api.apexmail.ee/emails` mit dem ApexMail-Schlüssel im Bearer-Slot senden; Antworten, IDs und Webhook-Ereignisse vergleichen | `200` mit einer ID bei jedem Test; Ereignisse kommen mit gültigen Signaturen an | Testroute zurück auf Resend richten |
| 3. 10 % verschieben | 10 % der Produktionssendungen über die Kompatibilitätsroute leiten; Bounce- und Beschwerdequoten gegen die AUP-Schwellenwerte beobachten (2 % Bounce, 0,1 % Beschwerden) | Zustellmetriken entsprechen Resend innerhalb der vereinbarten Toleranz im Beobachtungsfenster | Route zurückwechseln; Resend behält die übrigen 90 % |
| 4. 50 % verschieben | Den Anteil auf 50 % erhöhen, sobald das Fenster sauber schließt; beide Anbieter senden von derselben Domain | Anhaltende Parität beim höheren Anteil | Zurück auf 100 % Resend wechseln |
| 5. Auf 100 % umstellen | Alle Sendungen über `POST /emails` (und `/emails/batch`) auf ApexMail leiten | Volles Volumen auf ApexMail mit sauberen Metriken | Zurückwechseln; Schlüssel bleiben während des Aufbewahrungsfensters aktiv |
| 6. Alten Pfad stilllegen | Resend-DNS-Records entfernen, Schlüssel widerrufen, Vorlagen- und Audience-Konfiguration stilllegen | Records lösen nur noch auf ApexMail auf | Records aus Ihrer Änderungsdokumentation wiederherstellen |

## Nächste Schritte

- Vergleichen Sie beide Plattformen Merkmal für Merkmal im [Vergleich ApexMail vs. Resend](/de/compare/resend/).
- Lesen Sie die [API-Übersicht](/docs/api/) und die [OpenAPI-Spezifikation](/docs/api/openapi/) für den nativen Vertrag, einschließlich Batch-Versand und Vorlagen.
- Lesen Sie [Webhooks](/docs/webhooks/) für die Ereignis-Payload-Schemas und die Signaturprüfung.
- [Kontaktieren Sie den Vertrieb](/de/contact/sales/) für eine Migrationsbewertung, wenn Resend-Vorlagen, Audiences oder Broadcasts Teil Ihres Produktionsverkehrs sind.
