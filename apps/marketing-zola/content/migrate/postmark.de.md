+++
title = "Von Postmark zu ApexMail migrieren"
description = "Migrieren Sie eine Postmark-Integration zu ApexMail über einen Basis-URL-Wechsel: POST /email und POST /email/batch akzeptieren Ihren ApexMail-API-Schlüssel im Header X-Postmark-Server-Token, mit MessageStream-Zuordnung, benannten Ablehnungen, der DNS-Checkliste und einem 10/50/100-Umschaltplan."
template = "prose.html"

[extra]
last_updated = "2026-10-15"
og_image = "/images/og-image.png"
+++

ApexMail bedient `POST /email` und `POST /email/batch` auf einer Postmark-Kompatibilitätsoberfläche. Die Routen übersetzen die JSON-Nutzlasten in die kanonische Sende-Anfrage und rufen dann dieselben Handler auf, die `POST /v1/messages` und `POST /v1/messages/batch` nutzen. Absenderdomain-Prüfung, Unterdrückungs- und Einwilligungsfilter, Tarifberechtigungen, das Idempotenz-Ledger und der Queue-Eintrag laufen damit an einer Stelle. Ihre Integration behält ihre Nutzlastform und ihren Header; geändert werden Host und Token.

## Endpunkt-Zuordnung

| Postmark-Endpunkt | ApexMail-Kompatibilitätsoberfläche | Nativer ApexMail-Endpunkt |
|---|---|---|
| `POST https://api.postmarkapp.com/email` | `POST https://api.apexmail.ee/email` | `POST https://api.apexmail.ee/v1/messages` |
| `POST https://api.postmarkapp.com/email/batch` | `POST https://api.apexmail.ee/email/batch`, bis zu 500 Nachrichten | `POST https://api.apexmail.ee/v1/messages/batch`, bis zu 100 Nachrichten pro Aufruf |
| `POST /email/bulk` (vorlagengetriebener Massenversand) | Nicht bedient | `POST /v1/messages/batch` mit expliziten Bodies oder einer Vorlagen-ID pro Nachricht |

Ein erfolgreicher Versand antwortet mit `200` und `{"ErrorCode": 0, "Message": "OK", "MessageID": "<kanonische Nachrichten-ID>"}`. Die Batch-Route antwortet mit einem geordneten Array und einem Ergebnisobjekt pro angeforderter Nachricht: `ErrorCode` 0 mit der `MessageID` oder ein von 0 abweichender `ErrorCode` mit dem Ablehnungstext für diese Position, sodass ein teilweiser Batch nie als voller Erfolg gemeldet wird. Die Nachrichten-ID ist die kanonische ID, dieselbe, die `GET /v1/messages/{id}` liefert und die Webhook-Ereignisse in `data.messageId` tragen.

## Authentifizierung umstellen

Ihr Credential-Slot bleibt bestehen. Postmark sendet `X-Postmark-Server-Token`; ersetzen Sie den Wert durch den ApexMail-API-Schlüssel (`am_live_…` oder `am_test_…`) und geben Sie ihm den Scope `messages:send`.

| Element | Postmark heute | ApexMail-Kompatibilitätsoberfläche |
|---|---|---|
| Credential-Header | `X-Postmark-Server-Token: <server token>` | `X-Postmark-Server-Token: am_live_…` |
| Scope | Token auf Server-Ebene | `messages:send` |
| Idempotenz | Nicht angeboten | `Idempotency-Key: <uuid>` auf derselben Route; derselbe Schlüssel innerhalb von 24 Stunden liefert die ursprüngliche Antwort einschließlich derselben `MessageID` |
| Betreff-Klasse | `MessageStream` wählt den Stream | `MessageStream` `outbound` wird zu `transactional`, `broadcast` zu `marketing`; der Header `X-ApexMail-Category` funktioniert ebenfalls und akzeptiert `transactional`, `service` oder `marketing` |

## Feldzuordnung

Die kanonischen Feldnamen entsprechen dem Vertrag von `POST /v1/messages`, sodass dasselbe Nutzlastverständnis bei einem späteren Wechsel zur nativen API gilt.

| Postmark-Feld | Kanonisches Feld | Hinweise |
|---|---|---|
| `From` | `from` | Erforderlich |
| `To` | `to` | Kommagetrennter String oder Array; zitierte Anzeigenamen behalten ihre Kommas |
| `Cc` / `Bcc` | `cc` / `bcc` | |
| `Subject` | `subject` | |
| `HtmlBody` / `TextBody` | `html` / `text` | |
| `ReplyTo` | `reply_to` | |
| `Headers[].Name` / `.Value` | `headers` | `Reply-To` fällt in das dedizierte Feld `reply_to` |
| `Attachments[].Name` / `.Content` / `.ContentType` | `attachments[]` (`filename`, `content`, `contentType`) | `ContentType` hat den Standardwert `application/octet-stream` |
| `Tag` | `tags` (ein Tag) | |
| `Metadata` (String-Werte) | `metadata` | Nicht-String-Werte werden benannt abgelehnt |
| `MessageStream` `outbound` / `broadcast` | `category` `transactional` / `marketing` | |
| `TrackOpens` / `TrackLinks` `true` | Akzeptierter No-op | Die Plattform verfolgt Öffnungen und Klicks bei jedem Versand |
| `X-ApexMail-Category`-Header | `category` | Wird vom kanonischen Normalisierer validiert |

Ein geplanter Versand ist nicht Teil dieser Oberfläche: Postmarks Nutzlast hat kein Planungsfeld, also hat die Kompatibilitätsroute keines. Nutzen Sie `scheduled_at` (ISO 8601) im nativen `POST /v1/messages`.

## Felder, die die Oberfläche benannt ablehnt

Jede dieser Konstruktionen wird in Postmarks eigener Fehlerform `{"ErrorCode": <code>, "Message": "…"}` abgelehnt. Validierungsablehnungen antworten mit `422`; ein fehlender oder ungültiger Token antwortet mit `401` und `ErrorCode` 10.

| Postmark-Konstrukt | Ablehnung |
|---|---|
| `TemplateId`, `TemplateAlias` | Eine Postmark-Vorlagen-ID ist keine ApexMail-Vorlagen-ID; rendern Sie den Body clientseitig oder senden Sie eine ApexMail-`template_id` über die native API |
| `TemplateModel` | Der kanonische Sendepfad hat kein Äquivalent für dieses Feld |
| `InlineImages`, `Attachments[].ContentID` | Der kanonische Sendepfad kennt kein Inline-Teil; hängen Sie die Datei an, statt sie einzubetten |
| `TrackOpens: false`, `TrackLinks: false` | Die Plattform verfolgt Öffnungen und Klicks bei jedem Versand; Tracking pro Nachricht kann auf dieser Oberfläche nicht abgeschaltet werden |
| Jeder andere `MessageStream`-Wert | Nur `outbound` (transaktional) und `broadcast` (Marketing) bilden die kanonische Kategorie ab |
| Ein Batch-Array mit mehr als 500 Nachrichten | Ein Postmark-Batch trägt höchstens 500 Nachrichten |
| Jedes weitere Feld auf oberster Ebene | Kein kanonisches Äquivalent |
| Ein Nicht-String-Wert in `Metadata` | Metadata-Werte müssen Strings sein |
| Ein `Headers[].Name`, der zweimal gesendet wird | Der doppelte Header wird abgelehnt statt durch Auswahl eines Wertes aufgelöst |

## Was noch nicht weitergeleitet wird

Die Kompatibilitätsoberfläche bedient die beiden Sende-Routen. Für die folgenden Postmark-APIs gibt es keine Kompatibilitätsroute; nutzen Sie die native ApexMail-API oder das Dashboard.

- Vorlagen und Layouts (`/templates`, `TemplateModel`-Rendering).
- Verwaltung von Message Streams und Konfiguration pro Server.
- Suche nach ausgehenden Nachrichten, Statistiken und Bounce-Endpunkte; Bounce-Daten kommen stattdessen über `message.bounced`-Ereignisse.
- Der Endpunkt `/email/bulk` (vorlagengetriebener Massenversand).
- Konfiguration von Inbound-Webhooks. Die Inbound-Pipeline von ApexMail sendet das Ereignis `inbound`, und Inbound-E-Mail ist auf Business und Enterprise Cloud verfügbar.
- Unterdrückungsverwaltung über Postmarks API; Unterdrückungen liegen in der ApexMail-Unterdrückungsliste.

## DNS: Was sich ändert und was bleibt

Ihre Sende-Domain bleibt Ihre Domain, und ApexMail signiert DKIM mit einem pro Domain erzeugten Selektor auf derselben Domain. Fügen Sie die vier Records aus `GET /v1/domains/:id/dns-records` neben den Postmark-Records hinzu; entfernen Sie die Postmark-Records erst nach der Umschaltung und dem Aufbewahrungsfenster.

| Postmark-Record | ApexMail-Äquivalent |
|---|---|
| DKIM-Record (das TXT- oder CNAME-Paar, das der Anbieter pro Server ausstellt) | Direkter TXT-Record unter `<selector>._domainkey.<domain>` mit dem DKIM-Public-Key. Ein direkter TXT-Record, kein CNAME |
| Return-Path-CNAME (die Bounce-Domain des Anbieters) | MX-Record unter `bounce.<domain>`, Priorität 10, auf den Feedback-Host der Region, plus TXT-Record unter `bounce.<domain>` mit dem SPF-Wert der benutzerdefinierten MAIL-FROM-Domain |
| Branded-Link-Tracking-CNAME (wenn Link-Tracking Ihre Domain nutzt) | Kein Branded-Link-CNAME nötig. ApexMail schreibt Links auf die eigenen Tracking-Pfade um; eine benutzerdefinierte Tracking-Domain (CNAME auf einer Subdomain einer verifizierten Domain) ist ab Pro verfügbar |
| Domain-Authentifizierung | TXT-Record unter `_dmarc.<domain>` mit Ihrer DMARC-Richtlinie |

Checkliste:

1. Fügen Sie die Sende-Domain im Dashboard hinzu und rufen Sie ihre DNS-Records ab.
2. Veröffentlichen Sie die vier ApexMail-Records; lassen Sie die Postmark-Records bestehen.
3. Behalten Sie die Postmark-Records, solange Postmark sendet. Postmarks MAIL-FROM-Domain ist anbieterspezifisch, daher sind ihre Records unabhängig von ApexMails `bounce.<domain>`-Records.
4. Führen Sie die Domain-Verifizierung aus und prüfen Sie, dass der DKIM-Selektor auflöst.
5. Lassen Sie DMARC-Reporting (rua) während des Übergangs aktiv.
6. Entfernen Sie nach Umschaltung und Aufbewahrungsfenster die Postmark-Records und widerrufen Sie den alten Server-Token.

## Vorlagen

Postmark-Vorlagen, Layouts und Aliasse werden nicht weitergeleitet, und `TemplateId`, `TemplateAlias` und `TemplateModel` werden benannt abgelehnt. Zwei Konvertierungspfade:

- Rendern Sie den Body in Ihrer Anwendung und senden Sie `HtmlBody` und `TextBody` über dieselbe Kompatibilitätsroute. Kein Migrationsaufwand für Vorlagen, und der Versand behält seine Nutzlastform.
- Erstellen Sie eine Vorlage über `POST /v1/templates` und senden Sie sie mit `template_id` plus `template_data` über das native `POST /v1/messages`. Platzhalter werden als `{{variable}}` geschrieben; ein nicht aufgelöster Platzhalter wird unverändert gerendert statt als leerer String, sodass eine fehlende Variable in der Vorschau sichtbar ist.

Postmark-Layouts (eine gemeinsame Hülle um Nachrichtenvorlagen) bilden auf den Vorlagen-Body selbst ab: Falten Sie das Layout-HTML in jede ApexMail-Vorlage oder rendern Sie weiterhin in Ihrer Anwendung. Mustachio-Bedingungen und -Schleifen haben kein direktes Gegenstück im Platzhalter-Renderer; konvertieren Sie solche Vorlagen in Ihrer Anwendung zu fertigem HTML oder teilen Sie sie in Vorlagen pro Fall auf.

## Webhooks

Postmark-Webhooks senden JSON pro Message Stream an Ihren Endpunkt. Richten Sie den Endpunkt auf ApexMail, abonnieren Sie die genutzten Ereignisse und prüfen Sie die ApexMail-Signatur: `X-ApexMail-Signature: sha256=<hex>` über den rohen Request-Body zusammen mit `X-ApexMail-Timestamp`. Die Zustellung erfolgt mindestens einmal, daher deduplizieren Sie über das `id`-Feld des Ereignisses.

| Postmark-Webhook | ApexMail-Ereignis | Hinweise |
|---|---|---|
| `Delivery` | `message.delivered` | Empfangender Server hat die Nachricht angenommen |
| `Bounce` mit `Type: HardBounce` | `message.bounced` | Hard-Bounce |
| `Bounce` mit `Type: Transient` | `message.deferred` | 4xx-Aufschub; ein Retry ist geplant |
| `SpamComplaint` | `message.complained` | |
| `Open` | `message.opened` | |
| `Click` | `message.clicked` | |
| `SubscriptionChange` | `recipient.unsubscribed` | ApexMail sendet die Abmelde-Richtung; Wieder-Abonnements werden am Präferenzdatensatz vermerkt |
| `Inbound` | `inbound` | Inbound-E-Mail ist auf Business und Enterprise Cloud verfügbar |
| `SMTPAPIError` | Kein Ereignis-Äquivalent | Ablehnungen zum Annahmezeitpunkt kommen stattdessen in der API-Antwort zurück |

Die Payload-Form ändert sich mit dem Anbieter: ApexMail-Ereignisse nutzen den Umschlag `{id, event, timestamp, data}`, mit `data.messageId` bei Nachrichtenereignissen und `data.email` bei Unterdrückungsereignissen.

## Umschaltplan

Die Umschaltung ist ein Host-Wechsel pro Route oder pro Umgebung; ein Rollback ist derselbe Wechsel rückwärts. Es gibt keine Nutzlast- oder Vorlagenänderung, die zurückgebaut werden müsste.

| Schritt | Aktion | Abbruchkriterien | Rollback |
|---|---|---|---|
| 1. Bereitstellen | Konto erstellen, Sende-Domain hinzufügen und verifizieren, API-Schlüssel mit `messages:send` anlegen, Webhook-Ereignisse abonnieren | Verifizierung besteht; eine Testnachricht wird aus einer Staging-Umgebung versendet | Noch kein Produktionsverkehr |
| 2. Parallel validieren | Dieselben Nutzlasten an `https://api.apexmail.ee/email` mit dem ApexMail-Schlüssel in `X-Postmark-Server-Token` senden; Antworten, `MessageID`-Werte und Webhook-Ereignisse vergleichen | `ErrorCode` 0 bei jedem Test; Ereignisse kommen mit gültigen Signaturen an | Testroute zurück auf Postmark richten |
| 3. 10 % verschieben | 10 % der Produktionssendungen über die Kompatibilitätsroute leiten; Bounce- und Beschwerdequoten gegen die AUP-Schwellenwerte beobachten (2 % Bounce, 0,1 % Beschwerden) | Zustellmetriken entsprechen Postmark innerhalb der vereinbarten Toleranz im Beobachtungsfenster | Route zurückwechseln; Postmark behält die übrigen 90 % |
| 4. 50 % verschieben | Den Anteil auf 50 % erhöhen, sobald das Fenster sauber schließt; beide Anbieter senden von derselben Domain | Anhaltende Parität beim höheren Anteil | Zurück auf 100 % Postmark wechseln |
| 5. Auf 100 % umstellen | Alle Sendungen über `POST /email` (und `/email/batch`) auf ApexMail leiten | Volles Volumen auf ApexMail mit sauberen Metriken | Zurückwechseln; Tokens bleiben während des Aufbewahrungsfensters aktiv |
| 6. Alten Pfad stilllegen | Postmark-DNS-Records entfernen, Server-Token widerrufen, Vorlagen- und Stream-Konfiguration stilllegen | Records lösen nur noch auf ApexMail auf | Records aus Ihrer Änderungsdokumentation wiederherstellen |

## Nächste Schritte

- Vergleichen Sie beide Plattformen Merkmal für Merkmal im [Vergleich ApexMail vs. Postmark](/de/compare/postmark/).
- Lesen Sie die [API-Übersicht](/docs/api/) und die [OpenAPI-Spezifikation](/docs/api/openapi/) für den nativen Vertrag, einschließlich Batch-Versand und Vorlagen.
- Lesen Sie [Webhooks](/docs/webhooks/) für die Ereignis-Payload-Schemas und die Signaturprüfung.
- [Kontaktieren Sie den Vertrieb](/de/contact/sales/) für eine Migrationsbewertung, wenn Postmark-Vorlagen oder Inbound-Webhooks Teil Ihres Produktionsverkehrs sind.
