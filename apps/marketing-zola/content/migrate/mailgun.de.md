+++
title = "Von Mailgun zu ApexMail migrieren"
description = "Migrieren Sie eine Mailgun-Integration zu ApexMail über einen Basis-URL-Wechsel: POST /v3/{domain}/messages akzeptiert Ihren ApexMail-API-Schlüssel im Basic-Auth-Slot von Mailgun, mit exakter Feldzuordnung, benannten Ablehnungen, der messages.mime-Antwort, der DNS-Checkliste und einem 10/50/100-Umschaltplan."
template = "prose.html"

[extra]
last_updated = "2026-10-15"
og_image = "/images/og-image.png"
+++

ApexMail bedient `POST /v3/{domain}/messages` auf einer Mailgun-Kompatibilitätsoberfläche. Die Route übersetzt die Formularfelder in die kanonische Sende-Anfrage und ruft dann denselben Handler auf, den `POST /v1/messages` nutzt. Absenderdomain-Prüfung, Unterdrückungs- und Einwilligungsfilter, Tarifberechtigungen, das Idempotenz-Ledger und der Queue-Eintrag laufen damit an einer Stelle. Ihre Integration behält ihre Formularfelder und ihre Endpunktform; geändert werden Host und Schlüssel.

## Endpunkt-Zuordnung

| Mailgun-Endpunkt | ApexMail-Kompatibilitätsoberfläche | Nativer ApexMail-Endpunkt |
|---|---|---|
| `POST https://api.mailgun.net/v3/{domain}/messages` (EU: `api.eu.mailgun.net`) | `POST https://api.apexmail.ee/v3/{domain}/messages` | `POST https://api.apexmail.ee/v1/messages` |
| `POST /v3/{domain}/messages.mime` (rohes MIME) | Verdrahtet und nach der Authentifizierung mit `501` beantwortet, samt Begründung | `POST /v1/messages` mit strukturierten Feldern oder ein MTA-Relay über SMTP |
| Kein Batch-Endpunkt in dieser Oberfläche | Eine Anfrage pro Nachricht | `POST /v1/messages/batch`, bis zu 100 Nachrichten pro Aufruf |

Das Pfadsegment `{domain}` ist Mailguns Sende-Domain und muss der Domain der `from`-Adresse entsprechen. Der kanonische Sendepfad leitet die DKIM-Identität aus der Absenderdomain ab, daher wird eine Abweichung benannt abgelehnt statt mit einer anderen Signaturhoheit signiert.

Ein erfolgreicher Versand antwortet mit `200` und `{"id": "<kanonische Nachrichten-ID>@{domain}", "message": "Queued. Thank you."}`. Die ID in den Klammern ist die kanonische Nachrichten-ID, dieselbe, die `GET /v1/messages/{id}` liefert und die Webhook-Ereignisse in `data.messageId` tragen.

`messages.mime` antwortet mit einem benannten `501`: `POST /v3/{domain}/messages.mime is not implemented by the ApexMail compatibility surface: raw MIME passthrough would require a second MIME parser in the request path. Use /v3/{domain}/messages with structured fields (from/to/subject/html/text/attachment), or the canonical POST /v1/messages API.`

## Authentifizierung umstellen

Ihr Credential-Slot bleibt bestehen. Mailgun sendet `Authorization: Basic base64("api:<key>")`; ersetzen Sie den Schlüssel durch den ApexMail-API-Schlüssel (`am_live_…` oder `am_test_…`) und geben Sie ihm den Scope `messages:send`. Der Benutzername trägt keine Berechtigung und wird so akzeptiert, wie er gesendet wird.

| Element | Mailgun heute | ApexMail-Kompatibilitätsoberfläche |
|---|---|---|
| Credential-Header | `Authorization: Basic base64("api:<key>")` | `Authorization: Basic base64("api:am_live_…")` |
| Body-Typ | `application/x-www-form-urlencoded` oder `multipart/form-data` | Dieselben zwei Body-Typen |
| Scope | Schlüsselberechtigungen, optional pro Domain | `messages:send` |
| Idempotenz | Nicht angeboten | `Idempotency-Key: <uuid>` auf derselben Route; derselbe Schlüssel innerhalb von 24 Stunden liefert die ursprüngliche Antwort einschließlich derselben Nachrichten-ID |
| Betreff-Klasse | Kein Anbieterkonzept | `X-ApexMail-Category: transactional` (oder `service`) befreit den Versand vom Marketing-Präferenzfilter; ohne Header zählt der Versand als Standardklasse `marketing` und der Einwilligungsfilter greift |

## Feldzuordnung

Die kanonischen Feldnamen entsprechen dem Vertrag von `POST /v1/messages`, sodass dasselbe Nutzlastverständnis bei einem späteren Wechsel zur nativen API gilt.

| Mailgun-Feld | Kanonisches Feld | Hinweise |
|---|---|---|
| `from` | `from` | Erforderlich; die Domain muss dem Pfadsegment `{domain}` entsprechen |
| `to` | `to` | Wiederholbar oder kommagetrennt; zitierte Anzeigenamen behalten ihre Kommas |
| `cc` / `bcc` | `cc` / `bcc` | |
| `subject` | `subject` | |
| `html` / `text` | `html` / `text` | |
| `attachment` (Multipart-Dateipart) | `attachments[]` | Base64-Inhalt, Dateiname und Content-Type des Parts; der Content-Type hat den Standardwert `application/octet-stream` |
| `o:tag` | `tags` | Duplikate werden entfernt |
| `o:deliverytime` | `scheduled_at` | RFC-2822-Zeitstempel, zum Beispiel `Fri, 15 Oct 2026 12:00:00 -0000` |
| `h:X-Foo` | `headers` | Beliebiger Headername; `h:Reply-To` fällt in das dedizierte Feld `reply_to` |
| `v:my-var` | `metadata` | |
| `X-ApexMail-Category`-Header | `category` | Wird vom kanonischen Normalisierer validiert |
| `o:tracking=yes`, `o:tracking-clicks=yes`, `o:tracking-opens=yes`, `o:dkim=yes` | Akzeptierter No-op | Entspricht den Plattform-Standardwerten |
| `o:testmode=no` | Akzeptierter No-op | Testmodus ist aus, was dem Plattformverhalten entspricht |

## Felder, die die Oberfläche benannt ablehnt

Jede dieser Konstruktionen wird in Mailguns eigener Fehlerform `{"message": "…"}` mit Status `400` abgelehnt, nie stillschweigend verworfen. Mehrere Probleme in einer Anfrage werden in der einen Meldung zusammengeführt.

| Mailgun-Konstrukt | Ablehnung |
|---|---|
| `inline`-Dateipart | Der kanonische Sendepfad kennt kein Inline-Teil; hängen Sie die Datei an, statt sie einzubetten |
| `attachment` als Formularwert | Anhänge müssen als Multipart-Dateiparts gesendet werden (`-F attachment=@file`), nicht als Formularwerte |
| `template` (gespeicherte Vorlagen) | Feld hat kein kanonisches Äquivalent |
| `o:campaign` | Feld hat kein kanonisches Äquivalent |
| `o:require-tls` | Feld hat kein kanonisches Äquivalent |
| `o:skip-verification` | Feld hat kein kanonisches Äquivalent |
| `o:tracking=no`, `o:tracking-clicks=no`, `o:tracking-opens=no`, `o:dkim=no` | Diese Oberfläche kann das entsprechende Plattformverhalten nicht abschalten; Tracking und DKIM-Signierung sind Einstellungen auf Deployment-Ebene |
| `o:testmode=yes` | Der kanonische Sendepfad hat keinen Modus mit unterdrückter Zustellung pro Nachricht; nutzen Sie die Testmodus-Oberfläche der Plattform statt still zu senden |
| Jedes weitere `o:*`-Feld und jedes unbekannte Formularfeld | Kein kanonisches Äquivalent auf der Mailgun-Kompatibilitätsoberfläche |
| `{domain}`, die nicht zur `from`-Domain passt | Das Pfadsegment muss der Domain der `from`-Adresse entsprechen, weil der kanonische Sendepfad mit der Absenderdomain signiert |
| Ein Headername, der zweimal gesendet wird, oder zwei verschiedene `Reply-To`-Werte | Das Duplikat wird abgelehnt statt durch Auswahl eines Wertes aufgelöst |

## Was noch nicht weitergeleitet wird

Die Kompatibilitätsoberfläche bedient nur die Sende-Route. Für die folgenden Mailgun-APIs gibt es keine Kompatibilitätsroute; nutzen Sie die native ApexMail-API oder das Dashboard.

- Rohe MIME-Sendungen (`messages.mime`) und das Feld `template` für in Mailgun gespeicherte Vorlagen.
- Zustellsteuerung pro Nachricht: `o:require-tls`, `o:skip-verification`, `o:dkim=no`, `o:tracking*=no`, `o:testmode=yes`.
- Kampagnen (`o:campaign`), Mailinglisten sowie die Ereignis- und Statistik-APIs.
- Route-, Domain-, Webhook- und Unterdrückungs-APIs: Unterdrückungen liegen in der ApexMail-Unterdrückungsliste; Webhook-Abonnements laufen über `POST /v1/webhooks`.
- Inbound-Routing (Mailgun Routes) und das Abrufen gespeicherter Nachrichten.
- Ein Batch-Endpunkt auf der Kompatibilitätsoberfläche; Batch-Versand läuft über die native API (bis zu 100 pro Aufruf).

## DNS: Was sich ändert und was bleibt

Ihre Sende-Domain bleibt Ihre Domain, und ApexMail signiert DKIM mit einem pro Domain erzeugten Selektor auf derselben Domain. Fügen Sie die vier Records aus `GET /v1/domains/:id/dns-records` neben den Mailgun-Records hinzu; entfernen Sie die Mailgun-Records erst nach der Umschaltung und dem Aufbewahrungsfenster.

| Mailgun-Record | ApexMail-Äquivalent |
|---|---|
| DKIM-Record unter `mx._domainkey` oder dem DKIM-Host des Anbieters | Direkter TXT-Record unter `<selector>._domainkey.<domain>` mit dem DKIM-Public-Key. Ein direkter TXT-Record, kein CNAME |
| Return-Path-Records von Mailgun (`include:mailgun.org`-SPF-Mechanismus, MX auf der Bounce-Subdomain) | TXT-Record unter `bounce.<domain>` mit dem SPF-Wert der benutzerdefinierten MAIL-FROM-Domain, und MX-Record unter `bounce.<domain>`, Priorität 10, auf den Feedback-Host der Region |
| Branded-Link-Tracking-CNAME | Kein Branded-Link-CNAME nötig. ApexMail schreibt Links auf die eigenen Tracking-Pfade um; eine benutzerdefinierte Tracking-Domain (CNAME auf einer Subdomain einer verifizierten Domain) ist ab Pro verfügbar |
| Domain-Authentifizierung | TXT-Record unter `_dmarc.<domain>` mit Ihrer DMARC-Richtlinie |

Checkliste:

1. Fügen Sie die Sende-Domain im Dashboard hinzu und rufen Sie ihre DNS-Records ab.
2. Veröffentlichen Sie die vier ApexMail-Records; lassen Sie die Mailgun-Records bestehen.
3. Behalten Sie die Return-Path-Records von Mailgun, solange Mailgun sendet, denn Mailguns MAIL-FROM-Domain ist eine eigene Subdomain.
4. Führen Sie die Domain-Verifizierung aus und prüfen Sie, dass der DKIM-Selektor auflöst.
5. Lassen Sie DMARC-Reporting (rua) während des Übergangs aktiv.
6. Entfernen Sie nach Umschaltung und Aufbewahrungsfenster die Mailgun-Records und widerrufen Sie den alten Schlüssel.

## Vorlagen

In Mailgun gespeicherte Vorlagen (`template` plus `t:variables`) werden nicht weitergeleitet, und das Feld wird benannt abgelehnt. Zwei Konvertierungspfade:

- Rendern Sie den Body in Ihrer Anwendung und senden Sie `html` und `text` über dieselbe Kompatibilitätsroute. Kein Migrationsaufwand für Vorlagen, und der Versand behält seine Formularfelder.
- Erstellen Sie eine Vorlage über `POST /v1/templates` und senden Sie sie mit `template_id` plus `template_data` über das native `POST /v1/messages`. Platzhalter werden als `{{variable}}` geschrieben; ein nicht aufgelöster Platzhalter wird unverändert gerendert statt als leerer String, sodass eine fehlende Variable in der Vorschau sichtbar ist.

Mailgun-Vorlagenvariablen reisen als `t:name=value`-Formularfelder; nutzen Sie auf der Kompatibilitätsroute `v:`-Metadaten oder rendern Sie die Werte in den Body, und verschieben Sie die Variablen zu `template_data`, wenn Sie die native Vorlagen-API übernehmen.

## Webhooks

Mailgun-Webhooks senden JSON an Ihren Endpunkt (Typ `http-post`). Richten Sie den Endpunkt auf ApexMail, abonnieren Sie die genutzten Ereignisse und prüfen Sie die ApexMail-Signatur: `X-ApexMail-Signature: sha256=<hex>` über den rohen Request-Body zusammen mit `X-ApexMail-Timestamp`. Die Zustellung erfolgt mindestens einmal, daher deduplizieren Sie über das `id`-Feld des Ereignisses.

| Mailgun-Ereignis | ApexMail-Ereignis | Hinweise |
|---|---|---|
| `accepted` | `message.accepted` | Zur Zustellung angenommen |
| `stored` | `message.queued` | Nachricht ist in die Ausgangs-Warteschlange eingetreten |
| `delivered` | `message.delivered` | Empfangender Server hat die Nachricht angenommen |
| `failed` mit permanenter Schwere | `message.bounced` | Hard-Bounce |
| `failed` mit temporärer Schwere | `message.deferred` | 4xx-Aufschub; ein Retry ist geplant |
| `rejected` | `message.suppressed` | Ablehnung durch Unterdrückungsliste oder Richtlinie |
| `opened` | `message.opened` | |
| `clicked` | `message.clicked` | |
| `complained` | `message.complained` | |
| `unsubscribed` | `recipient.unsubscribed` | |

Die Payload-Form ändert sich mit dem Anbieter: ApexMail-Ereignisse nutzen den Umschlag `{id, event, timestamp, data}`, mit `data.messageId` bei Nachrichtenereignissen und `data.email` bei Unterdrückungsereignissen.

## Umschaltplan

Die Umschaltung ist ein Host-Wechsel pro Route oder pro Umgebung; ein Rollback ist derselbe Wechsel rückwärts. Es gibt keine Formularfeld- oder Vorlagenänderung, die zurückgebaut werden müsste.

| Schritt | Aktion | Abbruchkriterien | Rollback |
|---|---|---|---|
| 1. Bereitstellen | Konto erstellen, Sende-Domain hinzufügen und verifizieren, API-Schlüssel mit `messages:send` anlegen, Webhook-Ereignisse abonnieren | Verifizierung besteht; eine Testnachricht wird aus einer Staging-Umgebung versendet | Noch kein Produktionsverkehr |
| 2. Parallel validieren | Dieselben Formular-Nutzlasten an `https://api.apexmail.ee/v3/{domain}/messages` mit dem ApexMail-Schlüssel im Basic-Slot senden; Antworten, IDs und Webhook-Ereignisse vergleichen | `200` mit dem Body `Queued. Thank you.` bei jedem Test; Ereignisse kommen mit gültigen Signaturen an | Testroute zurück auf Mailgun richten |
| 3. 10 % verschieben | 10 % der Produktionssendungen über die Kompatibilitätsroute leiten; Bounce- und Beschwerdequoten gegen die AUP-Schwellenwerte beobachten (2 % Bounce, 0,1 % Beschwerden) | Zustellmetriken entsprechen Mailgun innerhalb der vereinbarten Toleranz im Beobachtungsfenster | Route zurückwechseln; Mailgun behält die übrigen 90 % |
| 4. 50 % verschieben | Den Anteil auf 50 % erhöhen, sobald das Fenster sauber schließt; beide Anbieter senden von derselben Domain | Anhaltende Parität beim höheren Anteil | Zurück auf 100 % Mailgun wechseln |
| 5. Auf 100 % umstellen | Alle Sendungen über `POST /v3/{domain}/messages` auf ApexMail leiten | Volles Volumen auf ApexMail mit sauberen Metriken | Zurückwechseln; Schlüssel bleiben während des Aufbewahrungsfensters aktiv |
| 6. Alten Pfad stilllegen | Mailgun-DNS-Records entfernen, Schlüssel widerrufen, gespeicherte Vorlagenkonfiguration stilllegen | Records lösen nur noch auf ApexMail auf | Records aus Ihrer Änderungsdokumentation wiederherstellen |

## Nächste Schritte

- Vergleichen Sie beide Plattformen Merkmal für Merkmal im [Vergleich ApexMail vs. Mailgun](/de/compare/mailgun/).
- Lesen Sie die [API-Übersicht](/docs/api/) und die [OpenAPI-Spezifikation](/docs/api/openapi/) für den nativen Vertrag, einschließlich Batch-Versand und Vorlagen.
- Lesen Sie [Webhooks](/docs/webhooks/) für die Ereignis-Payload-Schemas und die Signaturprüfung.
- [Kontaktieren Sie den Vertrieb](/de/contact/sales/) für eine Migrationsbewertung, wenn eine Raw-MIME-Route oder gespeicherte Vorlagen Teil Ihres Produktionsverkehrs sind.
