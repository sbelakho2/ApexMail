+++
title = "Von SendGrid zu ApexMail migrieren"
description = "Migrieren Sie eine SendGrid-Integration zu ApexMail über einen Basis-URL-Wechsel: Die Kompatibilitätsoberfläche bedient POST /v3/mail/send mit einem ApexMail-API-Schlüssel im bestehenden Authorization-Header, samt Feldzuordnung, benannten Ablehnungen, DNS-Checkliste, Webhook-Namen und 10/50/100-Umschaltplan."
template = "prose.html"

[extra]
last_updated = "2026-10-15"
og_image = "/images/og-image.png"
+++

ApexMail bedient `POST /v3/mail/send` auf einer SendGrid-Kompatibilitätsoberfläche. Die Route übersetzt die SendGrid-Nutzlast in die kanonische Sende-Anfrage und ruft dann denselben Handler auf, den `POST /v1/messages` nutzt. Absenderdomain-Prüfung, Unterdrückungs- und Einwilligungsfilter, Tarifberechtigungen, das Idempotenz-Ledger und der Queue-Eintrag laufen damit an einer Stelle. Ihre Integration behält ihre Anfrageform; geändert werden Basis-URL und Schlüssel.

## Endpunkt-Zuordnung

| SendGrid-Endpunkt | ApexMail-Kompatibilitätsoberfläche | Nativer ApexMail-Endpunkt |
|---|---|---|
| `POST https://api.sendgrid.com/v3/mail/send` | `POST https://api.apexmail.ee/v3/mail/send` | `POST https://api.apexmail.ee/v1/messages` |
| Kein Batch-Endpunkt in dieser Oberfläche | Eine Anfrage pro Nachricht | `POST https://api.apexmail.ee/v1/messages/batch`, bis zu 100 Nachrichten pro Aufruf |

Ein erfolgreicher Sende-Vorgang antwortet mit `202 Accepted`, leerem Body und der kanonischen Nachrichten-ID im Header `X-Message-Id`. Diese ID ist dieselbe, die `GET /v1/messages/{id}` liefert und die Webhook-Ereignisse in `data.messageId` tragen.

Ein `personalizations`-Eintrag pro Anfrage: Die Oberfläche verarbeitet genau einen. Eine Nutzlast mit mehreren Personalisierungen wird benannt abgelehnt statt mit verworfenen Betreff- oder Header-Werten versendet.

## Authentifizierung umstellen

Ihr Schlüssel-Slot bleibt bestehen. Senden Sie den ApexMail-API-Schlüssel (`am_live_…` oder `am_test_…`) dort, wo der SendGrid-Schlüssel stand, und geben Sie dem Schlüssel den Scope `messages:send`, den auch `POST /v1/messages` verlangt.

| Element | SendGrid heute | ApexMail-Kompatibilitätsoberfläche |
|---|---|---|
| Credential-Header | `Authorization: Bearer SG.…` | `Authorization: Bearer am_live_…` |
| Scope | Schlüsselberechtigungen | `messages:send` |
| Idempotenz | Nicht angeboten | `Idempotency-Key: <uuid>` auf derselben Route; derselbe Schlüssel innerhalb von 24 Stunden liefert die ursprüngliche Antwort einschließlich derselben `X-Message-Id` |
| Betreff-Klasse | Kein Anbieterkonzept | `X-ApexMail-Category: transactional` (oder `service`) befreit den Versand vom Marketing-Präferenzfilter; ohne Header zählt der Versand als Standardklasse `marketing` und der Einwilligungsfilter greift |

## Feldzuordnung

Die kanonischen Feldnamen entsprechen dem Vertrag von `POST /v1/messages`, sodass dasselbe Nutzlastverständnis bei einem späteren Wechsel zur nativen API gilt.

| SendGrid-Feld | Kanonisches Feld | Hinweise |
|---|---|---|
| `from` (`{email, name}` oder String) | `from` | `"Name <addr>"`, wenn ein Name vorhanden ist |
| `personalizations[0].to[]` | `to` | Erforderlich; Adressstrings, `"Name <addr>"`-Strings und `{email, name}`-Objekte werden akzeptiert |
| `personalizations[0].cc[]` / `.bcc[]` | `cc` / `bcc` | |
| `personalizations[0].subject` (sonst `subject` auf oberster Ebene) | `subject` | Bei beiden Werten gewinnt die Personalisierung |
| `personalizations[0].headers`, zusammengeführt unter `headers` der obersten Ebene | `headers` | Ein Header, der an beiden Stellen mit unterschiedlichen Werten gesetzt ist, wird abgelehnt |
| `content[]` mit `type` `text/plain` / `text/html` | `text` / `html` | Genau ein Teil pro Typ |
| `attachments[].content`, `.filename`, `.type` | `attachments[]` (`filename`, `content`, `contentType`) | `type` hat den Standardwert `application/octet-stream` |
| `categories[]` sowie `X-SMTPAPI` `category`/`categories` | `tags` | Doppelte Tags werden entfernt |
| `custom_args` sowie `X-SMTPAPI` `unique_args` | `metadata` | Nur String-Werte; ein Schlüssel, der an beiden Stellen mit unterschiedlichen Werten gesetzt ist, wird abgelehnt |
| `reply_to` | `reply_to` | |
| `send_at` (Unix-Sekunden) | `scheduled_at` | |
| `X-ApexMail-Category`-Header | `category` | Wird vom kanonischen Normalisierer validiert |
| `mail_settings.sandbox_mode.enable = false` | Akzeptierter No-op | Der dokumentierte SDK-Standardwert |

## Felder, die die Oberfläche benannt ablehnt

Jede dieser Konstruktionen wird in SendGrids eigener Fehlerform `{"errors": [{"message", "field", "help"}]}` abgelehnt, nie stillschweigend verworfen. Das kanonische Paar 400/422 wird als SendGrid-`400` ausgegeben.

| SendGrid-Konstrukt | Ablehnung |
|---|---|
| Mehr als ein `personalizations`-Eintrag | `more than one 'personalizations' entry is not supported by the ApexMail compatibility surface: per-personalization subject/headers would be dropped — send one request per personalization` |
| `personalizations[].substitutions`, `.dynamic_template_data` | Feld hat kein kanonisches Äquivalent |
| `template_id`, `dynamic_template_data` | SendGrid-Vorlagen-IDs sind keine ApexMail-Vorlagen-IDs |
| `attachments[].content_id`, `disposition: "inline"` | Der kanonische Sendepfad kennt kein Inline-Teil; hängen Sie die Datei an, statt sie einzubetten |
| `content[].type` außer `text/plain` und `text/html` | Nur diese beiden Teile haben ein kanonisches Äquivalent |
| `asm`, `batch_id`, `ip_pool_name` | Kein kanonisches Äquivalent |
| `mail_settings.*` außer dem Sandbox-No-op | Kein kanonisches Äquivalent |
| `mail_settings.sandbox_mode.enable = true` | Kein Sandbox-Modus pro Nachricht; nutzen Sie die Testmodus-Oberfläche der Plattform |
| `tracking_settings.*` | Kein kanonisches Äquivalent |
| `X-SMTPAPI`-Schlüssel außer `category`, `categories`, `unique_args` | Kein kanonisches Äquivalent |
| Jedes weitere Feld auf oberster Ebene | Kein kanonisches Äquivalent |

## Was noch nicht weitergeleitet wird

Die Kompatibilitätsoberfläche bedient nur die Sende-Route. Für die folgenden SendGrid-APIs gibt es keine Kompatibilitätsroute; nutzen Sie die native ApexMail-API oder das Dashboard.

- Vorlagenspeicherung und -Rendering (`/v3/templates`, Handlebars-`dynamic_template_data`): siehe Abschnitt Vorlagen.
- Unterdrückungsverwaltung (`/v3/asm/*`, `bypass_list_management`): Unterdrückungen liegen in der ApexMail-Unterdrückungsliste und werden im Dashboard oder über die native API verwaltet.
- Statistik-, Nachrichtenaktivitäts- und E-Mail-Validierungs-APIs.
- Marketing-Kontakte, Listen und Single-Send-Kampagnen-APIs.
- Inbound Parse.
- Sandbox-Modus pro Nachricht, Tracking-Schalter pro Nachricht und mehrere Personalisierungen.

## DNS: Was sich ändert und was bleibt

Ihre Sende-Domain bleibt Ihre Domain, und ApexMail signiert DKIM mit einem pro Domain erzeugten Selektor auf derselben Domain. Fügen Sie die vier Records aus `GET /v1/domains/:id/dns-records` neben den SendGrid-Records hinzu; entfernen Sie die SendGrid-Records erst nach der Umschaltung und dem Aufbewahrungsfenster.

| SendGrid-Record | ApexMail-Äquivalent |
|---|---|
| DKIM-CNAME-Paar (`s1._domainkey`, `s2._domainkey`) | Direkter TXT-Record unter `<selector>._domainkey.<domain>` mit dem DKIM-Public-Key. Ein direkter TXT-Record, kein CNAME |
| Link-Branding-CNAME (`url…`) | Kein Branded-Link-CNAME nötig. ApexMail schreibt Links auf die eigenen Tracking-Pfade um; eine benutzerdefinierte Tracking-Domain (CNAME auf einer Subdomain einer verifizierten Domain) ist ab Pro verfügbar |
| Bounce-Domain-CNAME | MX-Record unter `bounce.<domain>`, Priorität 10, auf den Feedback-Host der Region, plus TXT-Record unter `bounce.<domain>` mit dem SPF-Wert der benutzerdefinierten MAIL-FROM-Domain |
| Domain-Authentifizierung | TXT-Record unter `_dmarc.<domain>` mit Ihrer DMARC-Richtlinie |

Checkliste:

1. Fügen Sie die Sende-Domain im Dashboard hinzu und rufen Sie ihre DNS-Records ab.
2. Veröffentlichen Sie die vier ApexMail-Records; lassen Sie die SendGrid-Records bestehen.
3. Behalten Sie den SPF-Record der Root-Domain, solange SendGrid sendet. ApexMails SPF-Wert liegt auf der Subdomain `bounce.<domain>` (die benutzerdefinierte MAIL-FROM-Domain) und braucht keinen Eintrag im Root-Record.
4. Führen Sie die Domain-Verifizierung aus und prüfen Sie, dass der DKIM-Selektor auflöst.
5. Lassen Sie DMARC-Reporting (rua) während des Übergangs aktiv.
6. Entfernen Sie nach Umschaltung und Aufbewahrungsfenster die SendGrid-CNAMEs und jeden SendGrid-Mechanismus aus Ihren Records.

## Vorlagen

SendGrid-Vorlagen-IDs sind keine ApexMail-Vorlagen-IDs, und `template_id` mit `dynamic_template_data` wird auf der Kompatibilitätsroute benannt abgelehnt. Zwei Konvertierungspfade:

- Rendern Sie den Body in Ihrer Anwendung und senden Sie ihn als `content[]` über dieselbe Kompatibilitätsroute. Kein Migrationsaufwand für Vorlagen, und der Versand behält seine Anfrageform.
- Erstellen Sie eine Vorlage über `POST /v1/templates` und senden Sie sie mit `template_id` plus `template_data` über das native `POST /v1/messages`. Platzhalter werden als `{{variable}}` geschrieben; ein nicht aufgelöster Platzhalter wird unverändert gerendert statt als leerer String, sodass eine fehlende Variable in der Vorschau sichtbar ist.

Handlebars-Helfer (Bedingungen, Schleifen, `{{#each}}`) haben kein direktes Gegenstück im Platzhalter-Renderer; konvertieren Sie solche Vorlagen in Ihrer Anwendung zu fertigem HTML oder teilen Sie sie in Vorlagen pro Fall auf.

## Webhooks

Richten Sie Ihren Endpunkt auf ApexMail, abonnieren Sie die genutzten Ereignisse und prüfen Sie die ApexMail-Signatur: `X-ApexMail-Signature: sha256=<hex>` über den rohen Request-Body zusammen mit `X-ApexMail-Timestamp`. Die Zustellung erfolgt mindestens einmal, daher deduplizieren Sie über das `id`-Feld des Ereignisses.

| SendGrid-Ereignis | ApexMail-Ereignis | Hinweise |
|---|---|---|
| `processed` | `message.accepted` | Zur Zustellung angenommen |
| `delivered` | `message.delivered` | Empfangender Server hat die Nachricht angenommen |
| `bounce` | `message.bounced` | Hard-Bounce |
| `deferred` | `message.deferred` | 4xx-Aufschub; ein Retry ist geplant |
| `dropped` | `message.suppressed` | Empfänger steht auf der Unterdrückungsliste |
| `open` | `message.opened` | |
| `click` | `message.clicked` | |
| `spamreport` | `message.complained` | |
| `unsubscribe`, `group_unsubscribe` | `recipient.unsubscribed` | |
| `group_resubscribe` | Kein äquivalentes Ereignis | Das Wieder-Abonnieren wird am Präferenzdatensatz vermerkt, nicht als Ereignis |

## Umschaltplan

Die Umschaltung ist ein Basis-URL-Wechsel pro Route oder pro Umgebung; ein Rollback ist derselbe Wechsel rückwärts. Es gibt keine Nutzlast- oder Vorlagenänderung, die zurückgebaut werden müsste.

| Schritt | Aktion | Abbruchkriterien | Rollback |
|---|---|---|---|
| 1. Bereitstellen | Konto erstellen, Sende-Domain hinzufügen und verifizieren, API-Schlüssel mit `messages:send` anlegen, Webhook-Ereignisse abonnieren | Verifizierung besteht; eine Testnachricht wird aus einer Staging-Umgebung versendet | Noch kein Produktionsverkehr |
| 2. Parallel validieren | Dieselben Nutzlasten an `https://api.apexmail.ee/v3/mail/send` mit dem ApexMail-Schlüssel senden; Antworten, IDs und Webhook-Ereignisse vergleichen | `202` mit `X-Message-Id` bei jedem Test; Ereignisse kommen mit gültigen Signaturen an | Testroute zurück auf SendGrid richten |
| 3. 10 % verschieben | 10 % der Produktionssendungen über die Kompatibilitätsroute leiten; Bounce- und Beschwerdequoten gegen die AUP-Schwellenwerte beobachten (2 % Bounce, 0,1 % Beschwerden) | Zustellmetriken entsprechen SendGrid innerhalb der vereinbarten Toleranz im Beobachtungsfenster | Route zurückwechseln; SendGrid behält die übrigen 90 % |
| 4. 50 % verschieben | Den Anteil auf 50 % erhöhen, sobald das Fenster sauber schließt; beide Anbieter senden von derselben Domain | Anhaltende Parität beim höheren Anteil | Zurück auf 100 % SendGrid wechseln |
| 5. Auf 100 % umstellen | Alle Sendungen über `POST /v3/mail/send` auf ApexMail leiten | Volles Volumen auf ApexMail mit sauberen Metriken | Zurückwechseln; Schlüssel bleiben während des Aufbewahrungsfensters aktiv |
| 6. Alten Pfad stilllegen | SendGrid-CNAMEs und SPF-Mechanismus entfernen, Schlüssel widerrufen, verbliebene Vorlagenkonfiguration löschen | Records lösen nur noch auf ApexMail auf | Records aus Ihrer Änderungsdokumentation wiederherstellen |

## Nächste Schritte

- Vergleichen Sie beide Plattformen Merkmal für Merkmal im [Vergleich ApexMail vs. SendGrid](/de/compare/sendgrid/).
- Lesen Sie die [API-Übersicht](/docs/api/) und die [OpenAPI-Spezifikation](/docs/api/openapi/) für den nativen Vertrag, einschließlich Batch-Versand und Vorlagen.
- Lesen Sie [Webhooks](/docs/webhooks/) für die Ereignis-Payload-Schemas und die Signaturprüfung.
- [Kontaktieren Sie den Vertrieb](/de/contact/sales/) für eine Migrationsbewertung, wenn die oben abgelehnten Konstrukte Teil Ihres Produktionsverkehrs sind.
