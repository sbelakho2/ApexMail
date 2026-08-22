+++
title = "Migrationslösung"
description = "Migrieren Sie von SendGrid, Postmark, Mailgun, SES oder Resend zu ApexMail. IP-Warm-up, Domain-Übergang, Vorlagen-Migration und Parallelversand-Validierung."
template = "prose.html"
+++

## Migration

Überführen Sie Ihre Transaktions-E-Mail-Infrastruktur ohne Unterbrechung zu ApexMail. Diese Lösung umfasst Domain-Übergang, IP-Warm-up, Vorlagen-Migration, Webhook-Kompatibilität und Parallelversand-Validierung.

## Zielgruppe

Entwicklungsteams, die von SendGrid, Postmark, Mailgun, Amazon SES oder Resend migrieren. Betriebsteams, die die Umschaltung steuern. Compliance-Teams, die Datenresidenzanforderungen prüfen.

## Geschäftskontext

Die Migration eines E-Mail-Anbieters ist ein riskanter Vorgang. Verlorene Zustellungen während der Umschaltung bedeuten Umsatzverlust. IP-Warm-up ohne Automation riskiert Blacklisting. Die Domain-Reputation muss über Anbieter hinweg erhalten bleiben. Ohne strukturierten Migrationsplan riskieren Teams lang anhaltende Zustellverschlechterungen.

## Kernproblem

- Die IP-Reputation ist anbieterspezifisch und nicht übertragbar.
- Domain-Authentifizierungsrecords (SPF, DKIM, DMARC) erfordern koordinierte DNS-Änderungen.
- Die Vorlagensyntax unterscheidet sich zwischen Anbietern.
- Webhook-Payloads und Ereignistypen sind nicht standardisiert.
- Paralleles Senden während der Validierung erfordert Routing über zwei Anbieter.

## Die ApexMail-Lösung

- **Verwaltetes IP-Warm-up** — Automatischer Warm-up-Zeitplan für dedizierte IPs, mit Drosselung und Reputationsüberwachung.
- **Anleitung zum Domain-Übergang** — Schrittweise DNS-Konfiguration für SPF, DKIM, DMARC und benutzerdefinierten Return-Path.
- **Vorlagen-Import** — Überführen Sie bestehende Vorlagen in das ApexMail-Format, mit Erhalt von Variablen und Layouts.
- **Webhook-Kompatibilität** — Standardisierte Ereignistypen mit Dokumentation des Payload-Mappings.
- **Parallelversand-Validierung** — Leiten Sie einen konfigurierbaren Anteil des Verkehrs über ApexMail, während Sie Ihren bestehenden Anbieter weiterbetreiben.

## Technische Umsetzung

1. Erstellen Sie ein ApexMail-Konto und verifizieren Sie Ihre Sende-Domain.
2. Kopieren Sie den oder die domänenspezifischen DKIM-Records aus den Domain-Einstellungen neben die Selektoren Ihres bestehenden Anbieters.
3. Fügen Sie den generierten ApexMail-SPF-Mechanismus zum bestehenden SPF-Record hinzu; entfernen Sie den vorherigen Anbieter erst, nachdem der Übergang validiert wurde.
4. Setzen Sie die DMARC-Richtlinie während des Übergangs auf `p=none`, um Berichte ohne Durchsetzung zu sammeln.
5. Importieren Sie Vorlagen über die Vorlagen-API.
6. Konfigurieren Sie Webhook-Endpunkte für die Ereigniszustellung.
7. Beginnen Sie den Parallelversand mit 10% des Volumens und steigern Sie schrittweise unter Überwachung der Zustellmetriken.
8. Leiten Sie nach der Validierungsphase 100% über ApexMail und entfernen Sie die Konfiguration des vorherigen Anbieters.

## Relevante API-Endpunkte

| Endpunkt | Beschreibung |
|---|---|
| `POST /v1/emails` | E-Mail senden |
| `POST /v1/emails/batch` | Bis zu 1.000 E-Mails im Batch senden |
| `POST /v1/templates` | Vorlage erstellen |
| `GET /v1/templates` | Vorlagen auflisten |
| `PUT /v1/templates/:id` | Vorlage aktualisieren |

## Relevante Webhook-Ereignisse

| Ereignis | Auslöser |
|---|---|
| `email.delivered` | Empfangender Server hat die Nachricht angenommen |
| `email.bounced` | Hard- oder Soft-Bounce |
| `email.delayed` | Nachricht vom empfangenden Server verzögert |

## Erforderlicher Tarif

| Tarif | Dedizierte IP | Support |
|---|---|---|
| Growth | 1 dedizierte IP enthalten | E-Mail-Support |
| Scale | 3 dedizierte IPs enthalten | Prioritäts-Support |
| Enterprise | 10 dedizierte IPs enthalten | Dedizierter Support |

## Sicherheitshinweise

- DNS-Änderungen sollten in einem Wartungsfenster umgesetzt werden.
- Überwachen Sie die DMARC-Sammelberichte (RUA) während der gesamten Übergangsphase.
- Halten Sie die API-Keys beider Anbieter aktiv, bis die vollständige Validierung abgeschlossen ist.

## Compliance-Hinweise

- Bestätigen Sie Datenstandort- und AVV-Anforderungen während der Konto- oder Enterprise-Prüfung; eine technische Umschaltung begründet für sich genommen keine Residenz- oder Compliance-Zusage.
- Der Kunde bleibt für die Kontinuität der Empfänger-Einwilligungen während der Migration verantwortlich.

## Bekannte Einschränkungen

- Der Parallelversand kann während des Validierungszeitraums zu duplizierten Zustellereignissen führen.
- Das IP-Warm-up dauert für dedizierte IPs 2-4 Wochen.
- Die Vorlagen-Migration erfordert bei komplexer Bedingungslogik eine manuelle Prüfung.

## Empfohlener nächster Schritt

[Kontaktieren Sie den Vertrieb](/de/contact/sales/) für eine Migrationsbewertung und die Prüfung der Eignung für dedizierte IPs.
