+++
title = "ApexMail vs. Amazon SES | Funktionsvergleich"
description = "Faktischer Vergleich der Funktionen für Transaktions-E-Mails: ApexMail vs. Amazon SES. EU-Hosting, API, Zustellbarkeit, Compliance und Bereitstellungsmodelle."
template = "compare.html"

[extra]
noindex = true
competitor = "Amazon SES"
competitor_slug = "amazon-ses"
competitor_name = "Amazon SES"
competitor_description = "Amazon Simple Email Service (SES) ist ein cloudbasierter E-Mail-Versanddienst auf AWS-Infrastruktur, abgerechnet als Pay-as-you-go-Kapazität."
last_verified = "2026-07-29"
methodology = "Öffentliche AWS-SES-Dokumentation unter docs.aws.amazon.com/ses, geprüft am Verifikationsdatum. Preise verglichen nach Pay-as-you-go für 100.000 E-Mails/Monat. Monatliche Abrechnung. ApexMail ist verwaltete Infrastruktur; SES ist rohe Kapazität. Funktionen, Limits und Preise können sich ändern."
volume_assumption = "100.000 E-Mails/Monat"
billing_period = "monthly"
currency_note = "Preise werden in EUR angezeigt. Veröffentlicht ein Anbieter nur USD, wird der EUR-Betrag zum Kurs 1 USD = €0.92 (Referenzkurs, 2026-08-19) umgerechnet und der vom Anbieter veröffentlichte USD-Preis in Klammern angegeben. Angaben ohne anfallende Steuern."
# Feature comparison counts — update when capabilities change.
verdict_title = "Wie sich ApexMail von Amazon SES unterscheidet"
verdict_points = ["Verwaltete E-Mail-Infrastruktur mit API, Ereignissen und Support inklusive gegenüber Abrechnung roher Kapazität", "Diagnose-Dashboard für die Zustellung jeder Nachricht gegenüber selbst zusammengestelltem CloudWatch + SNS", "Idempotenzschlüssel in allen Tarifen gegenüber nicht nativ unterstützt", "EU/EWR-orientierte Bereitstellungskonfiguration mit pro Bereitstellung bestätigten aktiven Regionen", "Verwalteter Dienst mit dedizierter Tenancy gegenüber Selbstverwaltung auf AWS"]

# Comparison data (audit 3.3): rendered by partials/compare/table.html via a
# single loop, so design changes to the row/winner markup happen in ONE place.
# Cell values are raw HTML (rendered with | safe) to preserve color-emphasis
# spans, inline <code>, and <sup><a href="#src-sesN"> citations. Winner is one
# of: apexmail | competitor | tie | none. Bare "—" winner cells normalize to
# "none" (the winner_badge macro renders them as a spanned em-dash).
comparison_sections = [
  { title = "EWR-DATENVERARBEITUNG", rows = [
    { feature = "Primäre Hosting-Region", apex = 'EU-Rechenzentren (Deutschland primär, Finnland Backup) — keine Verarbeitung in den USA für Kerndaten', comp = 'Mehrere Regionen, darunter EU (Irland eu-west-1, Frankfurt eu-central-1 usw.)<sup><a href="#src-ses1">1</a></sup>', winner = "none" },
    { feature = "EWR-Datenverarbeitung standardmäßig", apex = 'EU/EWR-orientierte Standardkonfiguration; aktive Standorte sind vereinbarungsspezifisch', comp = 'Verfügbar — muss explizit konfiguriert werden; Regionsauswahl je Sende-Domain erforderlich<sup><a href="#src-ses1">1</a></sup>', winner = "none" },
    { feature = "AVV-Verfügbarkeit", apex = 'Verfügbar im Rahmen der anwendbaren ApexMail-Vereinbarung', comp = 'Verfügbar — AWS-AVV (Artifact) mit SCCs<sup><a href="#src-ses2">2</a></sup>', winner = "none" }
  ]},
  { title = "SENDEFUNKTIONEN", rows = [
    { feature = "REST-API", apex = 'Ja — native <code>POST /v1/messages</code> (ApexMail-API)', comp = 'Ja — AWS SDK (mehrere Sprachen) über <code>SendEmail</code>, <code>SendBulkEmail</code><sup><a href="#src-ses3">3</a></sup>', winner = "none" },
    { feature = "SMTP-Relay", apex = 'Ja — smtp.apexmail.ee:587 (STARTTLS)', comp = 'Ja — email-smtp.{region}.amazonaws.com:587 (STARTTLS)<sup><a href="#src-ses3">3</a></sup>', winner = "none" },
    { feature = "Idempotenzschlüssel", apex = 'Ja (alle Tarife) — Header <code>Idempotency-Key</code>', comp = 'Nicht nativ unterstützt — AWS empfiehlt Nachrichten-Deduplizierung auf Anwendungsebene<sup><a href="#src-ses3">3</a></sup>', winner = "apexmail" },
    { feature = "Nachrichten-Ereignisverfolgung", apex = 'Diagnose-Dashboard für die Zustellung jeder Nachricht mit 7-stufiger Zeitleiste', comp = 'CloudWatch-Metriken (send, bounce, complaint, delivery) + SNS-Benachrichtigungen für Ereignisse — Zusammenbau in Eigenleistung erforderlich<sup><a href="#src-ses4">4</a></sup>', winner = "apexmail" },
    { feature = "Eingehende E-Mails", apex = 'Scale- und Enterprise-Tarife', comp = 'Ja — SES-Empfangsregeln mit S3-, Lambda-, SNS- und SQS-Aktionen<sup><a href="#src-ses5">5</a></sup>', winner = "none" }
  ]},
  { title = "BEREITSTELLUNGSMODELLE", rows = [
    { feature = "Shared Cloud", apex = 'Ja (alle Tarife) — verwaltet, Multi-Tenant, in der EU gehostet', comp = 'Ja (alle Konten) — standardmäßig gemeinsamer IP-Pool<sup><a href="#src-ses6">6</a></sup>', winner = "none" },
    { feature = "Dedizierte IP", apex = 'Freigegebenes Add-on ab Pro; 1 enthalten ab Growth, 3 ab Scale', comp = 'Ja — €22.95 (US$24.95)/Monat pro dedizierter IP; IP-Pool-Verwaltung verfügbar<sup><a href="#src-ses6">6</a></sup>', winner = "none" },
    { feature = "Dedizierte Tenancy", apex = 'Vorbehaltlich Architektur- und Vertragsprüfung', comp = 'Selbst verwaltet — der Kunde plant dedizierte Tenancy auf AWS mit SES als Dienstkomponente<sup><a href="#src-ses6">6</a></sup>', winner = "none" },
    { feature = "BYOC / private Bereitstellung", apex = 'Vorbehaltlich Architektur- und Vertragsprüfung', comp = 'Systemimmanent — der Kunde betreibt im eigenen AWS-Konto; SES ist ein AWS-Dienst<sup><a href="#src-ses6">6</a></sup>', winner = "none" }
  ]},
  { title = "ENTERPRISE-KONTROLLEN", rows = [
    { feature = "SAML SSO", apex = 'Scale- und Enterprise-Tarife', comp = 'Über AWS IAM Identity Center — erfordert AWS-Organizations-Setup und IAM-Konfiguration<sup><a href="#src-ses7">7</a></sup>', winner = "none" },
    { feature = "Subaccounts / Isolation", apex = 'Scale (10) und Enterprise (100) — verwaltet, hierarchisch', comp = 'Über AWS Organizations mit separatem Konto pro Umgebung — selbst verwaltet<sup><a href="#src-ses7">7</a></sup>', winner = "none" },
    { feature = "Verwalteter Support", apex = 'Tarifspezifische Support-Konditionen', comp = 'AWS-Support-Pläne (Developer, Business, Enterprise) — getrennt von der SES-Nutzung zu erwerben<sup><a href="#src-ses8">8</a></sup>', winner = "none" },
    { feature = "HIPAA-Verfügbarkeit", apex = 'Derzeit nicht angeboten', comp = 'Ja — AWS-BAA verfügbar; SES ist ein HIPAA-fähiger Dienst<sup><a href="#src-ses9">9</a></sup>', winner = "competitor" }
  ]},
  { title = "PREISE BEI 100K/MONAT (verifiziert 2026-07-29)", rows = [
    { feature = "Verglichener Tarif", apex = 'Pro: €65/Monat (150.000 E-Mails enthalten, verwaltete Infrastruktur)', comp = 'Pay-as-you-go: ~€9.20 (US$10)/100K E-Mails (reiner Versand, ohne Verwaltung)<sup><a href="#src-ses10">10</a></sup>', winner = "none" },
    { feature = "Unterschied beim Preismodell", apex = 'Verwaltete E-Mail-Infrastruktur: API, Ereignisspeicherung, Webhook-Zustellung, Support und Analytik inklusive', comp = 'Abrechnung roher Kapazität: IaaS — Zahlung pro Versand plus zusätzliche AWS-Kosten (EC2, S3, CloudWatch, SNS, Support)<sup><a href="#src-ses10">10</a></sup>', winner = "none" },
    { feature = "Kostenlose Stufe", apex = '30.000 E-Mails/Monat (keine Kreditkarte, kein Zeitlimit)', comp = '62.000 E-Mails/Monat beim Versand von EC2 (erste 12 Monate); sonst 3.000/Monat<sup><a href="#src-ses10">10</a></sup>', winner = "none" }
  ]},
  { title = "BEREICHE, IN DENEN AMAZON SES STÄRKER IST", rows = [
    { feature = "Reine Kosten pro E-Mail", apex = 'Siehe den aktuellen öffentlichen Katalog und Checkout für die anwendbaren Nutzungsbedingungen', comp = '€0.09 (US$0.10)/1.000 E-Mails — niedrigste Kosten pro Nachricht unter den großen Anbietern<sup><a href="#src-ses10">10</a></sup>', winner = "competitor" },
    { feature = "AWS-Ökosystem-Integration", apex = 'Eigenständige Plattform mit API-Integration', comp = 'Tiefe Integration mit AWS-Diensten: Lambda, S3, CloudWatch, SNS, SQS, IAM, KMS, Organizations<sup><a href="#src-ses3">3</a></sup>', winner = "competitor" },
    { feature = "Maximales Sendevolumen", apex = 'Scale unterstützt bis zu 2 Millionen E-Mails/Monat; Enterprise-Konditionen sind vertraglich vereinbart', comp = 'Praktisch unbegrenzt — begrenzt durch Konto-Sendelimits, die mit der Reputation automatisch skalieren<sup><a href="#src-ses6">6</a></sup>', winner = "none" },
    { feature = "Globale Regionen", apex = 'Deutschland &amp; Finnland (EWR-Fokus)', comp = '22+ AWS-Regionen weltweit, darunter USA, EU, APAC, Südamerika<sup><a href="#src-ses1">1</a></sup>', winner = "competitor" }
  ]}
]

# Trailing footnote sources (rendered via macros::sources_block). Each source
# {ref, n, label, url} maps a <sup id="src-sesN"> definition. ref is the anchor
# suffix so the macro emits id="src-{{ref}}", matching the inline #src-sesN refs.
sources = [
  { ref = "ses1", n = 1, label = "AWS SES Regional Endpoints", url = "https://docs.aws.amazon.com/general/latest/gr/ses.html" },
  { ref = "ses2", n = 2, label = "AWS-GDPR-Center und DPA", url = "https://aws.amazon.com/compliance/gdpr-center/" },
  { ref = "ses3", n = 3, label = "AWS SES v2 SendEmail-API-Referenz", url = "https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_SendEmail.html" },
  { ref = "ses4", n = 4, label = "AWS-SES-Monitoring-Dokumentation", url = "https://docs.aws.amazon.com/ses/latest/dg/monitor-sending-activity.html" },
  { ref = "ses5", n = 5, label = "AWS-SES-Dokumentation zum Empfang von E-Mails", url = "https://docs.aws.amazon.com/ses/latest/dg/receiving-email.html" },
  { ref = "ses6", n = 6, label = "AWS-SES-Dokumentation zu dedizierten IPs", url = "https://docs.aws.amazon.com/ses/latest/dg/dedicated-ip.html" },
  { ref = "ses7", n = 7, label = "AWS-IAM-Identity-Center-Dokumentation (SSO)", url = "https://docs.aws.amazon.com/singlesignon/latest/userguide/" },
  { ref = "ses8", n = 8, label = "AWS-Support-Pläne", url = "https://aws.amazon.com/premiumsupport/plans/" },
  { ref = "ses9", n = 9, label = "AWS-Informationen zu HIPAA-Compliance und BAA", url = "https://aws.amazon.com/compliance/hipaa-compliance/" },
  { ref = "ses10", n = 10, label = "AWS-SES-Preisseite", url = "https://aws.amazon.com/ses/pricing/" }
]
sources_disclaimer = "Zuletzt verifiziert: 2026-08-19. Volumenannahme: 100.000 E-Mails/Monat, monatliche Abrechnung. Preise werden in EUR angezeigt. Veröffentlicht ein Anbieter nur USD, wird der EUR-Betrag zum Kurs 1 USD = €0.92 (Referenzkurs, 2026-08-19) umgerechnet und der vom Anbieter veröffentlichte USD-Preis in Klammern angegeben. Angaben ohne anfallende Steuern. ApexMail wird als verwaltete E-Mail-Infrastruktur bepreist; Amazon SES als rohe E-Mail-Versandkapazität. Geprüft von: ApexMail Marketing Engineering."
+++

<!-- Comparison rows and footnote sources are rendered from the
     [extra].comparison_sections, [extra].sources, and
     [extra].sources_disclaimer fields by partials/compare/table.html
     (which calls macros::sources_block). This body is intentionally empty. -->
