+++
title = "ApexMail vs. Mailgun | Funktionsvergleich"
description = "Faktischer Vergleich der Funktionen für Transaktions-E-Mails: ApexMail vs. Mailgun. EU-Hosting, API, Zustellbarkeit, Compliance und Bereitstellungsmodelle."
template = "compare.html"

[extra]
competitor = "Mailgun"
competitor_slug = "mailgun"
competitor_name = "Mailgun"
competitor_description = "Mailgun von Sinch ist eine E-Mail-Versandplattform mit APIs zum Senden, Empfangen und Verfolgen von E-Mails."
last_verified = "2026-07-29"
methodology = "Öffentliche Mailgun-Dokumentation unter mailgun.com/docs, geprüft am Verifikationsdatum. Preise verglichen mit dem Foundation-100K-Tarif. Monatliche Abrechnung. Funktionen, Limits und Preise können sich ändern."
volume_assumption = "100.000 E-Mails/Monat"
billing_period = "monthly"
currency_note = "Preise werden in EUR angezeigt. Veröffentlicht ein Anbieter nur USD, wird der EUR-Betrag zum Kurs 1 USD = €0.92 (Referenzkurs, 2026-08-19) umgerechnet und der vom Anbieter veröffentlichte USD-Preis in Klammern angegeben. Angaben ohne anfallende Steuern."
# Feature comparison counts — update when capabilities change
apexmail_wins = 4
competitor_wins = 2
verdict_title = "Wie sich ApexMail von Mailgun unterscheidet"
verdict_points = ["EU/EWR-orientierte Bereitstellungskonfiguration", "Aktueller öffentlicher Katalog (Mailgun veröffentlicht USD; EUR zum Referenzkurs umgerechnet)", "Zugriffskontrollen in Scale und Enterprise", "Audit-Logs ab Growth", "Architektur- und Vertragsprüfung für nicht standardisierte Bereitstellungen"]

# Comparison data (audit 3.3): rendered by partials/compare/table.html via a
# single loop, so design changes to the row/winner markup happen in ONE place.
# Cell values are raw HTML (rendered with | safe) to preserve color-emphasis
# spans, inline <code>, and <sup><a href="#src-mgN"> citations. Winner is one
# of: apexmail | competitor | tie | none.
comparison_sections = [
  { title = "EWR-DATENVERARBEITUNG", rows = [
    { feature = "Primäre Hosting-Region", apex = 'EU-Rechenzentren (Deutschland primär, Finnland Backup) — keine Verarbeitung in den USA für Kerndaten', comp = 'USA (EU-Region verfügbar ab Foundation 50K+ und höheren Tarifen)<sup><a href="#src-mg1">1</a></sup>', winner = "none" },
    { feature = "EWR-Datenverarbeitung standardmäßig", apex = 'EU/EWR-orientierte Standardkonfiguration; aktive Standorte sind vereinbarungsspezifisch', comp = 'Nein — standardmäßig US-basiert; EU-Region je Sende-Domain konfiguriert<sup><a href="#src-mg1">1</a></sup>', winner = "none" },
    { feature = "AVV-Verfügbarkeit", apex = 'Verfügbar im Rahmen der anwendbaren ApexMail-Vereinbarung', comp = 'Verfügbar — die Sinch-AVV deckt die Mailgun-Dienste ab<sup><a href="#src-mg2">2</a></sup>', winner = "none" }
  ]},
  { title = "SENDEFUNKTIONEN", rows = [
    { feature = "REST-API", apex = 'Ja — <code>POST /v1/messages</code>', comp = 'Ja — <code>POST /v3/{domain}/messages</code><sup><a href="#src-mg3">3</a></sup>', winner = "none" },
    { feature = "SMTP-Relay", apex = 'Ja — smtp.apexmail.ee:587 (STARTTLS)', comp = 'Ja — smtp.mailgun.org:587 (STARTTLS)<sup><a href="#src-mg3">3</a></sup>', winner = "none" },
    { feature = "Batch-Versand", apex = 'Verfügbar, sofern für den gebuchten Tarif aktiviert', comp = 'Ja — Batch-Versand über <code>recipient-variables</code> mit bis zu 1.000 Empfängern<sup><a href="#src-mg3">3</a></sup>', winner = "none" },
    { feature = "Idempotenzschlüssel", apex = 'Ja (alle Tarife) — Header <code>Idempotency-Key</code>', comp = 'Nicht unterstützt — Anwendungen müssen Deduplizierungslogik selbst implementieren<sup><a href="#src-mg3">3</a></sup>', winner = "apexmail" },
    { feature = "Geplantes Senden", apex = 'Verfügbar, sofern für den gebuchten Tarif aktiviert', comp = 'Ja — Parameter <code>o:deliverytime</code> (RFC 2822-Format, bis zu 3 Tage)<sup><a href="#src-mg3">3</a></sup>', winner = "none" },
    { feature = "Eingehende E-Mails", apex = 'Scale- und Enterprise-Tarife', comp = 'Ja — Inbound-Routen mit Weiterleitungs-, Speicher- und Webhook-Aktionen<sup><a href="#src-mg4">4</a></sup>', winner = "none" }
  ]},
  { title = "BEREITSTELLUNGSMODELLE", rows = [
    { feature = "Shared Cloud", apex = 'Ja (alle Tarife) — Multi-Tenant, in der EU gehostet', comp = 'Ja (alle Tarife)<sup><a href="#src-mg5">5</a></sup>', winner = "none" },
    { feature = "Dedizierte IP", apex = 'Freigegebenes Add-on ab Pro; 1 enthalten ab Growth, 3 ab Scale', comp = 'Als Add-on verfügbar ab dem Foundation-Tarif und darüber<sup><a href="#src-mg5">5</a></sup>', winner = "none" },
    { feature = "Dedizierte Tenancy", apex = 'Vorbehaltlich Architektur- und Vertragsprüfung', comp = 'Siehe Anbieter-Dokumentation<sup><a href="#src-mg5">5</a></sup>', winner = "none" },
    { feature = "BYOC / private Bereitstellung", apex = 'Vorbehaltlich Architektur- und Vertragsprüfung', comp = 'Siehe Anbieter-Dokumentation<sup><a href="#src-mg5">5</a></sup>', winner = "none" }
  ]},
  { title = "ENTERPRISE-KONTROLLEN", rows = [
    { feature = "SAML SSO", apex = 'Scale- und Enterprise-Tarife', comp = 'Ab dem Tarif Foundation 100K und darüber<sup><a href="#src-mg6">6</a></sup>', winner = "none" },
    { feature = "SCIM", apex = 'Enterprise-Tarif', comp = 'Zum Verifikationsdatum nicht dokumentiert — Benutzer-Provisioning über die Mailgun-API<sup><a href="#src-mg6">6</a></sup>', winner = "apexmail" },
    { feature = "Audit-Logs", apex = 'Ab Growth-Tarif — Kontoaktivität, API-Schlüssel-Nutzung, Konfigurationsänderungen; durchsuchbar, exportierbar', comp = 'Ereignisprotokolle über die Events API zugänglich; Aufbewahrung je nach Tarif; kein zusammengeführter Audit-Trail auf Kontoebene<sup><a href="#src-mg7">7</a></sup>', winner = "apexmail" }
  ]},
  { title = "PREISE BEI 100K/MONAT (verifiziert 2026-07-29)", rows = [
    { feature = "Verglichener Tarif", apex = 'Pro: €65/Monat (150.000 E-Mails enthalten)', comp = 'Scale: €82.80 (US$90)/Monat (100.000 E-Mails enthalten)<sup><a href="#src-mg8">8</a></sup>', winner = "none" },
    { feature = "Nutzungsbedingungen", apex = 'Siehe den aktuellen öffentlichen Katalog und Checkout für die anwendbaren Nutzungsbedingungen', comp = 'ab €1.20 (US$1.30)/1.000 bei Foundation-Überschreitung; Staffelraten ab Scale<sup><a href="#src-mg8">8</a></sup>', winner = "none" },
    { feature = "Kostenlose Stufe", apex = '30.000 E-Mails/Monat', comp = '100 E-Mails/Tag (Flex-Testphase — keine Kreditkarte)<sup><a href="#src-mg8">8</a></sup>', winner = "apexmail" }
  ]},
  { title = "BEREICHE, IN DENEN MAILGUN STÄRKER IST", rows = [
    { feature = "E-Mail-Validierung", apex = 'E-Mail-Grader-API (DNS/SPF/DKIM/DMARC/Inhalt/Reputation)', comp = 'Dedizierte E-Mail-Validierungs-API mit Echtzeit- und Massenvalidierung<sup><a href="#src-mg9">9</a></sup>', winner = "competitor" },
    { feature = "Verarbeitung eingehender E-Mails", apex = 'Eingehende E-Mails in den Scale- und Enterprise-Tarifen', comp = 'Inbound-Routing mit Weiterleitungs-, HTTP-Webhook- und Speicheraktionen; in allen Tarifen enthalten<sup><a href="#src-mg4">4</a></sup>', winner = "competitor" },
    { feature = "E-Mail-Test-Sandbox", apex = 'Sandbox-Umgebung mit Sandbox-Domains und Ratenbegrenzungen', comp = 'Sandbox-Domain zum Testen in allen Tarifen mit separaten Test-Zugangsdaten<sup><a href="#src-mg3">3</a></sup>', winner = "none" }
  ]}
]

# Sources block (rendered by macros::sources_block via partials/compare/table.html).
# Each entry: { ref = anchor suffix (e.g. "mg1"), n = display number, label, url }.
sources = [
  { ref = "mg1", n = 1, label = "Mailgun-Dokumentation zum EU-Rechenzentrum", url = "https://www.mailgun.com/eu-data-center/" },
  { ref = "mg2", n = 2, label = "Mailgun-Datenverarbeitungsvereinbarung", url = "https://www.mailgun.com/legal/dpa/" },
  { ref = "mg3", n = 3, label = "Mailgun-Sending-API-Referenz", url = "https://documentation.mailgun.com/en/latest/api-sending.html" },
  { ref = "mg4", n = 4, label = "Mailgun-Dokumentation zu eingehenden E-Mails", url = "https://documentation.mailgun.com/en/latest/user_manual.html#receiving-forwarding-and-storing-messages" },
  { ref = "mg5", n = 5, label = "Mailgun-Produktseite", url = "https://www.mailgun.com/products/" },
  { ref = "mg6", n = 6, label = "Mailgun-SSO-Dokumentation", url = "https://www.mailgun.com/products/sso/" },
  { ref = "mg7", n = 7, label = "Mailgun-Events-API-Referenz", url = "https://documentation.mailgun.com/en/latest/api-events.html" },
  { ref = "mg8", n = 8, label = "Mailgun-Preisseite", url = "https://www.mailgun.com/pricing/" },
  { ref = "mg9", n = 9, label = "Mailgun E-Mail-Validierung", url = "https://www.mailgun.com/email-validation/" }
]
sources_disclaimer = "Zuletzt verifiziert: 2026-08-19. Volumenannahme: 100.000 E-Mails/Monat, monatliche Abrechnung. Preise werden in EUR angezeigt. Veröffentlicht ein Anbieter nur USD, wird der EUR-Betrag zum Kurs 1 USD = €0.92 (Referenzkurs, 2026-08-19) umgerechnet und der vom Anbieter veröffentlichte USD-Preis in Klammern angegeben. Angaben ohne anfallende Steuern. Geprüft von: ApexMail Marketing Engineering."
+++

<!-- Comparison rows and sources block are rendered from the
     [extra].comparison_sections and [extra].sources arrays by
     partials/compare/table.html. This body is intentionally empty. -->
