+++
title = "Richtlinie zur akzeptablen Nutzung"
description = "ApexMail-Richtlinie zur akzeptablen Nutzung — Regeln für die Nutzung des E-Mail-Dienstes, geordnet nach Nachrichtenkategorie."
template = "prose.html"

[extra]
last_updated = "2026-07-30"
+++

Diese Richtlinie zur akzeptablen Nutzung („AUP") definiert verbotene und akzeptable Nutzungen der ApexMail-E-Mail-Infrastruktur. Verstöße können zur Aussetzung oder Kündigung führen. Diese AUP unterscheidet zwischen Marketing- und Werbe-E-Mails und Transaktions- und Service-E-Mails — jede Kategorie unterliegt unterschiedlichen Einwilligungs-, Abmelde- und Versandpflichten wie unten beschrieben.

## Marketing- und Werbe-E-Mails

Marketing- und Werbe-E-Mails umfassen Newsletter, Produktankündigungen, Angebote, Veranstaltungseinladungen und jede Nachricht, deren Hauptzweck kommerzielle Werbung oder Kundenbindung über die direkte Erfüllung einer Dienstleistung hinaus ist.

**Anforderungen für alle Marketing- und Werbe-E-Mails:**

- **Opt-in-Einwilligung.** Absender müssen vor dem Versand eine Opt-in-Einwilligung einholen und den Nachweis darüber aufbewahren. Wenn die Gerichtsbarkeit des Empfängers oder die regulatorischen Verpflichtungen des Absenders eine ausdrückliche Einwilligung erfordern (z. B. DSGVO Art. 7 für Direktmarketing an Personen im EWR, CAN-SPAM in den USA), muss der Absender diese Einwilligung einholen.
- **Rechtsgrundlage.** Absender müssen die Rechtsgrundlage für die Verarbeitung von Empfängerdaten nach allen anwendbaren Gesetzen identifizieren, dokumentieren und pflegen (z. B. Einwilligung nach DSGVO Art. 6 Abs. 1 lit. a, berechtigtes Interesse, soweit rechtlich zulässig). Der Absender trägt die alleinige Verantwortung dafür, dass für jede Marketingkommunikation vor dem Versand eine gültige Rechtsgrundlage besteht.
- **Absenderidentifikation.** Jede Nachricht muss die sendende Organisation klar identifizieren und korrekte `From`-, `Reply-To`- und physische Postanschrift-Header enthalten.
- **Funktionierender Abmeldemechanismus.** Jede Nachricht muss einen Ein-Klick-Abmeldemechanismus enthalten, der Abmeldeanfragen umgehend und dauerhaft bearbeitet. Abmeldelinks müssen mindestens 30 Tage nach dem Versand funktionsfähig bleiben.
- **Keine gekauften, gescrapten oder geernteten Listen.** Listen, die durch Kauf, Miete, Scraping oder Harvesting erworben wurden, sind nicht zulässig. Alle Empfängeradressen müssen direkt vom Absender durch einen Opt-in-Prozess gesammelt werden.
- **Beschwerdeüberwachung.** Absender müssen Missbrauchsbeschwerden überwachen und die Beschwerderate unter 0,1 % halten (berechnet als Beschwerden ÷ zugestellte Nachrichten pro Versanddomäne pro Tag).
- **Sperrlisten-Compliance.** Absender müssen Empfänger unterdrücken, die sich abgemeldet oder beschwert haben. ApexMail führt eine plattformweite Sperrliste; Kunden dürfen unterdrückte Adressen nicht erneut hinzufügen.

## Transaktions- und Service-E-Mails

Transaktions- und Service-E-Mails umfassen Nachrichten, die zur Erbringung einer vom Empfänger angeforderten Dienstleistung erforderlich sind oder zu deren Versand der Absender gesetzlich verpflichtet ist. Diese Nachrichten sind nicht primär werblich.

**Beispiele für Transaktions- und Service-E-Mails:**

- Passwort-Zurücksetzungen und Konto-Wiederherstellungslinks
- Authentifizierungscodes (Einmalpasswörter, Zwei-Faktor-Tokens)
- Sicherheitswarnungen (unbekannte Anmeldung, Gerätewechsel, Kontosperrungshinweis)
- Kaufbelege und Auftragsbestätigungen
- Rechnungen, Zahlungsbelege und Abrechnungsmitteilungen
- Kontostatus-Benachrichtigungen (Testablauf, Tarifwechsel, Abschluss des Datenexports)
- Service-Bestätigungen (Domain-Verifizierung, Webhook-Endpunkt-Validierung)
- Gesetzlich vorgeschriebene Nachrichten (Datenschutzerklärungs-Updates, bei denen Benachrichtigung vorgeschrieben ist, Meldungen von Datenschutzverletzungen)

**Anforderungen für Transaktions- und Service-E-Mails:**

- **Muss für den Dienst erforderlich sein.** Die Nachricht muss in direktem Zusammenhang mit dem Konto, der Transaktion oder der gesetzlichen Verpflichtung des Empfängers stehen. Werbe- oder Marketinginhalte dürfen nicht als Transaktionsnachricht getarnt werden.
- **Darf keine getarnte Werbung enthalten.** Wenn eine Transaktionsnachricht auch werbliche Inhalte enthält (z. B. eine Passwort-Zurücksetzung, die auch für ein neues Produkt wirbt), wird die gesamte Nachricht als Marketing behandelt und muss dem Abschnitt „Marketing- und Werbe-E-Mails" entsprechen.
- **Korrekte Absenderidentität.** Die Absenderidentität muss mit korrekten Domain- und Header-Informationen klar angegeben sein.
- **Verantwortung des Kunden für die Klassifizierung.** Der Kunde ist für die korrekte Klassifizierung seiner Nachrichten (Transaktion vs. Marketing) und für die Identifizierung der angemessenen Rechtsgrundlage verantwortlich. ApexMail bietet Nachrichtenkategorie-Tags in der API; die Verwendung eines Transaktions-Tags für Marketinginhalte verstößt gegen diese AUP.
- **Angemessene Aufbewahrung.** Absender dürfen Transaktionsnachrichtendaten nur so lange aufbewahren, wie es zur Erfüllung des Dienstzwecks oder zur Einhaltung geltender gesetzlicher Verpflichtungen erforderlich ist. Routinemäßige Transaktionsdaten (z. B. Zustellbestätigungen, Authentifizierungsprotokolle) dürfen nicht länger aufbewahrt werden, als für die Betriebsintegrität und die Einhaltung gesetzlicher Vorschriften erforderlich ist.
- **Zweckabhängige rechtliche Behandlung.** Jede Transaktionsnachrichtenkategorie wird nach ihrem spezifischen rechtlichen Zweck behandelt. Authentifizierungscodes sind Sicherheitsmaßnahmen nach DSGVO Art. 32. Rechnungen sind Finanzunterlagen, die Aufbewahrungspflichten unterliegen. Service-Bestätigungen sind Kommunikationen zur Vertragserfüllung. Der Absender muss den korrekten Rechtsrahmen für jede Nachrichtenkategorie anwenden. Die Verwendung einer unangemessenen Nachrichtenkategorie zur Umgehung rechtlicher Anforderungen (z. B. Kennzeichnung von Marketinginhalten als Transaktion) stellt einen Verstoß gegen diese AUP dar.

## Verbotene Inhalte (alle Kategorien)

Sie dürfen ApexMail nicht zum Versand folgender Inhalte nutzen:

- **Spam:** Unerwünschte Massen-E-Mails ohne die im Abschnitt „Marketing- und Werbe-E-Mails" beschriebene erforderliche Opt-in-Einwilligung.
- **Phishing:** E-Mails, die darauf abzielen, betrügerisch persönliche oder finanzielle Informationen zu erlangen.
- **Malware:** E-Mails mit Viren, Trojanern, Ransomware oder schädlichen Anhängen oder Links.
- **Illegale Inhalte:** Inhalte, die gegen geltende Gesetze in Estland, der EU oder der Gerichtsbarkeit des Empfängers verstoßen.
- **Belästigung:** Bedrohliche, missbräuchliche, verleumderische oder diskriminierende Inhalte.

## Allgemeine Versandanforderungen

Diese Anforderungen gelten für alle Nachrichtenkategorien:

- Die Absenderidentität muss klar angegeben sein (kein Domain- oder Header-Spoofing).
- Bounce-Raten müssen unter 2 % pro Versanddomäne pro Tag bleiben.
- Beschwerden müssen unter 0,1 % pro Versanddomäne pro Tag bleiben.
- Versanddomänen müssen mit gültigen SPF-, DKIM- und DMARC-Einträgen verifiziert sein.

## Infrastrukturschutz

- Versuchen Sie nicht, Ratenbegrenzungen, Kontingente oder Versandvolumenobergrenzen zu umgehen.
- Nutzen Sie den Dienst nicht für DDoS-Angriffe, Netzwerkmissbrauch oder Port-Scanning.
- Geben Sie API-Schlüssel oder Anmeldeinformationen nicht weiter. Jeder Benutzer muss seinen eigenen bereichsbezogenen API-Schlüssel haben.
- Versuchen Sie nicht, auf Daten, Konten oder Versandkonfigurationen anderer Kunden zuzugreifen oder diese zu beeinträchtigen.

## Durchsetzung

Wir überwachen Versandmuster und werden:

1. Bei ersten geringfügigen Verstößen warnen (z. B. erhöhte Bounce-Rate).
2. Bei wiederholten Problemen oder anhaltenden Richtlinienverstößen den Versand drosseln.
3. Bei schwerwiegenden Verstößen, einschließlich Spam-Beschwerden, Phishing oder Umgehungsversuchen, den Versand aussetzen (mit Benachrichtigung, sofern machbar).
4. Bei schwerwiegenden, wiederholten oder strafbaren Verstößen Konten kündigen.

## Meldung

Melden Sie Missbrauch oder AUP-Verstöße an: **abuse@apexmail.ee**

Alle Meldungen werden innerhalb von 1 Geschäftstag geprüft. Melder erhalten eine Bestätigung und, wo angemessen, eine Zusammenfassung der ergriffenen Maßnahmen.
