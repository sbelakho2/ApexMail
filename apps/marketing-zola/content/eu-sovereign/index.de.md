+++
title = "EU-Souveränität | In Europa gebaut, unter EU-Recht betrieben"
description = "Wie die EU-Souveränitätsposition von ApexMail tatsächlich funktioniert: ein estnisches Unternehmen unter EU-Recht, EU-Rechenzentren, der fail-closed EU-only-Routing-Modus, Ed25519-signierte Routing-Belege und die Unterauftragsverarbeiter-Kette, die EU-only entfernt — jede Aussage mit ihrem Beleg verlinkt."
template = "prose.html"

[extra]
last_updated = "2026-10-16"
og_image = "/images/og-image.png"
+++

## Das Versprechen — und die offene Grenze

ApexMail ist ein EU-Unternehmen (Bel Consulting OÜ, Tallinn, Estland). Die gemeinsame Cloud läuft in EU-Rechenzentren in Finnland. EU-only-Routing ist ein echter Modus mit einer Einstellung: Jede Nachricht verlässt das System über die eigenen EU-MTAs von ApexMail, ein Versand ohne eigene MTA-Route wird angehalten statt umgeleitet, und jede angenommene Nachricht trägt einen Ed25519-signierten Routing-Beleg, den jede dritte Partei mit dem veröffentlichten öffentlichen Schlüssel prüfen kann.

Die offene Grenze gehört auf dieselbe Seite: Das **Standard**-Routing von ApexMail ist Global, und Global-Zustellungen laufen über Amazon Web Services' SES in der konfigurierten EU-Region — eine EU-Region eines US-Unternehmens, abgedeckt durch den AWS-Auftragsverarbeitungsvertrag und, soweit anwendbar, EU-Standardvertragsklauseln. Der Satz „Ihre Mail berührt nie einen US-kontrollierten Anbieter" gilt **unter EU-only-Routing**; für ein Global-Konto gilt er nicht, und diese Website behauptet ihn nicht plattformweit. Die [Datenstandort-Matrix](/de/data-locations/) formuliert für die Speicherung denselben Umfang, den diese Seite für den Transport formuliert.

## Ein EU-Unternehmen unter EU-Recht

Vertragspartner ist die Bel Consulting OÜ (Handelsname ApexMail), registriert in Estland — Registrierungscode 16588745, USt-IdNr. EE102951727, Sakala tn 7-2, 10141 Tallinn. Für die Verträge von ApexMail gilt estnisches Recht; als Gerichtsstand ist das Harju County Court, Tallinn, Estland, vereinbart. Diese rechtliche Identität wird auf jeder Seite dieser Website aus einem kanonischen Datensatz gerendert.

Belege: Die [AGB](/de/terms/) nennen Vertragspartner und anwendbares Recht; die [AVV](/de/dpa/) ist die Auftragsverarbeitungsvereinbarung nach Artikel 28; die [Datenschutzerklärung](/de/privacy/) benennt die Rollen von Verantwortlichem und Auftragsverarbeiter; die Seite [Über uns](/de/about/) trägt die Registrierungsdaten des Unternehmens.

## EU-Rechenzentren

Die mitgelieferte gemeinsame Bereitstellung läuft auf Infrastruktur der Hetzner Online GmbH in Finnland. Kern-Servicedaten — Kontodaten, gehashte API-Schlüssel, Absender- und Empfängeradressen, Nachrichteninhalte, Anhänge, Zustellereignisse und -protokolle, Support-Tickets, Analytik und Backups — werden innerhalb des EWR verarbeitet und repliziert, ohne Drittlandübermittlung für diese Kategorien. Die tatsächlichen Ausnahmen werden benannt statt verborgen: optionale OAuth-Anmeldung (Google, GitHub) und Zahlungsabwicklung (Mollie B.V.) sind in der Matrix mit ihren eigenen Übermittlungsgarantien gesondert aufgeführt.

Belege: Die [Datenstandort-Matrix](/de/data-locations/) listet für jede Datenkategorie primären Standort, Backup und Verarbeitungsregion; das [Unterauftragsverarbeiter-Register](/de/subprocessors/) nennt die Unternehmen sowie ihre Verarbeitungs- und Speicherländer.

### Zahlungsabwickler

Mollie B.V. ist ein von der De Nederlandsche Bank (DNB) beaufsichtigtes Zahlungsinstitut mit Sitz unter Keizersgracht 126, 1015 CW Amsterdam, Niederlande. Zahlungsdaten werden in den Niederlanden (EU) verarbeitet; Kartennetzwerke können sie im Rahmen des Datenverarbeitungsvertrags von Mollie weltweit verarbeiten.

## EU-only-Routing: eine Einstellung, fail-closed

EU-only-Routing ist der Routing-Modus des Mandanten (`routingMode`, gespeichert als `global` oder `eu_only`). Unter `eu_only` muss jede Nachricht über die **eigenen Relay-MTAs** von ApexMail das System verlassen; der gemeinsame Drittanbieter-Transport (AWS SES) ist für diesen Mandanten ausgeschlossen, und der Code enthält keine Eingabe, die im EU-only-Modus zu einer Drittanbieter-Route führt.

Was passiert, wenn die eigene MTA-Route nicht verfügbar ist, macht den Modus zu einem Versprechen statt zu einer Vorliebe: **Die Nachricht wird angehalten** — in der Warteschlange zurückgestellt, mit benanntem Grund, sichtbar und freigebbar — sie wird niemals auf den Drittanbieter-Transport umgeleitet. Dieselbe Disziplin gilt, wenn die Konfiguration der Zeile nicht lesbar ist: Ein gespeicherter Routing-Wert, der nicht als `global` gelesen werden kann, wird als `eu_only` gelesen, denn eine angehaltene Nachricht ist wiederherstellbar, eine falsch geroutete nicht.

Was sich gegenüber Global ändert, klar ausgedrückt:

| | Global (Standard) | EU-only |
|---|---|---|
| Versand über dedizierte IPs | Eigene Relay-MTAs von ApexMail | Eigene Relay-MTAs von ApexMail |
| Alles Übrige | Gemeinsamer Pool — AWS SES in der konfigurierten EU-Region (die Deutschland umfassen kann) | Eigene EU-MTAs von ApexMail |
| Route nicht verfügbar | Anbieter-Failover | **Anhalten mit benanntem Grund** — kein Drittanbieter-Fallback |

Verfügbarkeit und Preis: enthalten bei [Enterprise](/de/enterprise/) Cloud und in der Compliance-Vertragslinie; in den Self-Service-Tarifen ist es das Add-on **EU-only routing** für **149 €/Monat (165 US$/Monat)** ab Pro — der exakte Katalogwert.

Belege: Die [Preisseite](/de/pricing/) rendert das Add-on und die Compliance-Linie aus dem Abrechnungskatalog; die [Compliance-Seite](/de/compliance/) dokumentiert die Workflow-Seite; die [Architekturseite](/architecture) beschreibt den Zustellpfad.

## Signierte Routing-Belege: prüfen statt vertrauen

Jede angenommene Nachricht erzeugt einen Routing-Beleg, signiert mit Ed25519 (RFC 8032, 64-Byte-Signatur). Die Signatur deckt exakte, nachrechenbare Bytes ab — eine LF-getrennte Nutzlast ohne Auffüllung:

```text
apexmail-routing-receipt/v1
message_id=<Plattform-Nachrichten-ID>
tenant_id=<Mandanten-ID>
transport=<Transport-Label>
accepted_at=<RFC 3339 UTC>
actual_source_ip=<IP>          ← nur vorhanden, wenn der Transport eine gemeldet hat
```

Jede Ed25519-Bibliothek kann diese Bytes aus den veröffentlichten Feldern des Belegs neu ableiten und die Signatur prüfen — ohne der Datenbank, der API-Oberfläche oder dem TLS-Stack von ApexMail vertrauen zu müssen. Der Prüfschlüssel wird unauthentifiziert ausgeliefert:

- `GET https://api.apexmail.ee/v1/routing/receipts/public-key` — der öffentliche Ed25519-Schlüssel, das Schema-Label und eine Schlüssel-ID (`hex(sha256(public_key))[0:16]`), die neben jeder Signatur festgehalten wird, sodass eine Schlüsselrotation auditierbar ist.
- `POST https://api.apexmail.ee/v1/routing/receipts/verify` — `{payload, signature}`; antwortet mit dem Prüfergebnis.

Das Schema ist in beide Richtungen fail-closed: Ein Beleg-Schreibvorgang ohne konfigurierten Signaturschlüssel wird verweigert (die Annahmezeile wird nicht als angenommen markiert), und die Dienste, denen der Annahmepfad gehört, verweigern in der Produktion den Start ohne Schlüssel. Ein unsignierter Beleg kann nicht stillschweigend existieren.

Belege: Beide Endpunkte sind live und unauthentifizierte Oberflächen der öffentlichen API; die [API-Dokumentation](/docs/api/) beschreibt den umgebenden Vertrag; die [Compliance-Vertragslinie](/de/pricing/) führt signierte Routing-Belege als enthaltene Leistung.

## Was EU-only aus der Unterauftragsverarbeiter-Kette entfernt

Das [Unterauftragsverarbeiter-Register](/de/subprocessors/) wird aus der Konfiguration der Bereitstellung selbst erzeugt; die gelistete Menge kann daher nicht von dem abweichen, was tatsächlich läuft. Unter EU-only-Routing trägt der Eintrag Amazon Web Services SES keine Mail eines Mandanten: Die Nachricht verlässt das System ausschließlich über die eigenen MTAs von ApexMail auf Hetzner-Infrastruktur (Hetzner Online GmbH, Finnland). Die übrigen Einträge sind Zahlungen (Mollie B.V., Amsterdam) und optionale OAuth-Anmeldung (Google, GitHub) — jeweils mit Verarbeitungsland und Übermittlungsmechanismus im Register ausgewiesen.

Anders gesagt: Unter EU-only trägt keine US-kontrollierte dritte Partei die Mail. Unter Global tut dies AWS SES — in EU-Regionen (die Deutschland umfassen können), unter dem AWS-AVV und den SCCs, und genau das sagt das Register.

Belege: Das [Unterauftragsverarbeiter-Register](/de/subprocessors/) (generiert, drift-gated), Abschnitt 5 der [AVV](/de/dpa/) und die [Datenstandort-Matrix](/de/data-locations/).

## Isolation des Vertriebsversands

Mail, die vom eigenen Sales-Autopilot von ApexMail versendet wird, wird anhand ihrer Herkunft klassifiziert und über einen dedizierten Vertriebs-Transport-Slot geroutet. Sie wird nie über den SES- oder Relay-Transport eines Kunden versendet, und wenn dieser Slot nicht konfiguriert ist, wird Vertriebsmail **angehalten** — der Kundentransport wird nicht als Fallback aufgerufen. Bounces und Beschwerden aus dem Vertrieb landen im Suppression-Set des Vertriebs-Mandanten, nicht in der Sende-Reputation von Kunden.

Belege: Die Isolation ist eine Eigenschaft der Routing-Entscheidung des Zustell-Workers, beschrieben auf der [Architekturseite](/architecture); der für Kunden sichtbare Effekt (getrennte Reputationsdomänen) entspricht dem Sendemodell, das unter den [Zustellbarkeitsfunktionen](/de/features/) dokumentiert ist.

## Das Evidenzpaket für Prüfungen

Für Einkäufer, die das Argument in prüfbarer Form statt als Prosa brauchen:

- **Compliance-Vertragslinie** — 1 Mio. E-Mails, EU-only-Routing enthalten, dedizierte IP, **DORA-/NIS2-Evidenzpaket**, DSGVO-Verarbeiterpaket, signierte Routing-Belege, 1 Jahr Audit-Log, SSO. Mit ihrem exakten Preis auf der [Preisseite](/de/pricing/) gerendert.
- **DSGVO-/AVV-Material** — die [AVV](/de/dpa/), die [Datenschutzerklärung](/de/privacy/) und die [Compliance-Workflow-Seite](/de/compliance/); Verarbeitungsdokumentation steht zur Prüfung bereit.
- **Offene Grenzen, als Grenzen benannt** — HIPAA wird derzeit nicht angeboten, eine ISO-27001-Zertifizierung wird derzeit nicht angeboten, und kein standardisiertes SIG-/CAIQ-/HECVAT-Paket ist eine Produktleistung; Sicherheitsfragebögen werden fallweise mit aktuellem Prüfmaterial bearbeitet. Diese Aussagen stammen aus demselben kanonischen Claims-Datensatz, der die Texte dieser Website absichert.

Belege: Die [Compliance-Seite](/de/compliance/) verlinkt ihre Dokumentation; für den Prüfprozess [Vertrieb kontaktieren](/de/contact/sales/).

## Sprachen und Support

Diese Website und die Kundenoberflächen des Produkts erscheinen in Englisch, Deutsch, Französisch und Spanisch. Der Support läuft per E-Mail (`support@apexmail.ee`) mit tarifabhängigen Support-Bedingungen; Business und Enterprise tragen die Verfügbarkeits- und Leistungszusagen der [SLA](/de/sla/), gemessen über externe Sonden und vergütet nach der Tarifmatrix.

Belege: Die vier Sprachausgaben jeder Seite (Sprachwahl im Header), die [SLA](/de/sla/) und die [Kontaktseite](/de/contact/).

## Wie es weitergeht

- [Datenstandort-Matrix](/de/data-locations/) — wo jede Datenkategorie liegt.
- [Unterauftragsverarbeiter-Register](/de/subprocessors/) — die generierte Anbieterliste.
- [Compliance-Workflows](/de/compliance/) und die [AVV](/de/dpa/) — die vertragliche Ebene.
- [Preise](/de/pricing/) — das EU-only-Add-on (149 €/Monat, ab Pro) und die Compliance-Linie.
- [Enterprise](/de/enterprise/) — Enterprise Cloud, in der EU-only-Routing enthalten ist.
- [ApexMail vs. Amazon SES](/de/compare/amazon-ses/) — der ehrliche Vergleich mit dem Transport, den EU-only entfernt.
- [Architektur](/architecture) — der Zustellpfad im technischen Detail.
