+++
title = "Sicherheitsübersicht"
description = "ApexMail-Sicherheitskontrollen: Verschlüsselung, Authentifizierung, Netzwerkverteidigung, Incident Response, Schwachstellenmanagement und Compliance-Nachweise."
template = "prose.html"

[extra]
last_updated = "2026-10-02"
+++

## Verschlüsselung

### Daten während der Übertragung

- TLS 1.2+ für alle API- und SMTP-Verbindungen erforderlich.
- TLS 1.3 bevorzugt, wo vom empfangenden MTA unterstützt.
- Private, nicht öffentliche Vernetzung für die dienstübergreifende Kommunikation (isolierte Deploy-Netzwerke; kein Dienst-zu-Dienst-Verkehr über das öffentliche Internet).

[roadmap] MTA-STS-Richtlinienveröffentlichung (`mode: enforce`) und DANE-Validierung (TLSA-Einträge) der MX-Server von Empfängern sind geplante Funktionen; sie werden auf den Mail-Pfaden der Managed Cloud heute nicht durchgesetzt.

### Daten im Ruhezustand

- AES-256-GCM-Verschlüsselung für Nachrichteninhalte und Anhänge.
- Argon2id für Passwort-Hashing (speicherhart, resistent gegen GPU/ASIC-Angriffe).
- Verschlüsselte Datenbank-Volumes (LUKS/dm-crypt).
- Verschlüsselte Backups mit separatem Schlüsselmanagement.
- Anforderungen an kundenseitig verwaltete Verschlüsselungsschlüssel können nur im Rahmen einer gesondert vereinbarten Bereitstellung geprüft werden; sie sind kein öffentliches Tarifmerkmal.

## Authentifizierung und Zugriffskontrolle

- API-Schlüssel pro Umgebung (Live/Test) mit konfigurierbaren Berechtigungen.
- Webhook-HMAC-Signaturen (SHA-256) für die Integrität von Ereignisnutzdaten.
- SAML SSO für Business- und Enterprise-Tarife; Bereitstellungszusagen werden im jeweiligen Vertrag bestätigt.
- Rollenbasierte Zugriffskontrolle (RBAC) mit benutzerdefinierten Rollen im Enterprise-Tarif.
- Multi-Faktor-Authentifizierung (TOTP) für den Dashboard-Zugriff.
- Sitzungsverwaltung mit konfigurierbarem Timeout und IP-Bindung.

## Anwendungssicherheit

### Anforderungsprüfung (Web Application Firewall)

Eine Anforderungsprüf-Firewall (WAF) auf Basis von SQLi/XSS/Traversal/Command-Injection/SSRF-Regeln wertet Methode, Pfad, Query-String und Header öffentlicher API-Anfragen aus: die verwaltete Produktionsbasis betreibt sie im Durchsetzungsmodus, Entscheidungen, die die Engine blocken würde, werden blockiert, und jede Entscheidung wird protokolliert. [roadmap] Die Prüfung von Anfragekörpern bleibt auf der Roadmap und ist keine aktive Kontrolle. Die Intrusion Detection ist eine aktive Kontrolle auf dem eingehenden Mailpfad: die IDS-Engine prüft jede vom MTA angenommene Nachricht, und die Produktionsbasis verweigert Nachrichten, die sie auslöst.

- Eingabevalidierung und -bereinigung an allen API-Endpunkten (Handler-Ebene).
- Ratenbegrenzung pro Endpunkt und API-Schlüssel.

### DDoS- und Missbrauchsschutz

Auf Anwendungsebene in den öffentlichen API-Anforderungspfad integrierte Abwehrmaßnahmen:

1. Kostenbasierte Anforderungsratenbegrenzung mit Mandanten-Budgets.
2. Adaptive Schwellenwerte pro IP (statistische z-Score-Anomalieerkennung über Anfragemuster).
3. Anforderungs-Fingerprinting (JA4/TLS- und HTTP/2-Fingerprints) für Reputationsentscheidungen.
4. Load-Shedding-Middleware vor der Authentifizierungs- und Ratenbegrenzungsarbeit.

### API-Authentifizierung

- Alle API-Endpunkte erfordern den `X-API-Key`-Header mit bereichsbezogenem API-Schlüssel.
- Webhook-Signaturen über HMAC-SHA256 verifiziert.
- OAuth 2.0 für Drittanbieter-Integrationen (Google, GitHub-Anmeldung).
- Sitzungsbasierte Authentifizierung mit sicheren, HTTP-only-Cookies für den Dashboard-Zugriff.

## Systemintegritätsprüfung

Die Systemintegrität wird durch automatisierte, wiederkehrende Prüfungen im gesamten Bereitstellungs- und Laufzeit-Stack verifiziert:

| Kontrolle | Was wird verifiziert | Häufigkeit | Nachweis |
|---|---|---|---|
| **Integrität der Bereitstellungsartefakte** | Container-Images werden per Digest verifiziert, nicht signiert: Jede Pipeline-Ausführung zeichnet ein Release-Manifest auf (SHA-256-Digests je Image, `SHA256SUMS.images`) und erzeugt eine digest-gepinnte Compose-Override-Datei; die Bereitstellung verweigert den Start jedes Images, dessen Digest nicht zum Manifest passt. | Jede Bereitstellung | Release-Manifest + Digest-Verifizierung vor dem Rollout in der Deploy-Stufe |
| **Audit-Log-Integrität** | Audit-Log-Tabellen tragen eine Hash-Kette: Der SHA-256-Digest jeder Zeile ist mit ihrem Vorgänger verkettet. | Kontinuierlich (je Schreibvorgang) | Audit-Log-Hash-Kette |
| **Bereitstellungsprotokolle** | Jede Pipeline-Ausführung zeichnet ein Manifest (Stufe, Status, Exit-Code, Dauer) sowie Stufen-Protokolle auf. Dies sind Betriebsprotokolle, kein manipulationssicheres, kundenseitiges Protokoll. | Jede Bereitstellung | CI-Run-Manifeste (`ci/runs/<ts>/manifest.json`) |
| **Backup-Verifizierung** | Jedes Backup wird automatisch entschlüsselt und strukturell validiert (`pg_restore --list`), bevor die Klartext-Kopie gelöscht wird, ein nicht lesbares Backup gilt nie als gut. Eine Wiederherstellungsübung stellt das neueste Backup automatisch in einer Scratch-Datenbank wieder her und zeichnet gemessene Wiederherstellungsnachweise auf. | Je Backup (automatische Validierung); alle 30 Tage (Wiederherstellungsübung) | Wiederherstellbarkeitsprüfung beim Backup; Nachweise der Wiederherstellungsübung |
| **Laufzeit-Resilienz** | Dienste laufen mit Healthchecks und automatischem Neustart; ein fehlgeschlagener Content-Probe nach dem Deploy löst automatisches Rollback auf die vorherigen Image-Pins aus. | Kontinuierlich | Container-Healthchecks; Verify-Stufe + Rollback |

## Infrastruktursicherheit

- Europäische Cloud-Infrastruktur (Compute, Storage und Networking) in Finnland (EU); die gesamte Infrastrukturverarbeitung bleibt innerhalb des EWR.
- CIS-gehärtete Debian/Ubuntu-Betriebssysteme.
- Automatisierte Sicherheitspatches mit gestaffelter Einführung.
- Deklarative, versionskontrollierte Bereitstellung: Der gesamte Stack ist in Docker-Compose-Dateien definiert und wird über die selbst gehostete CI-Pipeline ausgerollt.
- Docker-Netzwerksegmentierung zwischen Frontend-, Backend- und Datenbank-Netzwerken.
- Host-Firewall: Eingehender Zugriff auf die Mail-/Web-Service-Ports (25, 80, 443, 587, 993) sowie Verwaltungsports beschränkt; Datenbanken haben keine öffentliche Port-Freigabe.
- Geheimnisverwaltung über Docker Secrets aus berechtigungsbeschränkten Dateien (0600); keine Geheimnisse in Images oder Quellcode.

## Schwachstellenmanagement

- Automatisiertes Dependency-Scanning in der CI/CD-Pipeline.
- Automatisiertes Infrastruktur-Schwachstellen-Scanning (wöchentlich).
- Jährlicher Drittanbieter-Penetrationstest (geplant, derzeit in Beschaffung; Ergebnisse werden nach dem ersten Test und der Behebung veröffentlicht).
- Responsible-Disclosure-Programm: [security@apexmail.ee](mailto:security@apexmail.ee)
- Ziele für die Schwachstellenbehebung nach Schweregrad:
  - **Kritisch:** Sofortige Eindämmung erforderlich; dauerhafte Behebung innerhalb von 7 Tagen.
  - **Hoch:** Ziel innerhalb von 30 Tagen.
  - **Mittel:** Ziel innerhalb von 90 Tagen.
  - **Niedrig:** Risikobasiert, Behandlung in regelmäßigen Wartungszyklen.
  - **Aktiv ausgenutzt:** Notfallprozess unabhängig vom Schweregrad.

## Incident Response

- Dokumentierter Incident-Response-Plan mit halbjährlichen Tabletop-Übungen und jährlicher vollständiger Simulation.
- Klassifizierung des Schweregrads von Sicherheitsvorfällen: Kritisch (SEV-1), Hoch (SEV-2), Mittel (SEV-3), Niedrig (SEV-4).
- Statusseite wird innerhalb von 15 Minuten nach bestätigtem SEV-1/SEV-2-Vorfall aktualisiert. Kundenbenachrichtigung per E-Mail innerhalb von 1 Stunde bei kritischen Vorfällen.
- Zusammenfassung nach dem Vorfall innerhalb von 1 Geschäftstag für alle Vorfälle. Postmortem-Zeitplan:
  - Innerhalb von 5 Geschäftstagen für schwerwiegende Vorfälle (alle Deployment-Modelle).
  - Endgültige Ursachenanalyse wird veröffentlicht, wenn die Validierung abgeschlossen ist.
- Verfahren zur Meldung von Datenschutzverletzungen gemäß DSGVO Art. 33/34 (Aufsichtsbehörde innerhalb von 72 Stunden).

## Audit- und Compliance-Nachweise

- Zusammenfassung des Penetrationstests: geplant zur Veröffentlichung nach Abschluss des ersten externen Anwendungs-Penetrationstests und Behebung hoher/kritischer Ergebnisse. Derzeit nicht verfügbar.
- Sicherheitsfragebögen werden anhand aktueller Prüfdokumentation im Einzelfall bewertet; standardisierte SIG-, CAIQ- oder HECVAT-Pakete sind kein Produktmerkmal.
- ApexMail zeichnet API-, Konfigurations- und Admin-Aktionen in einem manipulationssicheren Audit-Trail auf; die Aufbewahrung richtet sich nach dem abonnierten Tarif.
- Unterstützung bei Kundenaudits unterliegt einer Enterprise-Vertragsprüfung.

## Betriebliche Sicherheit

- Jede Änderung muss die verpflichtenden CI- und Sicherheits-Gates des Repositories passieren, bevor sie ausgerollt wird; die Deploy-Pipeline verweigert jedes Build ohne frisches Gate-Blessing, das diese Lanes abdeckt.
- Zugriffsüberprüfungen erfolgen vierteljährlich.
- Produktionszugriff erfordert Multi-Faktor-Authentifizierung.
- Änderungsmanagement mit Rollback-Fähigkeit: CI-Logs, Audit-Trail und Gate-Blessing halten fest, was sich geändert hat und welche Gates gehalten haben, manipulationssichere Nachweise statt informeller Praxis.
- Hochriskante Kontrollen werden regelmäßig extern und unabhängig geprüft.

## Verwandte Themen

- [Compliance Center](/de/compliance)
- [Architekturübersicht](/architecture) (auf Englisch)
- [Datenschutzerklärung](/de/privacy)
- [Datenverarbeitungsvereinbarung](/de/dpa)
- [Richtlinie zur akzeptablen Nutzung](/de/acceptable-use)
- [Responsible Disclosure](/de/responsible-disclosure)
