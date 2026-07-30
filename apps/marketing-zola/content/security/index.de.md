+++
title = "Sicherheitsübersicht"
description = "ApexMail-Sicherheitskontrollen: Verschlüsselung, Authentifizierung, Netzwerkverteidigung, Incident Response, Schwachstellenmanagement und Compliance-Nachweise."
template = "prose.html"

[extra]
last_updated = "2026-07-29"
+++

## Verschlüsselung

### Daten während der Übertragung

- TLS 1.2+ für alle API- und SMTP-Verbindungen erforderlich.
- TLS 1.3 bevorzugt, wo vom empfangenden MTA unterstützt.
- MTA-STS-Richtlinie mit `mode: enforce` für eingehende SMTP.
- DANE (TLSA-Einträge) für ausgehende SMTP-Zustellung.
- WireGuard oder private Vernetzung für die dienstübergreifende Kommunikation.

### Daten im Ruhezustand

- AES-256-GCM-Verschlüsselung für Nachrichteninhalte und Anhänge.
- Argon2id für Passwort-Hashing (speicherhart, resistent gegen GPU/ASIC-Angriffe).
- Verschlüsselte Datenbank-Volumes (LUKS/dm-crypt).
- Verschlüsselte Backups mit separatem Schlüsselmanagement.
- Kundenseitig verwaltete Verschlüsselungsschlüssel bei Dedicated-Tenant- und BYOC-Tarifen.

## Authentifizierung und Zugriffskontrolle

- API-Schlüssel pro Umgebung (Live/Test) mit konfigurierbaren Berechtigungen.
- Webhook-HMAC-Signaturen (SHA-256) für die Integrität von Ereignisnutzdaten.
- SAML SSO und SCIM-Bereitstellung (Business- und Enterprise-Tarife).
- Rollenbasierte Zugriffskontrolle (RBAC) mit benutzerdefinierten Rollen im Enterprise-Tarif.
- Multi-Faktor-Authentifizierung (TOTP) für den Dashboard-Zugriff.
- Sitzungsverwaltung mit konfigurierbarem Timeout und IP-Bindung.

## Anwendungssicherheit

### Web Application Firewall (WAF)

- SQL-Injection-Erkennung (AST-basiert).
- XSS-Erkennung (AST-basiert).
- OWASP-CRS-kompatible Regeln.
- Eingabevalidierung und -bereinigung an allen API-Endpunkten.
- Ratenbegrenzung pro Endpunkt und API-Schlüssel.

### Intrusion Detection und Prevention (IDS/IPS)

- Signaturbasierte Erkennung.
- Protokollanomalieerkennung.
- Verbindungsverfolgung und Alarmierung.

### DDoS-Schutz (5-Schichten-Verteidigung)

1. Schicht 3/4: Ratenbegrenzung, SYN-Flood-Schutz
2. Schicht 7: Signaturanalyse von Anfragen, Challenge-Response
3. ML-basierte Anomalieerkennung
4. SMTP-Zustandsautomaten-Schutz
5. Adaptive Drosselung

### API-Authentifizierung

- Alle API-Endpunkte erfordern den `X-API-Key`-Header mit bereichsbezogenem API-Schlüssel.
- Webhook-Signaturen über HMAC-SHA256 verifiziert.
- OAuth 2.0 für Drittanbieter-Integrationen (Google, GitHub-Anmeldung).
- Sitzungsbasierte Authentifizierung mit sicheren, HTTP-only-Cookies für den Dashboard-Zugriff.

## Systemintegritätsprüfung

Die Systemintegrität wird durch automatisierte, wiederkehrende Prüfungen im gesamten Bereitstellungs- und Laufzeit-Stack verifiziert:

| Kontrolle | Was wird verifiziert | Häufigkeit | Nachweis |
|---|---|---|---|
| **Signierte Bereitstellungsartefakte** | Alle Anwendungsbinärdateien und Container-Images werden zum Build-Zeitpunkt kryptografisch signiert. Bereitstellungen validieren Signaturen vor dem Rollout. | Jeder Build | Build-Attestierungsprotokolle (unveränderlich, nur anhängend) |
| **Datenbankintegritätsprüfungen** | PostgreSQL-Prüfsummenvalidierung auf allen Datenseiten; Hash-Ketten-Integrität in Audit-Log-Tabellen über verkettete SHA-256-Digests. | Kontinuierlich (Prüfsumme beim Lesen); nächtlicher vollständiger Scan | Alarm bei Korruption; Audit-Log-Kettenverifikations-Endpunkt |
| **Unveränderliche Bereitstellungsprotokolle** | Jedes Bereitstellungsereignis (wer, was, wann, Git-Commit, Artefakt-Hash) wird in einem Nur-Anhängen-Protokoll aufgezeichnet. | Jede Bereitstellung | Bereitstellungsverlaufs-Endpunkt; manipulationssicheres Protokoll |
| **Dateiintegritätsüberwachung** | Systembinärdateien, Konfigurationsdateien und TLS-Zertifikate werden auf unbefugte Änderungen überwacht. | Kontinuierlich (inotify-basiert) | Alarm bei Änderungen außerhalb genehmigter Änderungsfenster |
| **Verifizierte Backup-Wiederherstellungen** | Automatisierte Wiederherstellungstests validieren Backup-Integrität und Wiederherstellbarkeit. | Wöchentlich | Wiederherstellungs-Erfolgs-/Fehlerprotokoll; Vergleich von Beispieldaten |
| **Laufzeitintegrität** | Anwendungsprozesse werden auf unerwartete Binäränderungen oder Konfigurationsabweichungen gegenüber dem deklarierten Infrastructure-as-Code-Zustand überwacht. | Kontinuierlich | Abweichungserkennungsalarm; Abstimmungsbericht |

## Infrastruktursicherheit

- Hetzner Online GmbH (Rechenzentren in Deutschland und Finnland) für Compute, Storage und Networking.
- CIS-gehärtete Debian/Ubuntu-Betriebssysteme.
- Automatisierte Sicherheitspatches mit gestaffelter Einführung.
- Unveränderliche Infrastruktur durch Infrastructure-as-Code.
- Netzwerksegmentierung zwischen Anwendungs-, Daten- und Managementebenen.
- Netzwerkisolation: Anwendungsserver, Datenbankserver und Verwaltungsschnittstellen in separaten VLANs.
- Geheimnisverwaltung über versiegelte Geheimnisse und Umgebungsisolation.

## Schwachstellenmanagement

- Automatisiertes Dependency-Scanning in der CI/CD-Pipeline.
- Automatisiertes Infrastruktur-Schwachstellen-Scanning (wöchentlich).
- Jährlicher Drittanbieter-Penetrationstest (geplant — derzeit in Beschaffung; Ergebnisse werden nach dem ersten Test und der Behebung veröffentlicht).
- Responsible-Disclosure-Programm: [security@apexmail.ee](mailto:security@apexmail.ee)
- Ziele für die Schwachstellenbehebung nach Schweregrad:
  - **Kritisch:** Sofortige Eindämmung erforderlich; dauerhafte Behebung innerhalb von 7 Tagen.
  - **Hoch:** Ziel innerhalb von 30 Tagen.
  - **Mittel:** Ziel innerhalb von 90 Tagen.
  - **Niedrig:** Risikobasiert — Behandlung in regelmäßigen Wartungszyklen.
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

- SOC 2 Type II ist geplant (Ziel Q2 2028, nach Type I in Q3 2027). Derzeit nicht verfügbar. Interne Kontrollen sind kartiert und eine Bereitschaftsbewertung ist im Gange.
- Zusammenfassung des Penetrationstests: geplant zur Veröffentlichung nach Abschluss des ersten externen Anwendungs-Penetrationstests und Behebung hoher/kritischer Ergebnisse. Derzeit nicht verfügbar.
- Sicherheitsfragebögen SIG, CAIQ und HECVAT sind in Bearbeitung und auf Anfrage für Enterprise-Kunden verfügbar.
- Audit-Protokolle mit konfigurierbarer Aufbewahrung (Premium-Audit-Protokolle für Enterprise).
- Kunden-Audit-Erleichterung für Enterprise- und Dedicated-Tenant-Tarife.

## Betriebliche Sicherheit

- Hintergrundüberprüfungen für Personal mit Produktionszugriff.
- Vierteljährliche Zugriffsüberprüfungen.
- Produktionszugriff erfordert Multi-Faktor-Authentifizierung und Genehmigung.
- Änderungsmanagement mit Peer-Review und Rollback-Fähigkeit.
- Aufgabentrennung zwischen Entwicklung und Betrieb.

## Verwandte Themen

- [Compliance Center](/compliance)
- [Architekturübersicht](/architecture)
- [Datenschutzerklärung](/privacy)
- [Datenverarbeitungsvereinbarung](/dpa)
- [Richtlinie zur akzeptablen Nutzung](/acceptable-use)
- [Responsible Disclosure](/responsible-disclosure)
