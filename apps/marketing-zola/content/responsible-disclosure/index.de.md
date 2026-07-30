+++
title = "Verantwortungsvolle Offenlegung"
description = "ApexMail-Richtlinie zur verantwortungsvollen Offenlegung — wie Sie Sicherheitslücken melden."
template = "prose.html"

[extra]
last_updated = "2026-07-29"
+++

## 1. Richtlinie

ApexMail nimmt die Sicherheit unserer Systeme und Kundendaten ernst. Wir begrüßen Meldungen von Sicherheitsforschern und der Öffentlichkeit über potenzielle Schwachstellen. Diese Richtlinie beschreibt, wie Sie Sicherheitsprobleme melden und was Sie von uns erwarten können.

## 2. Geltungsbereich

Diese Richtlinie gilt für:

- `apexmail.ee` und alle Subdomains
- `api.apexmail.ee`
- `smtp.apexmail.ee`
- `app.apexmail.ee`
- `cdn.apexmail.ee`
- Die ApexMail-API und Webanwendung

Dienste, die nicht von ApexMail betrieben werden (z. B. Drittanbieter-Integrationen), fallen nicht in den Geltungsbereich, es sei denn, die Schwachstelle betrifft unsere Integration mit diesem Dienst.

## 3. Meldung

Senden Sie Schwachstellenmeldungen an **[security@apexmail.ee](mailto:security@apexmail.ee)** .

Bitte geben Sie an:

- Eine detaillierte Beschreibung der Schwachstelle.
- Schritte zur Reproduktion, einschließlich etwaigen Proof-of-Concept-Codes.
- Die betroffene Domain, den Endpunkt oder die Komponente.
- Ihre Einschätzung der potenziellen Auswirkungen.
- Vorgeschlagene Behebungsmaßnahmen.

Verschlüsseln Sie vertrauliche Meldungen mit unserem [PGP-Schlüssel](/pgp-key.txt).

## 4. Was wir versprechen

- Eingangsbestätigung innerhalb von **48 Stunden**.
- Erste Bewertung innerhalb von **5 Geschäftstagen**.
- Wir halten Sie über den Fortschritt der Lösung auf dem Laufenden.
- Keine rechtlichen Schritte gegen Forscher, die dieser Richtlinie folgen.
- Anerkennung für Forscher, die gültige Schwachstellen melden (es sei denn, Sie bevorzugen Anonymität).

## 5. Was wir erbitten

- Greifen Sie nicht auf Daten zu, verändern oder löschen Sie diese nicht, die Ihnen nicht gehören.
- Beeinträchtigen Sie den Dienst nicht und stören Sie keine anderen Nutzer.
- Veröffentlichen Sie die Schwachstelle nicht, bevor wir angemessene Zeit zur Behebung hatten (Ziel: 90 Tage).
- Testen Sie keine physische Sicherheit, Social Engineering oder Denial-of-Service.

## 6. Anerkennung

Wir würdigen und danken Sicherheitsforschern, die uns bei der Verbesserung helfen. Gültige Schwachstellenmeldungen werden auf dieser Seite (mit Zustimmung des Melders) anerkannt.

## 7. Außerhalb des Geltungsbereichs

Folgendes wird im Allgemeinen als außerhalb des Geltungsbereichs betrachtet, wird jedoch geprüft:

- Probleme ohne eindeutige Sicherheitsauswirkung.
- Fehlende HTTP-Sicherheitsheader, die kein direktes Risiko darstellen.
- Self-XSS oder Angriffe, die physischen Zugriff auf das Gerät eines Opfers erfordern.
- Theoretische Schwachstellen ohne Machbarkeitsnachweis.
