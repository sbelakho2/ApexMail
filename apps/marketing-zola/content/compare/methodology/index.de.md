+++
title = "Vergleichsmethodik"
description = "Wie ApexMail Wettbewerbsvergleiche erstellt und pflegt: Evidenzstandards, Quellenpolitik, Update-Häufigkeit und Korrekturprozess."
template = "prose.html"

[extra]
last_updated = "2026-07-29"
+++

## Zweck

ApexMail veröffentlicht faktische, evidenzbasierte Vergleiche, um Entwicklern und Beschaffungsteams die Bewertung von Anbietern für Transaktions-E-Mails zu erleichtern. Jede Aussage in jedem Vergleich ist auf eine öffentliche Quelle zurückführbar.

## Offenlegungsstandards

Jede Vergleichsseite legt offen:

| Feld | Beschreibung |
|-------|-------------|
| **Verifikationsdatum** | Wann der Vergleich zuletzt gegen Live-Quellen geprüft wurde |
| **Verglichener Wettbewerber-Tarif** | Genauer Tarifname und Stufe, auf die Bezug genommen wird |
| **Verglichener ApexMail-Tarif** | Genauer ApexMail-Tarif für das Funktions-Mapping |
| **Monatliche Volumenannahme** | Das E-Mail-Volumen, mit dem die Preise berechnet werden |
| **Abrechnungszeitraum** | Monatliche oder jährliche Abrechnung für den Preisvergleich |
| **Währung** | Alle Preise werden in EUR angezeigt. ApexMail-Preise werden in EUR veröffentlicht; veröffentlicht ein Wettbewerber nur USD, wird der EUR-Betrag zum dokumentierten Referenzkurs (1 USD = €0.92, 2026-08-19) umgerechnet und der vom Anbieter veröffentlichte USD-Preis in Klammern angegeben |
| **Steuerbehandlung** | Alle Preise verstehen sich ohne MwSt., sofern nicht anders angegeben |
| **Funktionsdefinitionen** | Wie jede verglichene Funktion definiert ist |
| **Quellenpolitik** | Ausschließlich öffentliche, offizielle Dokumentation und Preisseiten |
| **Update-Häufigkeit** | Gezielte Prüfung alle 90 Tage; kritische Aussagen monatlich geprüft |
| **Korrekturprozess** | Korrekturen werden unter security@apexmail.ee angenommen; Verifikation innerhalb von 5 Werktagen |

## Evidenzfelder pro Vergleichszeile

Jede Zeile in einer Vergleichstabelle wird gestützt durch:

| Evidenzfeld | Erforderlich |
|----------------|----------|
| Funktionsname | Ja |
| ApexMail-Implementierung | Ja |
| Implementierung des Wettbewerbers | Ja |
| Genauer Tarif oder Stufe | Ja |
| Offizielle Quellen-URL | Ja |
| Quellen-Datum | Ja |
| Verifikationsdatum | Ja |
| Prüfer | Ja |
| Einschränkung (falls vorhanden) | Erforderlich, wenn die Aussage eingeschränkt ist |
| Screenshot oder archivierte Evidenz | Intern aufbewahrt |

## Regeln für Preisvergleiche

- Preisvergleiche verwenden auf beiden Seiten **äquivalente monatliche Volumina**.
- Jährliche Abrechnung wird nur verglichen, wenn der aktuelle öffentliche Katalog jedes Anbieters dies ausdrücklich unterstützt; es wird kein angenommener Rabatt angewendet.
- Variiert der Preis des Wettbewerbers je Volumenstaffel, wird die Staffel gewählt, die der genannten Volumenannahme am nächsten kommt.
- Währungen werden in ihrer ursprünglichen Nennung angezeigt. Wo Umrechnungskontext hilfreich ist, wird der EZB-Referenzkurs zum Verifikationsdatum vermerkt.

## Regeln für Funktionsvergleiche

- Funktionen werden auf Basis der **öffentlich dokumentierten Verfügbarkeit** in der genannten Tarifstufe verglichen.
- „In höheren Tarifen verfügbar“ wird nur vermerkt, wenn die Funktion im verglichenen Tarif nicht verfügbar ist.
- „Als Add-on verfügbar“ enthält, sofern veröffentlicht, den Add-on-Preis.
- Funktionen, die als „geplant“ oder „in Kürze verfügbar“ gelistet sind, werden ausgeschlossen, es sei denn, der Anbieter veröffentlicht ein verbindliches Release-Datum.
- ApexMail-Funktionen, die als „verfügbar“ gelistet sind, müssen zum Verifikationszeitpunkt in Produktion allgemein verfügbar sein.

## Richtlinie zu subjektiven Bewertungen

- Subjektive Bezeichnungen („besser“, „überlegen“, „einfach“, „eingeschränkt“) werden durch **messbare Aussagen** ersetzt.
- Ist eine qualitative Bewertung unvermeidbar, wird sie ausdrücklich als **redaktionelle Bewertung von ApexMail** mit genannten Kriterien gekennzeichnet.
- Vorteile des Wettbewerbers werden ausdrücklich und ohne Einschränkungen anerkannt.

## Korrektur- und Streitprozess

- Anbieter oder Leser können Korrekturen an security@apexmail.ee senden.
- Korrekturen werden innerhalb von 5 Werktagen gegen offizielle Quellen verifiziert.
- Verifizierte Korrekturen werden mit Korrekturdatum veröffentlicht.
- Ein Errata-Abschnitt mit dem Hinweis auf die Korrektur erscheint am Ende der betroffenen Seite.

## Prüfrythmus

| Prüfart | Häufigkeit |
|------------|-----------|
| Preisgenauigkeit (alle Wettbewerber) | Alle 90 Tage |
| Funktionsaussagen (kritische Zeilen) | Alle 30 Tage |
| Funktionsaussagen (alle Zeilen) | Alle 90 Tage |
| Gültigkeit der Quellen-URLs | Alle 90 Tage |
| Vollständige Re-Verifikation | Alle 180 Tage oder bei größeren Anbieter-Releases |

## Einschränkungen

- Vergleiche geben die öffentlich verfügbaren Informationen zum Verifikationsdatum wieder. Anbieter können Preise und Funktionen ohne Ankündigung ändern.
- Enterprise-Preise (individuelle Angebote, Volumenrabatte) werden nicht verglichen, sofern sie nicht öffentlich gelistet sind.
- Vergleiche stellen keine Rechtsberatung, Kaufempfehlungen oder vertraglichen Angebote dar.
- Leistungsbenchmarks (Latenz, Durchsatz) werden nicht verglichen, sofern sie nicht von ApexMail unter offengelegten Testbedingungen unabhängig gemessen wurden.
