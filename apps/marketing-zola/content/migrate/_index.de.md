+++
title = "Migrationsleitfäden je Anbieter"
sort_by = "title"
template = "section.html"
transparent = true
description = "Migrationsleitfäden je Anbieter für SendGrid, Mailgun, Postmark und Resend: Kompatibilitätsendpunkt, Auth-Umstellung, Feldzuordnung, benannte Ablehnungen, DNS-Checkliste, Webhook-Ereignisnamen und ein 10/50/100-Umschaltplan."
+++

Die Migration einer Sende-Integration ist bei ApexMail ein Basis-URL-Wechsel. Jeder Anbieter unten hat eine eigene Kompatibilitätsoberfläche, die die Anfrageform des Anbieters und den ApexMail-API-Schlüssel im Credential-Header des Anbieters akzeptiert und dann den kanonischen Sendepfad ausführt: Absenderdomain-Prüfung, Unterdrückungs- und Einwilligungsfilter, Tarifberechtigungen, das dauerhafte Idempotenz-Ledger und der Queue-Eintrag.

Jeder Leitfaden nennt die Endpunkt-Zuordnung, die exakten Felder, die die Oberfläche benannt ablehnt, was nicht weitergeleitet wird, die DNS-Records, die sich ändern und bleiben, die Webhook-Ereignisnamen für ein neues Abonnement und einen sechsschrittigen Umschaltplan, dessen Rollback derselbe Basis-URL-Wechsel rückwärts ist.
