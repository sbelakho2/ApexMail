+++
title = "Inbox-Platzierung, gemessen"
template = "prose.html"
description = "ApexMail fragt alle sechs Stunden Google Postmaster Tools und Microsoft SNDS ab, bewertet Ihre Absenderreputation und drosselt ausgehende Versände automatisch, wenn die Daten es nahelegen."

[extra]
og_image = "/images/og-image.png"
+++

## Inbox-Platzierung, belegt durch die Postfachanbieter selbst

Die meisten „Zustellbarkeits-Dashboards“ sind Seed-Listen-Theater. ApexMail liest das
**tatsächliche** Signal, das Gmail und Outlook über Ihre Domain veröffentlichen — und
handelt danach.

## Was wir messen

<div class="grid grid-cols-1 md:grid-cols-2 gap-6 my-10">
  <div class="bg-surface-900 border border-surface-800 rounded-lg p-6">
    <h3 class="text-xl font-semibold mb-3">Google Postmaster Tools</h3>
    <ul class="list-disc pl-5 space-y-1">
      <li>Domain-Reputation: HIGH / MEDIUM / LOW / BAD</li>
      <li>IP-Reputation je Sende-IP</li>
      <li>SPF-, DKIM- und DMARC-Bestehensquoten</li>
      <li>Anteil von Nutzern gemeldeten Spams</li>
      <li>TLS-Raten ein- und ausgehend</li>
      <li>Aufschlüsselung von Zustellfehlern</li>
    </ul>
  </div>
  <div class="bg-surface-900 border border-surface-800 rounded-lg p-6">
    <h3 class="text-xl font-semibold mb-3">Microsoft SNDS</h3>
    <ul class="list-disc pl-5 space-y-1">
      <li>Filterergebnis: GREEN / YELLOW / RED</li>
      <li>Beschwerdequote pro IP</li>
      <li>Spam-Trap-Treffer</li>
      <li>Annahmequote der Empfänger</li>
      <li>Feedback aus dem Junk Mail Reporting Program (JMRP)</li>
    </ul>
  </div>
</div>

## Wie wir darauf reagieren

Alle sechs Stunden durchläuft der Reputations-Scheduler von ApexMail:

1. **Abrufen** der aktuellen Statistiken für jede Domain und IP, von der aus Sie senden.
2. **Bewerten** auf einer transparenten Skala von 0–100 (der Algorithmus steht in unserer Dokumentation).
3. **Einordnen** des Scores in Bänder: Grün (≥70), Gelb (40–69), Rot (<40).
4. **Automatisches Drosseln** des ausgehenden Verkehrs zu diesem Anbieter:
   - Grün → 0% Drosselung (volle Geschwindigkeit)
   - Gelb → 50% Drosselung (probabilistische Verzögerung)
   - Rot → 90% Drosselung (nahezu Stopp, Alarm wird versendet)
5. **Benachrichtigen** der richtigen Personen — per Webhook, E-Mail oder Slack —, wenn ein Band abfällt.

Erholt sich Ihre Reputation, wird die Drosselung ohne manuellen Eingriff aufgehoben.

## Warum das für Ihren Umsatz zählt

Eine einzige fehlerhafte Sendung kann eine Absender-Domain für 30+ Tage auf Gmails BAD-Liste
bringen. Die meisten ESPs überbringen die schlechte Nachricht im nächsten Quartals-Review.
ApexMail begrenzt den Schadensradius **noch in derselben Schicht** — Ihre High-Volume-Tenants
stellen weiterhin über saubere Pfade zu, während sich die betroffene Domain abkühlt.

## Drossel-Overrides je Anbieter

Betreibende können eine Drosselung fixieren (z. B. 100% für zwei Stunden während eines
bekannten Vorfalls), ohne Code zu ändern. Jede Entscheidung wird mit Score, Band und Quelle
protokolliert — für Audits und Transparenz gegenüber Kunden.

## Reputations-Snapshot anfordern

Wir können Ihre bestehende Domain in weniger als einer Stunde auditieren — mit denselben
Google- und Microsoft-Datenströmen, die wir produktiv nutzen. [Zustellbarkeits-Review buchen](/de/contact/).
