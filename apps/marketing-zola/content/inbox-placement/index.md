+++
title = "Inbox Placement, Measured"
template = "prose.html"
description = "ApexMail polls Google Postmaster Tools and Microsoft SNDS every six hours, scores your sender reputation, and throttles outbound automatically when the data says back off."

[extra]
og_image = "/images/og-image.png"
+++

## Inbox Placement, Backed By the Mailbox Providers Themselves

Most deliverability dashboards only measure a fixed seed list. ApexMail reads the
**actual** signal that Gmail and Outlook publish about your domain — and
acts on it.

## What We Measure

<div class="grid grid-cols-1 md:grid-cols-2 gap-6 my-10">
  <div class="bg-surface-900 border border-surface-800 rounded-lg p-6">
    <h3 class="text-xl font-semibold mb-3">Google Postmaster Tools</h3>
    <ul class="list-disc pl-5 space-y-1">
      <li>Domain reputation: HIGH / MEDIUM / LOW / BAD</li>
      <li>IP reputation by sending IP</li>
      <li>SPF, DKIM, DMARC pass ratios</li>
      <li>User-reported spam ratio</li>
      <li>Inbound and outbound TLS rates</li>
      <li>Delivery error breakdown</li>
    </ul>
  </div>
  <div class="bg-surface-900 border border-surface-800 rounded-lg p-6">
    <h3 class="text-xl font-semibold mb-3">Microsoft SNDS</h3>
    <ul class="list-disc pl-5 space-y-1">
      <li>Filter result: GREEN / YELLOW / RED</li>
      <li>Complaint rate per IP</li>
      <li>Spam-trap hits</li>
      <li>Recipient acceptance ratio</li>
      <li>Junk Mail Reporting Program (JMRP) feedback</li>
    </ul>
  </div>
</div>

## How We Act on It

Every six hours, ApexMail's reputation scheduler:

1. **Pulls** the latest stats for every domain and IP you send from.
2. **Scores** them on a transparent 0–100 scale (the algorithm is in our docs).
3. **Bands** the score: Green (≥70), Amber (40–69), Red (<40).
4. **Throttles** outbound to that provider automatically:
   - Green → 0% throttle (full speed)
   - Amber → 50% throttle (probabilistic deferral)
   - Red → 90% throttle (near-stop, alert sent)
5. **Notifies your team** — webhook, email, or Slack — when a band drops.

When your reputation rebounds, throttle releases without a human in the loop.

## Why this matters for revenue

A single bad batch can put a sender domain on Gmail's BAD list for 30+ days.
Most ESPs give you the bad news in their next Quarterly Business Review.
ApexMail limits the damage immediately: your high-volume tenants
keep delivering through unaffected sending lanes while the impacted domain recovers.

## Per-Provider Throttle Overrides

Operators can pin a throttle (e.g. 100% for two hours during a known incident)
without code changes. Every decision is logged with score, band, and source for
audit and customer transparency.

## Get a Reputation Snapshot

We can audit your existing domain — typically within one business day — using
the same Google and Microsoft data feeds we use in production. [Book a deliverability review](/contact/).
