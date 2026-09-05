+++
title = "Comparison Methodology"
description = "How ApexMail builds and maintains competitive comparisons: evidence standards, source policy, update frequency, and correction process."
template = "prose.html"

[extra]
last_updated = "2026-07-29"
+++

## Purpose

ApexMail publishes factual, evidence-based comparisons to help developers and procurement teams evaluate transactional email providers. Claims are based on publicly available documentation and pricing pages at the stated review date.

## Disclosure Standards

Every comparison page discloses:

| Field | Description |
|-------|-------------|
| **Date verified** | When the comparison was last checked against live sources |
| **Competitor plan compared** | Exact plan name and tier referenced |
| **ApexMail plan compared** | Exact ApexMail plan used for feature-to-feature mapping |
| **Monthly volume assumption** | The email volume at which pricing is calculated |
| **Billing period** | Monthly or annual billing used for price comparison |
| **Currency** | All prices are shown in EUR. ApexMail prices are published in EUR; when a competitor publishes only USD, the EUR figure is converted at the documented reference rate (1 USD = €0.92, 2026-08-19) and the provider's published USD price is shown in parentheses |
| **Tax treatment** | All prices exclude VAT unless stated |
| **Feature definitions** | How each compared feature is defined |
| **Source policy** | Only public, official documentation and pricing pages |
| **Update frequency** | Targeted review every 90 days; critical claims reviewed monthly |
| **Correction process** | Corrections accepted at security@apexmail.ee; verified within 5 business days |

## Evidence Fields per Comparison Row

What actually backs a comparison row today:

| Evidence field | Status |
|----------------|--------|
| Feature name | On every row |
| ApexMail implementation | On every row |
| Competitor implementation | On every row |
| Winner callout | Only where a row is objectively decidable; many rows deliberately declare none |
| Inline source references with URLs | Only on the Amazon SES and Mailgun pages, which carry per-row numbered source links |
| Verification date | One review date per page (per-page `pricing_as_of`, rendered under the table) |
| Reviewer | ApexMail marketing engineering (named on the SES/Mailgun source footnotes) |

Rows on pages without inline source links (SendGrid, Postmark, Resend) summarize publicly documented provider behavior as of the page's review date, without per-row citation. Where we cannot verify a competitor figure, the cell says so ("not publicly documented", "see provider pricing") rather than asserting a number.

## Pricing Comparison Rules

- Pricing comparisons use **equivalent monthly volumes** on both sides.
- Annual billing is compared only when each provider's current public catalog expressly supports it; no assumed discount is applied.
- Where competitor pricing varies by volume tier, the tier closest to the stated volume assumption is selected.
- Prices are shown in EUR, converted from the provider's published list price where a provider publishes only USD (reference rate stated on each page; the provider's native price is shown in parentheses).

## Feature Comparison Rules

- Features are compared based on **publicly documented availability** at the stated plan tier.
- "Available on higher plans" is noted only when the feature is not available on the compared plan.
- "Available as add-on" includes the add-on price where published.
- Features listed as "planned" or "coming soon" are excluded unless a firm release date is published by the vendor.
- ApexMail features listed as "available" must be generally available in production at the time of verification.

## Subjective Assessment Policy

- Subjective labels ("better," "superior," "basic," "limited") are replaced with **measurable statements**.
- Where a qualitative assessment is unavoidable, it is explicitly labeled as an **ApexMail editorial assessment** with the criteria stated.
- Competitor advantages are acknowledged explicitly and without qualification.

## Correction and Dispute Process

- Vendors or readers may submit corrections to security@apexmail.ee.
- Corrections are verified against official sources within 5 business days.
- Verified corrections are published with a correction date.
- An errata section noting the correction appears at the bottom of the affected page.

## Review Cadence

| Check type | Frequency |
|------------|-----------|
| Pricing accuracy (all competitors) | Every 90 days |
| Feature claims (critical rows) | Every 30 days |
| Feature claims (all rows) | Every 90 days |
| Source URL validity | Every 90 days |
| Full re-verification | Every 180 days or on major vendor release |

## Limitations

- Comparisons reflect publicly available information at the verification date. Vendors may change pricing and features without notice.
- Enterprise pricing (custom quotes, volume discounts) is not compared unless publicly listed.
- Comparisons do not constitute legal advice, purchasing recommendations, or contractual offers.
- Performance benchmarks (latency, throughput) are not compared unless independently measured by ApexMail under disclosed test conditions.
