+++
title = "Comparison Methodology"
description = "How ApexMail builds and maintains competitive comparisons: evidence standards, source policy, update frequency, and correction process."
template = "prose.html"

[extra]
last_updated = "2026-07-29"
+++

## Purpose

ApexMail publishes factual, evidence-based comparisons to help developers and procurement teams evaluate transactional email providers. Every claim in every comparison is traceable to a public source.

## Disclosure Standards

Every comparison page discloses:

| Field | Description |
|-------|-------------|
| **Date verified** | When the comparison was last checked against live sources |
| **Competitor plan compared** | Exact plan name and tier referenced |
| **ApexMail plan compared** | Exact ApexMail plan used for feature-to-feature mapping |
| **Monthly volume assumption** | The email volume at which pricing is calculated |
| **Billing period** | Monthly or annual billing used for price comparison |
| **Currency** | Currency used (USD for ApexMail; competitor pricing shown in its published denomination) |
| **Tax treatment** | All prices exclude VAT unless stated |
| **Feature definitions** | How each compared feature is defined |
| **Source policy** | Only public, official documentation and pricing pages |
| **Update frequency** | Targeted review every 90 days; critical claims reviewed monthly |
| **Correction process** | Corrections accepted at security@apexmail.ee; verified within 5 business days |

## Evidence Fields per Comparison Row

Every row in a comparison table is backed by:

| Evidence field | Required |
|----------------|----------|
| Feature name | Yes |
| ApexMail implementation | Yes |
| Competitor implementation | Yes |
| Exact plan or tier | Yes |
| Official source URL | Yes |
| Source date | Yes |
| Verification date | Yes |
| Reviewer | Yes |
| Qualification (if any) | Required if claim is qualified |
| Screenshot or archived evidence | Retained internally |

## Pricing Comparison Rules

- Pricing comparisons use **equivalent monthly volumes** on both sides.
- Annual billing is compared only when each provider's current public catalog expressly supports it; no assumed discount is applied.
- Where competitor pricing varies by volume tier, the tier closest to the stated volume assumption is selected.
- Currencies are displayed in their native denomination. Where conversion context is useful, the ECB reference rate at the verification date is noted.

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
