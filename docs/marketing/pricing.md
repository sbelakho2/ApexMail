# Pricing Page — Marketing Documentation

> **Part of:** [`docs/marketing/README.md`](README.md)
> **Source of truth:** [`docs/pricing.md`](../pricing.md) — this is the single source of truth for all pricing. The marketing page must always reflect it.

## Overview

The ApexMail public pricing page is served from:
- **Static content:** [`apps/marketing-zola/content/pricing/`](../../apps/marketing-zola/content/pricing/)
- **Template partial:** [`apps/marketing-zola/templates/partials/pricing/plans.html`](../../apps/marketing-zola/templates/partials/pricing/plans.html)
- **Background pricing reference:** [`docs/pricing.md`](../pricing.md)

## Plans Displayed

| Plan       | Price/mo | Emails/mo   | Annual      |
|------------|----------|-------------|-------------|
| Free       | $0       | 30,000      | $0          |
| Starter    | $25      | 50,000      | $250/yr     |
| Pro        | $65      | 150,000     | $650/yr     |
| Growth     | $150     | 500,000     | $1,500/yr   |
| Scale      | $350     | 2,000,000   | $3,500/yr   |
| Enterprise | $3,000   | 5,000,000   | $30,000/yr  |

## Template Logic (`plans.html`)

The pricing template renders each plan as a card with:

- **Plan name** — `Free`, `Starter`, `Pro`, `Growth`, `Scale`, `Enterprise`
- **Price** — monthly price string (e.g., `$25`)
- **Period** — `"/mo"` for monthly plans, custom for Free (`"forever"`)
- **Description** — positioning tagline per tier
- **Features** — bullet list of plan-specific features
- **CTA Button** — call-to-action routing:
  - Free, Starter, Pro, Growth, Scale → `config.extra.app_url ~ "/signup"` (signup flow)
  - Enterprise → `/contact/sales/` (sales inquiry)
- **Popular highlight** — `Pro` plan is marked as most popular
- **Enterprise highlight** — `Enterprise` plan has distinct styling and CTA

## PAYG Pricing

Pay-As-You-Go pricing (for customers not on a subscription plan):

| Volume Tier | Price per email |
|-------------|----------------|
| 0–10,000    | $0.001         |
| 10,001–100K | $0.0008        |
| 100K–1M     | $0.0005        |
| 1M+         | $0.0003        |

API calls: first 100K free/month, then $0.10/1K.

## Dedicated IP Add-on

| Plan              | Price            |
|-------------------|------------------|
| Pro (add-on)      | $30/mo           |
| Growth            | 1 included       |
| Scale             | 3 included       |
| Enterprise        | 10 included      |

## Annual Billing

Annual plans are billed at 10× monthly price (2 months free; ~17% discount).

## Enterprise CTA

Enterprise plan routes to `/contact/sales/` for custom onboarding, annual contracts, dedicated CSM, HIPAA BAA lifecycle, SOC 2 evidence workflows, SIG/CAIQ/HECVAT answer packs, and white-label deployment.

## Related

- [Canonical Pricing Reference](../pricing.md)
- [Marketing Surface README](README.md)
- [Pricing Template](../../apps/marketing-zola/templates/partials/pricing/plans.html)
- [Billing Service Plan Definitions](../../services/mail-server/crates/billing-service/src/plans.rs)
