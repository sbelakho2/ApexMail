# Pricing Page — Marketing Documentation

> **Part of:** [`docs/marketing/README.md`](README.md)
> **Source of truth:** [`docs/pricing.md`](../pricing.md) — this is the single source of truth for all pricing. The marketing page must always reflect it.

## Overview

The ApexMail public pricing page is served from:
- **Static content:** [`apps/marketing-zola/content/pricing/`](../../apps/marketing-zola/content/pricing/)
- **Template partial:** [`apps/marketing-zola/templates/partials/pricing/plans.html`](../../apps/marketing-zola/templates/partials/pricing/plans.html)
- **Background pricing reference:** [`docs/pricing.md`](../pricing.md)

## Plans Displayed

> **Source (regenerated 2026-10-15, owner pricing plan):** this table is
> generated from [`docs/pricing.md`](../pricing.md) ("Subscription
> catalog") cross-checked against the runtime authority
> [`billing-service/src/plans.rs`](../../services/mail-server/crates/billing-service/src/plans.rs)
> (`default_plans()`: free 3,000 / starter €20 / pro €89 / growth €229 /
> business €699 / enterprise €1,750 — prices in cents ×100). Parity with
> the catalog is enforced by
> `python3 docs/marketing/check_pricing_parity.py` (exit 1 on drift).
> Rows use the
> catalog plan ID, with the display name the served pricing template shows
> (`plans.html`) in parentheses where the two differ.

| Plan                     | Price/mo | Emails/mo | Annual      |
|--------------------------|----------|-----------|-------------|
| Free                     | €0       | 3,000¹    | €0          |
| Starter (Developer)      | €20      | 50,000    | €200/yr     |
| Pro                      | €89      | 150,000   | €890/yr     |
| Growth                   | €229     | 500,000   | €2,290/yr   |
| Scale (Business)         | €699     | 2,000,000 | €6,990/yr   |
| Enterprise (Enterprise Cloud) | €1,750 | 5,000,000 | €17,500/yr |

¹ Free includes 3,000 emails/month forever plus a one-time
30,000-email launch allowance for the workspace's first 30 days
(`plans.rs` `free_plan_seed`; enforced in `usage.rs`
`resolve_plan_limits`).

## Template Logic (`plans.html`)

The pricing template renders two sections:

**Self-service subscription cards** — one card per plan:

- **Plan name** — `Free`, `Developer`, `Pro`, `Growth`, `Business`
  (the card titles; the underlying Checkout plan IDs are `free`,
  `starter`, `pro`, `growth`, `scale`)
- **Price** — monthly price string (e.g., `€20`)
- **Period** — `"/month"` on every card
- **Description** — positioning tagline per tier
- **Features** — bullet list of plan-specific features (Free card
  includes the one-time 30,000-email launch allowance)
- **CTA Button** — call-to-action routing:
  - Free → `config.extra.app_url ~ "/signup"`
  - Developer, Pro, Growth, Business → `config.extra.app_url ~ "/signup?plan=…"`
    (`starter`, `pro`, `growth`, `scale`)
- **Popular highlight** — `Pro` is marked as most popular

**Enterprise infrastructure** — three equal cards below the subscription
grid, all routing to `/contact/sales/`:

- **Enterprise Cloud** — `from €1,750 /mo, annual contract`
- **Dedicated Tenant** — `from €4,000 /mo + setup`
- **BYOC** — `from €6,500 /mo + setup`

## PAYG Pricing

Pay-As-You-Go pricing (for customers not on a subscription plan):

| Volume Tier | Price per email |
|-------------|----------------|
| 0–10,000    | €0.001         |
| 10,001–100K | €0.0008        |
| 100K–1M     | €0.0005        |
| 1M+         | €0.0003        |

API calls: first 100K free/month, then €0.10/1K.

## Dedicated IP Add-on

| Plan              | Price            |
|-------------------|------------------|
| Pro (add-on)      | €49/mo first, €69/mo each additional |
| Growth            | 1 included (after qualification) |
| Business          | 1 included (a second is assigned where traffic justifies it) |
| Enterprise Cloud  | up to 3 included based on architecture |

The same ladder is published in the served calculator
(`partials/pricing/calculator.html`) and validated against the runtime
estimator (`routes/explorer.rs`) by `tools/validate_pricing_drift.py`.

## Other Add-ons

| Add-on | Price | Availability |
|--------|-------|--------------|
| Inbox placement monitoring | €99/mo ($109) | Any paid plan |
| EU-only routing | €149/mo ($165) | Pro and above |

## Contract and Platform Lines

Sold on an annual contract (or an approved billing setup for mailboxes) and
never through generic public Checkout:

| Line | EUR | USD | Notes |
|------|----:|----:|-------|
| Compliance | €990/mo, annual | $1,090/mo | 1M emails, EU-only routing, dedicated IP, DORA/NIS2 evidence pack, GDPR processor pack, signed routing receipts, 1-year audit log, SSO |
| Enterprise Cloud | €1,750/mo, annual | $1,950/mo | 5M emails, 3 dedicated IPs, legal hold and archive, quarterly evidence refresh |
| Platform | €990/mo base + €0.30/1,000 above 1M + €1/active subaccount above 100 | $1,090 base + $0.35/1,000 + $1/subaccount | Isolated-reputation subaccounts, white-label tracking and bounce domains, provisioning API |
| Dedicated Tenant | from €4,000/mo, 12-month minimum, €10k–€40k setup | from $4,500/mo | Single-tenant stack on dedicated hardware, EU region by default, 5M recipients, 2 managed IPs, named owner, monthly review |
| Mailboxes | €6/seat/mo, 10-seat minimum; archive and journaling +€2/seat | $7/seat/mo; +$2 archive | EU-hosted IMAP/SMTP mailboxes, autoconfig, spam and AV filtering, self-serve import |

## Annual Billing

Annual plans are billed at 10× monthly price (10 monthly payments; ~17% discount).

## Enterprise CTA

Enterprise plan routes to `/contact/sales/` for custom onboarding, annual contracts, dedicated CSM, white-label deployment.

## Related

- [Canonical Pricing Reference](../pricing.md)
- [Marketing Surface README](README.md)
- [Pricing Template](../../apps/marketing-zola/templates/partials/pricing/plans.html)
- [Billing Service Plan Definitions](../../services/mail-server/crates/billing-service/src/plans.rs)
