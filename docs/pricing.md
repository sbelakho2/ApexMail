# ApexMail Pricing Reference

This is a public reference for the active subscription catalog. It is not the
runtime authority for entitlement or charging. The operational authority is
[the billing plan catalog](../services/mail-server/crates/billing-service/src/plans.rs),
the active `plans` records, and verified Stripe webhooks. See
[the authority map](pricing-authority.md) for the boundary between runtime and
presentation data.

All published prices below are EUR. A selected plan during registration is only
an intent: new workspaces start on Free, and paid access begins only after
Stripe confirms the subscription through a verified webhook.

## Subscription catalog

| Plan ID | Plan | Monthly | Annual | Emails/month | API calls/month | Domains | Team members | Event retention | Dedicated IPs |
|---|---|---:|---:|---:|---:|---:|---:|---:|---|
| `free` | Free | €0 | €0 | 3,000 | 30,000 | 1 | 1 | 7 days | — |
| `starter` | Developer | €29 | €290/year | 50,000 | 500,000 | 5 | 5 | 30 days | — |
| `pro` | Pro | €89 | €890/year | 150,000 | 2,000,000 | 25 | 10 | 60 days | Add-on eligible |
| `growth` | Growth | €229 | €2,290/year | 500,000 | 5,000,000 | 100 | 25 | 90 days | 1 included |
| `scale` | Business | €699 | €6,990/year | 2,000,000 | 20,000,000 | Unlimited | 50 | 365 days | 3 included |
| `enterprise` | Enterprise Cloud | €1,750 | €17,500/year | 5,000,000 | Unlimited | Unlimited | Unlimited | 730 days | 10 included |

Annual billing is 10 times the monthly price: two months free, or roughly a
17% discount compared with twelve monthly payments.

## Public purchase paths

- **Free** is the initial workspace entitlement.
- **Starter**, **Pro**, **Growth**, and **Scale** are the supported
  self-service Checkout plans.
- **Enterprise** is an annual sales and contract flow; it is not available
  through generic public Checkout.
- **PAYG** is configured through an approved billing setup, not a public plan
  switch or generic Checkout flow.

## Included feature gates

| Capability | Availability |
|---|---|
| REST API + SMTP relay | All subscription plans |
| Webhooks, custom templates, advanced analytics, data export | Starter and above |
| Custom tracking domain and send-time optimization | Pro and above |
| A/B testing, audit logs, time-travel debugging, custom retention | Growth and above |
| SAML SSO, inbound email, template approval workflow, subaccounts | Scale and Enterprise |
| 99.9% SLA and dedicated CSM | Scale (10% credit cap) and Enterprise (25% credit cap) |
| White-label, private cloud, and BYOIP capability flags | Enterprise |

HIPAA availability and SOC 2 certification are **not currently offered**.
Features must not be interpreted as a certification, a business associate
agreement, or authorization to process regulated workloads without written
confirmation and the required agreement.

## Overage and PAYG rates

**Enforcement and billing:** paid plans are not hard-blocked at the included
volume. Email sending on an active paid subscription continues into an
overage allowance (default: +100% of the plan limit — a 50K plan may send up
to 100K; tunable via `OVERAGE_ALLOWANCE_PERCENT`, 0 = hard stop), after which
sends are rejected with `403 email quota exceeded`. The overage accrued in a
billing cycle is invoiced automatically when the cycle ends: the daily
maintenance sweep creates an `Overage:` invoice line at €0.40 per 1,000
emails (rounded up), once per tenant per period. Free plans are hard-capped
at the plan limit. `POST /v1/billing/overage/estimate` previews the charge.
No separate subscription-plan API-call overage price is defined by the
runtime catalog.

PAYG pricing is metered independently of subscription plans:

| Email volume tier | EUR per email |
|---|---:|
| 0–10,000 | €0.0010 |
| 10,001–100,000 | €0.0008 |
| 100,001–1,000,000 | €0.0005 |
| Over 1,000,000 | €0.0003 |

PAYG API calls include the first 100,000 per month; subsequent API usage is
€0.10 per 1,000 calls.

## Dedicated IPs

Dedicated IPs are add-on eligible from Pro upward. The public calculator uses
€30/month per additional IP; Growth includes one, Scale includes three, and
Enterprise includes ten. Provisioning remains subject to operational and abuse
controls.

## Billing lifecycle

1. A customer creates or signs in to a workspace.
2. The authenticated billing surface creates a Stripe Checkout or billing
   portal session for an allowed catalog price.
3. ApexMail verifies Stripe's signed webhook and maps the Stripe price back to
   an active catalog plan.
4. Only `active` or `trialing` verified subscriptions grant the paid plan;
   incomplete, delinquent, paused, unpaid, and canceled subscriptions resolve
   to Free access.

See [billing lifecycle](architecture/billing-lifecycle.md) and the
[Stripe contract](tool-contracts/stripe.md) for the integration requirements.
