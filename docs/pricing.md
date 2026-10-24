# ApexMail Pricing Reference

This is a public reference for the active subscription catalog. It is not the
runtime authority for entitlement or charging. The canonical plan facts
(names, prices, limits, overage rates) live in
[the platform catalog](../services/mail-server/crates/platform-catalog/src/lib.rs);
the operational authority is
[the billing plan seeds](../services/mail-server/crates/billing-service/src/plans.rs),
the active `plans` records, and verified Mollie webhooks. See
[the authority map](pricing-authority.md) for the boundary between runtime and
presentation data.

All published prices below are EUR. A selected plan during registration is only
an intent: new workspaces start on Free, and paid access begins only after
Mollie reports a settled payment that ApexMail fetches and verifies with its
API key.

## Subscription catalog

| Plan ID | Plan | Monthly | Annual | Emails/month | API calls/month | Domains | Team members | Event retention | Dedicated IPs |
|---|---|---:|---:|---:|---:|---:|---:|---:|---|
| `free` | Free | €0 | €0 | 3,000 | 30,000 | 1 | 1 | 7 days | — |
| `starter` | Developer | €20 | €200/year | 50,000 | 500,000 | 5 | 5 | 30 days | — |
| `pro` | Pro | €89 | €890/year | 150,000 | 2,000,000 | 25 | 10 | 60 days | Add-on eligible |
| `growth` | Growth | €229 | €2,290/year | 500,000 | 5,000,000 | 100 | 25 | 90 days | 1 included |
| `scale` | Business | €699 | €6,990/year | 2,000,000 | 20,000,000 | Unlimited | 50 | 365 days | 1 included |
| `enterprise` | Enterprise Cloud | €1,750 | €17,500/year | 5,000,000 | Unlimited | Unlimited | Unlimited | 730 days | 3 included |

Annual billing is 10 times the monthly price: two months free, or a 16.7%
saving compared with twelve monthly payments.

## Contract and non-subscription lines

These lines are sold on an annual contract (or an approved billing setup for
mailboxes and pay-as-you-go); they are not part of the self-service
subscription catalog above and cannot be bought through public Checkout. EUR is the
billing currency; the USD figure is the published list price for the same
line.

| Line | EUR | USD | What it includes |
|---|---:|---:|---|
| Compliance | €990/month, annual | $1,090/month | 1M emails, EU-only routing included, dedicated IP, DORA/NIS2 evidence pack, GDPR processor pack (DPA, SCCs, sub-processor list), signed routing receipts, 1-year audit log, SSO |
| Enterprise Cloud | €1,750/month, annual | $1,950/month | 5M emails, 3 dedicated IPs, legal hold and archive, quarterly evidence refresh, EU-only routing included |
| Platform | €990/month base + €0.30 per 1,000 above 1M + €1 per active subaccount above 100 | $1,090 base + $0.35 per 1,000 + $1 per subaccount | Subaccounts with isolated reputation, white-label tracking and bounce domains, provisioning API |
| Dedicated Tenant | from €4,000/month (12-month minimum, €10k–€40k setup) | from $4,500/month | Single-tenant stack on dedicated hardware, EU region by default, 5M recipients, 2 managed IPs, named owner, monthly review |
| Mailboxes | €6 per seat/month (10-seat minimum); archive and journaling +€2 per seat | $7 per seat/month; +$2 archive | EU-hosted IMAP/SMTP mailboxes on the existing stack, autoconfig, spam and AV filtering, self-serve import |

## Public purchase paths

- **Free** is the initial workspace entitlement.
- **Developer** (`starter`), **Pro**, **Growth**, and **Business** (`scale`)
  are the supported self-service Checkout plans.
- **Enterprise Cloud** is an annual sales and contract flow; it is not
  available through generic public Checkout.
- **PAYG** is configured through an approved billing setup, not a public plan
  switch or generic Checkout flow.

## Included feature gates

| Capability | Availability |
|---|---|
| REST API + SMTP relay | All subscription plans |
| Webhooks, custom templates, advanced analytics, data export | Starter and above |
| Custom tracking domain and send-time optimization | Pro and above |
| A/B testing, audit logs, time-travel debugging, custom retention | Growth and above |
| SAML SSO, inbound email, template approval workflow, subaccounts | Business and Enterprise Cloud |
| 99.9% SLA and dedicated CSM | Business (graduated to 30%) and Enterprise Cloud (25%) |
| White-label, private cloud, and BYOIP capability flags | Enterprise Cloud |
| EU-only routing (own EU MTAs, no third-party transport) | Enterprise Cloud and the Compliance contract line; €149/$165 per month add-on on Pro and above |

HIPAA availability is **not currently offered**.
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
maintenance sweep creates an `Overage:` invoice line at the per-plan
rate (Developer €0.80, Pro €0.60, Growth/Business €0.35, Enterprise
€0.22–€0.35 contractual) per 1,000
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

Dedicated IPs are an add-on from €49/month (first) and €69/month (each
additional) on Pro and above — the same ladder the runtime estimator charges
(`routes/explorer.rs`). Growth includes one (after qualification), Business
includes one (a second is assigned where traffic justifies it), and Enterprise
Cloud includes up to three based on architecture. Provisioning remains subject
to operational and abuse controls.

Two further add-ons are sold on eligible plans (USD list prices in
parentheses):

- **Inbox placement monitoring** — €99/month ($109/month) on any paid plan;
  per-plan deliverability telemetry and provider postmaster signals.
- **EU-only routing** — €149/month ($165/month) on Pro and above; sends
  through ApexMail's own EU MTAs, with no third-party transport.

## Billing lifecycle

1. A customer creates or signs in to a workspace.
2. The authenticated billing surface resolves an allowed catalog plan and
   creates a Mollie payment (`sequenceType: first`) for it. Mollie returns the
   hosted checkout URL; there is no billing portal.
3. The customer pays at Mollie. Mollie posts an id-only webhook
   (`id=tr_…`); ApexMail fetches the payment with its Bearer API key and maps
   the fetched `paid` status and metadata back to an active catalog plan.
4. Only an `active` Mollie subscription grants the paid plan; `canceled`,
   `completed`, `suspended` and `pending` subscriptions resolve to Free
   access.

See [billing lifecycle](architecture/billing-lifecycle.md) and the
[Mollie contract](tool-contracts/mollie.md) for the integration requirements.
