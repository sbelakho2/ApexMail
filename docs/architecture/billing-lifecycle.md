# Billing Lifecycle

> **Implementation Note (2026-05):** This page reflects the current Rust billing implementation in `services/mail-server/crates/billing-service/`.

## Overview

The billing system covers four linked responsibilities:

- plan catalog and quota definitions
- subscription lifecycle and plan changes
- usage metering and quota checks
- invoice creation, VAT handling, and payment-state updates

The current implementation lives in the `billing-service` crate and is the source of truth for billing behavior exposed to the API and control plane.

## Plan Catalog

Plan facts (names, prices, included limits) live in the canonical
`platform-catalog` crate (`PLANS`); `src/plans.rs` seeds the `plans` table from
it and derives overage rates from it. The current ladder is Developer €20 /
Pro €89 / Growth €229 / Business €699 / Enterprise Cloud from €1,750; Free
3,000/month plus a one-time 30,000-email launch allowance for the first 30
days. Compliance, Platform, Dedicated Tenant and Mailboxes are contractual
lines outside the self-service catalog (see `docs/pricing.md`).

| Plan | Plan ID | Monthly | Yearly | Emails / month | API calls / month | Rate-limit tier |
|------|---------|---------|--------|----------------|-------------------|-----------------|
| Free | `free` | `0` cents | `0` cents | `3,000` + one-time 30,000 launch allowance | `30,000` | `Free` |
| Developer | `starter` | `2,000` cents | `20,000` cents | `50,000` | `500,000` | `Standard` |
| Pro | `pro` | `8,900` cents | `89,000` cents | `150,000` | `2,000,000` | `Standard` |
| Growth | `growth` | `22,900` cents | `229,000` cents | `500,000` | `5,000,000` | `High` |
| Business | `scale` | `69,900` cents | `699,000` cents | `2,000,000` | `20,000,000` | `High` |
| Enterprise Cloud | `enterprise` | `175,000` cents | `1,750,000` cents | `5,000,000` | unlimited (`-1`) | `Unlimited` |
| Pay As You Go | `payg` | `0` | `0` | unlimited (`-1`) | unlimited (`-1`) | `Standard` |

Rate-limit tiers map to API throughput in `src/types.rs`:

- `Free`: `10` requests / second
- `Standard`: `100` requests / second
- `High`: `500` requests / second
- `Unlimited`: `5,000` requests / second

See `docs/pricing.md` for the user-facing plan summary.

## Subscription Lifecycle

### Checkout and activation

Mollie is object-based: a customer (`cst_…`), a mandate (`mdt_…`), payments
(`tr_…`), refunds (`re_…`) and subscriptions (`sub_…`) are real provider
objects. ApexMail stores their ids and reconciles from authenticated fetches.

- `POST /v2/payments` creates a payment with `sequenceType: first`, the
  catalog amount as a decimal string, the approved return URL, the webhook URL
  (`/webhooks/mollie`) and the tenant/plan metadata. The response's
  `_links.checkout.href` is the hosted checkout URL; creating the payment does
  not grant access.
- The first paid payment that produced a mandate establishes the recurring
  contract. A `RECURRING_CONTRACT` event binds the Mollie customer/mandate
  (and `sequenceType: recurring`) onto the tenant's `mollie_subscriptions`
  rows; a mandate that arrives before any row exists is acknowledged and
  re-read from `GET /v2/customers/{cst}/mandates` when a row appears. Later
  recurring payments (`sequenceType: recurring` + customer + mandate) settle
  their invoices.
- The id-only webhook (`id=tr_…` / `id=re_…`) is never trusted by itself:
  ApexMail fetches the object with `Authorization: Bearer
  $MOLLIE_API_KEY` and derives the fact from the fetched status. `open`,
  `pending` and `authorized` are not settled facts.
- The live `plans` table persists the monthly and yearly plan codes used by
  checkout to resolve a `priceId` to its plan and interval; amounts come
  inline from the platform catalog. A generic public Checkout request is
  accepted only for an active Starter, Pro, Growth, or Scale plan;
  Enterprise and PAYG use managed flows.
- Entitlement follows the LOCAL `mollie_subscriptions` row (status plus the
  catalog plan), not a provider object: ApexMail creates no Mollie
  subscription objects, so recurring collection is an explicit payment
  against the mandate.
- When a recurring invoice settles, the billing service can auto-provision
  included dedicated IPs.

### Plan changes

`POST /checkout` accepts only a `priceId` that maps to an active self-service
ApexMail plan and its interval, and creates a Mollie payment whose metadata
carries the tenant, resolved plan, interval and price. What the code does and
does not do is stated here exactly:

- Payment creation does not change the tenant plan, and a paid checkout does
  not grant entitlement by itself: the checkout webhook is informational
  (the `RECURRING_CONTRACT` event binds the mandate it produced to the
  tenant's existing subscription rows).
- The console's plan-change form (`POST /web/billing/checkout`) does not open
  a checkout at all: it records the request for the billing team and says so
  in the flash, because plan activation (invoice issuance, proration and
  entitlement) is an operator action in the current product. The JSON
  `/v1/billing/checkout` endpoint exists for managed flows and carries the
  same rule: it takes no entitlement decision.
- `POST /switch-plan` is a retained compatibility endpoint that always returns
  `409 CHECKOUT_REQUIRED`; it cannot update tenant or subscription records.
- Proration previews are informational and never change a subscription or
  tenant entitlement.

### Refunds and chargebacks

- A refund is `POST /v2/payments/{paymentId}/refunds` (amount as a decimal
  string, description, `Idempotency-Key`) and is fetched back by
  `GET /v2/payments/{paymentId}/refunds/{refundId}`.
- A refund webhook carries only `id=re_…`; the payment id comes from the local
  `mollie_refunds` mapping, then the refund is fetched for its authoritative
  status.
- A payment status of `refunded` or `charged_back` is reconciled against the
  invoice/payment allocation; no local row is mutated from the webhook body.
- Settlements (`GET /v2/settlements`) are read for operator payout
  reconciliation; they are independent of customer entitlement and no
  automated settlement posting runs.

### Cancellation

`POST /cancel` changes the local subscription row; ApexMail owns it and
Mollie has no hosted billing portal. The provider-side guarantee is the
MANDATE: an immediate cancel revokes it
(`DELETE /v2/customers/{cst}/mandates/{mdt}`), so no recurring charge can ever
be created against the account again. The revocation is best-effort at the
moment of cancellation (the local state is already committed); a failure
leaves `mollie_customers.mandate_revoked_at` NULL and the 15-minute
maintenance sweep retries it until the provider confirms.

- A period-end cancel sets `cancel_at_period_end` and `canceled_at`. Access
  continues to `billing_cycle_end`. The period-end sweep then marks the row
  `canceled`, downgrades the tenant to `free`, and the same revocation sweep
  removes the mandate at the provider.
- An immediate cancel marks the row `canceled` now, downgrades the tenant now,
  and revokes the mandate immediately.
- With no active subscription the route answers `404`. A replay keeps the
  original `canceled_at`.
- Renewal paths skip `cancel_at_period_end` rows, so no next charge happens.
- The console form `POST /web/billing/cancel` calls the same service.

### Enterprise contracts

Enterprise entitlement is distinct from generic Checkout. A current signed
Enterprise contract can activate the tenant's Enterprise plan. Contract state
transitions are constrained to the signed lifecycle: only a pending-signature,
currently effective contract can be activated.

The contract cancellation API supports immediate termination only. It rejects a
future effective date rather than pretending that a scheduler will later change
access. Immediate termination is transactional: it downgrades the tenant to
Free only when no other current active Enterprise contract remains. It never
substitutes another paid plan or creates a Mollie entitlement locally.

## Proration Logic

Plan-change previews are diagnostic estimates only; Mollie is the source of
truth for charge and credit calculations.

The current implementation:

- calculates total days in the active billing period.
- calculates remaining days from `Utc::now()` to `current_period_end`.
- selects monthly or yearly plan price based on the subscription interval.
- uses integer cent arithmetic across the full current billing-period price.
- computes credit for unused time on the old plan and charge for remaining time on the new plan
- rounds both amounts to the nearest cent with integer math

Guardrails come from `BillingConfig`:

- maximum proration charge
- maximum proration credit
- warning threshold for large charges

The response returns a human-readable explanation plus `credit_amount`, `charge_amount`, and `net_amount` in cents.

## Usage Metering

Metering event types are defined in `src/types.rs`:

- `emails_sent`
- `emails_delivered`
- `api_calls`
- `webhooks_delivered`
- `dedicated_ip_hours`
- `storage_gb_hours`
- `bandwidth_gb`

### Recording flow

`record_usage()` uses a two-layer path:

1. write a 24-hour Redis dedup key keyed by event ID
2. insert the metering event into Postgres
3. increment a real-time Redis counter for the current billing month

Real-time counters are retained for 40 days.

### Quota checks

`check_quota()` currently evaluates the email quota for the current month.

- Redis is the fast path for current-month usage
- Postgres aggregation is the fallback when Redis is unavailable
- unlimited plans use `-1` limits

`record_with_quota_check()` is the atomic variant used to avoid a check-then-record race.

- It uses a Redis Lua script to check and increment the current-month counter in one operation.
- If the Postgres insert fails after the Redis reservation succeeds, the code rolls the Redis reservation back.
- Duplicate event IDs return `duplicate = true` without double-counting usage.

## Invoices

### Creation

`create_invoice()`:

- loads the tenant billing address
- calculates VAT per line item
- inserts a `draft` invoice with stored line items JSON
- defaults `due_at` to 30 days after issue time when not supplied

Invoice statuses in the current type model are:

- `draft`
- `pending`
- `paid`
- `void`
- `uncollectible`

### VAT behavior

VAT is calculated in `calculate_vat()`:

- Estonia (`EE`): `24%`
- EU B2B with VAT number: reverse charge (`0%`)
- EU B2C: destination-country VAT when configured, otherwise fallback to Estonia rate
- non-EU: `0%`

### PDF generation and storage

`generate_invoice_pdf()`:

- renders invoice data through the `pdf-renderer` service
- uploads the generated PDF to S3/R2-compatible object storage
- stores the resulting `pdf_url` back on the invoice record

### Payment-state updates

The id-only Mollie webhook plus an authenticated fetch drive the current
invoice state transitions:

- a fetched payment with status `paid` (normalized `AUTHORISATION` success)
  marks matching invoices as paid and sets `paid_at`
- a fetched payment with status `failed`, `canceled` or `expired` (normalized
  `AUTHORISATION` failure) records dunning state and enqueues a
  `payment_failed` notification
- a fetched refund with status `refunded` (normalized `REFUND`) reconciles the
  refund against the payment allocation; `charged_back` records the chargeback

## Operational Notes

- Dedicated IP auto-provisioning is tied to the local subscription's active state and the plan's `dedicated_ip_count` feature flag.
- The billing service also exposes PAYG pricing and estimate endpoints backed by `PaygPricing::default()`.
- The pricing tiers for PAYG are `0-10k`, `10k-100k`, `100k-1M`, and `1M+` emails, with API-call billing after the first `100,000` monthly API calls.

## Relevant Source Files

- `services/mail-server/crates/billing-service/src/plans.rs`
- `services/mail-server/crates/billing-service/src/routes.rs`
- `services/mail-server/crates/billing-service/src/subscriptions.rs`
- `services/mail-server/crates/billing-service/src/usage.rs`
- `services/mail-server/crates/billing-service/src/invoices.rs`
- `services/mail-server/crates/billing-service/src/mollie_webhooks.rs`
- `services/mail-server/crates/billing-service/src/types.rs`
- `services/mail-server/crates/billing-service/src/config.rs`