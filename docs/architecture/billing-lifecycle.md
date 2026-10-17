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

- An `AUTHORISATION` notification is recorded as an informational event only;
  it does not change tenant status or grant an entitlement.
- `RECURRING_CONTRACT` (`recurring.token.created`) notifications bind the
  stored recurring detail and upsert `adyen_subscriptions` after signature,
  tenant-binding, catalog-price, and status-transition checks; later
  successful recurring `AUTHORISATION` notifications reconcile the state
  changes.
- The live `plans` table persists the monthly and yearly Adyen plan codes;
  amounts come inline from the platform catalog. A generic public Checkout
  request is accepted only for an active Starter, Pro, Growth, or Scale plan;
  Enterprise and PAYG use managed flows.
- Only verified `active` and `trialing` Adyen subscriptions grant the mapped
	paid tenant plan. Incomplete, delinquent, paused, unpaid, and canceled
	states resolve the tenant to `free`.
- When a subscription becomes active, the billing service can auto-provision
	included dedicated IPs.

### Plan changes

`POST /checkout` is the only self-service plan-change entry point. It accepts
only an Adyen plan code that maps to an active self-service ApexMail plan and
adds the tenant and resolved plan name to the Adyen Checkout session metadata.

- Checkout creation does not change the tenant plan.
- A verified `RECURRING_CONTRACT` and successful recurring `AUTHORISATION`
  notifications map the confirmed charge back to the active ApexMail plan and
  update the tenant in a transaction.
- `POST /switch-plan` is a retained compatibility endpoint that always returns
  `409 CHECKOUT_REQUIRED`; it cannot update tenant or subscription records.
- Plan-change proration is calculated and applied by Adyen. Any ApexMail
  proration preview is informational only and never changes a subscription or
  tenant entitlement.

### Cancellation

`POST /cancel` is a LOCAL subscription state change (external audit 15 Oct,
H1). ApexMail owns the subscription: Adyen's Subscription processing model is
merchant-initiated and has no hosted billing portal, so the old
portal-redirect refusal left customers unable to stop renewals.

- `cancelImmediately=false` (default) sets `cancel_at_period_end` and
  `canceled_at`; access continues until `billing_cycle_end`, when the
  period-end sweep marks the subscription `canceled` and downgrades the tenant
  to `free`.
- `cancelImmediately=true` marks it `canceled` now and downgrades the tenant
  immediately.
- No active subscription answers `404`; a replay is idempotent and keeps the
  original `canceled_at`.
- Every renewal path (dunning retry / auto-pay) skips
  `cancel_at_period_end` rows, so the next renewal charge never happens.
- The console form `POST /web/billing/cancel` calls the same
  `billing_service::subscriptions::cancel_subscription` service.

### Enterprise contracts

Enterprise entitlement is distinct from generic Checkout. A current signed
Enterprise contract can activate the tenant's Enterprise plan. Contract state
transitions are constrained to the signed lifecycle: only a pending-signature,
currently effective contract can be activated.

The contract cancellation API supports immediate termination only. It rejects a
future effective date rather than pretending that a scheduler will later change
access. Immediate termination is transactional: it downgrades the tenant to
Free only when no other current active Enterprise contract remains. It never
substitutes another paid plan or creates a Adyen entitlement locally.

## Proration Logic

Plan-change previews are diagnostic estimates only; Adyen is the source of
truth for charge and credit calculations.

The current implementation:

- calculates total days in the active billing period
- calculates remaining days from `Utc::now()` to `current_period_end`
- selects monthly or yearly plan price based on the subscription interval
- uses integer cent arithmetic across the full current billing-period price
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

Adyen webhooks drive the current invoice state transitions:

- a successful `AUTHORISATION` marks matching invoices as paid and sets `paid_at`
- a failed `AUTHORISATION` records dunning state and enqueues a `payment_failed` notification

## Operational Notes

- Dedicated IP auto-provisioning is tied to active Adyen subscription state and the plan's `dedicated_ip_count` feature flag.
- The billing service also exposes PAYG pricing and estimate endpoints backed by `PaygPricing::default()`.
- The pricing tiers for PAYG are `0-10k`, `10k-100k`, `100k-1M`, and `1M+` emails, with API-call billing after the first `100,000` monthly API calls.

## Relevant Source Files

- `services/mail-server/crates/billing-service/src/plans.rs`
- `services/mail-server/crates/billing-service/src/routes.rs`
- `services/mail-server/crates/billing-service/src/subscriptions.rs`
- `services/mail-server/crates/billing-service/src/usage.rs`
- `services/mail-server/crates/billing-service/src/invoices.rs`
- `services/mail-server/crates/billing-service/src/adyen_webhooks.rs`
- `services/mail-server/crates/billing-service/src/types.rs`
- `services/mail-server/crates/billing-service/src/config.rs`