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

Default plans are seeded in `src/plans.rs` and persisted to the `plans` table.

| Plan | Monthly | Yearly | Emails / month | API calls / month | Rate-limit tier |
|------|---------|--------|----------------|-------------------|-----------------|
| Free | `0` | `0` | `30,000` | `300,000` | `Free` |
| Starter | `2,500` cents | `25,000` cents | `50,000` | `500,000` | `Standard` |
| Pro | `6,500` cents | `65,000` cents | `150,000` | `2,000,000` | `Standard` |
| Growth | `15,000` cents | `150,000` cents | `500,000` | `5,000,000` | `High` |
| Scale | `35,000` cents | `350,000` cents | `2,000,000` | `20,000,000` | `High` |
| Enterprise | `300,000` cents | `3,000,000` cents | `5,000,000` | unlimited (`-1`) | `Unlimited` |
| PAYG | `0` | `0` | unlimited (`-1`) | unlimited (`-1`) | `Standard` |

Rate-limit tiers map to API throughput in `src/types.rs`:

- `Free`: `10` requests / second
- `Standard`: `100` requests / second
- `High`: `500` requests / second
- `Unlimited`: `5,000` requests / second

See `docs/pricing.md` for the user-facing plan summary.

## Subscription Lifecycle

### Checkout and activation

- `checkout.session.completed` is recorded as an informational event only; it
	does not change tenant status or grant an entitlement.
- `customer.subscription.created` and `customer.subscription.updated` upsert
	`stripe_subscriptions` after signature, tenant-binding, catalog-price, and
	status-transition checks.
- The live `plans` table persists monthly and yearly Stripe price IDs. A
	generic public Checkout request is accepted only for an active Starter, Pro,
	Growth, or Scale price; Enterprise and PAYG use managed flows.
- Only verified `active` and `trialing` Stripe subscriptions grant the mapped
	paid tenant plan. Incomplete, delinquent, paused, unpaid, and canceled
	states resolve the tenant to `free`.
- When a subscription becomes active, the billing service can auto-provision
	included dedicated IPs.

### Plan changes

`POST /checkout` is the only self-service plan-change entry point. It accepts
only a Stripe price ID that maps to an active self-service ApexMail plan and
adds the tenant and resolved plan ID to Stripe Checkout and subscription
metadata.

- Checkout creation does not change the tenant plan.
- `customer.subscription.created` and `customer.subscription.updated` map the
	confirmed Stripe price back to the active ApexMail plan and update the tenant
	in a transaction.
- `POST /switch-plan` is a retained compatibility endpoint that always returns
	`409 CHECKOUT_REQUIRED`; it cannot update tenant or subscription records.
- Plan-change proration is calculated and applied by Stripe. Any ApexMail
  proration preview is informational only and never changes a subscription or
  tenant entitlement.

### Cancellation

`POST /cancel` is retained as a compatibility endpoint and always returns
`409 BILLING_PORTAL_REQUIRED`. A cancellation must be initiated through a
Stripe billing portal session, then reconciled from a verified Stripe webhook.

Stripe `customer.subscription.deleted` events mark the known Stripe
subscription canceled and downgrade the matching tenant to `free`.

### Enterprise contracts

Enterprise entitlement is distinct from generic Checkout. A current signed
Enterprise contract can activate the tenant's Enterprise plan. Contract state
transitions are constrained to the signed lifecycle: only a pending-signature,
currently effective contract can be activated.

The contract cancellation API supports immediate termination only. It rejects a
future effective date rather than pretending that a scheduler will later change
access. Immediate termination is transactional: it downgrades the tenant to
Free only when no other current active Enterprise contract remains. It never
substitutes another paid plan or creates a Stripe entitlement locally.

## Proration Logic

Plan-change previews are diagnostic estimates only; Stripe is the source of
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

Stripe webhooks drive the current invoice state transitions:

- `invoice.paid` marks matching invoices as paid and sets `paid_at`
- `invoice.payment_failed` records dunning state and enqueues a `payment_failed` notification

## Operational Notes

- Dedicated IP auto-provisioning is tied to active Stripe subscription state and the plan's `dedicated_ip_count` feature flag.
- The billing service also exposes PAYG pricing and estimate endpoints backed by `PaygPricing::default()`.
- The pricing tiers for PAYG are `0-10k`, `10k-100k`, `100k-1M`, and `1M+` emails, with API-call billing after the first `100,000` monthly API calls.

## Relevant Source Files

- `services/mail-server/crates/billing-service/src/plans.rs`
- `services/mail-server/crates/billing-service/src/routes.rs`
- `services/mail-server/crates/billing-service/src/subscriptions.rs`
- `services/mail-server/crates/billing-service/src/usage.rs`
- `services/mail-server/crates/billing-service/src/invoices.rs`
- `services/mail-server/crates/billing-service/src/stripe_webhooks.rs`
- `services/mail-server/crates/billing-service/src/types.rs`
- `services/mail-server/crates/billing-service/src/config.rs`