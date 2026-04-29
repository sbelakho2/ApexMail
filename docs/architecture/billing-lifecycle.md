# Billing Lifecycle

> **Implementation Note (2026-04):** This page reflects the current Rust billing implementation in `services/mail-server/crates/billing-service/`.

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
| Free | `0` | `0` | `3,000` | `50,000` | `Free` |
| Starter | `2,500` cents | `25,000` cents | `50,000` | `500,000` | `Standard` |
| Pro | `6,500` cents | `65,000` cents | `150,000` | `2,000,000` | `Standard` |
| Growth | `15,000` cents | `150,000` cents | `500,000` | `5,000,000` | `High` |
| Scale | `35,000` cents | `350,000` cents | `2,000,000` | `20,000,000` | `High` |
| Enterprise | `80,000` cents | `800,000` cents | `5,000,000` | unlimited (`-1`) | `Unlimited` |
| PAYG | `0` | `0` | unlimited (`-1`) | unlimited (`-1`) | `Standard` |

Rate-limit tiers map to API throughput in `src/types.rs`:

- `Free`: `10` requests / second
- `Standard`: `100` requests / second
- `High`: `500` requests / second
- `Unlimited`: `5,000` requests / second

See `docs/pricing.md` for the user-facing plan summary.

## Subscription Lifecycle

### Checkout and activation

- `checkout.session.completed` marks the tenant status as active.
- `customer.subscription.created` and `customer.subscription.updated` upsert `stripe_subscriptions`.
- The Stripe price ID is mapped back to an ApexMail plan via `plans.stripe_price_id_monthly` / `plans.stripe_price_id_yearly`.
- When a subscription becomes active, the billing service can auto-provision included dedicated IPs.

### Plan changes

`POST /switch-plan` drives the current plan-change flow.

- For subscription-to-subscription changes, the route previews proration first, then updates the active subscription row and tenant plan inside a transaction.
- For switches to `payg`, the current Stripe subscription is marked `cancel_at_period_end = true` and the tenant plan is updated to `payg` immediately; the response still returns the existing period end as the effective date of the Stripe cancellation.
- Every change writes an audit-log entry with the previous plan, new plan, billing interval, and proration details.

### Cancellation

`POST /cancel` supports two modes:

- end-of-period cancellation: sets `cancel_at_period_end = true`
- immediate cancellation: marks the subscription canceled now and downgrades the tenant to `free`

Stripe `customer.subscription.deleted` events also downgrade the tenant to `free` and mark the Stripe subscription canceled.

## Proration Logic

Plan-change previews are computed in `preview_plan_proration()`.

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

- Estonia (`EE`): `22%`
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