# Tool Contract: Stripe

This document describes the implementation boundary between ApexMail and
Stripe. Stripe remains the payment authority; ApexMail's local billing rows are
read-optimized records reconciled from verified Stripe webhooks.

## Catalog boundary

The active ApexMail catalog is defined by
[the billing plan seeds](../../services/mail-server/crates/billing-service/src/plans.rs)
and persisted in the `plans` table. Each active plan may have a monthly and/or
annual Stripe price ID.

All prices are USD:

| Plan | Monthly | Annual | Public generic Checkout |
|---|---:|---:|---|
| Free | $0 | $0 | No — initial entitlement |
| Starter | $25 | $250/year | Yes |
| Pro | $65 | $650/year | Yes |
| Growth | $150 | $1,500/year | Yes |
| Scale | $350 | $3,500/year | Yes |
| Enterprise | $3,000 | $30,000/year | No — sales and contract flow |
| PAYG | Usage priced | Usage priced | No — approved billing setup |

The public Checkout endpoint accepts a submitted Stripe price only when it
maps to an **active** Starter, Pro, Growth, or Scale catalog row. It rejects
unknown prices and cannot be used to purchase an arbitrary product in the
Stripe account.

## Checkout and portal flow

1. An authenticated tenant with `billing:write` selects a supported catalog
   price.
2. ApexMail creates a Stripe Checkout Session in subscription mode.
3. The Session and `subscription_data` include immutable `tenant_id` and
   server-resolved `plan_name` metadata.
4. Stripe redirects the customer to the approved return URL.
5. A signed `customer.subscription.created` or
   `customer.subscription.updated` webhook resolves the Stripe price back to
   an active ApexMail plan and updates local subscription state.

A `checkout.session.completed` event is informational only. It does not grant
an entitlement or reactivate a suspended tenant because a Checkout Session can
complete before a subscription reaches an entitled payment state.

Existing subscription changes and cancellations use a Stripe billing portal
session. The legacy direct `/switch-plan` and `/cancel` endpoints return a
conflict response and never mutate local entitlement rows.

## Entitlement reconciliation

For a verified Stripe subscription event, ApexMail validates all of the
following before updating the tenant:

- the event signature and timestamp tolerance;
- the Stripe subscription is bound to the metadata tenant, not another tenant;
- the primary recurring price maps to an **active** ApexMail plan and matches
  its monthly or annual interval;
- the Stripe status transition is valid.

Only `active` and `trialing` statuses grant the mapped paid plan. `incomplete`,
`incomplete_expired`, `past_due`, `unpaid`, `paused`, and `canceled` statuses
remain stored for reconciliation but resolve the tenant to Free access. A
`customer.subscription.deleted` event downgrades only if the deleted
subscription is already associated with that tenant.

Enterprise contract signature handling is the separate audited entitlement
path. It is not a generic Checkout purchase path.

An Enterprise contract cancellation is also separate from Stripe self-service
cancellation. The current API supports immediate termination only; a future
effective date is rejected instead of being stored as a non-executing schedule.
On an immediate termination, the tenant returns to Free only if no other
current active signed Enterprise contract authorizes Enterprise access.

## Webhooks

- **Endpoint:** `/webhooks/stripe` mounted by `billing-service`.
- **Signing secret:** `STRIPE_WEBHOOK_SECRET`.
- **Verification:** Stripe signature HMAC plus timestamp tolerance before event
  processing.
- **Idempotency:** `stripe_webhook_events` records the Stripe event ID and
  prevents duplicate processing.
- **Failure handling:** processing failures are returned to Stripe and stored
  in the Redis-backed dead-letter flow for controlled retry.

Consumed event families include:

| Event | Effect |
|---|---|
| `checkout.session.completed` | Log checkout completion; wait for subscription state webhook |
| `customer.subscription.created` | Validate and persist subscription state; reconcile entitlement |
| `customer.subscription.updated` | Validate and reconcile price/status changes |
| `customer.subscription.deleted` | Mark known subscription canceled and downgrade to Free |
| `invoice.paid` | Reconcile invoice/payment state |
| `invoice.payment_failed` | Record payment failure and dunning state |
| `customer.subscription.trial_will_end` | Trigger trial-ending handling when applicable |

## Operational rules

- Do not call local plan, subscription, or tenant-plan mutation helpers to
  simulate a payment event.
- Do not create a Stripe subscription from a public plan ID without first
  resolving an active catalog price on the server.
- Do not expose Enterprise or PAYG through generic public Checkout.
- If local billing state diverges from Stripe, reconcile from a verified Stripe
  event or an audited operational process; Stripe wins for subscription state.

See [the pricing reference](../pricing.md) and
[the billing lifecycle](../architecture/billing-lifecycle.md) for related
product behavior.
