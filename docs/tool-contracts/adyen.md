# Tool Contract: Adyen

This document describes the implementation boundary between ApexMail and
Adyen. Adyen remains the payment authority; ApexMail's local billing rows are
read-optimized records reconciled from verified Adyen webhooks.

## Catalog boundary

The active ApexMail catalog is defined by the canonical
[platform catalog](../../services/mail-server/crates/platform-catalog/src/lib.rs)
(`PLANS`), seeded into the `plans` table by
[the billing service seeds](../../services/mail-server/crates/billing-service/src/plans.rs).
Each active plan may carry a provider-facing monthly and/or annual Adyen plan
code; the amount is always sent inline from the platform catalog (minor
units, EUR).

All prices are EUR (the 2026-09-08 pricing review):

| Plan | Plan ID | Monthly | Annual | Generic public Checkout |
|---|---|---:|---:|---|
| Free | `free` | €0 | €0 | No — initial entitlement |
| Developer | `starter` | €20 | €200/year | Yes |
| Pro | `pro` | €89 | €890/year | Yes |
| Growth | `growth` | €229 | €2,290/year | Yes |
| Business | `scale` | €699 | €6,990/year | Yes |
| Enterprise Cloud | `enterprise` | €1,750 | €17,500/year | No — sales and contract flow |
| Pay As You Go | `payg` | Usage priced | Usage priced | No — approved billing setup |

Annual subscriptions are billed at 10× the monthly price (two months free).
Free includes 3,000 emails/month forever plus a one-time 30,000-email launch
allowance for the first 30 days.

The public Checkout endpoint accepts a submitted `priceId` only when it maps
to an **active** self-service catalog row: `starter` (Developer), `pro` (Pro),
`growth` (Growth), or `scale` (Business). It rejects unknown values and cannot
be used to purchase an arbitrary product in the Adyen account.

## Checkout and portal flow

1. An authenticated tenant with `billing:write` selects a supported catalog
   price.
2. ApexMail creates a Adyen Checkout Session in subscription mode.
3. The session carries the immutable `tenant_id` and the server-resolved
   `plan_name` in its inline `metadata`, binds the tenant's
   `shopperReference`, and sends the catalog amount inline (minor units, EUR).
4. Adyen redirects the customer to the approved return URL.
5. A verified `RECURRING_CONTRACT` (`recurring.token.created`) notification
   binds the stored recurring detail and resolves the merchant reference back
   to an active ApexMail plan; later recurring `AUTHORISATION` notifications
   update local subscription state.

An `AUTHORISATION` notification is informational only. It does not grant an
entitlement or reactivate a suspended tenant because a payment can succeed
before the subscription reaches an entitled state.

Existing subscription changes are checkout-gated: the retained `/switch-plan`
endpoint returns `409 CHECKOUT_REQUIRED` and never mutates local entitlement
rows. Cancellation is a local state change (external audit 15 Oct, H1):
`/cancel` sets `cancel_at_period_end` (or cancels immediately) because Adyen
has no hosted billing portal and the Subscription model charges are
merchant-initiated; every renewal path honours the flag.

## Entitlement reconciliation

For a verified Adyen notification, ApexMail validates all of the following
before updating the tenant:

- the in-body `additionalData.hmacSignature` HMAC;
- the Adyen subscription is bound to the metadata tenant, not another tenant;
- the notified amount maps to an **active** ApexMail plan and matches its
  monthly or annual interval;
- the Adyen status transition is valid.

Only `active` and `trialing` statuses grant the mapped paid plan. `incomplete`,
`incomplete_expired`, `past_due`, `unpaid`, `paused`, and `canceled` statuses
remain stored for reconciliation but resolve the tenant to Free access. A
reconciled cancellation downgrades only if the canceled subscription is
already associated with that tenant.

Enterprise contract signature handling is the separate audited entitlement
path. It is not a generic Checkout purchase path.

An Enterprise contract cancellation is also separate from Adyen self-service
cancellation. The current API supports immediate termination only; a future
effective date is rejected instead of being stored as a non-executing schedule.
On an immediate termination, the tenant returns to Free only if no other
current active signed Enterprise contract authorizes Enterprise access.

## Webhooks

- **Endpoint:** `/webhooks/adyen` mounted by `billing-service`.
- **Payload:** `{"notificationItems":[{"NotificationRequestItem": …}]}`.
- **Signing secret:** `ADYEN_HMAC_KEY`, hex-decoded.
- **Verification:** the in-body `additionalData.hmacSignature` (a base64
  HMAC SHA256 signature over the escaped colon-joined
  `pspReference:originalReference:merchantAccountCode:merchantReference:amount.value:amount.currency:eventCode:success`)
  must verify before any event is processed.
- **Answer:** an accepted notification is acknowledged with the bare body
  `[accepted]`.
- **Idempotency:** `adyen_webhook_events` dedupes on a digest over
  (eventCode, pspReference, success, eventDate, merchantReference) and stores
  the `pspReference` for support lookups.
- **Failure handling:** processing failures are returned to Adyen and stored
  in the Redis-backed dead-letter flow for controlled retry.

Consumed event families include:

| Event | Effect |
|---|---|
| `AUTHORISATION` (success `true`) | Confirm the payment and settle the matching invoice/payment state; informational for entitlement until the subscription resolves entitled |
| `AUTHORISATION` (success `false`) | Record the payment refusal and the dunning state |
| `RECURRING_CONTRACT` (`recurring.token.created`) | Bind the stored recurring detail; validate and persist subscription state; reconcile entitlement |
| `REFUND` | Reconcile the refund against the invoice/payment state |
| `REFUND_FAILED` | Record the failed refund for reconciliation |
| `CHARGEBACK` | Record the chargeback for reconciliation |
| `CHARGEBACK_REVERSED` | Record the reversal and restore the reconciled state |

## Operational rules

- Do not call local plan, subscription, or tenant-plan mutation helpers to
  simulate a payment event.
- Do not create a Adyen subscription from a public plan ID without first
  resolving it to an active catalog plan on the server.
- Do not expose Enterprise or PAYG through generic public Checkout.
- If local billing state diverges from Adyen, reconcile from a verified Adyen
  event or an audited operational process; Adyen wins for subscription state.

See [the pricing reference](../pricing.md) and
[the billing lifecycle](../architecture/billing-lifecycle.md) for related
product behavior.
