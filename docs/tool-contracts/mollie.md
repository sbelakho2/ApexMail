# Tool Contract: Mollie

This document describes the implementation boundary between ApexMail and
Mollie. Mollie remains the payment authority; ApexMail's local billing rows are
read-optimized records reconciled from Mollie objects fetched after an id-only
webhook.

## Catalog boundary

The active ApexMail catalog is defined by the canonical
[platform catalog](../../services/mail-server/crates/platform-catalog/src/lib.rs)
(`PLANS`), seeded into the `plans` table by
[the billing service seeds](../../services/mail-server/crates/billing-service/src/plans.rs).
The plans table may carry a monthly and/or annual plan code; checkout uses it
to resolve a `priceId` to its catalog row and interval. ApexMail creates no
Mollie subscription objects. Mollie has
no price object: the amount is always sent inline from the platform catalog as
a decimal string (`{"currency":"EUR","value":"20.00"}`), never as minor units.

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
be used to purchase an arbitrary product in the Mollie account.

## Customers, mandates and payments

Mollie models billing around real objects:

- **Customer** — `POST /v2/customers` returns `cst_…`. ApexMail stores the id
  on the tenant and reuses it for later payments and subscriptions.
- **Mandate** — `mdt_…`. Mollie creates the mandate with the **first**
  payment of a customer (`sequenceType: first`); ApexMail does not invent or
  inject mandate details.
- **Payment** — `POST /v2/payments` returns `tr_…`, `status: "open"` and a
  hosted `_links.checkout.href`. The customer completes the payment there.
- **Recurring charge** — `POST /v2/payments` with `sequenceType: recurring`
  plus `customerId` and `mandateId`.
- **Subscription** — `POST /v2/customers/{cst}/subscriptions` returns
  `sub_…` from the amount, interval and start date. Mollie generates the
  recurring charges; ApexMail never synthesizes a paid event.

Every create carries an `Idempotency-Key` header so a retried request cannot
create a second provider object.

## Checkout flow

1. An authenticated tenant with `billing:write` selects a supported catalog
   price.
2. ApexMail resolves `priceId` server-side to an **active** catalog plan and
   its interval; the client never supplies an amount or an arbitrary product.
3. ApexMail resolves (or creates) the Mollie customer `cst_…`.
4. ApexMail creates a Mollie payment with `sequenceType: "first"`, the
   catalog amount as a decimal string, the approved return URL, the derived
   webhook URL (`/webhooks/mollie`), the immutable `tenant_id` and the
   server-resolved `plan_name` in `metadata`, and an `Idempotency-Key`.
5. Mollie returns `_links.checkout.href`; ApexMail redirects the customer
   there. Creating the payment does **not** grant an entitlement.
6. When the customer pays, Mollie posts `id=tr_…` to the webhook. ApexMail
   fetches the payment with `Authorization: Bearer <MOLLIE_API_KEY>`, and the
   fetched `paid` status (plus the binding metadata) is the only normal
   self-service path that activates the paid plan.
7. The first paid payment that produced a mandate also establishes the
   recurring contract (`sequenceType: first` followed by the mandate id). A
   later recurring payment (`sequenceType: recurring`) settles its period.

An authorization is not a settlement: `open`, `pending` and `authorized` are
not facts and never grant access.

## Plan changes and cancellation

Existing subscription changes are checkout-gated. `/switch-plan` returns
`409 CHECKOUT_REQUIRED` and never mutates local rows. Cancellation changes the
local row (`POST /cancel` sets `cancel_at_period_end` or cancels immediately)
and, for an immediate cancel, REVOKES the mandate at the provider
(`DELETE /v2/customers/{cst}/mandates/{mdt}`) — the only provider-side
guarantee that the account can never be charged again. The revocation is
recorded on `mollie_customers.mandate_revoked_at`; a failure there is retried
by the maintenance sweep (15-minute interval) until Mollie confirms. Renewal
paths honour the local flag, and the provider state is always re-read with an
authenticated fetch rather than trusted from a webhook body.

## Refunds

A refund is created under the payment:

- `POST /v2/payments/{paymentId}/refunds` with `amount` (decimal string),
  `description` and an `Idempotency-Key`;
- `GET /v2/payments/{paymentId}/refunds/{refundId}` to fetch its status;
- `GET /v2/payments/{paymentId}/refunds` to reconcile a payment's refunds.

A refund object has its own `re_…` id. A refund webhook carries only
`id=re_…`, so ApexMail resolves the payment id from its own
`mollie_refunds` mapping table and then fetches the refund for the
authoritative status.

## Entitlement reconciliation

For a webhook id, ApexMail validates all of the following before updating the
tenant:

- the id has the documented shape (`tr_…` or `re_…`, charset
  `[A-Za-z0-9_]`) and the object fetches with the configured Bearer key;
- the fetched object is bound to the metadata tenant, not another tenant;
- a recurring charge names a local invoice, and its amount and currency must
  match that invoice exactly (the tax-truth gate persists an immutable
  snapshot before anything is marked paid);
- a checkout payment is informational: it never grants entitlement on its
  own.

Mollie payment statuses are `open | pending | authorized | paid | failed |
canceled | expired | refunded | charged_back`. Only `paid`, `refunded`,
`charged_back`, `failed`, `canceled` and `expired` are facts; `open`,
`pending` and `authorized` are not settled and are ignored until the status
changes.

ApexMail does not create Mollie subscription objects: recurring collection is
an explicit `sequenceType: recurring` payment against the customer's mandate,
so the LOCAL subscription row is authoritative for access and renewals, and
the mandate plus `mollie_customers.mandate_revoked_at` is the provider-side
truth for what may still be charged. There is therefore no provider
subscription state to reconcile, and no claim in this document depends on
one.

Enterprise contract signature handling is the separate audited entitlement
path. It is not a generic Checkout purchase path.

An Enterprise contract cancellation is also separate from Mollie self-service
cancellation. The current API supports immediate termination only; a future
effective date is rejected instead of being stored as a non-executing schedule.
On an immediate termination, the tenant returns to Free only if no other
current active signed Enterprise contract authorizes Enterprise access.

## Webhooks

- **Endpoint:** `POST /webhooks/mollie` mounted by `billing-service` and by
  `api-server` (the live ingest surface).
- **Content type:** `application/x-www-form-urlencoded`.
- **Payload:** a single `id` parameter — `id=tr_…` for a payment,
  `id=re_…` for a refund. There is no signature, no status and no event type.
- **Answer:** `200` for anything accepted, including an unknown id (Mollie
  stops retrying only on 200). Any other status makes Mollie retry (10
  attempts over roughly 26 hours).
- **Verification:** authenticate a fetch. ApexMail calls
  `GET /v2/payments/{id}` (or the refund fetch) with
  `Authorization: Bearer <MOLLIE_API_KEY>` and trusts the fetched object, not
  the webhook body. An id that cannot be fetched or is unknown is acknowledged
  with 200 and changes nothing.
- **Idempotency:** `mollie_webhook_events` dedupes on a content-addressed
  digest over the fetched fact (object id, normalized event code, amount,
  timestamp, refunded subtotal and status). Replays re-fetch and collapse;
  a status change is a new fact.
- **Failure handling:** processing failures are stored in the Redis-backed
  dead-letter flow for controlled retry.

ApexMail normalizes the fetched state into these internal event codes:

| Event code | Source | Effect |
|---|---|---|
| `AUTHORISATION` (success `true`) | payment status `paid` | Confirm the payment and settle the matching invoice/payment state |
| `AUTHORISATION` (success `false`) | `failed`, `canceled`, `expired` | Record the payment refusal and the dunning state |
| `RECURRING_CONTRACT` | first paid payment that produced a mandate | Bind the customer/mandate and persist the recurring state |
| `REFUND` | refund `refunded`/`processing`, or payment `refunded` | Reconcile the refund against the invoice/payment state |
| `REFUND_FAILED` | refund `failed`/`canceled` | Record the failed refund for reconciliation |
| `CHARGEBACK` | payment `charged_back` | Record the chargeback for reconciliation |

## Settlements

Mollie pays out through settlements. The API client exposes
`GET /v2/settlements` and `GET /v2/settlements/{id}` (the objects carry their
invoice and payment references) for OPERATOR payout reconciliation. No
automated settlement posting runs today, and customer entitlement never
depends on a settlement.

## Operational rules

- Do not call local plan, subscription, or tenant-plan mutation helpers to
  simulate a payment event.
- Do not create a Mollie subscription or payment from a client-supplied plan
  without resolving it to an active catalog plan on the server.
- Do not expose Enterprise or PAYG through generic public Checkout.
- Never trust a webhook body's status: the webhook carries only an id.
- If local billing state diverges from Mollie, reconcile from an authenticated
  fetch or an audited operational process. Mollie wins for the payments and
  refunds that back an invoice; the LOCAL subscription row is authoritative
  for entitlement and renewals.

See [the pricing reference](../pricing.md) and
[the billing lifecycle](../architecture/billing-lifecycle.md) for related
product behavior.
