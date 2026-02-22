# Tool Contract: Stripe

> Internal engineering document — specifies the interface contract between ApexMail and Stripe for billing and subscription management.

| Field | Value |
|-------|-------|
| **API Version** | `2024-12-18.acacia` (pinned) |
| **SDK** | `stripe` npm package (TypeScript) |
| **Role** | Subscription billing, payment processing, invoicing |
| **Data Residency** | EU (Stripe account region) |
| **Environments** | Test mode (dev/staging), Live mode (production) |

---

## 1. Products & Pricing

### Plans

| Plan | Stripe Product ID | Price (Monthly) | Email Limit | Contacts |
|------|--------------------|----------------|-------------|----------|
| Free | `prod_free` | $0 | 3,000/mo | 500 |
| Starter | `prod_starter` | $25/mo | 50,000/mo | 10,000 |
| Pro | `prod_pro` | $65/mo | 150,000/mo | 50,000 |
| Growth | `prod_growth` | $150/mo | 500,000/mo | 200,000 |
| Scale | `prod_scale` | $350/mo | 2,000,000/mo | 500,000 |
| Enterprise | `prod_enterprise` | $800/mo | 5,000,000/mo | Unlimited |

### Add-ons

| Add-on | Stripe Product ID | Price |
|--------|-------------------|-------|
| Dedicated IP | `prod_dedicated_ip` | $30/mo |

### Price Configuration

- All prices are in **USD** (single currency).
- Billing cycle: monthly, with annual option (2 months free) for Starter through Scale.
- Metered usage (overage emails) is tracked via Stripe Usage Records and billed at invoice time.
- Overage rate: $0.40 per 1,000 emails, reported via `stripe.subscriptionItems.createUsageRecord()`.

---

## 2. Subscription Lifecycle

### Creation Flow

```
User selects plan
  → API creates Stripe Checkout Session (mode: 'subscription')
  → User redirected to Stripe Checkout
  → Payment succeeds
  → Stripe fires `checkout.session.completed` webhook
  → API activates subscription in PostgreSQL
  → User redirected to app with success state
```

### State Machine

```
trial → active → past_due → canceled
                ↘ active (payment recovered)
trial → canceled (no conversion)
```

| State | Description | App Behavior |
|-------|-------------|-------------|
| `trialing` | 14-day free trial (Starter+ only) | Full access, trial banner shown |
| `active` | Paying customer | Full access |
| `past_due` | Payment failed, retrying | Full access for 7 d grace period, then read-only |
| `canceled` | Subscription ended | Downgrade to Free plan limits |
| `unpaid` | All retry attempts exhausted | Read-only access, data retained 90 d |

### Upgrade / Downgrade

- Plan changes use `stripe.subscriptions.update()` with `proration_behavior: 'create_prorations'`.
- Downgrades take effect at end of current billing period (`cancel_at_period_end` for old plan items is NOT used; we swap the price immediately with proration).
- Upgrades are immediate with prorated charges.

---

## 3. Webhook Events

### Endpoint

- URL: `https://api.apexmail.com/v1/webhooks/stripe`
- Signing secret: stored as `STRIPE_WEBHOOK_SECRET` env var.
- All events are verified using `stripe.webhooks.constructEvent()` before processing.

### Consumed Events

| Event | Handler | Action |
|-------|---------|--------|
| `checkout.session.completed` | `handleCheckoutComplete` | Create subscription record, activate plan, send welcome email |
| `invoice.paid` | `handleInvoicePaid` | Update `paid_through` date, reset usage counters, generate receipt |
| `invoice.payment_failed` | `handlePaymentFailed` | Mark subscription `past_due`, notify tenant admin, schedule retry warning |
| `customer.subscription.updated` | `handleSubscriptionUpdated` | Sync plan/status changes to local DB (handles Stripe-side changes) |
| `customer.subscription.deleted` | `handleSubscriptionDeleted` | Downgrade tenant to Free, send churn notification, trigger data retention policy |
| `invoice.upcoming` | `handleUpcomingInvoice` | Send "invoice coming" email 3 days before billing |
| `customer.updated` | `handleCustomerUpdated` | Sync billing email/name changes |
| `charge.dispute.created` | `handleDisputeCreated` | Alert ops, freeze tenant sending (anti-fraud) |

### Event Processing Rules

1. Every webhook handler is **idempotent**. Events may be delivered more than once.
2. Events are logged to the `stripe_events` table with the event ID as a unique constraint — duplicates are detected and skipped.
3. Events are processed within a database transaction. If the transaction fails, the webhook returns 500 and Stripe retries.
4. Unrecognized event types are logged and acknowledged with 200 (no action).
5. Webhook processing MUST complete in < **10 seconds**. Heavy work is deferred to the job queue.

---

## 4. Idempotency

### Idempotency Keys

All **mutating** Stripe API calls MUST include an idempotency key.

```ts
await stripe.subscriptions.update(subscriptionId, {
  items: [{ id: itemId, price: newPriceId }],
}, {
  idempotencyKey: `upgrade_${tenantId}_${newPriceId}_${Date.now()}`,
});
```

### Key Construction

Pattern: `<action>_<tenant_id>_<resource_id>_<timestamp_or_hash>`

- Keys are stored in Redis (`apx:stripe:idem:<key>`) with a 24 h TTL to prevent accidental reuse.
- Stripe retains idempotency keys for 24 h on their side.

---

## 5. Retry & Error Handling

### Stripe API Errors

| Error Type | Retry? | Action |
|-----------|--------|--------|
| `rate_limit_error` | Yes (exponential backoff, max 3) | Wait and retry |
| `api_connection_error` | Yes (max 3) | Wait and retry |
| `api_error` (500) | Yes (max 2) | Wait and retry |
| `card_error` | No | Surface to user |
| `invalid_request_error` | No | Log, alert engineering |
| `authentication_error` | No | Alert ops immediately |

### Webhook Retry

- If ApexMail returns non-2xx, Stripe retries with exponential backoff for up to 3 days.
- After 3 days of failures, the webhook endpoint is disabled by Stripe and ops is alerted.

---

## 6. Customer & Metadata Mapping

### Customer Object

```ts
const customer = await stripe.customers.create({
  email: tenant.billingEmail,
  name: tenant.companyName,
  metadata: {
    tenant_id: tenant.id,
    plan: 'growth',
    environment: 'production',
  },
});
```

### Metadata Conventions

| Object | Metadata Keys |
|--------|---------------|
| Customer | `tenant_id`, `plan`, `environment` |
| Subscription | `tenant_id`, `plan_name` |
| Invoice | `tenant_id` |
| Checkout Session | `tenant_id`, `plan_name`, `source` |

- `tenant_id` is present on **every** Stripe object for traceability.
- Metadata values are strings, max 500 characters each.

---

## 7. Test vs. Live Mode

| Aspect | Test Mode | Live Mode |
|--------|-----------|-----------|
| API Key prefix | `sk_test_` / `pk_test_` | `sk_live_` / `pk_live_` |
| Webhook secret | Separate per environment | Production secret |
| Used in | Development, staging, CI | Production only |
| Test cards | `4242424242424242` etc. | Real payment methods |
| Clock | Stripe Test Clocks for subscription testing | Real time |

### Rules

1. Live keys are NEVER stored in code or config files — injected via environment variables.
2. Test mode uses Stripe Test Clocks to simulate subscription lifecycle in CI.
3. All Stripe interactions in development hit test mode — there is no local mock.

---

## 8. EU Data Residency

- ApexMail's Stripe account is registered in the EU.
- Customer payment data is processed and stored by Stripe within the EU.
- No PCI-scoped cardholder data is stored in ApexMail's systems — Stripe Checkout handles card collection.
- The `stripe.Customer` object stores only non-sensitive data (email, name, metadata).
- Stripe's EU data processing addendum (DPA) is executed and on file.

---

## 9. Local Database Sync

### Synced Tables

| Table | Synced Fields | Source of Truth |
|-------|--------------|----------------|
| `subscriptions` | `stripe_subscription_id`, `status`, `plan`, `current_period_end` | Stripe (via webhooks) |
| `tenants` | `stripe_customer_id`, `plan` | Stripe (via webhooks) |
| `invoices` | `stripe_invoice_id`, `amount`, `status`, `paid_at` | Stripe (via webhooks) |

### Rules

1. Stripe is the **source of truth** for billing state. Local DB is a read-optimized cache.
2. If local state and Stripe diverge, Stripe wins. A daily reconciliation job (`tools/reconcile.ts`) detects and fixes drift.
3. Never modify subscription state locally without a corresponding Stripe API call.

---

*Last updated: 2026-02-09*
