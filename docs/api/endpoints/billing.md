# Billing API

**Base path:** `/v1/billing`  
**Authentication:** tenant API/session authentication  
**Scopes:** `billing:read` for reads and `billing:write` for billing actions

The plan catalog and entitlement lifecycle are described in
[Pricing](../../pricing.md) and
[the Stripe contract](../../tool-contracts/stripe.md).

## Catalog and usage endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/plans` | List active catalog plans |
| GET | `/plans/:planId` | Get an active plan by ID |
| GET | `/plans/tenant/current` | Get the authenticated tenant's active plan/limits |
| GET | `/plans/tenant/features` | Get feature flags for the active plan |
| GET | `/plans/tenant/limits` | Get plan quota limits |
| GET | `/plans/features/:feature` | Check an individual feature flag |
| GET | `/plans/compare/:planId1/:planId2` | Compare active catalog plans |
| GET | `/usage` | Get current billing-period usage |
| GET | `/usage/realtime/:metric` | Get a current Redis-backed usage counter |
| GET | `/payg/pricing` | Get the runtime PAYG pricing schedule |
| POST | `/payg/estimate` | Estimate PAYG cost for requested usage |
| GET | `/payg/usage` | Get PAYG usage for the authenticated tenant |
| POST | `/overage/estimate` | Estimate subscription overage cost |
| POST | `/alerts` | Configure usage-alert thresholds |
| GET | `/quota` | Check current quota state |

All catalog monetary fields are integer cents. Catalog prices are USD.

## Secure paid-plan flow

### Create Checkout

```http
POST /v1/billing/checkout
Content-Type: application/json
```

```json
{
  "priceId": "price_123",
  "successUrl": "https://app.apexmail.ee/settings/billing?checkout=success",
  "cancelUrl": "https://app.apexmail.ee/settings/billing?checkout=cancelled"
}
```

`priceId` must be a monthly or yearly Stripe price ID bound to an **active**
Starter, Pro, Growth, or Scale catalog row. The API rejects blank, unknown,
inactive, Enterprise, PAYG, and cross-product price IDs. Both redirect URLs
must be approved ApexMail URLs.

A successful response contains the hosted Stripe Checkout URL and session ID.
It does **not** grant paid access. The API records the resolved `tenant_id` and
`plan_name` in Stripe metadata; a verified Stripe subscription webhook is the
only normal self-service path that activates the paid entitlement.

### Create billing portal session

```http
POST /v1/billing/portal
Content-Type: application/json
```

```json
{
  "returnUrl": "https://app.apexmail.ee/settings/billing"
}
```

The portal is the supported path for subscription changes and cancellation.
It requires an existing Stripe customer and an approved return URL.

### Retired direct-mutation endpoints

The following compatibility endpoints require `billing:write` but never mutate
a local subscription or tenant plan:

| Method | Endpoint | HTTP status | Code | Required action |
|---|---|---:|---|---|
| POST | `/switch-plan` | 409 | `CHECKOUT_REQUIRED` | Start supported Stripe Checkout and await webhook reconciliation |
| POST | `/cancel` | 409 | `BILLING_PORTAL_REQUIRED` | Use the Stripe billing portal and await webhook reconciliation |

Direct JSON requests cannot create, switch, cancel, or immediately downgrade a
paid entitlement.

### Subscription and invoices

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/subscription` | Get local Stripe subscription state for the authenticated tenant |
| GET | `/invoices` | List tenant invoices |
| GET | `/invoices/:id` | Get an invoice |
| GET | `/invoices/:id/pdf` | Render/download invoice HTML for PDF handling |
| GET | `/invoices/:id/xml` | Get invoice XML |
| GET | `/proration/:planName` | Informational proration preview only; Stripe controls actual charges |

## Billing administration

Administrative endpoints are available under `/v1/billing/admin`. Plan
changes use `POST /admin/tenants/:tenantId/plan-override`, which requires a
valid active `planId` and a nonempty reason and writes an audit entry. Generic
tenant editing cannot change a tenant plan.

Other administrative routes cover tenant billing details, credits, dunning,
invoices, reports, and export. They do not replace the normal Stripe lifecycle
for customer-paid subscription changes.

## Billing company information

| Field | Value |
|---|---|
| Company | Bel Consulting OÜ (trading as ApexMail) |
| Address | Sakala 7-2, Tallinn 10141, Estonia |
| Registry code | 16588745 |
| VAT number | EE102951727 |
| Billing email | billing@apexmail.ee |
