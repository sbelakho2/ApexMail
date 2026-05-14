# Billing API

The Billing API manages plans, usage tracking, invoices, subscriptions, and billing administration.

## Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/billing/plans` | List available plans |
| GET | `/v1/billing/plans/:planId` | Get plan details |
| GET | `/v1/billing/plans/tenant/current` | Get current tenant plan |
| GET | `/v1/billing/plans/tenant/features` | Get enabled features for tenant |
| GET | `/v1/billing/plans/tenant/limits` | Get plan limits for tenant |
| GET | `/v1/billing/plans/features/:feature` | Check if feature is enabled |
| GET | `/v1/billing/plans/compare/:planId1/:planId2` | Compare two plans |
| GET | `/v1/billing/usage` | Get current usage |
| GET | `/v1/billing/usage/realtime/:metric` | Get realtime usage counter |
| GET | `/v1/billing/payg/pricing` | Get PAYG pricing |
| POST | `/v1/billing/payg/estimate` | Estimate PAYG cost |
| GET | `/v1/billing/payg/usage` | Get PAYG usage details |
| POST | `/v1/billing/overage/estimate` | Estimate overage cost |
| POST | `/v1/billing/alerts` | Configure usage alerts |
| POST | `/v1/billing/checkout` | Create checkout session |
| POST | `/v1/billing/portal` | Create customer portal session |
| GET | `/v1/billing/proration/:planName` | Preview plan change proration |
| POST | `/v1/billing/switch-plan` | Switch to a different plan |
| POST | `/v1/billing/cancel` | Request subscription cancellation |
| GET | `/v1/billing/subscription` | Get current subscription |
| GET | `/v1/billing/invoices` | List invoices |
| GET | `/v1/billing/invoices/:id` | Get invoice details |
| GET | `/v1/billing/invoices/:id/pdf` | Get invoice PDF |
| GET | `/v1/billing/invoices/:id/xml` | Get invoice XML |
| GET | `/v1/billing/quota` | Check current quota status |

### Admin Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/billing/admin/tenants` | List tenant billing details |
| GET | `/v1/billing/admin/tenants/:tenantId` | Get tenant billing details |
| POST | `/v1/billing/admin/tenants/:tenantId/credits` | Apply credit to tenant |
| POST | `/v1/billing/admin/tenants/:tenantId/plan-override` | Override tenant plan |
| POST | `/v1/billing/admin/tenants/:tenantId/subscription-status` | Force subscription status |
| POST | `/v1/billing/admin/tenants/:tenantId/dunning/reset` | Reset dunning process |
| POST | `/v1/billing/admin/tenants/:tenantId/invoices` | Create invoice for tenant |
| GET | `/v1/billing/admin/reports/revenue` | Revenue report |
| GET | `/v1/billing/admin/reports/mrr` | MRR report |
| GET | `/v1/billing/admin/reports/churn` | Churn report |
| GET | `/v1/billing/admin/reports/dunning` | Dunning report |
| GET | `/v1/billing/admin/reports/costs` | Cost report |
| GET | `/v1/billing/admin/export` | Export billing data |

---

## Plans

### List Plans

```http
GET /v1/billing/plans
X-API-Key: {{api_key}}
```

#### Response

```json
{
  "data": [
    {
      "id": "plan_free",
      "name": "Free",
      "description": "For individuals and small projects",
      "price_monthly": 0,
      "price_yearly": 0,
      "features": {
        "emails_per_month": 1000,
        "max_sending_domains": 1,
        "max_contacts": 100,
        "max_api_keys": 2,
        "dedicated_ip": false,
        "dedicated_ip_count": 0,
        "sso": false,
        "rate_limit_rps": 10
      }
    }
  ]
}
```

### Get Current Plan

```http
GET /v1/billing/plans/tenant/current
X-API-Key: {{api_key}}
```

#### Response

```json
{
  "plan_id": "plan_growth",
  "plan_name": "Growth",
  "status": "active",
  "billing_interval": "monthly",
  "current_period_start": "2024-01-01T00:00:00Z",
  "current_period_end": "2024-02-01T00:00:00Z",
  "features": {
    "emails_per_month": 50000,
    "max_sending_domains": 10,
    "max_contacts": 5000,
    "dedicated_ip": true,
    "dedicated_ip_count": 2,
    "rate_limit_rps": 500
  }
}
```

---

## Usage

### Get Usage

```http
GET /v1/billing/usage?metric=emails_sent&from=2024-01-01&to=2024-01-31
X-API-Key: {{api_key}}
```

#### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `metric` | string | | Usage metric to query |
| `from` | string | 30 days ago | Start date (ISO 8601) |
| `to` | string | now | End date (ISO 8601) |
| `interval` | string | day | Aggregation interval (`hour`, `day`, `week`, `month`) |

#### Response

```json
{
  "data": [
    {
      "date": "2024-01-15T00:00:00Z",
      "emails_sent": 1520,
      "emails_delivered": 1498,
      "emails_bounced": 22
    }
  ],
  "totals": {
    "emails_sent": 45200,
    "emails_delivered": 44500,
    "emails_bounced": 700
  },
  "plan_limit": 50000,
  "usage_percent": 90.4
}
```

---

## Invoices

### List Invoices

```http
GET /v1/billing/invoices?status=paid&limit=10
X-API-Key: {{api_key}}
```

#### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `status` | string | | Filter by status (`paid`, `open`, `overdue`, `void`) |
| `limit` | number | 20 | Results per page |
| `offset` | number | 0 | Pagination offset |

#### Response

```json
{
  "data": [
    {
      "id": "inv_abc123",
      "number": "INV-2024-001",
      "status": "paid",
      "currency": "EUR",
      "total_cents": 2990,
      "total_formatted": "29.90 €",
      "period_start": "2024-01-01T00:00:00Z",
      "period_end": "2024-02-01T00:00:00Z",
      "issued_at": "2024-01-01T00:00:00Z",
      "paid_at": "2024-01-01T12:00:00Z",
      "pdf_url": "https://billing.apexmail.ee/invoices/inv_abc123/pdf"
    }
  ]
}
```

### Get Invoice PDF

```http
GET /v1/billing/invoices/inv_abc123/pdf
X-API-Key: {{api_key}}
```

Returns the invoice as an HTML document suitable for PDF rendering (with `Content-Disposition: attachment`).

### Get Invoice XML

```http
GET /v1/billing/invoices/inv_abc123/xml
X-API-Key: {{api_key}}
```

Returns the invoice in XML format (compatible with EU e-invoicing standards).

---

## Subscription Management

### Switch Plan

```http
POST /v1/billing/switch-plan
X-API-Key: {{api_key}}
Content-Type: application/json
```

#### Request Body

```json
{
  "plan_id": "plan_growth",
  "billing_interval": "monthly"
}
```

#### Response

```json
{
  "success": true,
  "plan_id": "plan_growth",
  "effective_date": "2024-02-01T00:00:00Z",
  "proration": {
    "credit_cents": 1500,
    "charge_cents": 2990,
    "net_cents": 1490
  }
}
```

### Cancel Subscription

```http
POST /v1/billing/cancel
X-API-Key: {{api_key}}
Content-Type: application/json
```

#### Request Body

```json
{
  "reason": "Switching to self-hosted",
  "cancellation_date": "2024-02-01T00:00:00Z"
}
```

#### Response

```json
{
  "success": true,
  "effective_date": "2024-02-01T00:00:00Z",
  "message": "Subscription will not renew. Service continues until end of billing period."
}
```

---

## Configure Usage Alerts

Set up threshold-based usage alerts.

```http
POST /v1/billing/alerts
X-API-Key: {{api_key}}
Content-Type: application/json
```

```json
{
  "metric": "emails_sent",
  "threshold_percent": 80,
  "email_notifications": true,
  "webhook_url": "https://hooks.example.com/alerts"
}
```

#### Response

```json
{
  "success": true,
  "alert_id": "alert_abc123",
  "metric": "emails_sent",
  "threshold_percent": 80,
  "enabled": true
}
```

---

## Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `PLAN_NOT_FOUND` | 404 | Plan doesn't exist |
| `INVOICE_NOT_FOUND` | 404 | Invoice doesn't exist |
| `SUBSCRIPTION_ERROR` | 400 | Subscription operation failed |
| `INSUFFICIENT_QUOTA` | 402 | Usage limit reached |
| `PAYMENT_FAILED` | 402 | Payment processing failed |
| `INVALID_PLAN_CHANGE` | 400 | Cannot switch to specified plan |
| `PRORATION_ERROR` | 500 | Proration calculation failed |

---

## Rate Limits

| Plan | Rate Limit | Billing API specific limits |
|------|-----------|---------------------------|
| Free | 10 req/s | 60 req/min for invoice downloads |
| Standard | 100 req/s | 300 req/min |
| Growth | 500 req/s | 1000 req/min |
| Enterprise | 5,000 req/s | Custom |

---

## Billing Company Information

| Field | Value |
|-------|-------|
| Company | Bel Consulting OÜ (trading as ApexMail) |
| Address | Sakala 7-2, Tallinn 10141, Estonia |
| Registry Code | 16192499 |
| VAT Number | EE102951727 |
| Billing Email | billing@apexmail.ee |
| Bank | Swedbank AS (BIC: HABAEE2X) |
