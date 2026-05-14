# Inbox Placement API

Test and monitor how your emails are placed across major email providers (inbox vs. spam vs. bounced). The Inbox Placement API helps you measure deliverability rates, identify provider-specific issues, and track placement trends over time.

## Overview

The Inbox Placement system analyzes email delivery events across major providers and provides:

- **Placement summary** — overall inbox placement rate broken down by provider
- **Placement trends** — daily inbox/spam rates over time for tracking improvements or regressions
- **Provider classification** — automatic domain-to-provider mapping (Gmail, Outlook, Yahoo, iCloud, ProtonMail, etc.)
- **Actionable recommendations** — automated suggestions based on placement data

## How It Works

1. **Seed lists** — Configure a list of seed email addresses across major providers (e.g., Gmail, Outlook, Yahoo).
2. **Send test campaigns** — Send emails to your seed list through the regular send API.
3. **Analyze results** — Use the Inbox Placement API to retrieve placement summaries and trends.

Provider domains are automatically classified. Supported providers include:

| Provider | Domains |
|----------|---------|
| Gmail | `gmail.com`, `googlemail.com` |
| Outlook | `outlook.com`, `hotmail.com`, `live.com` |
| Yahoo | `yahoo.com`, `yahoo.co.uk`, `yahoo.fr`, etc. |
| iCloud | `icloud.com`, `me.com` |
| ProtonMail | `protonmail.com`, `proton.me` |
| Zoho | `zoho.com` |
| AOL | `aol.com` |
| Mail.com | `mail.com` |
| Other | All remaining domains |

## Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/v1/inbox-placement/providers` | Public | List supported providers and seed domain requirements |
| `POST` | `/v1/inbox-placement/tests` | Required | Create a new inbox placement test |
| `GET` | `/v1/inbox-placement/tests` | Required | List placement test history |
| `GET` | `/v1/inbox-placement/tests/:id` | Required | Get placement test details and results |
| `GET` | `/v1/inbox-placement/trends` | Required | Get placement trend data |

**Scope required (authenticated endpoints):** `analytics:read`

---

## List Providers

Public endpoint that returns the list of supported email providers and their seed domain requirements.

```http
GET /v1/inbox-placement/providers
```

### Response — `200 OK`

```json
{
  "providers": [
    {
      "name": "gmail",
      "domains": ["gmail.com"],
      "requiresSeed": true,
      "seedCount": 3
    },
    {
      "name": "outlook",
      "domains": ["outlook.com", "hotmail.com", "live.com"],
      "requiresSeed": true,
      "seedCount": 3
    },
    {
      "name": "yahoo",
      "domains": ["yahoo.com", "yahoo.co.uk"],
      "requiresSeed": true,
      "seedCount": 2
    },
    {
      "name": "icloud",
      "domains": ["icloud.com", "me.com"],
      "requiresSeed": true,
      "seedCount": 1
    },
    {
      "name": "protonmail",
      "domains": ["protonmail.com", "proton.me"],
      "requiresSeed": true,
      "seedCount": 1
    }
  ]
}
```

---

## Create Placement Test

Initiates a new inbox placement test campaign.

```http
POST /v1/inbox-placement/tests
Content-Type: application/json
X-API-Key: am_live_xxxxxxxxxxxxx
```

### Request Body

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | `string` | ✅ Yes | Test campaign name |
| `subject` | `string` | ✅ Yes | Email subject line |
| `content` | `object` | ✅ Yes | Email content (see below) |
| `content.html` | `string` | No | HTML body |
| `content.text` | `string` | No | Plain text body |
| `providers` | `string[]` | No | Target providers (default: all). Example: `["gmail", "outlook", "yahoo"]` |

At least one of `content.html` or `content.text` must be provided.

### Response — `201 Created`

```json
{
  "id": "ipt_abc123def456",
  "name": "Q3 Campaign Test",
  "status": "pending",
  "targetProviders": ["gmail", "outlook", "yahoo"],
  "seedCount": 8,
  "createdAt": "2025-07-15T10:00:00Z"
}
```

---

## List Tests

```http
GET /v1/inbox-placement/tests?page=1&perPage=20
X-API-Key: am_live_xxxxxxxxxxxxx
```

### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | `integer` | `1` | Page number |
| `perPage` | `integer` | `20` | Items per page (max 100) |

### Response — `200 OK`

```json
{
  "tests": [
    {
      "id": "ipt_abc123def456",
      "name": "Q3 Campaign Test",
      "status": "completed",
      "overallInboxRate": 0.92,
      "createdAt": "2025-07-15T10:00:00Z",
      "completedAt": "2025-07-15T10:15:00Z"
    }
  ],
  "total": 15,
  "page": 1,
  "perPage": 20
}
```

---

## Get Test Results

```http
GET /v1/inbox-placement/tests/ipt_abc123def456
X-API-Key: am_live_xxxxxxxxxxxxx
```

### Response — `200 OK`

```json
{
  "id": "ipt_abc123def456",
  "name": "Q3 Campaign Test",
  "status": "completed",
  "overallInboxRate": 0.92,
  "inboxCount": 92,
  "spamCount": 5,
  "bounceCount": 3,
  "byProvider": [
    {
      "provider": "gmail",
      "inbox": 45,
      "spam": 2,
      "bounced": 0,
      "inboxRate": 0.96
    },
    {
      "provider": "outlook",
      "inbox": 30,
      "spam": 2,
      "bounced": 1,
      "inboxRate": 0.91
    },
    {
      "provider": "yahoo",
      "inbox": 17,
      "spam": 1,
      "bounced": 2,
      "inboxRate": 0.85
    }
  ],
  "recommendations": [
    "Yahoo inbox rate (85%) is below the 90% threshold. Consider reviewing authentication (DKIM/SPF/DMARC) configuration for yahoo.com.",
    "2 providers have a bounce rate above 1%. Review list hygiene and remove invalid addresses."
  ],
  "createdAt": "2025-07-15T10:00:00Z",
  "completedAt": "2025-07-15T10:15:00Z"
}
```

### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `overallInboxRate` | `float` | Overall inbox placement rate (0.0–1.0) |
| `inboxCount` | `integer` | Total emails delivered to inbox |
| `spamCount` | `integer` | Total emails flagged as spam |
| `bounceCount` | `integer` | Total emails that bounced |
| `byProvider[].provider` | `string` | Provider name |
| `byProvider[].inbox` | `integer` | Inbox deliveries for this provider |
| `byProvider[].spam` | `integer` | Spam flaggings for this provider |
| `byProvider[].bounced` | `integer` | Bounces for this provider |
| `byProvider[].inboxRate` | `float` | Inbox rate for this provider (0.0–1.0) |
| `recommendations` | `string[]` | Actionable recommendations based on results |

---

## Get Placement Trends

```http
GET /v1/inbox-placement/trends?days=30
X-API-Key: am_live_xxxxxxxxxxxxx
```

### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `days` | `integer` | `30` | Number of days of trend data to return (max 90) |

### Response — `200 OK`

```json
{
  "trends": [
    {
      "date": "2025-07-15",
      "inboxRate": 0.95,
      "inboxCount": 95,
      "spamCount": 5
    },
    {
      "date": "2025-07-16",
      "inboxRate": 0.92,
      "inboxCount": 92,
      "spamCount": 8
    },
    {
      "date": "2025-07-17",
      "inboxRate": 0.89,
      "inboxCount": 89,
      "spamCount": 11
    }
  ]
}
```

### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `date` | `string` | ISO date string (`YYYY-MM-DD`) |
| `inboxRate` | `float` | Daily inbox placement rate (0.0–1.0) |
| `inboxCount` | `integer` | Daily inbox delivery count |
| `spamCount` | `integer` | Daily spam flagging count |

---

## Recommendation Rules

Recommendations are generated automatically based on the following thresholds:

| Condition | Recommendation |
|-----------|---------------|
| Provider inbox rate < 90% | Check authentication (DKIM/SPF/DMARC) for that provider |
| Bounce rate > 1% | Review list hygiene and remove invalid addresses |
| Spam rate > 5% | Review email content and sender reputation |
| Overall inbox rate < 95% | General deliverability review recommended |

---

## Interpreting Results

| Inbox Rate | Verdict |
|------------|---------|
| 95–100% | Excellent — good deliverability health |
| 90–94% | Good — minor improvements possible |
| 80–89% | Fair — review content and authentication |
| < 80% | Poor — significant deliverability issues |

---

## Error Codes

| HTTP Status | Code | Meaning |
|-------------|------|---------|
| `400` | `validation_error` | Invalid request parameters |
| `404` | `not_found` | Test not found |
| `429` | `rate_limit_exceeded` | Too many requests |

---

## Related Documentation

- [`Deliverability API`](endpoints/analytics.md) — broader analytics including deliverability metrics
- [`Inbox Placement Testing Guide`](../user-guide/inbox-placement-testing.md) — configuring seed addresses for placement testing
