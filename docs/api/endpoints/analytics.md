# Analytics API Endpoints

> **Base path:** `/v1/analytics`
> **Required scope:** `analytics:read`
> **Rate limit:** 60 requests/minute per API key

Analytics responses are cached to ensure fast, consistent performance. Concurrent identical queries are coalesced into a single computation, and results are cached for subsequent requests within the TTL window (default 60 s for dashboards, 300 s for exports).

---

## Authentication

Include your API key in the `Authorization` header:

```
X-API-Key: ak_live_...
```

---

## Common Query Parameters

| Parameter    | Type   | Required | Description |
|-------------|--------|----------|-------------|
| `start_date` | string | Yes      | ISO 8601 date (`2026-01-01` or `2026-01-01T00:00:00Z`) |
| `end_date`   | string | Yes      | ISO 8601 date, must be after `start_date` |

Maximum date range is **90 days**. Dates are evaluated in the organization's configured timezone.

---

## Common Error Codes

| HTTP Status | Code | Description |
|------------|------|-------------|
| 400 | `INVALID_DATE_RANGE` | `start_date` is after `end_date`, or range exceeds 90 days |
| 400 | `MISSING_PARAMETER` | A required query parameter is missing |
| 401 | `UNAUTHORIZED` | API key is missing or invalid |
| 403 | `INSUFFICIENT_SCOPE` | API key does not have the `analytics:read` scope |
| 404 | `NOT_FOUND` | Referenced resource (campaign, domain) does not exist |
| 429 | `RATE_LIMIT_EXCEEDED` | Rate limit exceeded; retry after `Retry-After` header value |
| 500 | `INTERNAL_ERROR` | Server-side error; request can be safely retried |

---

## Endpoints

### GET `/v1/analytics/overview`

Returns a high-level dashboard overview including totals for sends, deliveries, opens, clicks, bounces, complaints, and unsubscribes across the date range.

#### Query Parameters

| Parameter    | Type   | Required | Description |
|-------------|--------|----------|-------------|
| `start_date` | string | Yes      | Start of reporting window |
| `end_date`   | string | Yes      | End of reporting window |

#### Example Request

```bash
curl -X GET "https://api.apexmail.ee/v1/analytics/overview?start_date=2026-01-01&end_date=2026-01-31" \
  -H "X-API-Key: ak_live_xxxxxxxxxxxx"
```

#### Example Response

```json
{
  "data": {
    "period": {
      "start": "2026-01-01T00:00:00Z",
      "end": "2026-01-31T23:59:59Z"
    },
    "totals": {
      "sent": 1284350,
      "delivered": 1258903,
      "opens": 384210,
      "unique_opens": 256140,
      "clicks": 89430,
      "unique_clicks": 67215,
      "bounces": 25447,
      "hard_bounces": 8120,
      "soft_bounces": 17327,
      "complaints": 412,
      "unsubscribes": 3891
    },
    "rates": {
      "delivery_rate": 0.9802,
      "open_rate": 0.3053,
      "click_rate": 0.0711,
      "click_to_open_rate": 0.2325,
      "bounce_rate": 0.0198,
      "complaint_rate": 0.0003,
      "unsubscribe_rate": 0.0031
    },
    "comparison": {
      "vs_previous_period": {
        "sent": 0.0512,
        "delivery_rate": 0.003,
        "open_rate": -0.012,
        "click_rate": 0.008
      }
    }
  },
  "meta": {
    "cached": true,
    "cache_ttl": 60,
    "generated_at": "2026-01-31T14:22:10Z"
  }
}
```

---

### GET `/v1/analytics/timeseries`

Returns time-bucketed metric data suitable for charting. Supports multiple interval granularities.

#### Query Parameters

| Parameter  | Type   | Required | Description |
|-----------|--------|----------|-------------|
| `start_date` | string | Yes | Start of reporting window |
| `end_date`   | string | Yes | End of reporting window |
| `interval`   | string | Yes | Bucket size: `hour`, `day`, `week`, `month` |
| `metric`     | string | Yes | Metric to return: `sent`, `delivered`, `opens`, `unique_opens`, `clicks`, `unique_clicks`, `bounces`, `complaints`, `unsubscribes` |

#### Example Request

```bash
curl -X GET "https://api.apexmail.ee/v1/analytics/timeseries?start_date=2026-01-01&end_date=2026-01-07&interval=day&metric=delivered" \
  -H "X-API-Key: ak_live_xxxxxxxxxxxx"
```

#### Example Response

```json
{
  "data": {
    "metric": "delivered",
    "interval": "day",
    "period": {
      "start": "2026-01-01T00:00:00Z",
      "end": "2026-01-07T23:59:59Z"
    },
    "points": [
      { "timestamp": "2026-01-01T00:00:00Z", "value": 42130 },
      { "timestamp": "2026-01-02T00:00:00Z", "value": 38945 },
      { "timestamp": "2026-01-03T00:00:00Z", "value": 41200 },
      { "timestamp": "2026-01-04T00:00:00Z", "value": 29875 },
      { "timestamp": "2026-01-05T00:00:00Z", "value": 27430 },
      { "timestamp": "2026-01-06T00:00:00Z", "value": 40120 },
      { "timestamp": "2026-01-07T00:00:00Z", "value": 43010 }
    ],
    "summary": {
      "total": 262710,
      "average": 37530,
      "min": 27430,
      "max": 43010
    }
  },
  "meta": {
    "cached": true,
    "cache_ttl": 60,
    "generated_at": "2026-01-08T09:15:00Z"
  }
}
```

---

### GET `/v1/analytics/campaigns`

Returns per-campaign performance data with sorting and optional filtering to a single campaign.

#### Query Parameters

| Parameter     | Type   | Required | Description |
|--------------|--------|----------|-------------|
| `start_date`  | string | Yes      | Start of reporting window |
| `end_date`    | string | Yes      | End of reporting window |
| `campaign_id` | string | No       | Filter to a specific campaign |
| `sort_by`     | string | No       | Sort field: `sent`, `open_rate`, `click_rate`, `bounce_rate`, `created_at` (default: `sent`) |

#### Example Request

```bash
curl -X GET "https://api.apexmail.ee/v1/analytics/campaigns?start_date=2026-01-01&end_date=2026-01-31&sort_by=open_rate" \
  -H "X-API-Key: ak_live_xxxxxxxxxxxx"
```

#### Example Response

```json
{
  "data": [
    {
      "campaign_id": "cmp_8f3a1b2c",
      "name": "January Product Update",
      "sent_at": "2026-01-15T10:00:00Z",
      "totals": {
        "sent": 52400,
        "delivered": 51870,
        "opens": 21250,
        "unique_opens": 17800,
        "clicks": 6420,
        "unique_clicks": 5130,
        "bounces": 530,
        "complaints": 12,
        "unsubscribes": 85
      },
      "rates": {
        "delivery_rate": 0.9899,
        "open_rate": 0.4053,
        "click_rate": 0.1225,
        "click_to_open_rate": 0.3021,
        "bounce_rate": 0.0101,
        "complaint_rate": 0.0002
      }
    }
  ],
  "pagination": {
    "total": 18,
    "page": 1,
    "per_page": 25
  },
  "meta": {
    "cached": true,
    "cache_ttl": 60,
    "generated_at": "2026-02-01T08:30:00Z"
  }
}
```

---

### GET `/v1/analytics/domains`

Returns performance metrics broken down by sending domain. Useful for monitoring domain reputation.

#### Query Parameters

| Parameter   | Type   | Required | Description |
|------------|--------|----------|-------------|
| `start_date` | string | Yes | Start of reporting window |
| `end_date`   | string | Yes | End of reporting window |
| `domain_id`  | string | No  | Filter to a specific domain |

#### Example Request

```bash
curl -X GET "https://api.apexmail.ee/v1/analytics/domains?start_date=2026-01-01&end_date=2026-01-31" \
  -H "X-API-Key: ak_live_xxxxxxxxxxxx"
```

#### Example Response

```json
{
  "data": [
    {
      "domain_id": "dom_4e9c2a1f",
      "domain": "updates.example.com",
      "totals": {
        "sent": 645000,
        "delivered": 637200,
        "bounces": 7800,
        "complaints": 185
      },
      "rates": {
        "delivery_rate": 0.9879,
        "bounce_rate": 0.0121,
        "complaint_rate": 0.0003
      },
      "reputation": {
        "score": 92,
        "trend": "stable"
      }
    },
    {
      "domain_id": "dom_7b3d5e8a",
      "domain": "promo.example.com",
      "totals": {
        "sent": 639350,
        "delivered": 621703,
        "bounces": 17647,
        "complaints": 227
      },
      "rates": {
        "delivery_rate": 0.9724,
        "bounce_rate": 0.0276,
        "complaint_rate": 0.0004
      },
      "reputation": {
        "score": 85,
        "trend": "declining"
      }
    }
  ],
  "meta": {
    "cached": true,
    "cache_ttl": 60,
    "generated_at": "2026-02-01T08:35:00Z"
  }
}
```

---

### GET `/v1/analytics/engagement`

Returns detailed engagement metrics such as open/click heatmaps, device breakdowns, and link-level performance.

#### Query Parameters

| Parameter  | Type   | Required | Description |
|-----------|--------|----------|-------------|
| `start_date` | string | Yes | Start of reporting window |
| `end_date`   | string | Yes | End of reporting window |
| `metric`     | string | No  | Focus metric: `opens`, `clicks`, `devices`, `links`, `geo` (default: `opens`) |

#### Example Request

```bash
curl -X GET "https://api.apexmail.ee/v1/analytics/engagement?start_date=2026-01-01&end_date=2026-01-31&metric=clicks" \
  -H "X-API-Key: ak_live_xxxxxxxxxxxx"
```

#### Example Response

```json
{
  "data": {
    "metric": "clicks",
    "period": {
      "start": "2026-01-01T00:00:00Z",
      "end": "2026-01-31T23:59:59Z"
    },
    "summary": {
      "total_clicks": 89430,
      "unique_clicks": 67215,
      "click_to_open_rate": 0.2325
    },
    "by_hour": [
      { "hour": 0, "clicks": 1210 },
      { "hour": 9, "clicks": 12480 },
      { "hour": 14, "clicks": 9870 }
    ],
    "by_device": {
      "mobile": 0.58,
      "desktop": 0.34,
      "tablet": 0.06,
      "other": 0.02
    },
    "top_links": [
      {
        "url": "https://example.com/product",
        "clicks": 18340,
        "unique_clicks": 14200,
        "share": 0.2051
      },
      {
        "url": "https://example.com/pricing",
        "clicks": 12150,
        "unique_clicks": 10430,
        "share": 0.1359
      }
    ]
  },
  "meta": {
    "cached": true,
    "cache_ttl": 60,
    "generated_at": "2026-02-01T08:40:00Z"
  }
}
```

---

### GET `/v1/analytics/providers`

Returns delivery and engagement metrics broken down by receiving ISP / mailbox provider.

#### Query Parameters

| Parameter    | Type   | Required | Description |
|-------------|--------|----------|-------------|
| `start_date` | string | Yes | Start of reporting window |
| `end_date`   | string | Yes | End of reporting window |

#### Example Request

```bash
curl -X GET "https://api.apexmail.ee/v1/analytics/providers?start_date=2026-01-01&end_date=2026-01-31" \
  -H "X-API-Key: ak_live_xxxxxxxxxxxx"
```

#### Example Response

```json
{
  "data": [
    {
      "provider": "Gmail",
      "totals": {
        "sent": 512000,
        "delivered": 504320,
        "opens": 168400,
        "clicks": 38200,
        "bounces": 7680,
        "complaints": 102
      },
      "rates": {
        "delivery_rate": 0.9850,
        "open_rate": 0.3340,
        "click_rate": 0.0758,
        "bounce_rate": 0.0150,
        "complaint_rate": 0.0002
      },
      "inbox_placement": 0.965
    },
    {
      "provider": "Microsoft (Outlook/Hotmail)",
      "totals": {
        "sent": 320000,
        "delivered": 313600,
        "opens": 87800,
        "clicks": 21500,
        "bounces": 6400,
        "complaints": 128
      },
      "rates": {
        "delivery_rate": 0.9800,
        "open_rate": 0.2800,
        "click_rate": 0.0686,
        "bounce_rate": 0.0200,
        "complaint_rate": 0.0004
      },
      "inbox_placement": 0.938
    },
    {
      "provider": "Yahoo/AOL",
      "totals": {
        "sent": 185000,
        "delivered": 181300,
        "opens": 47140,
        "clicks": 11100,
        "bounces": 3700,
        "complaints": 74
      },
      "rates": {
        "delivery_rate": 0.9800,
        "open_rate": 0.2600,
        "click_rate": 0.0613,
        "bounce_rate": 0.0200,
        "complaint_rate": 0.0004
      },
      "inbox_placement": 0.941
    }
  ],
  "meta": {
    "cached": true,
    "cache_ttl": 60,
    "generated_at": "2026-02-01T08:45:00Z"
  }
}
```

---

### GET `/v1/analytics/deliverability`

Returns aggregate deliverability statistics including inbox placement estimates, authentication pass rates, and reputation indicators.

#### Query Parameters

| Parameter    | Type   | Required | Description |
|-------------|--------|----------|-------------|
| `start_date` | string | Yes | Start of reporting window |
| `end_date`   | string | Yes | End of reporting window |

#### Example Request

```bash
curl -X GET "https://api.apexmail.ee/v1/analytics/deliverability?start_date=2026-01-01&end_date=2026-01-31" \
  -H "X-API-Key: ak_live_xxxxxxxxxxxx"
```

#### Example Response

```json
{
  "data": {
    "period": {
      "start": "2026-01-01T00:00:00Z",
      "end": "2026-01-31T23:59:59Z"
    },
    "deliverability": {
      "delivery_rate": 0.9802,
      "estimated_inbox_rate": 0.952,
      "estimated_spam_rate": 0.028
    },
    "authentication": {
      "spf_pass_rate": 0.998,
      "dkim_pass_rate": 0.997,
      "dmarc_pass_rate": 0.995
    },
    "reputation": {
      "overall_score": 89,
      "trend": "stable",
      "blocklist_status": "clean",
      "feedback_loops_active": 4
    },
    "alerts": [
      {
        "severity": "warning",
        "message": "Bounce rate for promo.example.com exceeds 2.5% threshold",
        "domain": "promo.example.com",
        "value": 0.0276
      }
    ]
  },
  "meta": {
    "cached": true,
    "cache_ttl": 60,
    "generated_at": "2026-02-01T08:50:00Z"
  }
}
```

---

### GET `/v1/analytics/bounce-analysis`

Returns a detailed breakdown of bounce events by category, type, ISP, and SMTP response code.

#### Query Parameters

| Parameter    | Type   | Required | Description |
|-------------|--------|----------|-------------|
| `start_date` | string | Yes | Start of reporting window |
| `end_date`   | string | Yes | End of reporting window |

#### Example Request

```bash
curl -X GET "https://api.apexmail.ee/v1/analytics/bounce-analysis?start_date=2026-01-01&end_date=2026-01-31" \
  -H "X-API-Key: ak_live_xxxxxxxxxxxx"
```

#### Example Response

```json
{
  "data": {
    "period": {
      "start": "2026-01-01T00:00:00Z",
      "end": "2026-01-31T23:59:59Z"
    },
    "totals": {
      "total_bounces": 25447,
      "hard_bounces": 8120,
      "soft_bounces": 17327,
      "bounce_rate": 0.0198
    },
    "by_category": {
      "invalid_recipient": 6540,
      "mailbox_full": 8920,
      "content_rejected": 2310,
      "dns_failure": 1450,
      "policy_related": 3120,
      "protocol_error": 890,
      "other": 2217
    },
    "by_smtp_code": [
      { "code": "550", "description": "Mailbox not found", "count": 6120 },
      { "code": "552", "description": "Mailbox full", "count": 8920 },
      { "code": "554", "description": "Message rejected", "count": 4310 },
      { "code": "421", "description": "Service unavailable (temp)", "count": 3850 },
      { "code": "450", "description": "Mailbox busy (temp)", "count": 2247 }
    ],
    "by_provider": [
      { "provider": "Gmail", "bounces": 7680, "hard": 2450, "soft": 5230 },
      { "provider": "Microsoft", "bounces": 6400, "hard": 2100, "soft": 4300 },
      { "provider": "Yahoo/AOL", "bounces": 3700, "hard": 1200, "soft": 2500 }
    ]
  },
  "meta": {
    "cached": true,
    "cache_ttl": 60,
    "generated_at": "2026-02-01T08:55:00Z"
  }
}
```

---

### GET `/v1/analytics/export`

Exports analytics data as JSON or CSV. Large exports are processed asynchronously; the response includes a download URL.

#### Query Parameters

| Parameter     | Type   | Required | Description |
|--------------|--------|----------|-------------|
| `start_date`  | string | Yes      | Start of reporting window |
| `end_date`    | string | Yes      | End of reporting window |
| `format`      | string | Yes      | Export format: `json` or `csv` |
| `report_type` | string | Yes      | Report type: `summary`, `campaigns`, `domains` |

#### Example Request

```bash
curl -X GET "https://api.apexmail.ee/v1/analytics/export?start_date=2026-01-01&end_date=2026-01-31&format=csv&report_type=campaigns" \
  -H "X-API-Key: ak_live_xxxxxxxxxxxx"
```

#### Example Response (synchronous — small dataset)

For small exports the response body is the file content directly, with the appropriate `Content-Type` header (`text/csv` or `application/json`).

#### Example Response (asynchronous — large dataset)

```json
{
  "data": {
    "export_id": "exp_9a2b3c4d",
    "status": "processing",
    "format": "csv",
    "report_type": "campaigns",
    "period": {
      "start": "2026-01-01T00:00:00Z",
      "end": "2026-01-31T23:59:59Z"
    },
    "estimated_completion": "2026-02-01T09:02:00Z",
    "download_url": null
  }
}
```

Poll `GET /v1/analytics/export/:export_id` until `status` becomes `completed` and `download_url` is populated. Download URLs expire after **24 hours**.

---

## Caching Behaviour

| Endpoint | Cache TTL | Notes |
|----------|-----------|-------|
| `/overview` | 60 s | Coalesced via singleflight |
| `/timeseries` | 60 s | Cache key includes `interval` + `metric` |
| `/campaigns` | 60 s | Invalidated on new send completion |
| `/domains` | 60 s | Invalidated on domain config change |
| `/engagement` | 60 s | Cache key includes `metric` |
| `/providers` | 60 s | Coalesced via singleflight |
| `/deliverability` | 60 s | Coalesced via singleflight |
| `/bounce-analysis` | 60 s | Coalesced via singleflight |
| `/export` | 300 s | Download URL cached separately |

Responses include a `meta.cached` boolean and `meta.cache_ttl` value. To force a fresh query, pass the `Cache-Control: no-cache` request header (note: this is rate-limited to prevent abuse).
