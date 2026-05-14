# Dedicated IPs API

The Dedicated IPs API provides full lifecycle management for dedicated sending IP addresses, including allocation, warmup, monitoring, and release.

> **Note**: Dedicated IPs are provisioned via Hetzner Cloud floating IPs. SES handles shared-pool sending only. This feature requires a plan with `dedicated_ip = true`.

## Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/dedicated-ips` | Allocate a new dedicated IP |
| GET | `/v1/dedicated-ips` | List dedicated IPs |
| DELETE | `/v1/dedicated-ips/:id` | Release a dedicated IP |
| POST | `/v1/dedicated-ips/:id/warmup` | Start IP warmup |

---

## Allocate IP

Allocate a new dedicated sending IP address.

### Request

```http
POST /v1/dedicated-ips
X-API-Key: {{api_key}}
Content-Type: application/json
```

### Request Body

```json
{
  "region": "eu-central"
}
```

### Parameters

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `region` | string | | Hetzner Cloud region (default: provider-configured) |

### Response (201)

```json
{
  "id": "dip_abc123",
  "ip_address": "203.0.113.42",
  "region": "eu-central",
  "status": "allocating",
  "warmup_day": 0,
  "daily_limit": 50,
  "daily_sent": 0,
  "is_fully_warmed": false,
  "created_at": "2024-01-15T10:30:00Z"
}
```

### IP Status Values

| Status | Description |
|--------|-------------|
| `allocating` | IP being provisioned in Hetzner Cloud |
| `active` | IP allocated and ready for sending |
| `warming` | IP in warmup phase (sending volume gradually increasing) |
| `matured` | Warmup complete, full sending capacity |
| `releasing` | IP being decommissioned |
| `released` | IP released back to pool |
| `failed` | Allocation or warmup failed |

---

## List Dedicated IPs

Retrieve all dedicated IPs for the tenant.

### Request

```http
GET /v1/dedicated-ips
X-API-Key: {{api_key}}
```

### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `status` | string | | Filter by status |
| `limit` | number | 20 | Results per page |
| `offset` | number | 0 | Pagination offset |

### Response

```json
{
  "data": [
    {
      "id": "dip_abc123",
      "ip_address": "203.0.113.42",
      "region": "eu-central",
      "status": "warming",
      "warmup_day": 3,
      "daily_limit": 500,
      "daily_sent": 234,
      "is_fully_warmed": false,
      "plan_included": true,
      "created_at": "2024-01-15T10:30:00Z"
    }
  ]
}
```

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique identifier |
| `ip_address` | string | The allocated IP address |
| `region` | string | Hetzner Cloud region |
| `status` | string | Current lifecycle status |
| `warmup_day` | number | Current day in warmup schedule (0 = not started) |
| `daily_limit` | number | Maximum sends allowed today |
| `daily_sent` | number | Sends sent today |
| `is_fully_warmed` | boolean | Whether warmup is complete |
| `plan_included` | boolean | Whether IP is included in plan (vs. additional charge) |
| `created_at` | string | Allocation timestamp |

---

## Release IP

Release a dedicated IP back to the pool.

### Request

```http
DELETE /v1/dedicated-ips/dip_abc123
X-API-Key: {{api_key}}
```

### Response (204)

No content.

---

## Start Warmup

Begin or resume the IP warmup process.

### Request

```http
POST /v1/dedicated-ips/dip_abc123/warmup
X-API-Key: {{api_key}}
```

### Response

```json
{
  "id": "dip_abc123",
  "ip_address": "203.0.113.42",
  "status": "warming",
  "warmup_day": 1,
  "daily_limit": 50,
  "daily_sent": 0,
  "warmup_started_at": "2024-01-15T10:30:00Z"
}
```

---

## Warmup Schedule

The warmup process gradually increases daily sending limits over a period of approximately 4 weeks:

| Week | Daily Limit | Cumulative |
|------|-------------|------------|
| 1 | 50 → 200 | ~875 |
| 2 | 500 → 2,000 | ~8,750 |
| 3 | 3,000 → 10,000 | ~45,000 |
| 4 | 15,000 → Full | Full capacity |

> **Note**: Actual warmup schedule is dynamically calculated based on domain reputation and sending history.

---

## Pricing

| Type | Monthly Cost |
|------|-------------|
| Plan-included IPs | $0 (included in plan) |
| Additional IPs | $30/month each |

---

## Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `PLAN_LIMIT_EXCEEDED` | 402 | Plan does not include dedicated IPs |
| `IP_NOT_FOUND` | 404 | IP doesn't exist |
| `ALLOCATION_FAILED` | 500 | Hetzner Cloud API error |
| `WARMUP_IN_PROGRESS` | 400 | Warmup already active |
| `IP_NOT_RELEASABLE` | 400 | IP currently in use, cannot release |
