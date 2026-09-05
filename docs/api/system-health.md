# System Health API

Internal high-availability (HA) monitoring endpoint for the ApexMail control plane. Provides a comprehensive view of system health, including queue depths, worker status, MTA node states, and active alerts.

> **Note:** This is an authenticated admin-only endpoint. It requires the `*` (wildcard) scope and is intended for control-plane operators and monitoring systems.

## Endpoint

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/admin/system/health` | Comprehensive system health check |

**Scope required:** `*` (admin)

---

## Get System Health

```http
GET /v1/admin/system/health
X-API-Key: am_live_xxxxxxxxxxxxx
```

### Response — `200 OK`

```json
{
  "queues": [
    {
      "name": "email_delivery",
      "depth": 1520,
      "processing": 45,
      "status": "warning"
    },
    {
      "name": "webhook_delivery",
      "depth": 89,
      "processing": 3,
      "status": "healthy"
    },
    {
      "name": "bounce_processing",
      "depth": 12,
      "processing": 1,
      "status": "healthy"
    }
  ],
  "workers": [
    {
      "name": "email_delivery-worker",
      "type": "email_delivery",
      "status": "running",
      "lastHeartbeat": "2025-07-15T14:30:00Z",
      "id": "worker_abc123"
    },
    {
      "name": "webhook_delivery-worker",
      "type": "webhook_delivery",
      "status": "idle",
      "lastHeartbeat": "2025-07-15T14:25:00Z",
      "id": "worker_def456"
    }
  ],
  "mtaNodes": [
    {
      "id": "mta_001",
      "ipAddress": "203.0.113.42",
      "poolId": "pool_standard",
      "status": "active",
      "warmupDay": 14,
      "dailyLimit": 50000,
      "dailySent": 32450,
      "isFullyWarmed": false
    },
    {
      "id": "mta_002",
      "ipAddress": "203.0.113.43",
      "poolId": "pool_standard",
      "status": "active",
      "warmupDay": null,
      "dailyLimit": 100000,
      "dailySent": 87500,
      "isFullyWarmed": true
    }
  ],
  "alerts": [
    {
      "id": "alert_001",
      "severity": "warning",
      "component": "email_delivery",
      "message": "Queue depth exceeds 1000 for email_delivery",
      "timestamp": "2025-07-15T14:29:00Z",
      "acknowledged": false
    }
  ]
}
```

### Response Fields

#### Queues

| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | Queue name (e.g., `email_delivery`, `webhook_delivery`, `bounce_processing`) |
| `depth` | `integer` | Number of pending jobs in the queue |
| `processing` | `integer` | Number of jobs currently being processed |
| `status` | `string` | Health status: `"healthy"` (depth ≤ 1000) or `"warning"` (depth > 1000) |

#### Workers

| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | Worker display name (`{queue}-worker`) |
| `type` | `string` | Queue type the worker is assigned to |
| `status` | `string` | Worker status: `"running"` (heartbeat within 5 min) or `"idle"` |
| `lastHeartbeat` | `string` | ISO 8601 timestamp of last worker heartbeat |
| `id` | `string` | Unique worker identifier |

#### MTA Nodes

| Field | Type | Description |
|-------|------|-------------|
| `id` | `string` | MTA node unique identifier |
| `ipAddress` | `string` | IP address of the MTA node |
| `poolId` | `string` | IP pool assignment |
| `status` | `string` | Node status (e.g., `"active"`, `"warming"`, `"suspended"`) |
| `warmupDay` | `integer` | Current warmup day (null if fully warmed) |
| `dailyLimit` | `integer` | Maximum daily send limit for this IP |
| `dailySent` | `integer` | Emails sent today on this IP |
| `isFullyWarmed` | `boolean` | Whether the IP has completed warmup |

#### Alerts

| Field | Type | Description |
|-------|------|-------------|
| `id` | `string` | Alert identifier |
| `severity` | `string` | Severity level: `"critical"`, `"warning"`, `"info"` |
| `component` | `string` | System component generating the alert |
| `message` | `string` | Human-readable alert description |
| `timestamp` | `string` | ISO 8601 timestamp when the alert was raised |
| `acknowledged` | `boolean` | Whether the alert has been acknowledged |

---

## Health Status Interpretation

### Queue Status

| Depth | Status | Action |
|-------|--------|--------|
| 0–1000 | `healthy` | Normal operation |
| > 1000 | `warning` | Queue backing up — may need more workers |

### Worker Status

| Condition | Status | Meaning |
|-----------|--------|---------|
| Heartbeat within 5 min | `running` | Worker is actively processing |
| Heartbeat > 5 min ago | `idle` | Worker may have stalled or crashed |

### MTA Node Status

- **`active`** — Node is sending normally
- **`warming`** — IP is in warmup phase, daily limit increases gradually
- **`suspended`** — Node has been temporarily disabled (e.g., due to bounce rate thresholds)

---

## Error Codes

| HTTP Status | Code | Meaning |
|-------------|------|---------|
| `401` | `unauthorized` | Missing or invalid authentication |
| `403` | `forbidden` | Insufficient scope (requires `*`) |
| `500` | `internal_error` | Failed to query system tables |

---

## Related Endpoints

- [`GET /health/live`](endpoints/health.md) — Public liveness probe
- [`GET /health/ready`](endpoints/health.md) — Public readiness probe
- [`GET /health/deep`](endpoints/health.md) — Public deep health check
