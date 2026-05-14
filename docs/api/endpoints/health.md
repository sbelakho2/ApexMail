# Health Check API

Health check endpoints for monitoring API server availability and dependency health. These are **unauthenticated public endpoints** suitable for load balancer health checks and monitoring systems.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health/live` | Liveness probe — always returns 200 if server is running |
| `GET` | `/health/ready` | Readiness probe — checks database and Redis connectivity |
| `GET` | `/health/deep` | Deep health check — comprehensive check with response times |

---

## Liveness

```http
GET /health/live
```

Simplest health check. Returns immediately with a `200` status as long as the server process is running and accepting connections.

### Response — `200 OK`

```json
{
  "status": "ok"
}
```

> **Use case:** Load balancer health checks, container orchestration liveness probes (Kubernetes `livenessProbe`).

---

## Readiness

```http
GET /health/ready
```

Checks that the server can connect to its core dependencies:
- **PostgreSQL database** — executes `SELECT 1` with circuit breaker protection
- **Redis cache** — checks connectivity via the connection pool

If either dependency is unavailable, returns `503 Service Unavailable`.

### Response — `200 OK`

```json
{
  "status": "ok",
  "database": "healthy",
  "redis": "healthy"
}
```

### Response — `503 Service Unavailable`

```json
{
  "status": "degraded",
  "database": "unhealthy",
  "redis": "healthy"
}
```

> **Use case:** Kubernetes `readinessProbe`, load balancer health checks that should stop routing traffic when dependencies fail.
>
> **Circuit breaker:** The database check uses a circuit breaker to fail fast when the database is unavailable, preventing cascading connection timeouts.

---

## Deep Health Check

```http
GET /health/deep
```

Comprehensive health check that measures response times for each dependency check. Useful for diagnostics and performance monitoring.

### Response — `200 OK`

```json
{
  "status": "ok",
  "checks": {
    "database": {
      "status": "healthy",
      "responseTimeMs": 3
    },
    "redis": {
      "status": "healthy",
      "responseTimeMs": 1
    }
  },
  "uptime": 3600
}
```

| Field | Type | Description |
|-------|------|-------------|
| `checks.database.status` | `string` | `"healthy"` or `"unhealthy"` |
| `checks.database.responseTimeMs` | `integer` | Database query response time in milliseconds |
| `checks.redis.status` | `string` | `"healthy"` or `"unhealthy"` |
| `checks.redis.responseTimeMs` | `integer` | Redis ping response time in milliseconds |
| `uptime` | `integer` | Server uptime in seconds |

> **Use case:** Detailed monitoring dashboards, automated diagnostics, pre-deployment health gates.

---

## Internal HA System Health

In addition to the public health endpoints above, an authenticated **system health** endpoint is available for control-plane operators:

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/admin/system/health` | Comprehensive system health (requires `*` scope) |

This endpoint returns the status of queues, workers, MTA nodes, and system alerts. See [`system-health.md`](../system-health.md) for full documentation.

**Scope required:** `*` (admin)

---

## Error Codes

| HTTP Status | Code | Meaning |
|-------------|------|---------|
| `503` | `service_unavailable` | Dependency check failed |

Health endpoints do not rate-limit or require authentication.
