# Monitoring and Observability Guide

> **ApexMail Internal Documentation**
> Last updated: 2026-02-09

This document describes the monitoring, observability, and alerting infrastructure for the ApexMail platform. It covers Prometheus metrics, distributed tracing, health checks, alerting rules, dashboards, SLO management, and structured logging.

---

## Table of Contents

- [Prometheus Metrics](#prometheus-metrics)
- [OpenTelemetry Tracing](#opentelemetry-tracing)
- [Health Check Endpoints](#health-check-endpoints)
- [Worker Heartbeat](#worker-heartbeat)
- [Alerting](#alerting)
- [Dashboards](#dashboards)
- [SLO Management](#slo-management)
- [Logging](#logging)

---

## Prometheus Metrics

ApexMail exports Prometheus-compatible metrics from all services. Metrics are scraped by a Prometheus instance and used for alerting, dashboards, and capacity planning.

### Metrics Endpoint

| Parameter       | Value                                  |
|-----------------|----------------------------------------|
| Path            | `/metrics`                             |
| Port            | 9092 (tracking app)                    |
| Format          | Prometheus text exposition format      |
| Authentication  | Internal network only (not exposed)    |

### Email Metrics

| Metric                              | Type      | Labels                          | Description                                      |
|-------------------------------------|-----------|----------------------------------|--------------------------------------------------|
| `apexmail_emails_sent_total`        | Counter   | `tenant_id`, `domain`, `status` | Total emails sent                                 |
| `apexmail_emails_bounced_total`     | Counter   | `tenant_id`, `bounce_type`      | Total bounced emails (hard/soft)                  |
| `apexmail_emails_dropped_total`     | Counter   | `tenant_id`, `reason`           | Total dropped emails (suppressed, rate-limited)   |
| `apexmail_email_queue_size`         | Gauge     | `queue_name`                    | Current email send queue depth                    |
| `apexmail_email_active_jobs`        | Gauge     | `worker_id`                     | Currently active email send jobs                  |
| `apexmail_email_send_duration_seconds` | Histogram | `tenant_id`, `provider`      | Email send duration distribution                  |

### Webhook Metrics

| Metric                                 | Type      | Labels                            | Description                                      |
|----------------------------------------|-----------|-----------------------------------|--------------------------------------------------|
| `apexmail_webhooks_delivered_total`    | Counter   | `tenant_id`, `event_type`, `status` | Total webhook deliveries (success/failure)       |
| `apexmail_webhook_queue_size`          | Gauge     | `queue_name`                      | Current webhook delivery queue depth              |
| `apexmail_webhook_active_jobs`         | Gauge     | `worker_id`                       | Currently active webhook delivery jobs            |
| `apexmail_webhook_delivery_duration_seconds` | Histogram | `tenant_id`, `status`       | Webhook delivery duration distribution            |

### Analytics Metrics

| Metric                                         | Type      | Labels           | Description                                  |
|------------------------------------------------|-----------|------------------|----------------------------------------------|
| `apexmail_analytics_events_processed_total`    | Counter   | `event_type`     | Total analytics events processed              |
| `apexmail_analytics_buffer_size`               | Gauge     | `buffer_name`    | Current analytics event buffer depth          |
| `apexmail_analytics_active_jobs`               | Gauge     | `worker_id`      | Currently active analytics processing jobs    |

### System Metrics

| Metric                                | Type      | Labels     | Description                                    |
|---------------------------------------|-----------|------------|------------------------------------------------|
| `process_cpu_seconds_total`           | Counter   | —          | Total CPU time consumed by the process          |
| `process_resident_memory_bytes`       | Gauge     | —          | Resident set size (RSS) memory in bytes         |
| `nodejs_heap_size_total_bytes`        | Gauge     | —          | V8 total heap size                              |
| `nodejs_heap_size_used_bytes`         | Gauge     | —          | V8 used heap size                               |
| `process_start_time_seconds`          | Gauge     | —          | Unix timestamp of process start (uptime calc)   |

### Database Metrics

| Metric                                | Type      | Labels     | Description                                    |
|---------------------------------------|-----------|------------|------------------------------------------------|
| `apexmail_db_pool_total_connections`  | Gauge     | `pool`     | Total connections in the database pool          |
| `apexmail_db_pool_idle_connections`   | Gauge     | `pool`     | Idle connections in the database pool           |
| `apexmail_db_pool_waiting_requests`   | Gauge     | `pool`     | Requests waiting for a database connection      |

### Redis Metrics

| Metric                                | Type      | Labels     | Description                                    |
|---------------------------------------|-----------|------------|------------------------------------------------|
| `apexmail_redis_connection_status`    | Gauge     | `instance` | Redis connection status (1 = connected, 0 = disconnected) |

### SQL Injection Prevention

Metric label values derived from user input (e.g., tenant IDs, domain names) are sanitized before being set on Prometheus metrics. This prevents label cardinality explosion and injection of arbitrary label values that could be used to corrupt metric data or exploit downstream systems (Grafana, alerting rules).

Sanitization rules:
- Label values are restricted to alphanumeric characters, hyphens, dots, and underscores.
- Values exceeding 128 characters are truncated.
- Unknown or unexpected values are replaced with a sentinel (`__unknown__`).

---

## OpenTelemetry Tracing

ApexMail supports distributed tracing via OpenTelemetry (OTel) for end-to-end request visibility across services.

### Supported Backends

| Backend            | Protocol                | Description                          |
|--------------------|-------------------------|--------------------------------------|
| Jaeger             | Thrift over HTTP/gRPC   | Distributed tracing backend          |
| Zipkin             | Zipkin v2 JSON          | Alternative tracing backend          |
| W3C Trace Context  | HTTP headers            | Cross-service trace propagation      |

### Trace Propagation

Trace context is propagated across service boundaries using **W3C Trace Context** headers:

- `traceparent`: Contains the trace ID, parent span ID, and trace flags.
- `tracestate`: Vendor-specific trace metadata.

All outbound HTTP requests, Redis commands, and database queries automatically propagate trace context.

### Structured Logging with Trace Correlation

Log entries include trace and span IDs when a trace context is active:

```json
{
  "level": "info",
  "message": "Email sent successfully",
  "traceId": "4bf92f3577b34da6a3ce929d0e0e4736",
  "spanId": "00f067aa0ba902b7",
  "tenantId": "tenant_abc123",
  "messageId": "msg_xyz789",
  "timestamp": "2026-02-09T14:30:00.000Z"
}
```

This enables direct correlation between log entries and trace spans in the tracing UI.

### Distributed Tracing Across Services

Traces span the full email lifecycle:

```
API (receive send request)
  └── Worker (queue processing)
       └── MTA (SMTP delivery)
            └── Tracking (open/click events)
                 └── Analytics (event aggregation)
```

Each service creates child spans under the parent trace, providing a complete timeline of email processing.

---

## Health Check Endpoints

ApexMail exposes multiple health check endpoints for orchestrator probes, load balancer checks, and operational monitoring.

### Endpoint Summary

| Endpoint             | Method | Purpose                                   | Auth Required      |
|----------------------|--------|-------------------------------------------|-------------------|
| `GET /health`        | GET    | Basic liveness check                      | No                |
| `GET /healthz`       | GET    | Kubernetes liveness probe                 | No                |
| `GET /readyz`        | GET    | Kubernetes readiness probe                | No                |
| `GET /health/detailed` | GET | Comprehensive system health               | Yes (production)  |
| `GET /version`       | GET    | Version and build information             | No                |

### GET /health

Returns a simple `200 OK` if the process is alive. No dependency checks are performed.

```json
{ "status": "ok" }
```

### GET /healthz — Kubernetes Liveness Probe

Identical to `/health`. Used as the Kubernetes liveness probe target. If this endpoint fails, Kubernetes will restart the pod.

```json
{ "status": "ok" }
```

### GET /readyz — Kubernetes Readiness Probe

Performs dependency checks to determine if the service is ready to accept traffic:

| Check          | Description                                              | Failure Impact             |
|----------------|----------------------------------------------------------|----------------------------|
| Database       | Connection pool has available connections                  | 503 — not ready            |
| Redis          | Redis connection is established and responsive            | 503 — not ready            |
| Pool           | Connection pool is not exhausted                          | 503 — not ready            |

**Graceful shutdown behavior**: During shutdown, `/readyz` immediately returns `503 Service Unavailable`. This signals the load balancer to stop routing traffic to this instance while in-flight requests drain.

```json
// Healthy
{ "status": "ready", "checks": { "database": "ok", "redis": "ok", "pool": "ok" } }

// Not ready
{ "status": "not_ready", "checks": { "database": "ok", "redis": "error", "pool": "ok" } }
```

### GET /health/detailed

Comprehensive health check that includes all dependency checks plus system resource metrics. **Requires authentication in production** to prevent information disclosure.

| Check            | Description                                                |
|------------------|------------------------------------------------------------|
| Database         | Connection status and query latency                        |
| Schema           | Database schema version matches expected version           |
| Memory           | Heap usage, RSS, and percentage of available memory        |
| Event loop       | Event loop lag (p50, p99)                                  |

```json
{
  "status": "healthy",
  "uptime": 864000,
  "checks": {
    "database": { "status": "ok", "latency_ms": 2 },
    "schema": { "status": "ok", "version": "2026.02.01" },
    "memory": {
      "status": "ok",
      "heap_used_mb": 256,
      "heap_total_mb": 512,
      "rss_mb": 384,
      "usage_percent": 50
    },
    "event_loop": {
      "status": "ok",
      "lag_p50_ms": 1.2,
      "lag_p99_ms": 8.5
    }
  }
}
```

### GET /version

Returns the application version and build metadata. **Internal fields are redacted in production** to prevent leaking deployment details.

```json
// Development
{
  "version": "2.14.0",
  "commit": "a1b2c3d4e5f6",
  "build_date": "2026-02-09T10:00:00Z",
  "node_version": "v22.0.0",
  "environment": "development"
}

// Production (redacted)
{
  "version": "2.14.0",
  "environment": "production"
}
```

---

## Worker Heartbeat

Background workers emit periodic heartbeats to signal liveness and report resource utilization.

### Heartbeat Configuration

| Parameter          | Value       |
|--------------------|-------------|
| Interval           | 30 seconds  |
| Transport          | Redis pub/sub |
| TTL                | 90 seconds (3× interval — missed = stale) |

### Heartbeat Payload

Each heartbeat contains:

```json
{
  "workerId": "worker-01",
  "timestamp": "2026-02-09T14:30:00.000Z",
  "memory": {
    "rss_mb": 384,
    "heap_used_mb": 256,
    "heap_total_mb": 512,
    "usage_percent": 75
  },
  "heap": {
    "total_heap_size": 536870912,
    "used_heap_size": 268435456,
    "heap_size_limit": 1073741824
  },
  "eventLoop": {
    "lag_ms": 4.2
  },
  "activeJobs": 12,
  "processedSinceLastHeartbeat": 847
}
```

### Alert Thresholds

| Metric                | Threshold    | Severity  | Action                                   |
|-----------------------|--------------|-----------|------------------------------------------|
| Memory usage          | > 80%        | Warning   | Alert ops team, consider scaling          |
| Event loop lag        | > 100ms      | Warning   | Alert ops team, investigate blocking I/O  |
| Missed heartbeats     | 3 consecutive| Critical  | Worker considered dead, jobs reassigned   |

---

## Alerting

ApexMail implements multi-channel alerting with escalation policies for different severity levels.

### Alert Channels

Alerts are dispatched to one or more channels based on severity and the configured escalation policy:

- **Webhook**: HTTP POST to a configured URL (Slack, PagerDuty, Opsgenie, custom).
- **Email**: Alert notifications sent to the ops team distribution list.
- **In-app**: Alerts surfaced in the control plane dashboard.

### Usage Alerts

Usage alerts notify tenants when they approach their plan's sending limits:

| Threshold | Alert Level | Cooldown   | Message                                       |
|-----------|-------------|------------|-----------------------------------------------|
| 50%       | Info        | 60 minutes | "You've used 50% of your monthly send quota"  |
| 80%       | Warning     | 60 minutes | "You've used 80% of your monthly send quota"  |
| 100%      | Critical    | 60 minutes | "You've reached your monthly send quota"       |

- **Cooldown**: After an alert fires, the same threshold will not re-trigger for 60 minutes. This prevents alert storms when usage fluctuates near a threshold.
- Tenants can configure which thresholds trigger notifications via the control plane.

### Complaint Rate Alert

| Metric           | Threshold | Severity  | Action                                       |
|------------------|-----------|-----------|----------------------------------------------|
| Complaint rate   | > 0.1%    | Critical  | Alert tenant + ops, sending may be throttled  |

The complaint rate is calculated as a rolling 7-day ratio of complaints to delivered emails. Sustained rates above 0.1% risk deliverability penalties from major ISPs (Gmail, Microsoft, Yahoo).

### Cost Circuit Breaker

The billing system monitors per-tenant cost margins and triggers protective alerts:

| Condition                    | Severity  | Action                                        |
|------------------------------|-----------|-----------------------------------------------|
| Margin < 20%                 | Warning   | Alert finance/ops team                        |
| Margin < 10%                 | Critical  | Throttle sending to prevent loss              |
| Day-over-day cost > +50%     | Warning   | Alert ops team, investigate cost spike         |

- **Throttling**: When the critical circuit breaker trips, the tenant's sending rate is reduced to a baseline level until the margin recovers or an operator manually overrides.
- **Cost spike detection**: A >50% increase in daily infrastructure cost (compute, bandwidth, storage) compared to the previous day triggers investigation.

---

## Dashboards

ApexMail provides pre-built dashboard templates for operational visibility.

### Dashboard Infrastructure

| Component       | Technology     | Description                                    |
|-----------------|----------------|------------------------------------------------|
| Visualization   | Grafana        | Dashboard rendering and exploration            |
| Data source     | Prometheus     | Time-series metrics                            |
| Real-time data  | Redis counters | Live counters for dashboard display            |

### Panel Types

The dashboard system supports **14 panel types**:

| Panel Type           | Description                                         |
|----------------------|-----------------------------------------------------|
| Time series          | Line/area chart over time                            |
| Stat                 | Single large value with optional sparkline           |
| Gauge                | Visual gauge with thresholds                         |
| Bar gauge            | Horizontal/vertical bar with thresholds              |
| Table                | Tabular data with sorting and filtering              |
| Heatmap              | 2D density visualization                             |
| Histogram            | Distribution bucketing                               |
| Pie chart            | Proportional breakdown                               |
| Alert list           | Active and recent alerts                             |
| Logs                 | Log stream with search                               |
| Node graph           | Service dependency visualization                     |
| Geomap               | Geographic data plotting                             |
| Text/Markdown        | Static text, documentation, annotations              |
| Status map           | Service/component status grid                        |

### Dashboard Templates

**5 pre-built dashboard templates** are available:

| Template              | Panels | Description                                              |
|-----------------------|--------|----------------------------------------------------------|
| Email Operations      | 12     | Send volume, bounce rates, queue depth, latency p50/p95  |
| Webhook Delivery      | 8      | Delivery success rate, queue depth, retry distribution   |
| System Resources      | 10     | CPU, memory, heap, event loop, connection pools          |
| Tenant Overview       | 14     | Per-tenant sending volume, quota usage, complaint rates  |
| Deliverability        | 10     | Bounce classification, complaint rates, reputation score |

### Real-Time Redis Counters

For low-latency dashboard display, key metrics are maintained as Redis counters:

- Counters are incremented atomically on each event (email sent, bounce, click, etc.).
- Counters use Redis `INCRBY` with TTL-based expiration for windowed aggregation.
- Dashboards poll counters directly for sub-second refresh rates.
- Counters are periodically reconciled with Prometheus for consistency.

---

## SLO Management

Service Level Objectives (SLOs) are managed by the **ops** application and define the reliability targets for ApexMail.

### Default SLOs

The platform ships with **5 default SLOs**:

| SLO                          | Target    | Window   | Description                                |
|------------------------------|-----------|----------|--------------------------------------------|
| API Availability             | 99.95%    | 30 days  | Percentage of successful API responses      |
| Email Delivery Latency (p99) | < 30s     | 30 days  | 99th percentile time from API call to SMTP delivery |
| Webhook Delivery Success     | 99.9%     | 30 days  | Percentage of webhooks delivered within retry window |
| Bounce Processing Latency    | < 60s     | 30 days  | Time from bounce receipt to suppression     |
| Control Plane Availability   | 99.9%     | 30 days  | Percentage of successful control plane requests |

### Multi-Window Burn-Rate Alerting

SLO alerts use a multi-window burn-rate approach to balance sensitivity with noise reduction:

| Alert Window | Burn Rate | Severity  | Description                                   |
|--------------|-----------|-----------|-----------------------------------------------|
| 5 min / 1 hr | 14.4×    | Critical  | Rapid error budget consumption — page on-call  |
| 30 min / 6 hr | 6×      | Warning   | Elevated error rate — investigate soon          |
| 6 hr / 3 day  | 1×      | Info      | Slow burn — review in next business day         |

**Burn rate** is the rate at which the error budget is being consumed relative to a uniform consumption rate over the SLO window. A burn rate of 1× means the budget will be exactly exhausted by the end of the window.

The multi-window approach requires both a short window (fast detection) and a long window (noise suppression) to fire simultaneously before triggering an alert.

### Error Budget Tracking

- **Error budget** = `1 - SLO target` expressed as a count of allowed failures within the SLO window.
- Example: An API availability SLO of 99.95% over 30 days allows ~21.6 minutes of downtime.
- Error budget remaining is displayed as a percentage in the ops dashboard.
- When the error budget is exhausted, new feature deployments are frozen until the budget recovers.

### Review Cadence

- **Weekly**: SLO status review in the engineering standup.
- **Monthly**: Formal SLO review with burn-rate trend analysis and error budget reconciliation.
- **Quarterly**: SLO target adjustment based on historical performance and business requirements.

---

## Logging

ApexMail uses structured JSON logging across all services for consistent parsing, indexing, and querying.

### Log Format

All log entries are emitted as single-line JSON objects:

```json
{
  "level": "info",
  "message": "Request completed",
  "timestamp": "2026-02-09T14:30:00.123Z",
  "requestId": "req_abc123def456",
  "tenantId": "tenant_xyz789",
  "method": "POST",
  "path": "/api/v1/messages",
  "statusCode": 202,
  "duration_ms": 45,
  "traceId": "4bf92f3577b34da6a3ce929d0e0e4736",
  "spanId": "00f067aa0ba902b7"
}
```

### Request ID Correlation

Every inbound HTTP request is assigned a unique request ID:

- The `X-Request-ID` header is checked first. If the client provides a request ID, it is used (after sanitization).
- If no `X-Request-ID` is present, a new UUID v4 is generated.
- The request ID is:
  - Included in every log entry produced during the request lifecycle.
  - Returned to the client in the `X-Request-ID` response header.
  - Propagated to downstream service calls.
  - Attached to background jobs spawned by the request.

This enables end-to-end tracing of a single request across all log sources.

### Slow Request Warnings

Requests exceeding a configurable duration threshold are logged at the `warn` level:

| Parameter          | Value       |
|--------------------|-------------|
| Threshold          | 3 seconds   |
| Log level          | `warn`      |
| Additional fields  | `slow: true`, `duration_ms` |

```json
{
  "level": "warn",
  "message": "Slow request detected",
  "slow": true,
  "requestId": "req_abc123def456",
  "method": "GET",
  "path": "/api/v1/analytics/overview",
  "duration_ms": 4521,
  "timestamp": "2026-02-09T14:30:04.521Z"
}
```

Slow request logs are used to identify performance regressions, expensive queries, and endpoints that need optimization.

### Production Safety

**Stack traces are never leaked in production responses.**

| Environment  | Error Response Body                    | Log Output                        |
|--------------|----------------------------------------|-----------------------------------|
| Development  | Full error message + stack trace       | Full stack trace in log entry     |
| Production   | Generic error message + request ID     | Full stack trace in log entry     |

- In production, API error responses contain only a generic message (e.g., `"Internal server error"`) and the `requestId` for support correlation.
- The full error details, including the stack trace, are logged server-side and can be retrieved using the request ID.
- This prevents information disclosure while maintaining full debuggability for the engineering team.

### Log Levels

| Level    | Usage                                                                 |
|----------|-----------------------------------------------------------------------|
| `error`  | Unrecoverable failures, unhandled exceptions, data integrity issues   |
| `warn`   | Degraded operation, slow requests, approaching limits, retryable failures |
| `info`   | Normal operations — request completion, job processing, state changes |
| `debug`  | Detailed diagnostic information — disabled in production by default   |
| `trace`  | Extremely verbose — individual function calls, wire-level data        |

Production log level is set to `info` by default. It can be dynamically adjusted to `debug` for a specific tenant or request path via the control plane without a restart.
