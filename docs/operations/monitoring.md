# Monitoring and Observability Guide

> **ApexMail Internal Documentation**
> Last updated: 2026-02-23

This document describes the monitoring, observability, and alerting infrastructure for the ApexMail platform.

---

## Table of Contents

- [Prometheus Metrics](#prometheus-metrics)
- [Health Check Endpoints](#health-check-endpoints)
- [Alerting](#alerting)
- [Dashboards](#dashboards)
- [SLO Management](#slo-management)
- [Logging](#logging)

---

## Prometheus Metrics

ApexMail exports Prometheus-compatible metrics from the tracking service. Metrics are scraped by a Prometheus instance and used for alerting, dashboards, and capacity planning.

### Metrics Endpoint

| Parameter       | Value                                  |
|-----------------|----------------------------------------|
| Path            | `/metrics`                             |
| Port            | 9092 (tracking service)                |
| Format          | Prometheus text exposition format      |
| Authentication  | Internal network only (not exposed)    |

### Tracking Metrics

| Metric                              | Type      | Labels                          | Description                                      |
|-------------------------------------|-----------|----------------------------------|--------------------------------------------------|
| `tracking_opens_total`              | Counter   | `tenant_id`                     | Total open events recorded                        |
| `tracking_clicks_total`             | Counter   | `tenant_id`                     | Total click events recorded                       |
| `tracking_unsubscribes_total`       | Counter   | `tenant_id`                     | Total unsubscribe events                          |
| `tracking_request_duration_seconds` | Histogram | `method`, `path`, `status`      | HTTP request duration distribution                |
| `tracking_db_query_duration_seconds`| Histogram | `query_type`                    | Database query latency                            |
| `tracking_redis_operation_duration` | Histogram | `operation`                     | Redis operation latency                           |

### System Metrics (Rust)

| Metric                                | Type      | Labels     | Description                                    |
|---------------------------------------|-----------|------------|------------------------------------------------|
| `process_cpu_seconds_total`           | Counter   | —          | Total CPU time consumed by the process          |
| `process_resident_memory_bytes`       | Gauge     | —          | Resident set size (RSS) memory in bytes         |
| `process_open_fds`                    | Gauge     | —          | Number of open file descriptors                 |
| `process_start_time_seconds`          | Gauge     | —          | Unix timestamp of process start (uptime calc)   |

### Database Metrics

| Metric                                | Type      | Labels     | Description                                    |
|---------------------------------------|-----------|------------|------------------------------------------------|
| `db_pool_connections_total`           | Gauge     | `state`    | Total connections (active/idle)                 |
| `db_pool_connections_waiting`         | Gauge     | —          | Requests waiting for a connection               |

### Redis Metrics

| Metric                                | Type      | Labels     | Description                                    |
|---------------------------------------|-----------|------------|------------------------------------------------|
| `redis_connection_status`             | Gauge     | —          | Connection status (1 = connected, 0 = disconnected) |
| `redis_commands_total`                | Counter   | `command`  | Total Redis commands executed                   |

---

## Health Check Endpoints

ApexMail exposes health check endpoints for orchestrator probes, load balancer checks, and operational monitoring.

### Endpoint Summary

| Endpoint       | Method | Purpose                                   | Auth Required |
|----------------|--------|-------------------------------------------|---------------|
| `GET /health`  | GET    | Basic liveness check                      | No            |
| `GET /ready`   | GET    | Readiness probe (checks DB + Redis)       | No            |

### GET /health — Liveness Probe

Returns `200 OK` if the process is alive. Returns `503` during graceful shutdown.

```json
{ "status": "ok" }
```

### GET /ready — Readiness Probe

Performs dependency checks to determine if the service is ready to accept traffic:

| Check      | Description                                              | Failure Impact |
|------------|----------------------------------------------------------|----------------|
| Database   | Connection pool has available connections                 | 503 — not ready |
| Redis      | Redis connection is established and responsive           | 503 — not ready |

**Graceful shutdown behavior**: During shutdown, `/ready` immediately returns `503`. This signals the load balancer to stop routing traffic while in-flight requests drain.

```json
// Healthy
{ "status": "ready", "checks": { "database": "ok", "redis": "ok" } }

// Not ready
{ "status": "not_ready", "checks": { "database": "ok", "redis": "error" } }
```

---

## Alerting

ApexMail implements multi-channel alerting with escalation policies for different severity levels.

### Alert Channels

- **PagerDuty**: Critical alerts page on-call
- **Slack**: Warning/info alerts to `#alerts-warning` and `#alerts-info`

### Service Alerts

| Alert | Threshold | Severity | Action |
|-------|-----------|----------|--------|
| Tracking down | `/health` fails for 1 min | Critical | Page on-call |
| High error rate | > 1% 5xx responses | Warning | Investigate |
| High latency | P99 > 500ms for 5 min | Warning | Investigate |
| Database down | Connection fails | Critical | Page on-call |
| Redis down | Connection fails | Critical | Page on-call |

### Alert Configuration

Alert rules are defined in [deploy/alerting-rules.yml](../../deploy/alerting-rules.yml).

---

## Dashboards

### Dashboard Infrastructure

| Component       | Technology     | Description                                    |
|-----------------|----------------|------------------------------------------------|
| Visualization   | Grafana        | Dashboard rendering and exploration            |
| Data source     | Prometheus     | Time-series metrics                            |
| Real-time data  | Redis counters | Live counters for dashboard display            |

### Available Dashboards

| Dashboard         | Panels | Description                                              |
|-------------------|--------|----------------------------------------------------------|
| Tracking Overview | 8      | Request rate, latency, error rate, cache hit rate        |
| System Resources  | 6      | CPU, memory, open file descriptors, uptime               |
| Database          | 6      | Connection pool, query latency, active queries           |
| Redis             | 4      | Memory, connection status, command rate                  |

### Prometheus Scrape Configuration

```yaml
scrape_configs:
  - job_name: 'apexmail-tracking'
    static_configs:
      - targets: ['tracking:9092']
    scrape_interval: 15s
```

---

## SLO Management

See [slo-management.md](./slo-management.md) for detailed SLO definitions and error budget tracking.

### Core SLOs

| SLO                     | Target    | Window   |
|-------------------------|-----------|----------|
| Tracking Availability   | 99.95%    | 30 days  |
| Tracking Latency (P99)  | < 100ms   | 30 days  |

---

## Logging

ApexMail uses structured JSON logging for consistent parsing and querying.

### Log Format

The tracking service emits JSON logs (configurable via `RUST_LOG`):

```json
{
  "timestamp": "2026-02-23T14:30:00.123Z",
  "level": "INFO",
  "target": "tracking_service::routes::pixel",
  "message": "Open event recorded",
  "tracking_id": "abc123",
  "tenant_id": "tenant_xyz",
  "ip": "1.2.3.4",
  "user_agent": "Mozilla/5.0..."
}
```

### Log Levels

| Level   | Usage                                                                 |
|---------|-----------------------------------------------------------------------|
| `error` | Unrecoverable failures, unhandled exceptions                          |
| `warn`  | Degraded operation, slow requests, retryable failures                 |
| `info`  | Normal operations — request completion, events recorded               |
| `debug` | Detailed diagnostic information                                       |
| `trace` | Extremely verbose — individual function calls                         |

### Configuration

Set log level via environment variable:

```bash
RUST_LOG=info                           # Production default
RUST_LOG=tracking_service=debug         # Debug specific module
RUST_LOG=debug                           # Debug all
```

### Log Aggregation

Logs are collected via Docker's JSON log driver and can be viewed with:

```bash
docker compose logs -f tracking
docker compose logs --tail=100 tracking
```

For persistent log storage, configure Docker to forward to a log aggregator (e.g., Loki, Elasticsearch).
