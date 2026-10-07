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

ApexMail services export Prometheus-compatible metrics on dedicated listener
ports; a Prometheus instance scrapes them with the job names defined in
[deploy/prometheus.yml](../../deploy/prometheus.yml). The series back
alerting, dashboards, and capacity planning.

### Metrics Endpoints

| Service             | Scrape job              | Port | Path       |
|---------------------|-------------------------|------|------------|
| API server          | `apexmail-api`          | 9090 | `/metrics` |
| Tracking service    | `apexmail-tracking`     | 9092 | `/metrics` |
| MTA                 | `apexmail-mta`          | 9090 | `/metrics` |
| Worker processors   | `apexmail-worker`       | 9093 | `/metrics` |
| Outbound MTA relay  | `apexmail-outbound-mta` | 8093 | `/metrics` |
| Observability       | `apexmail-observability`| 4400 | `/metrics` |

The listeners are on the internal network only (not publicly exposed).

### API Server Metrics (job `apexmail-api`)

| Metric                                   | Type      | Labels                              | Description                             |
|------------------------------------------|-----------|-------------------------------------|-----------------------------------------|
| `apexmail_http_requests_total`           | Counter   | `method`, `path_pattern`, `status`  | HTTP requests by matched route pattern  |
| `apexmail_http_request_duration_seconds` | Histogram | `method`, `path_pattern`, `status`  | HTTP request duration distribution      |
| `apexmail_http_requests_in_flight`       | Gauge     | `method`                            | Requests currently being served         |

`path_pattern` is the matched axum route pattern (e.g. `/v1/messages/:id`),
or the literal `unmatched` for 404s. The middleware emits no `endpoint`
label — queries must group by `path_pattern`.

### Tracking Metrics (job `apexmail-tracking`)

| Metric                                            | Type    | Labels | Description                              |
|---------------------------------------------------|---------|--------|------------------------------------------|
| `apexmail_tracking_clickhouse_events_total`       | Counter | —      | Open/click events written to ClickHouse  |
| `apexmail_tracking_clickhouse_failures_total`     | Counter | —      | ClickHouse write failures                |
| `apexmail_tracking_dedup_total`                   | Counter | —      | Duplicate events dropped                 |
| `apexmail_tracking_dead_letter_total`             | Counter | —      | Events dead-lettered                     |
| `apexmail_tracking_click_redirects_blocked_total` | Counter | —      | Blocked click redirects                  |
| `apexmail_tracking_open_recorder_dropped_total`   | Counter | —      | Dropped open recordings                  |

### System / Process Metrics

ApexMail's Rust services do **not** export `process_*` series. The deployed
`metrics-exporter-prometheus` (0.16.2) ships no process collector and no
service depends on `metrics-process`, so `process_cpu_seconds_total`,
`process_resident_memory_bytes`, `process_open_fds` and
`process_start_time_seconds` can never be scraped from a service job. Host and
process resource panels read node-exporter series under `job="node"` instead:

| Metric                                                           | Type    | Description                                        |
|------------------------------------------------------------------|---------|----------------------------------------------------|
| `node_cpu_seconds_total`                                         | Counter | Host CPU time by `mode` (`idle` for idle time)     |
| `node_memory_MemTotal_bytes` / `node_memory_MemAvailable_bytes`  | Gauge   | Host memory total / available                      |
| `node_filefd_allocated`                                          | Gauge   | Allocated file descriptors on the host             |
| `node_boot_time_seconds`                                         | Gauge   | Host boot time (`time() - value` = uptime)         |

### Redis Metrics (job `apexmail-observability`)

| Metric                            | Type    | Description                    |
|-----------------------------------|---------|--------------------------------|
| `redis_used_memory_bytes`         | Gauge   | Redis used memory              |
| `redis_maxmemory_bytes`           | Gauge   | Configured `maxmemory`         |
| `redis_memory_utilization_ratio`  | Gauge   | used / `maxmemory`             |
| `redis_evicted_keys_total`        | Counter | Keys evicted by maxmemory      |
| `redis_eviction_rate_per_minute`  | Gauge   | Eviction rate                  |
| `redis_info_poll_errors_total`    | Counter | Failed INFO polls              |

The separate `redis` job (redis-exporter) adds the exporter's standard
server-level `redis_*` series (memory, connected clients, command rate).

### Database Metrics (job `postgres`)

Database signals come from the postgres-exporter (`pg_*` series) and the
exporter's `pg_stat_*` views. The `apexmail-db` crate registers
`db_query_duration_seconds` in the `prometheus` crate's default registry,
which no service exposes on its `/metrics` endpoint today — do not panel on
that series until it is bridged to the exporter recorder.

---

## Health Check Endpoints

ApexMail exposes health check endpoints for orchestrator probes, load balancer checks, and operational monitoring.

### Endpoint Summary

| Endpoint           | Method | Purpose                                              | Auth Required |
|--------------------|--------|------------------------------------------------------|---------------|
| `GET /health`      | GET    | Liveness alias (same handler as `/health/live`)      | No            |
| `GET /health/live` | GET    | Liveness probe                                       | No            |
| `GET /health/ready`| GET    | Readiness probe (DB + Redis + required console schema)| No           |
| `GET /health/deep` | GET    | Deep check with per-dependency response times        | No            |

### GET /health and /health/live — Liveness

Returns `200 OK` when the process is alive.

```json
{ "status": "ok" }
```

### GET /health/ready — Readiness Probe

Performs dependency checks to determine if the service is ready to accept
traffic. Any failed check returns `503` with `"status": "degraded"`:

| Check    | Description                                                     | Failure Impact  |
|----------|-----------------------------------------------------------------|-----------------|
| Database | `SELECT 1` through the pool circuit breaker                     | 503 — not ready |
| Redis    | `PING` answers `PONG`                                           | 503 — not ready |
| Schema   | Required console tables/columns are present (`missing_required_console_schema`) | 503 — not ready |

```json
// Healthy (200)
{ "status": "ok", "db": "connected", "redis": "connected", "schema": "complete" }

// Not ready (503)
{ "status": "degraded", "db": "connected", "redis": "disconnected", "schema": ["web_campaigns"] }
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

The provisioned set lives in `deploy/grafana/dashboards/` (14 dashboards; the
ones below are the core four — see that directory for the full list):

| Dashboard         | Panels | Description                                                    |
|-------------------|--------|----------------------------------------------------------------|
| Tracking Overview | 3      | Ingested event rate, ClickHouse ingest failures, dedup/blocked redirects |
| System Resources  | 4      | Host CPU, memory, open file descriptors, uptime                |
| Database          | 4      | Connections, read latency, commit rate, rollback rate          |
| Redis             | 4      | Memory, connected clients, command rate, availability          |

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
