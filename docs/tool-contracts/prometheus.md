# Tool Contract: Prometheus & Grafana

> Internal engineering document — specifies the interface contract for ApexMail's monitoring and observability stack.

| Field | Value |
|-------|-------|
| **Prometheus** | v2.50+ |
| **Grafana** | v10+ |
| **Hosting** | `apx-mon-1` (Hetzner CAX41 ARM) |
| **Retention** | 30 days local TSDB |
| **Scrape Interval** | 15 s (global default) |

---

## 1. Metric Naming Convention

All application metrics MUST follow this pattern:

```
apexmail_<subsystem>_<metric>_<unit>
```

### Rules

1. Prefix: always `apexmail_`.
2. Subsystem: one of `api`, `worker`, `mta`, `tracking`, `billing`, `db`, `redis`, `queue`.
3. Metric name: descriptive, snake_case.
4. Unit suffix: `_total` (counters), `_seconds` (durations), `_bytes` (sizes), `_ratio` (0–1).
5. Use base units: seconds (not milliseconds), bytes (not kilobytes).

### Examples

```
apexmail_api_requests_total{method="POST", route="/api/v1/emails", status="200"}
apexmail_api_request_duration_seconds{method="GET", route="/api/v1/campaigns"}
apexmail_worker_emails_sent_total{tenant_id="t_abc", status="delivered"}
apexmail_mta_queue_depth{priority="high"}
apexmail_billing_stripe_webhook_duration_seconds{event="invoice.paid"}
```

---

## 2. Metric Types

### Counters

Monotonically increasing values. Reset only on process restart.

| Metric | Labels | Description |
|--------|--------|-------------|
| `apexmail_api_requests_total` | `method`, `route`, `status` | Total HTTP requests |
| `apexmail_worker_emails_sent_total` | `tenant_id`, `status` | Emails processed |
| `apexmail_worker_emails_bounced_total` | `tenant_id`, `bounce_type` | Bounce events |
| `apexmail_mta_connections_total` | `direction` (inbound/outbound) | SMTP connections |
| `apexmail_billing_webhook_events_total` | `event`, `status` | Stripe webhook events |
| `apexmail_tracking_opens_total` | `tenant_id` | Email opens tracked |
| `apexmail_tracking_clicks_total` | `tenant_id` | Link clicks tracked |

### Histograms

Distribution of observed values in configurable buckets.

| Metric | Buckets | Description |
|--------|---------|-------------|
| `apexmail_api_request_duration_seconds` | 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5 | API latency |
| `apexmail_worker_email_processing_seconds` | 0.1, 0.5, 1, 5, 10, 30 | Email send pipeline time |
| `apexmail_db_query_duration_seconds` | 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1 | PostgreSQL query time |
| `apexmail_mta_delivery_duration_seconds` | 0.5, 1, 5, 10, 30, 60 | SMTP delivery time |

### Gauges

Point-in-time values that can go up or down.

| Metric | Description |
|--------|-------------|
| `apexmail_queue_depth` | Current job queue size (by priority) |
| `apexmail_db_connections_active` | Active PostgreSQL connections |
| `apexmail_redis_memory_used_bytes` | Redis memory usage |
| `apexmail_api_websocket_connections` | Active WebSocket connections |
| `apexmail_mta_queue_size` | Emails queued in MTA |

---

## 3. Label Conventions

### Rules

1. Labels use **snake_case**.
2. Keep label cardinality **low**. High-cardinality labels (e.g., `email_id`, `user_id`) are FORBIDDEN — they cause TSDB explosion.
3. `tenant_id` is the ONLY high-cardinality label permitted, and only on aggregate metrics (send totals, not per-request).
4. HTTP route labels use the **route pattern** (`/api/v1/emails/:id`), never the resolved URL (`/api/v1/emails/abc123`).
5. Status labels use HTTP status codes as strings (`"200"`, `"404"`), not grouped (`"2xx"`).

### Standard Labels

| Label | Values | Used On |
|-------|--------|---------|
| `method` | GET, POST, PUT, DELETE, PATCH | API request metrics |
| `route` | Route pattern | API request metrics |
| `status` | HTTP status code | API request metrics |
| `tenant_id` | Tenant UUID prefix | Aggregate business metrics only |
| `priority` | high, normal, low | Queue metrics |
| `bounce_type` | hard, soft, complaint | Bounce metrics |

---

## 4. Scrape Targets

Configuration lives in `deploy/prometheus.yml`.

| Target | Endpoint | Port | Interval |
|--------|----------|------|----------|
| API | `apx-api-1:9100/metrics` | 9100 | 15 s |
| Worker | `apx-worker-1:9100/metrics` | 9100 | 15 s |
| MTA | `apx-worker-1:9101/metrics` | 9101 | 15 s |
| Tracking | `apx-api-1:9102/metrics` | 9102 | 15 s |
| Node Exporter (all) | `<host>:9110/metrics` | 9110 | 30 s |
| Redis Exporter | `apx-api-1:9121/metrics` | 9121 | 30 s |
| PostgreSQL Exporter | `apx-db-1:9187/metrics` | 9187 | 30 s |

### Metrics Endpoint Rules

1. Every ApexMail service exposes a `/metrics` endpoint using the `prom-client` library.
2. The metrics endpoint is bound to the **private network interface only** — not exposed publicly.
3. Default metrics (Node.js process metrics) are enabled.
4. Metrics endpoints MUST respond in < 1 s. Heavy computation is pre-aggregated.

---

## 5. Alert Rules

Alert rules are defined in `deploy/alerting-rules.yml` and evaluated by Prometheus.

### Critical (Page)

| Alert | Condition | For | Severity |
|-------|-----------|-----|----------|
| `APIDown` | `up{job="api"} == 0` | 2 min | critical |
| `DatabaseDown` | `up{job="postgresql"} == 0` | 1 min | critical |
| `HighErrorRate` | `rate(apexmail_api_requests_total{status=~"5.."}[5m]) / rate(apexmail_api_requests_total[5m]) > 0.05` | 5 min | critical |
| `DiskSpaceCritical` | `node_filesystem_avail_bytes / node_filesystem_size_bytes < 0.1` | 5 min | critical |
| `ReplicationLag` | `pg_replication_lag_seconds > 30` | 5 min | critical |

### Warning (Notify)

| Alert | Condition | For | Severity |
|-------|-----------|-----|----------|
| `HighLatency` | `histogram_quantile(0.95, rate(apexmail_api_request_duration_seconds_bucket[5m])) > 1` | 10 min | warning |
| `QueueBacklog` | `apexmail_queue_depth > 10000` | 15 min | warning |
| `HighMemory` | `node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes < 0.15` | 10 min | warning |
| `RedisHighMemory` | `redis_memory_used_bytes > 1.6e9` | 5 min | warning |
| `CertExpiringSoon` | `ssl_cert_not_after - time() < 7 * 86400` | 1 h | warning |
| `HighBounceRate` | `rate(apexmail_worker_emails_bounced_total[1h]) / rate(apexmail_worker_emails_sent_total[1h]) > 0.05` | 30 min | warning |

### Alert Routing

- Critical alerts → PagerDuty (or equivalent on-call tool).
- Warning alerts → `#ops-alerts` Slack/Discord channel.
- Resolved notifications are sent for both severities.

---

## 6. Grafana Dashboards

### Dashboard Structure

| Dashboard | Panels | Audience |
|-----------|--------|----------|
| **System Overview** | CPU, memory, disk, network per server | Ops |
| **API Performance** | Request rate, latency p50/p95/p99, error rate, top routes | Engineering |
| **Email Pipeline** | Send rate, queue depth, delivery time, bounce rate | Engineering / Ops |
| **Database Health** | Query latency, connections, replication lag, dead tuples | Engineering |
| **Redis Health** | Memory, hit rate, evictions, connected clients | Engineering |
| **Billing** | Webhook event rate, processing time, failure rate | Engineering |
| **Tenant Health** | Per-tenant send volume, bounce rate, complaint rate | Support |

### Dashboard Rules

1. Every dashboard has a **time range selector** and **auto-refresh** (default: 30 s).
2. Tenant Health dashboard uses the `tenant_id` variable for filtering.
3. Dashboards are version-controlled as JSON exports in `deploy/grafana/dashboards/`.
4. Grafana is accessible at `http://apx-mon-1:3000` (private network only, accessed via SSH tunnel or VPN).

---

*Last updated: 2026-02-09*
