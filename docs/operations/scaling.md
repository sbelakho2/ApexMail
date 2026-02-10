# Scaling Guide

> Internal document — Bel Consulting OÜ

## Overview

This guide covers horizontal and vertical scaling strategies for every ApexMail component. Scaling decisions should be data-driven — use the capacity planning thresholds at the end of this document as triggers.

---

## Architecture Refresher

```
Zone.ee (DNS) → nginx (reverse proxy / load balancer)
    │
    ▼
┌────────────────┐   ┌────────────────┐   ┌────────────────┐
│   Hono API     │   │   Tracking     │   │  Control Plane │
│   (N instances)│   │   (N instances)│   │  (Next.js)     │
└───────┬────────┘   └───────┬────────┘   └───────┬────────┘
        │                    │                    │
        ▼                    ▼                    │
┌────────────────┐   ┌────────────────┐           │
│  Redis Queue   │   │  Redis Events  │           │
└───────┬────────┘   └────────────────┘           │
        │                                         │
        ▼                                         ▼
┌────────────────┐                        ┌────────────────┐
│   Workers      │                        │  PostgreSQL    │
│   (N instances)│───────────────────────▶│  (+ PgBouncer) │
└───────┬────────┘                        └────────────────┘
        │
        ▼
┌────────────────┐
│   MTA Servers  │
│   (N instances)│
└────────────────┘
```

---

## Vertical Scaling — Hetzner Server Upgrades

The simplest scaling lever. Upgrade the Hetzner Cloud server type.

| Server Type | vCPU | RAM | NVMe | Monthly Cost | Use When |
|-------------|------|-----|------|-------------|----------|
| CAX11 | 2 | 4 GB | 40 GB | ~€4 | Development / staging-lite |
| CAX21 | 4 | 8 GB | 80 GB | ~€7 | Light staging |
| CAX31 | 8 | 16 GB | 160 GB | ~€14 | Staging |
| **CAX41** | **16** | **32 GB** | **320 GB** | **~€27** | **Current production** |
| CCX33 | 8 | 32 GB | 240 GB | ~€46 | Next step (dedicated vCPU) |
| CCX43 | 16 | 64 GB | 480 GB | ~€90 | High-load production |
| CCX53 | 32 | 128 GB | 600 GB | ~€170 | Peak traffic / large tenants |

### Upgrade Procedure

1. Schedule a maintenance window (< 5 min downtime for resize).
2. Snapshot the server via Hetzner Cloud console.
3. Resize: `hcloud server change-type apexmail-prod <new-type> --keep-disk`.
4. Verify all services restart correctly.
5. Run smoke tests.
6. Update capacity planning spreadsheet.

> **Note:** ARM (CAX) to x86 (CCX) migration requires Docker image rebuild for the target architecture.

---

## Horizontal Scaling — Application Layer

### API Servers

The Hono API is stateless — scale by running multiple instances behind nginx.

**Single-server scaling (Docker):**

```yaml
# docker-compose.prod.yml
services:
  api:
    deploy:
      replicas: 4    # scale up from default 1
    # ...
```

**Multi-server scaling:**

1. Provision additional Hetzner Cloud ARM servers.
2. Deploy the API container on each.
3. Add server IPs to the nginx upstream group.
4. nginx handles health checks and round-robin distribution.

**Session affinity:** Not required — API is fully stateless. Auth tokens are verified on every request.

### Workers

Workers are the primary throughput bottleneck for email sending. Scale aggressively.

**Single-server scaling:**

```yaml
services:
  worker:
    deploy:
      replicas: 8    # scale based on queue depth
```

**Multi-server scaling:**

1. Provision dedicated worker server(s) — can be cheaper CPX instances since workers are CPU-bound.
2. Workers connect to the shared Redis queue and PostgreSQL.
3. No additional configuration needed — BullMQ handles distributed consumption.

**Partition by tenant:** For large Enterprise tenants, dedicate worker instances to prevent queue starvation:

```
WORKER_TENANT_FILTER=acme-enterprise  # env var to restrict worker to specific tenant queue
```

### Tracking Service

Scale identically to API servers. Most tracking requests should hit nginx reverse-proxy cache (pixel responses are cacheable).

---

## Database Scaling — PostgreSQL

### Connection Pooling (PgBouncer)

PgBouncer sits between the application and PostgreSQL, multiplexing connections.

| Parameter | Current | Scaled |
|-----------|---------|--------|
| `max_client_conn` | 200 | 1 000 |
| `default_pool_size` | 20 | 50 |
| `reserve_pool_size` | 5 | 10 |
| `pool_mode` | `transaction` | `transaction` |

```ini
# /etc/pgbouncer/pgbouncer.ini
[databases]
apexmail = host=127.0.0.1 port=5432 dbname=apexmail

[pgbouncer]
listen_port = 6432
max_client_conn = 1000
default_pool_size = 50
reserve_pool_size = 10
pool_mode = transaction
```

### Read Replicas

For read-heavy workloads (analytics, reporting, dashboard queries):

1. Create a PostgreSQL streaming replica on a separate server.
2. Configure the application to route read queries to the replica:
   ```
   DATABASE_READ_URL=postgresql://replica-host:5432/apexmail
   ```
3. Analytics service (`apps/analytics`) and control plane read queries can be directed to the replica.
4. Write operations always go to the primary.

**Replication lag monitoring:** Alert if replica lag exceeds 10 seconds (see [alerting-rules.yml](../../deploy/alerting-rules.yml)).

### Table Partitioning

For high-volume tables, partition by time:

- `events` — partition by month (most queried by date range).
- `email_logs` — partition by month.
- `analytics_daily` — partition by month.

Partitioning is managed via migrations in the respective app directories.

### Vacuum & Maintenance

- `autovacuum` is enabled with aggressive settings for high-churn tables.
- Weekly `VACUUM ANALYZE` on large tables via cron.
- Monitor bloat with `pgstattuple` extension.

---

## Redis Scaling

### Single-Instance Optimisation

Before scaling out, optimise the single instance:

| Parameter | Value |
|-----------|-------|
| `maxmemory` | 80 % of available RAM |
| `maxmemory-policy` | `allkeys-lru` |
| `save` | Disabled (persistence via AOF if needed) |
| `tcp-keepalive` | 300 |

### Functional Sharding

Split Redis usage across dedicated instances:

| Instance | Purpose | Persistence |
|----------|---------|-------------|
| `redis-queue` | BullMQ job queues | AOF (appendfsync everysec) |
| `redis-cache` | API response cache, session data | None (volatile) |
| `redis-events` | Tracking event buffer | AOF |
| `redis-rate-limit` | Rate limiting counters | None (volatile) |

### Redis Cluster

When a single instance is insufficient:

1. Deploy a 6-node Redis Cluster (3 primaries + 3 replicas).
2. Use `ioredis` cluster mode in the application.
3. BullMQ supports Redis Cluster natively.

> **Note:** Redis Cluster adds operational complexity. Prefer vertical scaling and functional sharding first.

---

## MTA Scaling

### Adding MTA Servers

Each MTA server needs:

1. Dedicated IP address (for reputation isolation).
2. Proper rDNS, SPF, DKIM, DMARC configuration for the IP.
3. IP warmup schedule (see runbook: [IP Warmup](./runbooks/README.md)).

### IP Warmup Schedule

New IPs must be warmed gradually:

| Day | Daily Volume |
|-----|-------------|
| 1–3 | 500 |
| 4–7 | 2 000 |
| 8–14 | 10 000 |
| 15–21 | 50 000 |
| 22–30 | Full volume |

### MTA Pool Architecture

```
Workers
  │
  ├─▶ MTA-1 (IP: x.x.x.1) — Primary, warmed
  ├─▶ MTA-2 (IP: x.x.x.2) — Primary, warmed
  ├─▶ MTA-3 (IP: x.x.x.3) — Overflow / new (warming)
  └─▶ MTA-4 (IP: x.x.x.4) — Dedicated to Enterprise tenant
```

Traffic is distributed across MTAs based on volume, reputation score, and tenant assignment.

---

## nginx Reverse-Proxy Caching

### Cacheable Resources

| Resource | Cache TTL | Cache Scope |
|----------|-----------|-------------|
| Tracking pixel (`/t/pixel.gif`) | 1 hour | proxy_cache |
| Static assets (JS, CSS, images) | 1 year | proxy_cache |
| Marketing site pages | 1 hour | proxy_cache |
| API responses | Not cached | proxy_no_cache |
| Control plane SSR | 0 (revalidate) | proxy_no_cache |

### Cache Configuration

Configured in `/etc/nginx/conf.d/cache.conf`:

- `/t/*` → `proxy_cache_valid 200 1h;`
- `/api/*` → `proxy_no_cache 1; proxy_cache_bypass 1;`
- `/_next/static/*` → `proxy_cache_valid 200 365d;`

---

## Capacity Planning Thresholds

These thresholds trigger scaling discussions. Monitor via the `capacity-planning` Grafana dashboard.

| Metric | Yellow (Plan) | Red (Act Now) |
|--------|--------------|---------------|
| CPU utilisation (sustained) | > 60 % | > 80 % |
| Memory utilisation | > 70 % | > 85 % |
| Disk utilisation | > 70 % | > 85 % |
| PostgreSQL connections (% of pool) | > 60 % | > 80 % |
| PostgreSQL disk IOPS | > 70 % of provisioned | > 85 % |
| Redis memory (% of maxmemory) | > 60 % | > 80 % |
| Queue depth (sustained) | > 10 000 jobs | > 50 000 jobs |
| Queue processing latency | > 5 s | > 30 s |
| API p95 latency | > 150 ms | > 300 ms |
| MTA queue depth | > 50 000 | > 200 000 |
| Email delivery rate | < 95 % | < 90 % |

---

## Scaling Decision Matrix

| Signal | First Action | Second Action |
|--------|-------------|---------------|
| API latency high | Add API replicas (Docker) | Provision second API server |
| Queue backlog growing | Add worker replicas | Provision dedicated worker server |
| Database connections exhausted | Increase PgBouncer pool | Add read replica |
| Database queries slow | Add indexes / optimise queries | Vertical upgrade or read replica |
| Redis memory full | Increase `maxmemory` / vertical upgrade | Functional sharding |
| MTA throughput capped | Add MTA server + IP | Dedicated MTA per large tenant |
| Disk full | Prune logs / old data | Resize server disk |

---

*Last updated: 2026-02-09*
