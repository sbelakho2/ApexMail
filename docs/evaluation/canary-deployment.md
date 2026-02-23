# Canary Deployment Process

> Internal document — Bel Consulting OÜ

## Overview

ApexMail uses canary deployments to gradually roll out changes to production, minimising blast radius. Traffic splitting is handled at the **application level** (reverse proxy / load balancer on the server), and automated health checks gate each promotion stage.

---

## Traffic Stages

| Stage | Traffic % | Minimum Duration | Promotion Criteria |
|-------|-----------|-----------------|-------------------|
| 1 — Canary | 5 % | 15 minutes | All health checks green |
| 2 — Early adopters | 25 % | 15 minutes | All health checks green |
| 3 — Majority | 50 % | 15 minutes | All health checks green |
| 4 — Full rollout | 100 % | — | Stable for 30 min post-promotion |

Each stage runs for **at least** the minimum duration. Promotion is manual (engineer confirms) or automatic if CI is configured for auto-promote.

---

## Health Check Criteria

Every stage is gated on the following thresholds, measured over a rolling 5-minute window:

| Metric | Threshold | Source |
|--------|-----------|--------|
| HTTP error rate (5xx) | < 0.1 % | Prometheus (`http_requests_total`) |
| Tracking latency p95 | < 200 ms | Prometheus (`http_request_duration_seconds`) |
| Tracking latency p99 | < 500 ms | Prometheus |
| Tracking error rate | < 0.05 % | Prometheus (`tracking_errors_total`) |
| PostgreSQL active connections | < 80 % of pool | PgBouncer metrics |
| Redis memory usage | < 80 % of max | Redis `INFO memory` |

If **any** metric breaches its threshold during a stage, the canary is **halted** and an alert fires.

---

## Automatic Rollback Triggers

Immediate, automated rollback to the previous stable version occurs when:

1. **Error rate** exceeds 0.5 % for 2 consecutive minutes at any stage.
2. **Latency p99** exceeds 2 000 ms for 3 consecutive minutes.
3. **Health endpoint** (`/health`) returns non-200 for 1 minute.
4. **Tracking container crash loop** — more than 3 restarts within 5 minutes.
5. **Database connection failures** — any stage reporting connection pool exhaustion.

Rollback is executed by updating the reverse proxy config to route 100 % to stable and rolling back canary Docker containers.

---

## Application-Level Traffic Splitting

Traffic splitting is implemented via **nginx** (or Caddy) running on the Hetzner server as a reverse proxy.

### Mechanism

The reverse proxy uses weighted upstream groups to route a configurable percentage of requests to either the **stable** or **canary** application instance. Both run as separate Docker containers on the same server (or on separate servers when scaling).

```
┌─────────────┐     ┌──────────────────────┐
│   Client     │────▶│  nginx reverse proxy  │
└─────────────┘     │  (traffic splitter)   │
                    └──────┬───────┬────────┘
                           │       │
                     stable│       │canary
                           ▼       ▼
                    ┌──────────┐ ┌──────────┐
                    │ container│ │ container│
                    │ :3000    │ │ :3001    │
                    └──────────┘ └──────────┘
```

- **Session stickiness:** An `__apx_canary` cookie ensures a user stays on the same variant for the duration of a session.
- **API traffic:** Routed identically — canary applies to both web and API.
- **Excluded paths:** `/healthz`, `/metrics`, and static assets are always served from the stable upstream.

### nginx Upstream Configuration

```nginx
upstream apexmail_backend {
    server 127.0.0.1:3000 weight=95;  # stable
    server 127.0.0.1:3001 weight=5;   # canary
}
```

### Updating Traffic Split

```bash
# Set canary to 5 %
./tools/canary.sh set 5

# Promote to 25 %
./tools/canary.sh set 25

# Full rollout
./tools/canary.sh set 100

# Emergency rollback
./tools/canary.sh rollback
```

The script updates the nginx upstream weights and reloads the configuration (`nginx -s reload`).

---

## Deployment Workflow

```
1. Tag release candidate (vX.Y.Z-rc.N)
2. Build & push canary Docker images
3. Deploy canary container on port 3001
4. Run smoke tests against canary directly
5. Enable 5 % traffic split (update nginx weights)
6. Monitor for 15 min
   └─ FAIL → automatic rollback
   └─ PASS → promote to 25 %
7. Monitor for 15 min
   └─ FAIL → automatic rollback
   └─ PASS → promote to 50 %
8. Monitor for 15 min
   └─ FAIL → automatic rollback
   └─ PASS → promote to 100 %
9. Monitor for 30 min at 100 %
10. Tag final release (vX.Y.Z)
11. Replace stable container with new version on port 3000
12. Remove canary container and reset nginx config
```

---

## Monitoring During Canary

### Grafana Dashboard

Dashboard UID: `canary-deployment`

Panels compare canary vs stable side-by-side:

- Request rate per upstream
- Error rate per upstream
- Latency percentiles per upstream
- Tracking event throughput per container
- Database query duration per container

### Prometheus Labels

Canary and stable containers expose metrics with distinct labels:

```yaml
# Stable container
apexmail_http_requests_total{deployment="stable", ...}

# Canary container
apexmail_http_requests_total{deployment="canary", ...}
```

This allows PromQL queries to compare:

```promql
# Error rate comparison
sum(rate(apexmail_http_requests_total{deployment="canary", status=~"5.."}[5m]))
/
sum(rate(apexmail_http_requests_total{deployment="canary"}[5m]))
```

---

## Related Documents

- [Load Testing](./load-testing.md) — performance baselines
- [On-Call](../operations/on-call.md) — escalation during canary issues
- [Monitoring](../operations/monitoring.md) — metrics and alerting
