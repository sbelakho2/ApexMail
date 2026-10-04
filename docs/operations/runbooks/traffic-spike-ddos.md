# Traffic Spike / DDoS Runbook

**Severity:** SEV1–SEV3 (depending on impact on tenants)

> **Architecture truth:** ApexMail runs as a single Hetzner host with Docker
> Compose (see [`ARCHITECTURE.md`](../../../ARCHITECTURE.md)). Every command in
> this runbook is a Compose command (or a host command) executed on the deploy
> host at `/opt/apexmail`. There is no Kubernetes ingress, HPA, or cluster
> anywhere in this deployment — rate limiting lives in the host nginx
> ([`deploy/nginx/nginx.conf`](../../../deploy/nginx/nginx.conf)) and in the
> application.

## Table of Contents
- [Architecture Context](#architecture-context)
- [Symptoms](#symptoms)
- [Severity Classification](#severity-classification)
- [Initial Diagnosis](#initial-diagnosis)
- [Mitigation Procedures](#mitigation-procedures)
  - [Procedure 1: Traffic Analysis](#procedure-1-traffic-analysis)
  - [Procedure 2: Rate Limiting Tuning](#procedure-2-rate-limiting-tuning)
  - [Procedure 3: IP Blocking via the Edge and Hetzner Firewall](#procedure-3-ip-blocking-via-the-edge-and-hetzner-firewall)
  - [Procedure 4: Resource Tuning](#procedure-4-resource-tuning)
  - [Procedure 5: Emergency Mitigation (Circuit Breakers)](#procedure-5-emergency-mitigation-circuit-breakers)
  - [Procedure 6: Abuse Detection and Tenant Isolation](#procedure-6-abuse-detection-and-tenant-isolation)
- [Post-Incident Actions](#post-incident-actions)
- [Escalation](#escalation)

## Architecture Context

ApexMail is rate-limited at multiple layers:
- **Edge (nginx):** `limit_req` zones in [`deploy/nginx/nginx.conf`](../../../deploy/nginx/nginx.conf) — `global` 30 r/s, `login` 10 r/m, `signup` 5 r/m, `admin` 10 r/s, each applied per-location with burst
- **Application:** Token bucket rate limiters per tenant (configurable burst/tier)
- **Circuit breakers:** Redis-backed state machine (CLOSED → OPEN → HALF-OPEN)
- **Capacity:** single host — there is **no autoscaler**; headroom is tuned via the compose resource limits (`deploy.resources.limits` in [`docker-compose.prod.yml`](../../../docker-compose.prod.yml)) and recreated with `docker compose up -d <service>`
- **Connection budget:** total DB connections = SUM of per-service `DATABASE_POOL_MAX` (see [`docker-compose.yml`](../../../docker-compose.yml))

**Command conventions (all commands run on the deploy host):** the compose
prefix is `docker compose -f docker-compose.yml -f docker-compose.prod.yml`
from `/opt/apexmail`. Redis commands authenticate with the `redis_password`
compose secret via the `rc` helper defined in the
[Redis failure runbook](./redis-failure.md).

## Symptoms

- Alerts: `ApiRateLimitThrottling`, `ApiRateLimitExhaustion`, `ApiErrorRateSpike`, `ApiHighLatencyP99`
- Metrics: request rate > 2× normal baseline, p95 latency > 5s, error rate > 5%
- Users: 429 Too Many Requests, 503 Service Unavailable, timeouts
- Infrastructure: worker/MTA saturation, connection pool exhaustion, CPU/memory saturation

## Severity Classification

| Severity | Criteria | Response Time |
|----------|----------|---------------|
| SEV1 | All tenant traffic impacted, >20% error rate | 5 min |
| SEV2 | Single tenant abuse, elevated error rate (5–20%) | 15 min |
| SEV3 | Non-tenant traffic (health checks, monitoring) | 30 min |

## Initial Diagnosis

1. **Check traffic volume vs baseline** (nginx access log; the edge container
   writes `/var/log/nginx/access.log`):
   ```bash
   cd /opt/apexmail
   docker compose -f docker-compose.yml -f docker-compose.prod.yml exec nginx sh -c \
     'tail -20000 /var/log/nginx/access.log' | awk '{print $4}' | cut -d: -f1-2 | sort | uniq -c
   # Requests per minute for the recent window — compare to the Grafana
   # baseline panels (observability stack, --profile monitoring).
   ```

2. **Identify top IPs:**
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.prod.yml exec nginx sh -c \
     'tail -10000 /var/log/nginx/access.log' | awk '{print $1}' | sort | uniq -c | sort -rn | head -20
   ```

3. **Identify top endpoints:**
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.prod.yml exec nginx sh -c \
     'tail -10000 /var/log/nginx/access.log' | awk '{print $7}' | sort | uniq -c | sort -rn | head -20
   ```

4. **Check rate limiter metrics:**
   ```bash
   # PromQL in Grafana Explore
   # Rate limit hits by tenant
   rate(apexmail_rate_limiter_blocked_requests_total[5m])
   #
   # Token bucket fill levels
   apexmail_rate_limiter_tokens_remaining{tenant_id!=""}
   ```

5. **Check for specific tenant abuse:**
   ```bash
   # Check tenant-level metrics
   curl -s http://localhost:9090/metrics | grep 'apexmail_send_count' | sort -t= -k2 -rn | head -10
   ```

## Mitigation Procedures

### Procedure 1: Traffic Analysis

1. **Identify if the spike is:**
   - **Legitimate burst:** Valid customer scaling up (e.g., marketing campaign)
   - **Abusive tenant:** One tenant exceeding fair use
   - **DDoS:** Distributed attack across many IPs
   - **Bug:** Infinite retry loop or misconfigured client

2. **Check for common DDoS patterns:**
   ```bash
   # High ratio of POST to total requests
   # Many requests to auth/login endpoints (credential stuffing)
   # Requests from unexpected geographic regions
   # Requests to non-existent endpoints
   ```

### Procedure 2: Rate Limiting Tuning

1. **Tighten the edge rate limit** (edit the zone rates, then hot-reload nginx):
   ```bash
   # In deploy/nginx/nginx.conf (lines ~132-136): lower the zone rates, e.g.
   #   limit_req_zone $binary_remote_addr zone=global:10m rate=10r/s;
   cd /opt/apexmail
   docker compose -f docker-compose.yml -f docker-compose.prod.yml exec nginx nginx -s reload
   # (deploy/scripts/deploy.sh uses a retried variant of this same reload)
   ```

2. **Enable connection limit per IP** (add/raise `limit_conn` in the same
   `nginx.conf`, then `nginx -s reload` as above).

3. **Tighten per-tenant rate limits:**
   ```bash
   # Temporarily lower the offending tenant's rate limit
   docker compose -f docker-compose.yml -f docker-compose.prod.yml exec redis sh -c \
     'redis-cli --no-auth-warning -a "$(cat /run/secrets/redis_password)" \
        SET "rate-limit:tenant:<tenant-id>:limit" "50"'
   docker compose -f docker-compose.yml -f docker-compose.prod.yml exec redis sh -c \
     'redis-cli --no-auth-warning -a "$(cat /run/secrets/redis_password)" \
        SET "rate-limit:tenant:<tenant-id>:burst" "75"'
   ```

### Procedure 3: IP Blocking via the Edge and Hetzner Firewall

1. **Block specific IPs at the nginx edge** (add a `deny` list in
   `deploy/nginx/nginx.conf`, then reload — same `nginx -s reload` as
   Procedure 2):
   ```nginx
   # http{} block of deploy/nginx/nginx.conf:
   geo $blocked_client {
       default 0;
       1.2.3.4 1;
       5.6.7.8 1;
   }
   # server{}: if ($blocked_client) { return 403; }
   ```

2. **Rate-limit or block upstream at the Hetzner Cloud Firewall level:**
   ```bash
   # Add rate limiting rule via Hetzner Cloud API
   curl -X POST https://api.hetzner.cloud/v1/firewalls/<id>/actions/set_rules \
     -H "Authorization: Bearer $HCLOUD_API_TOKEN" \
     -d '{"rules": [{"direction": "in", "protocol": "tcp", "port": "443", "source_ips": ["0.0.0.0/0"], "rate_limit": {"packets_per_second": 1000}}]}'
   ```

### Procedure 4: Resource Tuning

1. **Raise api-server headroom** (single host — adjust the compose limits and
   recreate; there is no autoscaler):
   ```yaml
   # docker-compose.prod.yml, api-server service:
   deploy:
     resources:
       limits: { cpus: '2.0', memory: 2G }
   ```
   ```bash
   cd /opt/apexmail
   docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d api-server
   ```

2. **Scale out worker queue consumers:** one worker service runs per host —
   raise its processing concurrency and recreate it:
   ```bash
   # In /opt/apexmail/.env (or the prod env file): WORKER_CONCURRENCY=<higher value>
   cd /opt/apexmail
   docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d worker
   ```

3. **If DB connection pool is bottleneck:**
   ```bash
   # Check current connection count
   docker compose -f docker-compose.yml -f docker-compose.prod.yml exec postgres psql -U apexmail -c \
     "SELECT count(*) FROM pg_stat_activity;"
   # Temporarily increase (if within host resources)
   docker compose -f docker-compose.yml -f docker-compose.prod.yml exec postgres psql -U postgres -c \
     "ALTER SYSTEM SET max_connections = 400; SELECT pg_reload_conf();"
   ```

### Procedure 5: Emergency Mitigation (Circuit Breakers)

If the API server is overwhelmed and needs to shed load:

1. **Enable global rate limiter override:**
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.prod.yml exec redis sh -c \
     'redis-cli --no-auth-warning -a "$(cat /run/secrets/redis_password)" \
        SET "circuit-breaker:global-rate-limit" "OPEN"'
   docker compose -f docker-compose.yml -f docker-compose.prod.yml exec redis sh -c \
     'redis-cli --no-auth-warning -a "$(cat /run/secrets/redis_password)" \
        SET "circuit-breaker:global-rate-limit:threshold" "200"'
   # All requests beyond 200/s are rejected with 503
   ```

2. **Disable non-critical endpoints:**
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.prod.yml exec redis sh -c \
     'redis-cli --no-auth-warning -a "$(cat /run/secrets/redis_password)" SET "feature:analytics-api" "disabled"'
   docker compose -f docker-compose.yml -f docker-compose.prod.yml exec redis sh -c \
     'redis-cli --no-auth-warning -a "$(cat /run/secrets/redis_password)" SET "feature:webhook-delivery" "disabled"'
   ```

3. **Serve a maintenance page** for non-critical services (add a catch-all
   `return 503` location for the affected host in `deploy/nginx/nginx.conf`,
   then `nginx -s reload` as in Procedure 2).

### Procedure 6: Abuse Detection and Tenant Isolation

1. **Identify abusive tenant:**
   ```bash
   # From rate limiter metrics
   docker compose -f docker-compose.yml -f docker-compose.prod.yml exec redis sh -c \
     'redis-cli --no-auth-warning -a "$(cat /run/secrets/redis_password)" --scan --pattern "rate-limit:*"'
   docker compose -f docker-compose.yml -f docker-compose.prod.yml exec redis sh -c \
     'redis-cli --no-auth-warning -a "$(cat /run/secrets/redis_password)" GET "rate-limit:tenant:<id>:counter"'
   ```

2. **Suspend abusive tenant (temporary):**
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.prod.yml exec redis sh -c \
     'redis-cli --no-auth-warning -a "$(cat /run/secrets/redis_password)" SET "tenant:suspended:<tenant-id>" "true"'
   docker compose -f docker-compose.yml -f docker-compose.prod.yml exec redis sh -c \
     'redis-cli --no-auth-warning -a "$(cat /run/secrets/redis_password)" EXPIRE "tenant:suspended:<tenant-id>" 3600'
   # Auto-expire in 1 hour
   ```

3. **Move abusive tenant to isolated queue:**
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.prod.yml exec redis sh -c \
     'redis-cli --no-auth-warning -a "$(cat /run/secrets/redis_password)" SET "tenant:isolated-queue:<tenant-id>" "true"'
   docker compose -f docker-compose.yml -f docker-compose.prod.yml exec redis sh -c \
     'redis-cli --no-auth-warning -a "$(cat /run/secrets/redis_password)" EXPIRE "tenant:isolated-queue:<tenant-id>" 86400'
   ```

## Post-Incident Actions

1. **Analyze traffic pattern:**
   ```bash
   docker stats --no-stream   # per-container CPU/memory over the incident
   # Export the nginx access log for offline analysis
   docker compose -f docker-compose.yml -f docker-compose.prod.yml exec nginx \
     cat /var/log/nginx/access.log > /tmp/nginx-logs.txt
   ```

2. **Update rate limits** based on observed patterns (permanent changes go in
   the checked-in files, not runtime state):
   ```bash
   # deploy/nginx/nginx.conf -> limit_req_zone rates
   # docker-compose.prod.yml -> deploy.resources.limits per service
   ```

3. **Implement any new DDoS protection rules.**

4. **File post-mortem** documenting:
   - Timeline of traffic spike
   - Mitigation steps taken
   - Effectiveness (time to mitigate)
   - Permanent rate limit adjustments

## Escalation

| Role | Contact | When |
|------|---------|------|
| Infrastructure lead | @oncall-infra | Rate limiting tuning, edge config |
| Security lead | @oncall-security | Suspected DDoS or abuse |
| Engineering lead | @oncall-eng | Feature disable decisions |
| Abuse team | @abuse | Tenant suspension decisions |

## Related

- [API alerting rules](../../../deploy/prometheus/alerts/api-alerts.yml)
- [Secret Rotation Runbook](../secret-rotation.md)
- [Cache Warming Strategy](../cache-warming.md)
- [nginx rate-limit zones](../../../deploy/nginx/nginx.conf)
