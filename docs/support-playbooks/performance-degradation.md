# Performance Degradation

**Classification:** Infrastructure / Platform
**Severity:** P1 (P0 if customer-facing impact >5 minutes)
**Owner:** SRE / Platform Team
**Last Updated:** 2026-02-09

---

## Symptoms

- API response times elevated (p99 > 1s, normal baseline: ~200ms)
- Email sending queue depth increasing (sends delayed)
- Control plane dashboard loading slowly or timing out
- Workers falling behind on job processing
- Customer reports: "emails are delayed" or "API is slow"
- Grafana alerts firing:
  - `api_latency_p99 > 1s` (warning)
  - `api_latency_p99 > 2s` (critical — page on-call)
  - `queue_depth > 10000` (warning)
  - `queue_depth > 50000` (critical)
  - `postgres_connection_pool_exhausted` (critical)
  - `redis_memory_usage > 80%` (warning)

### Impact Assessment

Before diagnosing, quickly assess the scope:

1. **Is it tenant-specific or global?** Check if multiple tenants are affected
2. **Which layer?** API, worker, MTA, database, cache
3. **When did it start?** Correlate with deployments, config changes, or external events
4. **Is it getting worse?** Check if the trend is degrading or stabilizing

---

## Diagnosis

### Step 1: Grafana Dashboard Overview

Open the following Grafana dashboards (Prometheus data source):

| Dashboard | Key Panels | URL |
|-----------|-----------|-----|
| API Overview | Request rate, latency p50/p95/p99, error rate, status codes | `/d/api-overview` |
| Queue & Workers | Queue depth, processing rate, worker lag, job failure rate | `/d/queue-workers` |
| PostgreSQL | Active connections, query duration, locks, replication lag | `/d/postgresql` |
| Redis | Memory usage, connected clients, ops/sec, keyspace | `/d/redis` |
| MTA | Throughput, queue size, delivery rate, bounce rate | `/d/mta` |
| System | CPU, memory, disk I/O, network (per Hetzner Cloud ARM node) | `/d/system` |

### Step 2: Identify the Bottleneck Layer

#### API Layer (Hono on Node.js)

```bash
# Check API process health on the Hetzner server
ssh apexmail-api "systemctl status apexmail-api"

# Check Node.js event loop lag
curl -s http://localhost:3000/metrics | grep "nodejs_eventloop_lag"

# Check active HTTP connections
curl -s http://localhost:3000/metrics | grep "http_requests_in_flight"
```

Prometheus queries for Grafana:

```promql
# API latency p99 (last 15 minutes)
histogram_quantile(0.99, rate(http_request_duration_seconds_bucket{service="api"}[5m]))

# Error rate
rate(http_requests_total{service="api", status=~"5.."}[5m])
  / rate(http_requests_total{service="api"}[5m])

# Request rate
rate(http_requests_total{service="api"}[5m])
```

#### PostgreSQL

```bash
# Connect to PostgreSQL
psql -h <PG_HOST> -U apexmail -d apexmail
```

```sql
-- Active queries and their duration
SELECT pid, now() - pg_stat_activity.query_start AS duration,
       query, state, wait_event_type, wait_event
FROM pg_stat_activity
WHERE state != 'idle'
  AND query NOT ILIKE '%pg_stat_activity%'
ORDER BY duration DESC;

-- Connection pool usage
SELECT count(*) AS total_connections,
       count(*) FILTER (WHERE state = 'active') AS active,
       count(*) FILTER (WHERE state = 'idle') AS idle,
       count(*) FILTER (WHERE state = 'idle in transaction') AS idle_in_tx
FROM pg_stat_activity
WHERE datname = 'apexmail';

-- Slow queries (top 10 by mean time from pg_stat_statements)
SELECT query, calls, mean_exec_time AS mean_ms,
       total_exec_time AS total_ms, rows,
       stddev_exec_time AS stddev_ms
FROM pg_stat_statements
ORDER BY mean_exec_time DESC
LIMIT 10;

-- Lock contention
SELECT blocked_locks.pid AS blocked_pid,
       blocked_activity.query AS blocked_query,
       blocking_locks.pid AS blocking_pid,
       blocking_activity.query AS blocking_query
FROM pg_catalog.pg_locks blocked_locks
JOIN pg_catalog.pg_stat_activity blocked_activity
  ON blocked_activity.pid = blocked_locks.pid
JOIN pg_catalog.pg_locks blocking_locks
  ON blocking_locks.locktype = blocked_locks.locktype
  AND blocking_locks.relation = blocked_locks.relation
  AND blocking_locks.pid != blocked_locks.pid
JOIN pg_catalog.pg_stat_activity blocking_activity
  ON blocking_activity.pid = blocking_locks.pid
WHERE NOT blocked_locks.granted;

-- Table bloat / dead tuples
SELECT schemaname, relname, n_dead_tup, n_live_tup,
       ROUND(n_dead_tup::numeric / NULLIF(n_live_tup, 0) * 100, 2) AS dead_pct,
       last_vacuum, last_autovacuum
FROM pg_stat_user_tables
WHERE n_dead_tup > 10000
ORDER BY n_dead_tup DESC
LIMIT 10;
```

#### Redis

```bash
# Connect to Redis
redis-cli -h <REDIS_HOST> -p 6379

# Memory usage
INFO memory
# Look for: used_memory_human, used_memory_peak_human, maxmemory

# Connected clients
INFO clients
# Look for: connected_clients, blocked_clients

# Operations per second
INFO stats
# Look for: instantaneous_ops_per_sec

# Slow log (commands taking >10ms)
SLOWLOG GET 20

# Key count by pattern (identify bloated namespaces)
# WARNING: KEYS is expensive — use SCAN in production
INFO keyspace
```

```bash
# Check Redis memory breakdown by key pattern (sampled)
redis-cli --bigkeys
```

#### MTA

```bash
# Check MTA process and queue
ssh apexmail-mta "systemctl status apexmail-mta"

# MTA queue depth
curl -s http://localhost:3001/metrics | grep "mta_queue_depth"

# MTA throughput
curl -s http://localhost:3001/metrics | grep "mta_emails_sent_total"
```

```promql
# MTA throughput rate
rate(mta_emails_sent_total[5m])

# MTA queue depth
mta_queue_depth

# MTA delivery latency p99
histogram_quantile(0.99, rate(mta_delivery_duration_seconds_bucket[5m]))
```

#### Worker Queue

```bash
# Check worker process
ssh apexmail-worker "systemctl status apexmail-worker"

# Queue depth by job type
curl -s http://localhost:3002/metrics | grep "worker_queue_depth"
```

```promql
# Queue processing rate
rate(worker_jobs_completed_total[5m])

# Queue depth trend
worker_queue_depth

# Job failure rate
rate(worker_jobs_failed_total[5m])
  / rate(worker_jobs_completed_total[5m])
```

#### nginx Reverse Proxy

Check if nginx is the bottleneck:

```bash
# Check nginx process and error log
ssh apexmail-api "systemctl status nginx"
ssh apexmail-api "tail -50 /var/log/nginx/error.log"

# Check active connections and request rate
ssh apexmail-api "curl -s http://127.0.0.1/nginx_status"
```

Look for:
- nginx 502/504 responses in access logs (origin app is unresponsive)
- Connection refused errors (upstream app crashed)
- High active-connection count (upstream backpressure)

#### Hetzner System Resources

```bash
# CPU usage (ARM64)
ssh apexmail-api "top -bn1 | head -5"

# Memory usage
ssh apexmail-api "free -h"

# Disk I/O
ssh apexmail-api "iostat -x 1 3"

# Network
ssh apexmail-api "ss -s"

# Disk space
ssh apexmail-api "df -h"
```

### Step 3: Check for Recent Changes

```bash
# Recent deployments
git log --oneline --since="24 hours ago" --all

# Check deployment history
ssh apexmail-api "journalctl -u apexmail-api --since '24 hours ago' | grep -i 'started\|restarted\|deploy'"
```

```sql
-- Recent configuration changes
SELECT * FROM audit_logs
WHERE action ILIKE '%config%'
  AND created_at > NOW() - INTERVAL '24 hours'
ORDER BY created_at DESC;
```

---

## Common Causes and Resolutions

### 1. PostgreSQL Slow Queries

**Symptoms:** High API latency, `pg_stat_statements` shows queries with mean_exec_time > 500ms

**Resolution:**

```sql
-- Identify missing indexes (sequential scans on large tables)
SELECT schemaname, relname, seq_scan, seq_tup_read,
       idx_scan, idx_tup_fetch
FROM pg_stat_user_tables
WHERE seq_scan > 100
  AND seq_tup_read > 100000
ORDER BY seq_tup_read DESC
LIMIT 10;
```

- Add missing indexes (coordinate with engineering)
- Kill long-running queries if they're blocking:

```sql
-- Kill a specific query (use with caution)
SELECT pg_terminate_backend(<PID>);
```

- Run `VACUUM ANALYZE` on bloated tables:

```sql
VACUUM ANALYZE <TABLE_NAME>;
```

### 2. Redis Memory Pressure

**Symptoms:** Redis memory > 80% of maxmemory, eviction happening, slow operations

**Resolution:**

```bash
# Check eviction policy
redis-cli CONFIG GET maxmemory-policy

# Identify large keys
redis-cli --bigkeys

# Flush expired keys aggressively
redis-cli DEBUG SET-ACTIVE-EXPIRE 1
```

- Clear stale data: expired sessions, old rate limit counters, completed job results
- If memory is genuinely exhausted, increase `maxmemory` in Redis config (requires restart)

### 3. MTA Queue Backlog

**Symptoms:** Queue depth > 10,000, email delivery delayed by > 5 minutes

**Resolution:**

```bash
# Scale up workers (run additional worker instances)
ssh apexmail-worker "systemctl start apexmail-worker@2"
ssh apexmail-worker "systemctl start apexmail-worker@3"
```

- Check for stuck items in the queue:

```bash
# Find jobs stuck in processing state for >10 minutes
redis-cli ZRANGEBYSCORE mta:processing 0 $(date -d '10 minutes ago' +%s)
```

- Re-enqueue stuck items:

```bash
node apps/ops/dist/cli.js mta requeue-stuck --older-than 10m
```

- Check if a specific tenant is flooding the queue:

```sql
SELECT tenant_id, COUNT(*) AS pending
FROM mta_queue
WHERE status = 'pending'
GROUP BY tenant_id
ORDER BY pending DESC
LIMIT 10;
```

### 4. nginx Rate Limiting

**Symptoms:** 429 responses from nginx rate-limiting module, legitimate API requests being rejected

**Resolution:**

- Check nginx rate limit configuration in `/etc/nginx/conf.d/rate-limit.conf`
- Review access logs for rejected requests: `grep ' 429 ' /var/log/nginx/access.log | tail -20`
- Whitelist internal service IPs if they're being rate limited
- Adjust `limit_req_zone` thresholds if they're too aggressive
- Application-level rate limiting is handled by the API (Redis-backed) and is the primary mechanism

### 5. Connection Pool Exhaustion

**Symptoms:** `postgres_connection_pool_exhausted` alert, new queries timing out waiting for connections

**Resolution:**

```sql
-- Check what's using all connections
SELECT client_addr, state, COUNT(*)
FROM pg_stat_activity
WHERE datname = 'apexmail'
GROUP BY client_addr, state
ORDER BY count DESC;
```

- Kill idle-in-transaction connections older than 5 minutes:

```sql
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE state = 'idle in transaction'
  AND query_start < NOW() - INTERVAL '5 minutes';
```

- Increase pool size temporarily (in application config, requires restart)
- Check for connection leaks in recent code changes

### 6. AWS SES Fallback Throttling

**Symptoms:** MTA falling back to AWS SES eu-west-1, but SES is throttling

**Resolution:**

- Check SES sending quota and current usage:

```bash
aws ses get-send-quota --region eu-west-1
```

- Check SES bounce/complaint notifications
- If SES is throttling, reduce sending rate or request a quota increase
- Check primary MTA path — why is fallback being used?

---

## Emergency Actions

### If p99 > 2s for > 5 minutes

1. **Page on-call SRE immediately** (PagerDuty `apexmail-platform`)
2. **Identify the bottleneck** (follow diagnosis steps above)
3. **Apply immediate mitigation:**
   - Scale workers if queue backlog
   - Kill slow queries if PostgreSQL
   - Restart API if event loop is stuck
   - If DDoS suspected, enable nginx connection limiting and notify Hetzner

### If Complete Outage

1. **Page on-call SRE + engineering lead**
2. **Check server availability:**

```bash
# Ping all Hetzner Cloud ARM nodes
for host in apexmail-api apexmail-worker apexmail-mta; do
  echo -n "$host: "; ssh -o ConnectTimeout=5 $host "echo OK" 2>/dev/null || echo "UNREACHABLE"
done
```

3. **Check Hetzner status page:** https://status.hetzner.com
4. **Failover if needed:** Activate DR plan (see `docs/operations/disaster-recovery.md`)

---

## Post-Incident

After the issue is resolved:

- [ ] Verify all metrics have returned to baseline on Grafana
- [ ] Scale down any temporary additional workers
- [ ] Revert any temporary configuration changes
- [ ] Write a brief incident summary in `#incidents` Slack channel
- [ ] If customer-impacting (>5 min), create a post-incident review (PIR) ticket
- [ ] Update runbooks if a new failure mode was discovered

---

## Escalation

- **P2:** Elevated latency but within SLA (p99 < 2s), no customer reports → SRE monitors
- **P1:** p99 > 2s OR queue depth > 50,000 OR customer reports → Page on-call SRE
- **P0:** Complete outage, multiple systems down, or data integrity risk → Page on-call SRE + Engineering Lead + CEO notification

**Escalation contacts:**
- SRE Team Slack: `#sre-oncall`
- Platform Team Slack: `#platform-eng`
- On-call SRE pager: PagerDuty `apexmail-platform`
- Engineering Lead pager: PagerDuty `apexmail-eng-lead`

---

## Related

- [Webhook Failures](webhook-failures.md) — performance degradation can delay webhook delivery
- [Sending Suspended](sending-suspended.md) — tenant-specific rate limiting may look like performance issues
- Internal: `deploy/alerting-rules.yml` — Prometheus alerting rules
- Internal: `deploy/prometheus.yml` — Prometheus scrape configuration
- Grafana: All dashboards linked in Step 1 above
- Runbook: `docs/operations/disaster-recovery.md` — DR procedures
- Runbook: `docs/operations/scaling.md` — scaling procedures for Hetzner Cloud ARM nodes
