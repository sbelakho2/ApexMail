# Redis Failure Runbook

**Severity:** SEV1–SEV3 (depending on impact)

> **Architecture truth:** ApexMail runs as a single Hetzner host with Docker
> Compose (see [`ARCHITECTURE.md`](../../../ARCHITECTURE.md)). Every command in
> this runbook is a Compose command executed on the deploy host at
> `/opt/apexmail`. There is one Redis instance; there is no Kubernetes or Helm
> anywhere in this deployment.

## Table of Contents
- [Architecture Context](#architecture-context)
- [Symptoms](#symptoms)
- [Severity Classification](#severity-classification)
- [Initial Diagnosis](#initial-diagnosis)
- [Recovery Procedures](#recovery-procedures)
  - [Procedure 1: Connection Failure](#procedure-1-connection-failure)
  - [Procedure 2: Memory Exhaustion](#procedure-2-memory-exhaustion)
  - [Procedure 3: Data Loss / Corruption](#procedure-3-data-loss--corruption)
  - [Procedure 4: Replication Failure](#procedure-4-replication-failure)
  - [Procedure 5: AOF / RDB Write Failure](#procedure-5-aof--rdb-write-failure)
- [Post-Recovery Verification](#post-recovery-verification)
- [Data Reconciliation](#data-reconciliation)

## Architecture Context

Redis is used by ApexMail for:
- **Rate limiting:** Token buckets per tenant (volatile, can be regenerated)
- **Session cache:** User sessions (moderate impact — re-login)
- **Circuit breakers:** Service state machine (can be re-initialized)
- **Email queue retry tracking:** Transient state (can be rebuilt)
- **Analytics counters:** Real-time metrics (will reset, no data loss)
- **Distributed locking:** Failover coordination (locks auto-expire)

**Eviction policy:** dev `noeviction`, prod `volatile-lru` (configured via `REDIS_MAXMEMORY_POLICY` in [`docker-compose.yml`](../../../docker-compose.yml); the prod overlay raises memory to 768mb under a 1G container cap)
**Max memory:** dev 512MB / prod 768MB (`REDIS_MAXMEMORY`; container memory limit set in the compose files)
**Persistence:** AOF with `appendfsync everysec` (the entrypoint in [`deploy/redis/entrypoint.sh`](../../../deploy/redis/entrypoint.sh) owns the config)

**Operator auth (applies to every command below).** The `default` Redis user
(authenticates with the `redis_password` compose secret) has `CONFIG`,
`SHUTDOWN`, `FLUSHALL` and replication commands **revoked** by the ACL in the
entrypoint. Read/diagnostic commands work with it; commands that change
server config need the break-glass `admin` user, enabled by setting
`REDIS_ADMIN_PASSWORD` (see the entrypoint header). The helper used below:

```bash
cd /opt/apexmail
rc() { docker compose -f docker-compose.yml -f docker-compose.prod.yml exec redis \
       sh -c "redis-cli --no-auth-warning -a \"\$(cat /run/secrets/redis_password)\" $*"; }
```

## Symptoms

- Alerts: `HighMemoryUsage` on the redis container, `ApiHighLatencyP99` (Redis calls timing out), `ApiRateLimitThrottling` (rate limiter unavailable = deny)
- Application errors: `redis: connection refused`, `redis: read timeout`, `redis: out of memory`
- Metrics: Redis `used_memory` near `maxmemory`, `evicted_keys` > 0, `rejected_connections` > 0
- Behavioral: Rate limiting fails open? (Check config — default should fail **closed** = deny if Redis down)

## Severity Classification

| Severity | Criteria | Response Time |
|----------|----------|---------------|
| SEV1 | Redis completely down, all features degraded | 10 min |
| SEV2 | High memory usage, OOM, eviction spikes | 20 min |
| SEV3 | Single replica failure (if replicas exist) | 30 min |

## Initial Diagnosis

1. **Check Redis availability:**
   ```bash
   rc PING
   # Expected: PONG
   ```

2. **Check memory usage:**
   ```bash
   rc INFO memory | grep -E 'used_memory|maxmemory|maxmemory_policy'
   ```

3. **Check eviction rate:**
   ```bash
   rc INFO stats | grep evicted_keys
   # If > 0, memory is under pressure
   ```

4. **Check the keyspace hit rate:**
   ```bash
   rc INFO stats | grep -E 'keyspace_hits|keyspace_misses'
   # Hit rate should be > 90%
   ```

5. **Check connected clients:**
   ```bash
   rc INFO clients | grep connected_clients
   ```

6. **Check slow queries:**
   ```bash
   rc SLOWLOG GET 10
   ```

## Recovery Procedures

### Procedure 1: Connection Failure

**When:** Redis is not accepting connections.

1. **Verify the redis container is running:**
   ```bash
   cd /opt/apexmail
   docker compose -f docker-compose.yml -f docker-compose.prod.yml ps redis
   ```

2. **Check Redis logs:**
   ```bash
   cd /opt/apexmail
   docker compose -f docker-compose.yml -f docker-compose.prod.yml logs --tail=100 redis
   ```

3. **Check if Redis crashed and restarted** (restart count and last state):
   ```bash
   docker inspect apexmail-redis --format '{{.RestartCount}} {{.State.Status}} {{.State.ExitCode}}'
   ```

4. **Restart Redis:**
   ```bash
   cd /opt/apexmail
   docker compose -f docker-compose.yml -f docker-compose.prod.yml restart redis
   ```

5. **If persistent disk issue:**
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.prod.yml exec redis df -h /data
   # Check AOF/RDB directory space
   ```

### Procedure 2: Memory Exhaustion

**When:** Redis is evicting keys (`evicted_keys` > 0) or rejecting writes.

1. **Temporarily increase `maxmemory`** (needs the break-glass `admin` user —
   the ACL revokes `CONFIG` from the app user; it only lasts until restart):
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.prod.yml exec redis sh -c \
     'redis-cli --no-auth-warning --user admin -a "$REDIS_ADMIN_PASSWORD" CONFIG SET maxmemory 1536mb'
   # Permanent fix: raise REDIS_MAXMEMORY in the prod env and recreate the
   # service — see step 5.
   ```

2. **Identify largest keys:**
   ```bash
   rc --bigkeys
   ```

3. **Clear non-critical keys:**
   ```bash
   # Flush only specific key patterns (not all!)
   rc KEYS "analytics:*" | head -100 | xargs -r rc DEL
   rc KEYS "temp:*" | xargs -r rc DEL
   ```

4. **Check for memory leak:**
   ```bash
   rc INFO keyspace
   # Compare key count to baseline
   rc DBSIZE
   ```

5. **Permanent fix — raise `REDIS_MAXMEMORY` / change `REDIS_MAXMEMORY_POLICY`**
   in the prod env file, then recreate the service:
   ```bash
   # In /opt/apexmail/.env (or the prod env file): REDIS_MAXMEMORY=1536mb
   cd /opt/apexmail
   docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d redis
   ```

### Procedure 3: Data Loss / Corruption

**When:** AOF or RDB file is corrupted.

1. **Stop Redis:**
   ```bash
   cd /opt/apexmail
   docker compose -f docker-compose.yml -f docker-compose.prod.yml stop redis
   ```

2. **Attempt AOF repair** (the data volume is `redis_data`, mounted at `/data`;
   `redis-check-aof` runs from a throwaway container because the service is stopped):
   ```bash
   cd /opt/apexmail
   docker compose -f docker-compose.yml -f docker-compose.prod.yml run --rm --entrypoint redis-check-aof redis \
     --fix /data/appendonly.aof
   ```

3. **If AOF repair fails:** restore the latest encrypted Redis backup
   (produced by the `redis-backup` service / deploy/hardening — same decrypt
   pattern as the postgres restore in the [db recovery runbook](./db-recovery.md)),
   or rebuild the cache from scratch (step 4) — every Redis consumer in
   ApexMail repopulates (see [Data Reconciliation](#data-reconciliation)).

4. **Rebuild cache from scratch:**
   ```bash
   # Run the cache warming script
   ./deploy/scripts/cache-warm.sh --all --force
   ```

### Procedure 4: Replication Failure

**When:** n/a on this deployment — ApexMail runs a **single** Redis instance;
there are no replicas to sync. (`REPLICAOF` is additionally revoked by the
Redis ACL, so a rogue replication attempt fails closed.) A clustered/replicated
Redis topology is a roadmap item only — see
[`redis-cluster-migration.md`](../../architecture/redis-cluster-migration.md),
which is marked as a roadmap document. If Redis itself is down, follow
[Procedure 1](#procedure-1-connection-failure).

### Procedure 5: AOF / RDB Write Failure

**When:** Persistent storage full or permissions issue.

1. **Check disk space on the redis volume:**
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.prod.yml exec redis df -h /data
   ```

2. **Rewrite the AOF to reclaim space:**
   ```bash
   rc BGREWRITEAOF
   ```

3. **Disable AOF temporarily** (emergency only; needs the break-glass `admin`
   user — the app-user ACL revokes `CONFIG`):
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.prod.yml exec redis sh -c \
     'redis-cli --no-auth-warning --user admin -a "$REDIS_ADMIN_PASSWORD" CONFIG SET appendonly no'
   # Re-enable after recovery: CONFIG SET appendonly yes
   ```

## Post-Recovery Verification

After any Redis recovery procedure:

```bash
# 1. Basic connectivity
rc PING

# 2. Memory within limits
rc INFO memory | grep used_memory_human

# 3. Keyspace functional
rc SET test-key "test-value" EX 10
rc GET test-key
# Should return "test-value" then auto-expire

# 4. Rate limiter functional
rc INCR "rate-limiter:test:counter"

# 5. Application health
curl -sf https://api.apexmail.ee/health/deep | jq '.components.redis'
```

## Data Reconciliation

After a Redis failure with data loss, automatically re-populated data:

| Data Type | Auto-Recovery | Mechanism |
|-----------|---------------|-----------|
| Rate limiter tokens | Yes | Token bucket resets on first request |
| Circuit breakers | Yes | State machine transitions to CLOSED |
| Session cache | Partial | Users re-authenticate |
| Analytics counters | No (best effort) | Counters reset; trend analysis unaffected |
| Distributed locks | Yes | Locks auto-expire via TTL |

Run the cache warming script to speed up recovery:

```bash
./deploy/scripts/cache-warm.sh --rate-limiter --all
```

## Related

- [Cache Warming Strategy](../cache-warming.md)
- [docker-compose.yml (Redis service)](../../../docker-compose.yml)
- [Cache warming script](../../../deploy/scripts/cache-warm.sh)
- [Incident Response Runbook](./incident-response.md)
