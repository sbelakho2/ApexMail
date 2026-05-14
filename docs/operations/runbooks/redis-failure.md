# Redis Failure Runbook

**Severity:** SEV1–SEV3 (depending on impact)

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

**Eviction policy:** `allkeys-lru` (configured in [`values.yaml`](../../deploy/helm/apexmail/values.yaml:380))
**Max memory:** 512MB (configuration), 1Gi limit (values.yaml:390)
**Persistence:** AOF with `appendfsync everysec`

## Symptoms

- Alerts: `HighMemoryUsage` on Redis pods, `ApiHighLatencyP99` (Redis calls timing out), `ApiRateLimitThrottling` (rate limiter unavailable = deny)
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
   kubectl exec -n apexmail deploy/redis-master -- redis-cli PING
   # Expected: PONG
   ```

2. **Check memory usage:**
   ```bash
   kubectl exec -n apexmail deploy/redis-master -- redis-cli INFO memory | grep -E 'used_memory|maxmemory|maxmemory_policy'
   ```

3. **Check eviction rate:**
   ```bash
   kubectl exec -n apexmail deploy/redis-master -- redis-cli INFO stats | grep evicted_keys
   # If > 0, memory is under pressure
   ```

4. **Check the keyspace hit rate:**
   ```bash
   kubectl exec -n apexmail deploy/redis-master -- redis-cli INFO stats | grep -E 'keyspace_hits|keyspace_misses'
   # Hit rate should be > 90%
   ```

5. **Check connected clients:**
   ```bash
   kubectl exec -n apexmail deploy/redis-master -- redis-cli INFO clients | grep connected_clients
   ```

6. **Check slow queries:**
   ```bash
   kubectl exec -n apexmail deploy/redis-master -- redis-cli SLOWLOG GET 10
   ```

## Recovery Procedures

### Procedure 1: Connection Failure

**When:** Redis is not accepting connections.

1. **Verify Redis process is running:**
   ```bash
   kubectl exec -n apexmail deploy/redis-master -- ps aux | grep redis
   ```

2. **Check Redis logs:**
   ```bash
   kubectl logs -n apexmail deploy/redis-master --tail=100
   ```

3. **Check if Redis crashed:**
   ```bash
   kubectl describe pod -n apexmail -l app.kubernetes.io/name=redis
   # Check restart count and last state
   ```

4. **Restart Redis:**
   ```bash
   kubectl rollout restart deploy/redis-master -n apexmail
   ```

5. **If persistent disk issue:**
   ```bash
   kubectl exec -n apexmail deploy/redis-master -- df -h
   # Check AOF/RDB directory space
   ```

### Procedure 2: Memory Exhaustion

**When:** Redis is evicting keys (`evicted_keys` > 0) or rejecting writes.

1. **Temporarily increase `maxmemory`:**
   ```bash
   kubectl exec -n apexmail deploy/redis-master -- redis-cli CONFIG SET maxmemory "1gb"
   # Note: This only lasts until restart. Update Helm values permanently.
   ```

2. **Identify largest keys:**
   ```bash
   kubectl exec -n apexmail deploy/redis-master -- redis-cli --bigkeys
   ```

3. **Clear non-critical keys:**
   ```bash
   # Flush only specific key patterns (not all!)
   kubectl exec -n apexmail deploy/redis-master -- redis-cli KEYS "analytics:*" | head -100 | xargs -r redis-cli DEL
   kubectl exec -n apexmail deploy/redis-master -- redis-cli KEYS "temp:*" | xargs -r redis-cli DEL
   ```

4. **Check for memory leak:**
   ```bash
   kubectl exec -n apexmail deploy/redis-master -- redis-cli INFO keyspace
   # Compare key count to baseline
   kubectl exec -n apexmail deploy/redis-master -- redis-cli DBSIZE
   ```

5. **Permanent fix update [`values.yaml`](../../deploy/helm/apexmail/values.yaml:379):**
   ```yaml
   redis:
     configuration: |-
       maxmemory 2gb
       maxmemory-policy allkeys-lru
   ```

### Procedure 3: Data Loss / Corruption

**When:** AOF or RDB file is corrupted.

1. **Stop Redis:**
   ```bash
   kubectl scale deployment redis-master -n apexmail --replicas=0
   ```

2. **Attempt AOF repair:**
   ```bash
   # Find the AOF file
   kubectl exec -n apexmail deploy/redis-master -- ls -la /data/appendonly.aof
   # Run redis-check-aof
   kubectl exec -n apexmail deploy/redis-master -- redis-check-aof --fix /data/appendonly.aof
   ```

3. **If AOF repair fails, start without persistence:**
   ```bash
   kubectl exec -n apexmail deploy/redis-master -- redis-server \
     --appendonly no --save "" --loadmodule /usr/lib/redis/modules/redisbloom.so
   ```

4. **Rebuild cache from scratch:**
   ```bash
   # Run the cache warming script
   ./deploy/scripts/cache-warm.sh --all --force
   ```

### Procedure 4: Replication Failure

**When:** Redis replicas are not syncing.

1. **Check replication status:**
   ```bash
   kubectl exec -n apexmail deploy/redis-master -- redis-cli INFO replication
   ```

2. **Check replica connectivity:**
   ```bash
   kubectl exec -n apexmail deploy/redis-replica -- redis-cli PING
   kubectl exec -n apexmail deploy/redis-replica -- redis-cli ROLE
   ```

3. **Re-sync from master:**
   ```bash
   kubectl exec -n apexmail deploy/redis-replica -- redis-cli REPLICAOF <master-ip> 6379
   ```

### Procedure 5: AOF / RDB Write Failure

**When:** Persistent storage full or permissions issue.

1. **Check disk space on Redis volume:**
   ```bash
   kubectl exec -n apexmail deploy/redis-master -- df -h /data
   ```

2. **Clean up old AOF files:**
   ```bash
   kubectl exec -n apexmail deploy/redis-master -- redis-cli BGREWRITEAOF
   ```

3. **Disable AOF temporarily** (emergency only):
   ```bash
   kubectl exec -n apexmail deploy/redis-master -- redis-cli CONFIG SET appendonly no
   # Re-enable after recovery: CONFIG SET appendonly yes
   ```

## Post-Recovery Verification

After any Redis recovery procedure:

```bash
# 1. Basic connectivity
kubectl exec -n apexmail deploy/redis-master -- redis-cli PING

# 2. Memory within limits
kubectl exec -n apexmail deploy/redis-master -- redis-cli INFO memory | grep used_memory_human

# 3. Keyspace functional
kubectl exec -n apexmail deploy/redis-master -- redis-cli SET test-key "test-value" EX 10
kubectl exec -n apexmail deploy/redis-master -- redis-cli GET test-key
# Should return "test-value" then auto-expire

# 4. Rate limiter functional
kubectl exec -n apexmail deploy/redis-master -- redis-cli INCR "rate-limiter:test:counter"

# 5. Application health
curl -sf https://api.apexmail.ee/v1/health | jq '.components.redis'
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
- [Helm chart values (Redis)](../../deploy/helm/apexmail/values.yaml:374)
- [Cache warming script](../../deploy/scripts/cache-warm.sh)
- [Incident Response Runbook](./incident-response.md)
