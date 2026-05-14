# Network Partition Runbook

**Severity:** SEV1–SEV2 (partial or full region isolation)

## Table of Contents
- [Architecture Context](#architecture-context)
- [Symptoms](#symptoms)
- [Initial Diagnosis](#initial-diagnosis)
- [Recovery Procedures](#recovery-procedures)
  - [Procedure 1: Single Service Partition](#procedure-1-single-service-partition)
  - [Procedure 2: Cross-Region Partition (Finland ↔ Germany)](#procedure-2-cross-region-partition-finland--germany)
  - [Procedure 3: Full Region Isolation](#procedure-3-full-region-isolation)
- [Post-Recovery Verification](#post-recovery-verification)
- [Prevention](#prevention)

## Architecture Context

ApexMail runs across two Hetzner regions (Finland primary, Germany standby) with:
- **WireGuard tunnel** for cross-region PostgreSQL streaming replication
- **Redis replication** across regions for cache and circuit breaker state
- **Zone.ee DNS** for regional failover routing
- **Kubernetes Network Policies** for intra-service communication
- **Circuit breakers** with Redis-backed state to prevent cascading failures

## Symptoms

- Alerts: `PodNetworkUnavailable`, `ApiHighLatencyP99` (timeout errors), replication lag spike
- Application errors: `connection timeout`, `connection reset by peer`, `i/o timeout`
- Metrics: dropped packets on WireGuard interface, TCP retransmit rate > 5%
- Users: intermittent errors, partial data visibility

## Initial Diagnosis

1. **Check cross-region connectivity:**
   ```bash
   # Ping WireGuard tunnel endpoint
   kubectl exec -n apexmail deploy/api-server -- ping -c 5 <standby-wireguard-ip>
   
   # Check WireGuard interface status
   kubectl exec -n apexmail deploy/wireguard -- wg show
   ```

2. **Check Kubernetes network policies:**
   ```bash
   kubectl get networkpolicies -n apexmail
   kubectl describe networkpolicies -n apexmail
   ```

3. **Check DNS resolution:**
   ```bash
   kubectl exec -n apexmail deploy/api-server -- nslookup postgres.apexmail.svc.cluster.local
   kubectl exec -n apexmail deploy/api-server -- nslookup api.apexmail.ee
   ```

4. **Check circuit breaker states:**
   ```bash
   # Circuit breaker keys stored in Redis
   kubectl exec -n apexmail deploy/redis-master -- redis-cli KEYS "circuit-breaker:*"
   kubectl exec -n apexmail deploy/redis-master -- redis-cli GET "circuit-breaker:postgres-primary"
   kubectl exec -n apexmail deploy/redis-master -- redis-clI GET "circuit-breaker:redis-standby"
   ```

5. **Check replication lag:**
   ```bash
   kubectl exec -n apexmail deploy/postgres -- psql -U apexmail -c \
     "SELECT pid, application_name, state, sync_state,
             pg_wal_lsn_diff(pg_current_wal_lsn(), replay_lsn) AS lag_bytes
      FROM pg_stat_replication;"
   ```

## Recovery Procedures

### Procedure 1: Single Service Partition

A single service (e.g., `api-server`) cannot reach a dependency.

1. **Identify which service is partitioned:**
   ```bash
   # Check connectivity from each service to its dependencies
   kubectl exec -n apexmail deploy/api-server -- curl -sf --connect-timeout 5 http://postgres:5432
   kubectl exec -n apexmail deploy/api-server -- curl -sf --connect-timeout 5 http://redis-master:6379
   ```

2. **Restart the affected pods** (may re-establish connections):
   ```bash
   kubectl rollout restart deployment/api-server -n apexmail
   ```

3. **Check if NetworkPolicy is blocking:**
   ```bash
   # Check if there are dropped packets
   kubectl exec -n apexmail deploy/api-server -- iptables -L -n -v 2>/dev/null | grep DROP
   ```

4. **Temporarily relax NetworkPolicy** for diagnosis:
   ```bash
   kubectl label pod -n apexmail -l app=api-server network-policy=debug
   ```

### Procedure 2: Cross-Region Partition (Finland ↔ Germany)

The WireGuard tunnel between regions is down.

1. **Check WireGuard status on both sides:**
   ```bash
   # Finland
   kubectl exec -n apexmail deploy/wireguard-fi -- wg show
   # Germany
   kubectl exec -n apexmail deploy/wireguard-de -- wg show
   ```

2. **Restart WireGuard on both sides:**
   ```bash
   kubectl rollout restart deploy/wireguard-fi -n apexmail
   kubectl rollout restart deploy/wireguard-de -n apexmail
   ```

3. **Check firewall rules** (Hetzner Cloud Firewall):
   ```bash
   # Verify UDP port 51820 is open on both sides
   # Check for any Hetzner Cloud Firewall changes
   # Review: https://console.hetzner.cloud/firewall
   ```

4. **If tunnel cannot be restored, enter failover state:**
   ```bash
   # Promote Germany replica to primary
   ./scripts/dr-failover.sh --execute --skip-fencing
   ```

5. **While partitioned, both regions operate independently:**
   - Finland continues with local PostgreSQL
   - Germany processes writes on promoted primary
   - Data sync must be resolved when partition heals

### Procedure 3: Full Region Isolation

The entire Finland (primary) region is isolated from the internet.

1. **Check external connectivity:**
   ```bash
   # From a Finland node
   kubectl exec -n apexmail deploy/api-server -- curl -sf https://api.apexmail.ee/v1/health
   # From external monitoring (e.g., Grafana, external probes)
   curl -sf https://api.apexmail.ee/v1/health
   ```

2. **If Finland is isolated but Germany is reachable:**
   - Execute failover to Germany as per Procedure 2 in disaster-recovery.md
   - Update DNS to point to Germany ingress IP
   ```bash
   ./scripts/dr-failover.sh --execute
   ```

3. **If Germany is isolated but Finland is healthy:**
   - Verify replication is paused (not failing)
   - Check circuit breaker: Germany should be marked as `half-open`
   - Monitor for partition healing — replication resumes automatically
   ```bash
   # Set Germany circuit breaker to half-open
   kubectl exec -n apexmail deploy/redis-master -- redis-cli SET "circuit-breaker:germany" "half-open" EX 300
   ```

4. **During partition, consider degraded mode:**
   - Disable non-critical cross-region features (cross-region analytics queries)
   - Increase circuit breaker timeouts to avoid premature tripping
   - Alert on-call infrastructure team with timeline

## Post-Recovery Verification

After the network partition heals:

```bash
# 1. Verify WireGuard tunnel
kubectl exec -n apexmail deploy/wireguard-fi -- wg show | grep -c "latest handshake"
# Should be > 0 (handshake completed)

# 2. Verify replication resumed
kubectl exec -n apexmail deploy/postgres -- psql -U apexmail -c \
  "SELECT pg_wal_lsn_diff(pg_current_wal_lsn(), replay_lsn) AS lag_bytes
   FROM pg_stat_replication;"
# Should be < 100MB

# 3. Verify data consistency (compare checksums)
kubectl exec -n apexmail deploy/postgres -- psql -U apexmail -c \
  "SELECT schemaname, tablename, n_live_tup
   FROM pg_stat_user_tables
   ORDER BY n_live_tup DESC;"

# 4. Reset circuit breakers
kubectl exec -n apexmail deploy/redis-master -- redis-cli DEL "circuit-breaker:germany" "circuit-breaker:postgres-standby"

# 5. Verify application health
curl -sf https://api.apexmail.ee/v1/health | jq '.'
```

## Prevention

- **Monitor WireGuard handshake age** (< 5 min is healthy). Alert in Prometheus:
  ```yaml
  # Prometheus alert rule
  - alert: WireGuardHandshakeStale
    expr: time() - node_network_up{device="wg0"} > 300
    for: 1m
  ```

- **Configure keepalive** on WireGuard (25 seconds):
  ```
  PersistentKeepalive = 25
  ```

- **Test network partition quarterly** as part of DR testing.
- **Review Kubernetes NetworkPolicy** log entries for blocked traffic patterns.
- **Circuit breakers** should have Redis-backed persistence to survive pod restarts.

## Related

- [Disaster Recovery & Backup Procedures](../disaster-recovery.md)
- [DR Failover Script](../../scripts/dr-failover.sh)
- [Infrastructure alerting rules](../../deploy/prometheus/alerts/infrastructure-alerts.yml)
- [Helm chart network policies](../../deploy/helm/apexmail/values.yaml:476)
