# Redis Cluster Migration Strategy

> **Document Owner:** Infrastructure Team
> **Last Updated:** 2026-05-11
> **Related:** [`docker-compose.yml` Redis service](../../docker-compose.yml), [`rate-limiter/src/redis_limiter.rs`](../../services/mail-server/crates/rate-limiter/src/redis_limiter.rs)

## 1. Overview

ApexMail currently uses a single-node Redis deployment for rate limiting, caching, and session storage. As traffic scales, this single-node architecture presents risks:

- **Single point of failure** — Redis downtime affects rate limiting, caching, and sessions
- **Memory bottleneck** — Single node memory cap limits cache sizes
- **No horizontal scaling** — Cannot distribute load across nodes
- **No failover** — Manual recovery required on node failure

This document evaluates the migration to a clustered Redis topology.

## 2. Redis Cluster vs Redis Sentinel

### 2.1 Comparison

| Feature | Redis Cluster | Redis Sentinel |
|---------|--------------|----------------|
| **Sharding** | Automatic (16384 slots) | None (single primary) |
| **High Availability** | Automatic failover | Automatic failover |
| **Write Scaling** | Multi-primary writes | Single primary |
| **Read Scaling** | Read from any replica | Read from replicas |
| **Client Complexity** | Cluster-aware client required | Standard client + sentinel |
| **Multi-Key Operations** | All keys must be in same slot | Supported globally |
| **Pipeline Support** | Limited (keys must be in same slot) | Full support |
| **Scan/KEYS** | Cluster-wide scan required | Single node |
| **Data Loss on Failover** | Up to 5 seconds (asynchronous replication) | Up to 5 seconds |
| **Minimum Nodes** | 3 masters + 3 replicas | 1 primary + 2 replicas + 3 sentinels |
| **Operational Complexity** | Higher | Moderate |

### 2.2 Recommendation: Redis Cluster

**Redis Cluster is recommended** for ApexMail because:

1. **Rate limiting scales horizontally** — Different tenants' rate limit counters are distributed across shards
2. **Cache capacity grows with nodes** — Total cache memory = sum of all node memories
3. **Automatic sharding** eliminates manual key distribution
4. **No single point of failure** — Automatic failover for each shard
5. **Future-proof** — Cluster can grow from 3 to 10+ nodes

**Exception:** For `billing-service` Lua scripts that use multi-key operations, use **hash tags** `{billing}` to pin keys to the same slot.

## 3. Recommended Topology

### 3.1 Initial Deployment (3 Shards)

```
┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│  Master A   │  │  Master B   │  │  Master C   │
│  Slot 0-5460│  │  Slot 5461-│  │  Slot 10923-│
│             │  │  10922     │  │  16383     │
└──────┬──────┘  └──────┬──────┘  └──────┬──────┘
       │                 │                 │
┌──────┴──────┐  ┌──────┴──────┐  ┌──────┴──────┐
│  Replica A1 │  │  Replica B1 │  │  Replica C1 │
└─────────────┘  └─────────────┘  └─────────────┘
```

### 3.2 Resource Requirements

| Component | CPU | Memory | Storage | Count |
|-----------|-----|--------|---------|-------|
| Master | 2 cores | 4GB RAM | 10GB SSD | 3 |
| Replica | 2 cores | 4GB RAM | 10GB SSD | 3 |
| **Total** | **12 cores** | **24GB RAM** | **60GB SSD** | **6** |

### 3.3 Helm Configuration

```yaml
# deploy/helm/apexmail/values.yaml (redis section)
redis:
  architecture: cluster
  cluster:
    nodes: 6
    replicas: 1
    shards: 3
  master:
    resources:
      requests:
        cpu: 1
        memory: 2Gi
      limits:
        cpu: 2
        memory: 4Gi
    persistence:
      size: 10Gi
  replica:
    resources:
      requests:
        cpu: 500m
        memory: 1Gi
      limits:
        cpu: 2
        memory: 4Gi
    persistence:
      size: 10Gi
  metrics:
    enabled: true
    serviceMonitor:
      enabled: true
```

## 4. Data Migration Procedure

### 4.1 Prerequisites

- [ ] Redis Cluster deployed and operational (6 nodes: 3 masters + 3 replicas)
- [ ] All client libraries updated to support Redis Cluster
- [ ] Rate limiter Lua scripts updated to use hash tags where needed
- [ ] Rollback plan documented and tested
- [ ] Maintenance window scheduled

### 4.2 Pre-Migration

```bash
# 1. Export data from single-node Redis
redis-cli --rdb /tmp/redis-dump.rdb

# 2. Take inventory of key patterns
redis-cli --scan --pattern '*' | sort -u > /tmp/redis-keys.txt

# 3. Check key distribution by hash slot
redis-cli --cluster check localhost:6379

# 4. Verify hash tag usage for multi-key operations
grep -r "redis.call" services/mail-server/crates/rate-limiter/src/*.rs
grep -r "redis::pipe" services/mail-server/crates/rate-limiter/src/*.rs
```

### 4.3 Migration Steps

```bash
# Step 1: Set up Redis Cluster with empty nodes
helm upgrade --install redis deploy/helm/apexmail/charts/redis \
  --set architecture=cluster \
  --set cluster.nodes=6 \
  --set cluster.replicas=1 \
  --set cluster.shards=3

# Step 2: Verify cluster status
redis-cli -h redis-cluster -p 6379 CLUSTER INFO
redis-cli -h redis-cluster -p 6379 CLUSTER NODES

# Step 3: Migrate data using redis-cli (offline method)
# Note: This requires a maintenance window
redis-cli -h old-redis -p 6379 --rdb /tmp/dump.rdb
# Shutdown old Redis, start cluster, restore RDB to one node
# Let cluster replicate automatically

# Step 4: Alternative: Online migration using redis-migrate
pip install redis-trib
redis-trib.rb migrate old-redis:6379 redis-cluster:6379

# Step 5: Verify data integrity
redis-cli -h redis-cluster -p 6379 DBSIZE
redis-cli -h old-redis -p 6379 DBSIZE
# Verify specific keys
redis-cli -h redis-cluster -p 6379 GET rate_limit:config:tenant-123
```

### 4.4 Client-Side Migration

```rust
// Before: Single-node Redis connection
let client = redis::Client::open(redis_url)?;
let mut conn = client.get_async_connection().await?;

// After: Redis Cluster connection
use redis::cluster::ClusterClient;

let nodes = vec![
    "redis://redis-cluster-0:6379",
    "redis://redis-cluster-1:6379",
    "redis://redis-cluster-2:6379",
    "redis://redis-cluster-3:6379",
    "redis://redis-cluster-4:6379",
    "redis://redis-cluster-5:6379",
];
let client = ClusterClient::new(nodes)?;

// Use cluster connection (routes to correct node automatically)
let mut conn = client.get_async_connection().await?;
```

### 4.5 Hash Tag Usage

For multi-key operations (Lua scripts), use `{tags}` to ensure all keys hash to the same slot:

```lua
-- Before (keys may be on different slots):
local tokens = redis.call('HMGET', 'rate_limit:budget:tenant-123', 'tokens', 'last_refill')

-- After (hash tags ensure same slot):
local tokens = redis.call('HMGET', '{rate_limit}:budget:tenant-123', 'tokens', 'last_refill')
```

```rust
// Rust helper for hash tags
pub fn rate_limiter_key(tenant_id: &str, key: &str) -> String {
    // Use hash tag to ensure tenant keys are on the same slot
    format!("{{rate_limit}}:{}:{}", tenant_id, key)
}
```

## 5. Client-Side Routing Changes

### 5.1 Required Code Changes

| File | Change | Priority |
|------|--------|----------|
| [`rate-limiter/src/redis_limiter.rs`](../../services/mail-server/crates/rate-limiter/src/redis_limiter.rs) | Switch from `redis::Client` to `redis::cluster::ClusterClient` | Critical |
| [`analytics/src/send_time_optimizer.rs`](../../services/mail-server/crates/analytics/src/send_time_optimizer.rs) | Update Redis connection for cluster | High |
| `api-server/src/session.rs` | Update session store for cluster | High |
| `billing-service/src/usage.rs` | Add hash tags to Lua scripts | Medium |
| `observability-service/src/config.rs` | Update Redis URL parsing for multiple nodes | Medium |

### 5.2 Configuration Changes

```yaml
# Before (single node):
REDIS_URL: "redis://redis-master:6379"

# After (cluster):
REDIS_CLUSTER_NODES: "redis://redis-cluster-0:6379,redis://redis-cluster-1:6379,redis://redis-cluster-2:6379,redis://redis-cluster-3:6379,redis://redis-cluster-4:6379,redis://redis-cluster-5:6379"
REDIS_CLUSTER_ENABLED: "true"
```

## 6. Monitoring Cluster Health

### 6.1 Prometheus Metrics

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| `redis_cluster_state` | 1 = OK, 0 = FAIL | 0 for > 1m |
| `redis_cluster_slots_ok` | Number of slots in OK state | < 16384 |
| `redis_cluster_known_nodes` | Total nodes in cluster | < 6 |
| `redis_cluster_size` | Number of master nodes | < 3 |
| `redis_memory_used_bytes` | Memory used per node | > 80% of limit |
| `redis_cpu_sys_seconds_total` | CPU utilization | > 80% |
| `redis_connected_clients` | Connected clients per node | > 1000 |
| `redis_cluster_failover_count` | Failover events | > 0 in 1h |

### 6.2 Grafana Dashboard

The existing [`Redis dashboard`](../../deploy/grafana/dashboards/redis.json) should be updated to include:

- Cluster topology visualization
- Per-shard memory and CPU usage
- Slot distribution map
- Failover event timeline
- Client connection distribution

### 6.3 Health Check Commands

```bash
# Cluster info
redis-cli -h redis-cluster -p 6379 CLUSTER INFO

# Node list
redis-cli -h redis-cluster -p 6379 CLUSTER NODES

# Check slot assignment
redis-cli -h redis-cluster -p 6379 CLUSTER SLOTS

# Check for FAIL nodes
redis-cli -h redis-cluster -p 6379 CLUSTER NODES | grep fail

# Memory stats per node
for node in redis-cluster-0 redis-cluster-1 redis-cluster-2; do
    echo "=== $node ==="
    redis-cli -h $node -p 6379 INFO memory | grep used_memory_human
    redis-cli -h $node -p 6379 INFO stats | grep -E "keyspace|expired"
done
```

## 7. Failover Testing Procedures

### 7.1 Manual Failover Test

```bash
# 1. Identify a master node
MASTER_NODE=$(redis-cli -h redis-cluster -p 6379 CLUSTER NODES | grep master | head -1 | awk '{print $1}')

# 2. Trigger manual failover to replica
redis-cli -h redis-cluster -p 6379 CLUSTER FAILOVER

# 3. Verify cluster recovered
redis-cli -h redis-cluster -p 6379 CLUSTER INFO | grep cluster_state
# Expected: cluster_state:ok

# 4. Verify data still accessible
redis-cli -h redis-cluster -p 6379 GET rate_limit:config:tenant-test

# 5. Verify metrics
curl http://redis-exporter:9121/metrics | grep redis_cluster_state

# 6. Verify application health
curl http://api-server:3000/health
```

### 7.2 Node Failure Test

```bash
# 1. Kill a master node
kubectl exec redis-cluster-0 -- kill 1

# 2. Wait for failover (10-15 seconds)
sleep 15

# 3. Verify replica promoted to master
redis-cli -h redis-cluster -p 6379 CLUSTER NODES | grep master

# 4. Verify cluster state
redis-cli -h redis-cluster -p 6379 CLUSTER INFO | grep cluster_state

# 5. Verify rate limiting still works
curl -X POST http://api-server:3000/v1/messages \
  -H "X-API-Key: <test-api-key>" \
  -H "Content-Type: application/json" \
  -d '{"to": ["test@example.com"], "subject": "test", "text_body": "test"}'

# 6. Restart killed node
kubectl rollout restart statefulset redis-cluster
```

### 7.3 Network Partition Test

```bash
# 1. Isolate a master node
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: redis-isolate-test
  namespace: apexmail
spec:
  podSelector:
    matchLabels:
      statefulset.kubernetes.io/pod-name: redis-cluster-0
  policyTypes:
  - Ingress
  - Egress
EOF

# 2. Wait for cluster to detect partition
sleep 30

# 3. Verify cluster remains available
redis-cli -h redis-cluster -p 6379 CLUSTER INFO | grep cluster_state

# 4. Remove isolation
kubectl delete networkpolicy redis-isolate-test

# 5. Verify node rejoins
redis-cli -h redis-cluster -p 6379 CLUSTER NODES | grep redis-cluster-0
```

## 8. Rollback Plan

### 8.1 Rollback Triggers

- Cluster fails to form (nodes cannot see each other)
- Data inconsistency detected during migration
- Application errors related to Redis connectivity
- Latency increases > 2x baseline
- More than 10% of rate limit operations fail

### 8.2 Rollback Steps

```bash
# 1. Switch application back to single-node Redis
kubectl set env deployment/api-server REDIS_CLUSTER_ENABLED=false
kubectl set env deployment/api-server REDIS_URL="redis://redis-fallback:6379"

# 2. Verify application health
kubectl rollout status deployment/api-server

# 3. Scale down cluster
helm upgrade --install redis deploy/helm/apexmail/charts/redis \
  --set architecture=standalone

# 4. Restore data from backup
redis-cli -h redis-fallback -p 6379 --pipe < /tmp/redis-dump.rdb

# 5. Verify all operations
curl http://api-server:3000/health
```

## 9. Capacity Planning

| Metric | Current (Single) | Target (Cluster) | Growth Factor |
|--------|-----------------|-------------------|---------------|
| Max Memory | 4GB | 24GB (6 × 4GB) | 6x |
| Max Connections | 10,000 | 60,000 | 6x |
| Write Throughput | ~50K ops/s | ~300K ops/s | 6x |
| Read Throughput | ~100K ops/s | ~600K ops/s (with replicas) | 6x |
| Availability | Single point of failure | Automatic failover | HA |
| Shards | 1 | 3 | 3x |

## 10. Production Readiness Checklist

- [ ] All Lua scripts use `{hash_tags}` for multi-key operations
- [ ] All client libraries updated to `redis::cluster::ClusterClient`
- [ ] `REDIS_CLUSTER_ENABLED` feature flag implemented
- [ ] Cluster exporter and metrics configured
- [ ] Grafana dashboard updated with cluster panels
- [ ] Alerting rules deployed for cluster state
- [ ] Failover test completed successfully
- [ ] Network partition test completed successfully
- [ ] Rollback plan verified
- [ ] Capacity monitoring in place
- [ ] Backup/recovery procedure updated for cluster
