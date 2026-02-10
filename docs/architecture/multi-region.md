# Multi-Region Deployment Architecture

> **ApexMail** — High availability, failover orchestration, and disaster recovery across European infrastructure.

---

## Table of Contents

- [Overview](#overview)
- [Infrastructure Layout](#infrastructure-layout)
- [Routing Modes](#routing-modes)
- [Failover State Machine](#failover-state-machine)
- [Circuit Breakers](#circuit-breakers)
- [Replication Monitoring](#replication-monitoring)
- [Chaos Engineering Framework](#chaos-engineering-framework)
- [Data Residency](#data-residency)
- [Backup Strategy](#backup-strategy)
- [DNS Failover](#dns-failover)
- [Operational Runbooks](#operational-runbooks)

---

## Overview

ApexMail runs entirely on **European infrastructure**. Both primary and standby servers are hosted in the EU via [Hetzner](https://www.hetzner.com/), with DNS managed through [Zone.ee](https://www.zone.ee/). No AWS, GCP, or Azure infrastructure is used for core platform services. The only exception is that certain outbound email processing paths may route through AWS SES as a secondary delivery provider for specific ISP-level deliverability optimisation.

The HA (High Availability) application (`apps/ha/`) provides the core infrastructure for routing, failover, circuit breaking, and replication monitoring.

### Design Principles

| Principle | Implementation |
|-----------|----------------|
| **EU-only data residency** | All data stored in Hetzner datacentres (Finland and Germany) |
| **Zero data loss** | PostgreSQL streaming replication with synchronous commit option |
| **Minimal downtime** | Automated failover with fencing tokens and STONITH |
| **No cloud vendor lock-in** | Hetzner Cloud ARM servers, no proprietary cloud services |

---

## Infrastructure Layout

```
                        ┌──────────────────┐
                        │     Zone.ee      │
                        │    DNS Manager    │
                        └────────┬─────────┘
                                 │
                 ┌───────────────┼───────────────┐
                 │                               │
        ┌────────▼────────┐            ┌─────────▼───────┐
        │  Hetzner Finland │            │  Hetzner Germany │
        │    (Primary)     │            │    (Standby)     │
        │                  │            │                  │
        │  API, Web, MTA   │ ──WAL──▶  │  API, Web, MTA   │
        │  Worker, Tracking│ streaming  │  Worker, Tracking│
        │  PostgreSQL (RW) │ repl.      │  PostgreSQL (RO) │
        │  Redis (primary) │            │  Redis (replica) │
        └──────────────────┘            └──────────────────┘
                 │
                 │  outbound email (secondary path only)
                 ▼
        ┌──────────────────┐
        │   AWS SES (EU)   │  ← used only as a fallback
        │   eu-west-1      │    delivery provider for
        └──────────────────┘    specific ISP optimisation
```

### Service Distribution

| Service | Finland (Primary) | Germany (Standby) | Notes |
|---------|-------------------|-------------------|-------|
| API (Hono) | ✅ Active | ⏳ Hot standby | Port 3000 |
| Web App (Next.js) | ✅ Active | ⏳ Hot standby | Customer dashboard |
| MTA Inbound | ✅ Active | ⏳ Hot standby | Ports 25/465, 2525, 2526 |
| Worker | ✅ Active | ⏳ Hot standby | Email sending, webhooks, analytics |
| Tracking | ✅ Active | ⏳ Hot standby | Port 3002 |
| Control Plane | ✅ Active | ❌ Not replicated | Port 3020, internal only |
| PostgreSQL | ✅ Primary (RW) | ✅ Replica (RO) | Streaming replication |
| Redis | ✅ Primary | ✅ Replica | Sentinel-managed |
| Billing | ✅ Active | ⏳ Hot standby | Port 4100, Stripe EU |

---

## Routing Modes

ApexMail supports **6 routing modes**, selectable per deployment:

### 1. Active-Passive (Default)

```
                    ┌─────────────────┐
  All traffic ────▶ │  Hetzner Finland │
                    │    (Primary)     │
                    └────────┬────────┘
                             │ streaming replication
                    ┌────────▼────────┐
                    │  Hetzner Germany  │
                    │    (Standby)     │  ← receives WAL, no client queries
                    └─────────────────┘
```

- **Write path:** All writes go to the Finland primary.
- **Read path:** All reads go to the Finland primary.
- **Standby role:** Germany receives the WAL stream. Promoted only on primary failure.
- **Use case:** Default configuration. Simplest operation, suitable for most deployments.

### 2. Active-Active (Read Replicas)

```
  Read traffic ──┬──▶ │   Finland    │ ◀── streaming replication ──▶ │   Germany    │ ◀──┬── Read traffic
                 │    └──────────────┘                                └──────────────┘    │
  Write traffic ─┘         ▲                                                              └─ Write traffic
                           └───────────── All writes routed to Finland ───────────────────────┘
```

- **Write path:** All writes routed to Finland primary regardless of which server receives the request.
- **Read path:** Reads can be served from either location.
- **Consistency:** Reads from Germany replica may be slightly stale (async replication lag, typically < 50ms within EU).
- **Use case:** Read-heavy workloads where distributing analytics/dashboard queries reduces primary load.

### 3. Geographic

- Routes requests by **client location** (IP geolocation or tenant configuration).
- Both regions are in the EU, so this primarily optimises latency for Nordic vs Central European users.
- Tenant-level override available for organisations with specific sub-EU residency requirements (e.g., data must stay in Germany only).

### 4. Latency-Based

- Routes each request to the server with the **lowest measured latency** from the client.
- Latency measured via periodic health probes from internal monitoring.
- Dynamic — routing decisions update as network conditions change.
- Within the EU, latency difference between Finland and Germany is typically 15–30ms.

### 5. Weighted

- Distributes traffic according to **configured weight percentages**.
- Example: 80% to Finland, 20% to Germany.
- Useful for gradual migrations, capacity testing, or load shedding during maintenance.
- Weights adjustable dynamically without redeployment.

### 6. Failover

- Finland receives 100% of traffic.
- On health check failure, traffic **automatically fails over** to Germany.
- Health checks run every 10 seconds from multiple internal monitoring nodes.
- Failback can be automatic or manual, depending on configuration.

---

## Failover State Machine

### Leader Election

Failover decisions are coordinated through a **distributed leader election** backed by Redis:

```
┌─────────────────────────────────────────────────────┐
│                  Leader Election                     │
│                                                     │
│  1. Candidate acquires Redis distributed lock       │
│     SET failover:leader <worker-id> NX PX 30000     │
│                                                     │
│  2. Leader holds lock with periodic renewal          │
│     Every 10s: SET failover:leader ... XX PX 30000  │
│                                                     │
│  3. If leader fails to renew, lock expires           │
│     Another candidate acquires leadership            │
└─────────────────────────────────────────────────────┘
```

Only the elected leader can initiate failover operations. This prevents split-brain scenarios where multiple nodes independently decide to trigger failover.

### Fencing Tokens

To prevent **split-brain during network partitions**, the failover system uses monotonically increasing **fencing tokens**:

```typescript
interface FencingToken {
    epoch: number;      // Monotonically increasing, persisted in PostgreSQL
    issuedAt: Date;     // When the token was issued
    issuedBy: string;   // Which node issued the token
    expiresAt: Date;    // Token validity window
}
```

**How fencing prevents split-brain:**

1. When a new leader is elected, it increments the global epoch counter and issues a fencing token.
2. All operations (replication commands, DNS updates, promotion) include the fencing token.
3. Recipients reject operations with a fencing token older than the last seen token.
4. If a stale leader (partitioned away, then reconnected) attempts to issue commands, its old fencing token is rejected.

### STONITH Fencing

For **hard failure scenarios** where a node is unresponsive but may still be accepting writes, the system implements **STONITH (Shoot The Other Node In The Head)**:

| Step | Action |
|------|--------|
| 1 | Leader detects Finland primary is unreachable. |
| 2 | Leader acquires STONITH lock in Redis. |
| 3 | Leader issues shutdown command to old primary via Hetzner Cloud API or SSH. |
| 4 | Leader waits for confirmation of shutdown (or timeout). |
| 5 | Leader promotes Germany standby to primary. |
| 6 | Leader updates Zone.ee DNS to route traffic to Germany. |

STONITH ensures that at no point are **two nodes accepting writes** simultaneously, which would cause irreconcilable data divergence.

---

## Circuit Breakers

### Distributed Circuit Breaker Architecture

Circuit breakers use **Redis-backed distributed state**, ensuring all workers share a consistent view of circuit health:

```
           ┌──────────┐     Success     ┌──────────┐
           │          │ ◀────────────── │          │
      ────▶│  CLOSED  │                 │ HALF_OPEN│◀──── Reset timeout elapsed
           │          │ ──────────────▶ │          │
           └────┬─────┘   Failure       └────┬─────┘
                │          threshold          │
                │                             │ Success → CLOSED
                ▼                             │ Failure → OPEN
           ┌──────────┐                       │
           │          │ ──────────────────────┘
           │   OPEN   │    After reset timeout
           │          │
           └──────────┘
```

### Circuit Breaker Configurations

| Context | Failure Threshold | Reset Timeout | Sliding Window |
|---------|-------------------|---------------|----------------|
| **Per-SMTP-host** (email processor) | 10 failures | 60 seconds | 2 minutes |
| **Per-webhook-endpoint** | 5 failures | 30 seconds | — |
| **Error rate breaker** (email processor) | 10 failures in 20-outcome window | 60 seconds pause | Rolling 20 outcomes |

When a circuit opens for a specific SMTP host, emails are **deferred** (rescheduled) rather than failed. This prevents transient SMTP server issues from generating hard bounces.

Webhook circuit breakers are keyed by endpoint URL, so one customer's broken endpoint does not affect other customers.

### Redis Implementation

**Rolling window tracking** via sorted sets:

```
ZADD circuit:{key}:failures <timestamp> <failure-id>
ZREMRANGEBYSCORE circuit:{key}:failures 0 <window-start>
ZCARD circuit:{key}:failures  →  current failure count
```

**Transition guard** — `SETNX` ensures only one caller transitions OPEN → HALF_OPEN:

```
SET circuit:{key}:half_open <worker-id> NX PX 10000
```

**Key TTL** — All keys expire after **24 hours** to prevent unbounded accumulation.

---

## Replication Monitoring

### PostgreSQL Streaming Replication

The HA app continuously monitors replication between Finland and Germany:

```sql
-- On Finland primary: check replication to Germany
SELECT
    client_addr,
    state,
    sent_lsn,
    replay_lsn,
    sent_lsn - replay_lsn AS replication_lag_bytes,
    NOW() - write_lag AS write_lag_interval
FROM pg_stat_replication;
```

### Lag Detection and Alerting

| Metric | Warning | Critical | Action |
|--------|---------|----------|--------|
| Replication lag (bytes) | > 16 MB | > 256 MB | Alert, investigate |
| Replication lag (time) | > 5 seconds | > 30 seconds | Alert, consider read routing changes |
| Replication state | — | `disconnected` | Alert, initiate reconnection |
| WAL sender state | — | `catchup` > 5 min | Alert, check network/IO |

### Automatic Promotion

On confirmed primary failure (health checks fail + replication connection lost):

1. **Verify** Finland primary is truly unreachable (multiple probes from internal monitoring).
2. **Fence** the old primary via Hetzner Cloud API (STONITH).
3. **Promote** Germany standby: `SELECT pg_promote()`.
4. **Verify** Germany is accepting writes.
5. **Update** Zone.ee DNS to route traffic to Germany.
6. **Notify** operations team via Slack/email alerts.

---

## Chaos Engineering Framework

### Experiment Types

The HA app includes a chaos engineering framework (`tools/chaos/`) for resilience testing in staging environments. **8 experiment types** are supported:

| # | Experiment | Description |
|---|-----------|-------------|
| 1 | **Network Partition** | Simulates network split between Finland and Germany using iptables |
| 2 | **Latency Injection** | Adds 50–500ms latency to inter-datacentre traffic |
| 3 | **Primary Kill** | Abruptly terminates the PostgreSQL primary process |
| 4 | **Disk Full** | Fills WAL directory to trigger disk-pressure handling |
| 5 | **DNS Failure** | Poisons DNS responses for service endpoints |
| 6 | **Clock Skew** | Shifts system clock to test time-sensitive logic |
| 7 | **Connection Exhaustion** | Saturates PostgreSQL connection pool to test backpressure |
| 8 | **Memory Pressure** | Allocates memory to trigger OOM handling and graceful degradation |

### Controlled Fault Injection

All experiments run within a **controlled blast radius**:

- Maximum duration: 5 minutes (automatic rollback).
- **Kill switch** immediately reverses all injected faults.
- Full before/after state logged for post-mortem analysis.
- **Never run in production** — enforced by environment checks at startup.

---

## Data Residency

### All Data Stays in the EU

| Aspect | Detail |
|--------|--------|
| **Primary datacentre** | Hetzner, Helsinki, Finland |
| **Standby datacentre** | Hetzner, Falkenstein/Nuremberg, Germany |
| **DNS** | Zone.ee (Estonian registrar, EU) |
| **Payment processing** | Stripe (EU entity, data processed in EU) |
| **Backups** | Stored in the same Hetzner region as the source data |
| **Email delivery (primary)** | Direct SMTP from Hetzner infrastructure |
| **Email delivery (secondary)** | AWS SES `eu-west-1` (Ireland) — fallback delivery provider only |

### What AWS SES Is Used For

AWS SES in `eu-west-1` is used **only** as a secondary outbound email delivery path. It is not used for:

- ❌ Data storage
- ❌ Database hosting
- ❌ Application hosting
- ❌ Backup storage
- ❌ Queue processing
- ❌ Any inbound email processing

It is used for:

- ✅ Outbound email delivery when specific ISPs show better inbox placement rates via SES-sourced IPs
- ✅ Overflow capacity during high-volume sending periods
- ✅ Deliverability optimisation for recipients at ISPs that trust Amazon IP ranges

Email content transits through SES but is **not stored** there. SES is configured with the minimum retention (0 days) and no logging of message bodies.

### GDPR Compliance

| Layer | Mechanism |
|-------|-----------|
| **Routing** | All application requests served from Hetzner EU |
| **Storage** | All databases, caches, and file storage in Hetzner Finland/Germany |
| **Replication** | Streaming replication stays within EU (Finland ↔ Germany) |
| **Backups** | AES-256-GCM encrypted, stored in same Hetzner region |
| **Audit trail** | All data movement logged in compliance audit log |
| **Sub-processors** | Stripe (EU), Hetzner (EU), Zone.ee (EU), AWS SES eu-west-1 (EU, transit only) |

### Tenant-Level Residency Override

Enterprise tenants can restrict data to a single EU country:

```json
{
    "tenant_id": "ent-12345",
    "data_residency": {
        "primary_region": "eu-fi",
        "allowed_regions": ["eu-fi"],
        "dr_region": "eu-de",
        "restrict_replication": false
    }
}
```

When `restrict_replication` is `true`, data is **never replicated** outside the specified country. The tenant accepts increased risk of data loss in exchange for stricter residency guarantees.

---

## Backup Strategy

### Backup Types

| Type | Schedule | Description |
|------|----------|-------------|
| **Full backup** | Daily (configurable time) | Complete `pg_basebackup` of the PostgreSQL cluster |
| **Incremental** | Continuous | WAL segments archived as they are produced |
| **WAL archiving** | Continuous | Enables Point-In-Time Recovery (PITR) to any second |

### Point-In-Time Recovery (PITR)

WAL archiving enables recovery to **any arbitrary point in time**:

```bash
# Recover to a specific timestamp
recovery_target_time = '2026-02-09 14:30:00 UTC'

# Recover to a specific transaction
recovery_target_xid = '12345678'

# Recover to a named restore point
recovery_target_name = 'before_migration_042'
```

Restore points can be created before risky operations:

```sql
SELECT pg_create_restore_point('before_migration_042');
```

### Encryption

All backups are encrypted at rest using **AES-256-GCM**:

| Aspect | Detail |
|--------|--------|
| **Algorithm** | AES-256-GCM (authenticated encryption) |
| **Key management** | Encryption keys stored separately, rotated quarterly |
| **Envelope encryption** | Each backup has a unique DEK, encrypted by a master KEK |
| **Verification** | GCM authentication tag verified on restore to detect tampering |

### Retention

| Backup Type | Default Retention | Configurable |
|-------------|-------------------|--------------|
| Daily full | 30 days | Yes |
| WAL segments | 30 days | Yes |
| Monthly archive | 12 months | Yes |

Expired backups are purged automatically. Deletion is logged in the audit trail.

### Data Retention by Plan

| Plan | Event/Log Retention |
|------|---------------------|
| Free | 7 days |
| Starter | 30 days |
| Pro | 60 days |
| Growth | 90 days |
| Scale | 365 days |
| Enterprise | 730 days |

### Backup Verification

Backups are **automatically verified weekly**:

1. Restore the latest full backup to an isolated test instance.
2. Replay WAL segments to the latest state.
3. Run consistency checks (`pg_amcheck`, custom data integrity queries).
4. Report success/failure to monitoring.
5. Tear down the test instance.

---

## DNS Failover

### Health Check-Based DNS Updates

DNS is managed through **Zone.ee** (via their API), with our own health check system driving automatic failover:

```
┌───────────────┐       Updates DNS         ┌──────────────┐
│  Zone.ee API  │ ◀──────────────────────── │  HA Service   │
│  DNS Records  │                           │  (apps/ha)    │
└──────┬────────┘                           └──────┬───────┘
       │                                           │
       │  A/AAAA record changes                    │  Probes every 10s
       │  propagated via DNS                       │  from monitoring nodes
       ▼                                           ▼
┌───────────────┐                           ┌───────────────┐
│  DNS Resolvers│                           │  /health/ready │
│  (recursive)  │                           │  endpoints     │
└───────────────┘                           └───────────────┘
```

**Failover trigger criteria:**

- Health check fails from **2 out of 3** monitoring probes.
- Failures persist for **3 consecutive checks** (30 seconds at 10-second intervals).
- This prevents DNS flapping from transient network blips.

### TTL Management

DNS TTLs are managed dynamically:

| State | TTL | Rationale |
|-------|-----|-----------|
| Healthy | 300s (5m) | Standard caching, reduces DNS query load |
| Degraded | 60s (1m) | Faster failover if the situation worsens |
| Failover | 30s | Minimise stale cache impact during active failover |
| Recovery | 60s (1m) | Gradual return to normal, verify stability first |

When the system enters a **degraded** state (e.g., replication lag exceeds warning thresholds), TTLs are proactively reduced **before** a full failover is necessary.

---

## Operational Runbooks

### Planned Maintenance (e.g., Finland Server Upgrade)

```
1. Lower Zone.ee DNS TTL to 30s (wait for old TTL to expire).
2. Shift traffic to Germany (update Zone.ee DNS A record to point to Germany).
3. Verify Germany is handling all traffic successfully.
4. Perform maintenance on Finland servers.
5. Verify Finland is healthy (health checks pass, replication caught up).
6. Shift traffic back to Finland (100/0).
7. Restore DNS TTL to 300s.
```

### Unplanned Failure (Finland Down)

```
1. HA service health checks detect failure; updates Zone.ee DNS to Germany.
2. STONITH fences Finland via Hetzner Cloud API.
3. Germany standby is promoted to PostgreSQL primary.
4. Zone.ee DNS confirmed pointing to Germany.
5. Alerts fire to operations team (Slack + email).
6. Post-incident:
   a. Investigate root cause with Hetzner support.
   b. Rebuild Finland as new standby.
   c. Re-establish streaming replication (Germany → Finland).
   d. Run post-mortem and update procedures if needed.
```

### Failback After Recovery

```
1. Verify Finland is rebuilt and healthy.
2. Establish replication from Germany (current primary) to Finland.
3. Wait for replication lag to reach zero.
4. Schedule maintenance window.
5. Execute planned failover (see above).
6. Verify Finland is serving traffic correctly as primary.
7. Update monitoring baselines.
```

### AWS SES Fallback Activation

```
1. Monitor primary SMTP delivery metrics (bounce rate, delivery latency).
2. If direct SMTP delivery to specific ISPs degrades:
   a. Enable SES routing for affected ISP domains via worker configuration.
   b. Verify SES sending identity (DKIM, SPF) is valid.
   c. Monitor SES delivery metrics in CloudWatch.
3. When direct delivery recovers, disable SES routing.
4. SES is never used as the sole delivery path — always a secondary option.
```
