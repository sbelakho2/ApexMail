# Disaster Recovery & Backup Procedures

This document describes ApexMail's disaster recovery (DR) architecture, backup strategies, failover mechanisms, and recovery procedures. The systems described here are primarily implemented in the HA (High Availability) application and the Control Plane.

All infrastructure runs on **Hetzner Cloud servers** (Hetzner Cloud ARM) in Finland (primary) and Germany (standby). **AWS SES** is used as the primary outbound email delivery transport (see [ADR 0011](../adr/0011-dual-delivery-ses-primary.md)). Self-hosted SMTP is available as an opt-in alternative.

---

## Table of Contents

- [Backup Strategy](#backup-strategy)
- [Point-In-Time Recovery (PITR)](#point-in-time-recovery-pitr)
- [Backup Encryption](#backup-encryption)
- [Failover State Machine](#failover-state-machine)
- [STONITH Fencing](#stonith-fencing)
- [Circuit Breakers with Redis Persistence](#circuit-breakers-with-redis-persistence)
- [Replication Monitoring](#replication-monitoring)
- [Chaos Engineering](#chaos-engineering)
- [Recovery Procedures](#recovery-procedures)
- [Data Retention Policies](#data-retention-policies)
- [DR Testing Cadence](#dr-testing-cadence)

---

## Backup Strategy

ApexMail employs a multi-layered backup strategy to ensure data durability and rapid recovery.

### Backup Types

| Type | Description | Frequency | Retention |
|------|-------------|-----------|-----------|
| **Full backup** | Complete snapshot of all databases and configuration | Daily (configurable) | 30 days (configurable) |
| **Incremental backup** | Only changed data since the last full or incremental backup | Every 6 hours | 30 days |
| **WAL archiving** | Continuous archiving of PostgreSQL Write-Ahead Log segments | Continuous (real-time) | 30 days |

### Backup Configuration

Default settings (configurable via Control Plane):

```yaml
backup:
  schedule:
    full: "0 2 * * *"         # Daily at 02:00 UTC
    incremental: "0 */6 * * *" # Every 6 hours
  retention:
    days: 30
  storage:
    primary: s3://apexmail-backup-fi/   # Hetzner S3 object storage (Finland)
    replica: s3://apexmail-backup-de/   # Hetzner S3 object storage (Germany)
  dr_region: eu-de  # Germany standby
```

Backups are stored on **Hetzner S3-compatible object storage** co-located in the same Hetzner datacentre as each server. Cross-site copies are replicated via S3 cross-region replication over the Hetzner internal network.

### Backup Verification

Every backup is verified post-completion:

1. **Checksum validation** — SHA-256 checksums are computed and stored alongside backup artifacts.
2. **Restore test** — Automated weekly restore to a staging environment validates backup integrity.
3. **Size anomaly detection** — Backups that deviate more than ±20% from the rolling average trigger an alert.

---

## Point-In-Time Recovery (PITR)

PITR enables recovery to any specific point in time within the WAL retention window by replaying Write-Ahead Log segments on top of a base backup.

### How PITR Works

1. Select the most recent full backup that precedes the target recovery time.
2. Restore the full backup to a new database cluster.
3. Replay WAL segments from the archive up to the specified recovery target.
4. The database is brought online at the exact requested state.

### PITR Configuration

```yaml
pitr:
  wal_archive:
    location: /backup/apexmail/wal-archive/
    compression: zstd
    encryption: aes-256-gcm
  recovery_target:
    # Specify one of the following:
    time: "2026-02-09T14:30:00Z"     # Recover to a specific timestamp
    xid: "12345678"                   # Recover to a specific transaction ID
    lsn: "0/1A2B3C4D"                # Recover to a specific WAL position
    name: "pre-migration-snapshot"    # Recover to a named restore point
```

### Recovery Time Objectives

| Metric | Target |
|--------|--------|
| RPO (Recovery Point Objective) | < 1 minute (continuous WAL archiving) |
| RTO (Recovery Time Objective) | < 15 minutes for same-site; < 30 minutes for cross-site (Finland ↔ Germany) |

---

## Backup Encryption

All backup data is encrypted at rest and in transit.

### Encryption Specification

| Layer | Algorithm | Details |
|-------|-----------|---------|
| Data encryption | AES-256-GCM | Each backup artifact is encrypted with a unique data encryption key (DEK) |
| Key encryption | AES-256-KW | DEKs are wrapped by a key encryption key (KEK) managed locally |
| In-transit | TLS 1.3 | All backup transfers between Finland and Germany use TLS 1.3 |
| WAL segments | AES-256-GCM | Encrypted before writing to the archive |

### Key Management

- **KEK rotation:** Automatic rotation every 90 days. KEKs are stored in an encrypted keyfile on a separate volume from the backup data.
- **DEK lifecycle:** A new DEK is generated for each backup. DEKs are encrypted (wrapped) with the current KEK and stored in the backup metadata.
- **Key access audit:** All key access events are logged to the compliance audit log.
- **Emergency access:** Break-glass procedure requires two authorised operators and generates a security incident ticket.

---

## Failover State Machine

The failover system uses a distributed state machine with Redis-based coordination to manage primary/replica role transitions.

### States

```
                    ┌──────────┐
         ┌─────────│  NORMAL  │─────────┐
         │         └──────────┘         │
    health check        │          manual trigger
      failure           │
         │              ▼
         │     ┌──────────────┐
         └────▶│  DETECTING   │
               └──────────────┘
                       │
              confirmed failure
                       │
                       ▼
               ┌──────────────┐
               │  FENCING     │──── fence fails ────▶ BLOCKED
               └──────────────┘
                       │
                fence success
                       │
                       ▼
               ┌──────────────┐
               │  PROMOTING   │
               └──────────────┘
                       │
              promotion complete
                       │
                       ▼
               ┌──────────────┐
               │  REDIRECTING │
               └──────────────┘
                       │
              traffic switched
                       │
                       ▼
               ┌──────────────┐
               │  COMPLETED   │
               └──────────────┘
```

### Distributed Locking

Failover coordination uses Redis-based distributed locks to prevent split-brain scenarios:

- **Lock key:** `failover:lock:{cluster_id}`
- **Lock TTL:** 30 seconds (auto-renewed every 10 seconds by the lock holder)
- **Fencing tokens:** Monotonically increasing tokens are issued with each lock acquisition. Any operation presenting a stale fencing token is rejected.
- **Lock contention:** If multiple nodes detect a failure simultaneously, only the first to acquire the lock proceeds with failover. Others enter an observer state.

### Failover Timeline

| Phase | Typical Duration | Description |
|-------|-----------------|-------------|
| Detection | 5–10 seconds | Three consecutive health check failures trigger detection |
| Fencing | 2–5 seconds | STONITH fencing isolates the failed primary |
| Promotion | 3–8 seconds | Replica is promoted; WAL replay completes |
| Redirection | 1–3 seconds | Zone.ee DNS updated; connections drained |
| **Total** | **11–26 seconds** | End-to-end automatic failover |

---

## STONITH Fencing

**STONITH** (Shoot The Other Node In The Head) prevents split-brain conditions where two nodes believe they are the primary.

### Fencing Mechanisms

| Method | Description | Use Case |
|--------|-------------|----------|
| **Hetzner Cloud API** | API call to Hetzner's cloud server management to force a server reset or shutdown | Primary method |
| **SSH fencing** | SSH into the node and issue `systemctl stop postgresql` or `poweroff` | Fallback if Cloud API is slow |
| **Network fencing** | Firewall rule injection (iptables) to block all PostgreSQL traffic to/from the failed node | Fallback if API and SSH fail |
| **Self-fencing** | Failed node detects loss of quorum and voluntarily demotes itself | Cooperative split-brain resolution |

### Fencing Order

1. Attempt Hetzner Cloud API fencing (timeout: 10 seconds).
2. If API fencing fails, attempt SSH fencing (timeout: 5 seconds).
3. If SSH fencing fails, apply network fencing via iptables (timeout: 5 seconds).
4. If all remote fencing fails, wait for self-fencing (timeout: 15 seconds).
5. If self-fencing does not occur, the failover enters `BLOCKED` state and requires manual intervention.

### Fencing Verification

After fencing, the system verifies isolation:

- TCP check confirms the fenced node is unreachable on PostgreSQL port.
- The fencing token is written to Redis; any connection from the fenced node presenting a stale token is rejected.

---

## Circuit Breakers with Redis Persistence

Circuit breaker state is persisted in Redis to survive process restarts and ensure consistent behaviour across a distributed worker fleet.

### Redis Key Schema

```
circuit:{service}:{destination} → {
  state: "closed" | "open" | "half-open",
  failure_count: number,
  last_failure: ISO 8601 timestamp,
  opened_at: ISO 8601 timestamp | null,
  half_open_attempts: number
}
```

**TTL:** Circuit breaker keys expire after 24 hours of inactivity.

### State Transitions

| Current State | Event | Next State | Action |
|---------------|-------|------------|--------|
| Closed | Failure count ≥ threshold | Open | Stop sending; set `opened_at` |
| Open | Reset timeout elapsed | Half-Open | Allow single probe request |
| Half-Open | Probe succeeds | Closed | Reset failure count |
| Half-Open | Probe fails | Open | Restart reset timeout |

### Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `failure_threshold` | 10 | Number of failures before opening |
| `reset_timeout` | 60s | Time before transitioning from open to half-open |
| `monitoring_window` | 120s | Sliding window for failure counting |
| `half_open_max_attempts` | 3 | Max probes in half-open state before requiring manual reset |

---

## Replication Monitoring

Continuous monitoring of PostgreSQL streaming replication between Hetzner Finland and Germany.

### Monitored Metrics

| Metric | Warning Threshold | Critical Threshold | Check Interval |
|--------|------------------|--------------------|----------------|
| Replication lag (seconds) | > 5s | > 30s | 10s |
| Replication lag (bytes) | > 16 MB | > 256 MB | 10s |
| Replication slot WAL retention | > 1 GB | > 5 GB | 60s |
| Replica connection status | Disconnected > 10s | Disconnected > 60s | 5s |
| WAL archive success rate | < 99% | < 95% | 60s |

### Alerting

Alerts are delivered via:

- Slack `#ops-alerts` channel (warning and critical)
- Email to the on-call rotation (critical)
- Control Plane dashboard (all severity levels)

---

## Chaos Engineering

ApexMail includes a built-in chaos engineering framework (`tools/chaos/`) for validating DR readiness.

### Experiment Types

| # | Experiment | Description | Blast Radius |
|---|-----------|-------------|--------------|
| 1 | **Node failure** | Terminate a random worker or API process | Single node |
| 2 | **Network partition** | Isolate Finland from Germany using iptables rules | Cross-site |
| 3 | **Disk failure** | Simulate I/O errors on the data volume | Single node |
| 4 | **DNS failure** | Block DNS resolution for specific domains | Cluster-wide |
| 5 | **Clock skew** | Introduce time drift on a node (±30 seconds) | Single node |
| 6 | **Memory pressure** | Consume available memory to trigger OOM conditions | Single node |
| 7 | **Database failover** | Force a primary database failover | Cluster-wide |
| 8 | **Connection exhaustion** | Saturate PostgreSQL connection pool to test backpressure | Single node |

### Safety Controls

- **Abort conditions:** Experiments automatically abort if customer-facing error rates exceed 1%.
- **Blast radius limits:** Maximum percentage of nodes affected is configurable (default: 25%).
- **Scheduling:** Experiments run only during maintenance windows unless overridden.
- **Rollback:** Each experiment includes an automatic rollback procedure that executes on abort or completion.
- **Audit trail:** All experiments are logged with operator, parameters, duration, and outcome.
- **Never run in production** — enforced by environment checks at startup.

### Running Experiments

Experiments are run via scripts in `tools/chaos/`:

```bash
# Run a chaos experiment
cd tools/chaos
./run-experiment.sh --experiment node-failure --target tracking

# Dry run (no actual disruption)
./run-experiment.sh --experiment network-partition --dry-run

# Force a database failover test in staging
./run-experiment.sh --experiment database-failover --target postgres
```

---

## Recovery Procedures

### Procedure 1: Single-Node Recovery

**Scenario:** A single worker or API process fails on the Finland server.

| Step | Action | Expected Duration |
|------|--------|-------------------|
| 1 | Systemd restarts the failed service automatically | 5–15 seconds |
| 2 | Service runs health checks and connects to DB/Redis | 10–30 seconds |
| 3 | Health check endpoint returns healthy; traffic resumes | 5–10 seconds |
| **Total** | | **20–55 seconds** |

If the process repeatedly fails (3 restarts within 5 minutes), an alert fires for manual investigation.

### Procedure 2: Database Failover (Finland → Germany)

**Scenario:** Finland PostgreSQL primary becomes unavailable.

| Step | Action | Expected Duration |
|------|--------|-------------------|
| 1 | Health check detects failure (3 consecutive failures) | 15–30 seconds |
| 2 | Failover state machine acquires lock and initiates fencing | 2–5 seconds |
| 3 | STONITH fences Finland primary via Hetzner Cloud API | 5–15 seconds |
| 4 | Germany replica promoted to primary (`pg_promote()`) | 3–8 seconds |
| 5 | Zone.ee DNS updated; application reconnects | 1–3 seconds |
| **Total** | | **26–61 seconds** |

### Procedure 3: Full Site Recovery (Finland Down)

**Scenario:** The entire Hetzner Finland datacentre becomes unavailable.

| Step | Action | Expected Duration |
|------|--------|-------------------|
| 1 | HA service detects health check failures across all Finland endpoints | 30–60 seconds |
| 2 | HA service updates Zone.ee DNS to route traffic to Germany | 30–60 seconds |
| 3 | Germany services start accepting full traffic | 1–2 minutes |
| 4 | Germany PostgreSQL promoted to primary (if not already) | 3–8 seconds |
| 5 | Verification and traffic ramp-up | 2–5 minutes |
| **Total** | | **4–9 minutes** |

### Procedure 4: Data Corruption Recovery

**Scenario:** Data corruption detected (accidental deletion, bad migration, etc.).

| Step | Action | Expected Duration |
|------|--------|-------------------|
| 1 | Identify the point in time immediately before corruption | Manual (variable) |
| 2 | Provision new database cluster on an isolated Hetzner server | 2–5 minutes |
| 3 | Restore from latest full backup preceding the corruption event | 5–20 minutes |
| 4 | Replay WAL segments up to the target recovery point (PITR) | 5–30 minutes |
| 5 | Validate recovered data integrity | 5–15 minutes |
| 6 | Switch application to recovered database | 1–3 minutes |
| **Total** | | **18–73 minutes** (depending on data volume) |

---

## Data Retention Policies

Data retention periods vary by subscription plan. Data beyond the retention window is permanently deleted.

### Retention by Plan

| Plan | Event Data | Analytics | Audit Logs | Backups |
|------|------------|-----------|------------|---------|
| **Free** | 7 days | 7 days | 7 days | None |
| **Starter** | 30 days | 30 days | 30 days | 7 days |
| **Pro** | 60 days | 60 days | 60 days | 30 days |
| **Growth** | 90 days | 90 days | 90 days | 30 days |
| **Scale** | 365 days | 365 days | 365 days | 90 days |
| **Enterprise** | 730 days | 730 days | 730 days | 365 days |

### Retention Enforcement

- A nightly job scans for data beyond the retention window and schedules it for deletion.
- Deletion is soft-delete first (data marked as expired), followed by hard-delete after a 48-hour grace period.
- Enterprise customers can configure custom retention periods up to 7 years for compliance requirements.
- Audit logs are exempt from standard retention and are retained for a minimum of 3 years (730 days default, configurable).

---

## DR Testing Cadence

Regular testing validates that disaster recovery procedures work as documented.

### Recommended Schedule

| Test Type | Frequency | Scope | Participants |
|-----------|-----------|-------|-------------|
| Backup restore verification | Weekly (automated) | Single database | Automated pipeline |
| Single-node failover | Monthly | Staging | On-call engineer |
| Database failover | Monthly | Staging cluster | Database team |
| Cross-site failover (Finland ↔ Germany) | Quarterly | Production (controlled) | SRE team + stakeholders |
| Full DR exercise | Semi-annually | All systems | Entire engineering org |
| Chaos engineering experiments | Bi-weekly | Staging; monthly in production | SRE team |
| Tabletop exercise | Quarterly | N/A (discussion-based) | Engineering + leadership |

### Post-Test Deliverables

After each DR test:

1. **Incident report** — Document what happened, what worked, and what didn't.
2. **Runbook updates** — Amend recovery procedures based on findings.
3. **RTO/RPO validation** — Confirm actual recovery times against stated objectives.
4. **Action items** — Track improvements in the engineering backlog with assigned owners and deadlines.
