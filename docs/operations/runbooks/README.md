# Runbook Index

> Internal document — Bel Consulting OÜ

## Overview

This is the central index of operational runbooks for the ApexMail platform. Runbooks provide step-by-step procedures for common operational tasks and incident response scenarios.

Each runbook should be self-contained, actionable, and usable by any on-call engineer without deep system knowledge. See the [on-call guide](../on-call.md) for alert response context.

---

## Active Runbooks

| Runbook | Description |
|---------|-------------|
| [Incident Response](./incident-response.md) | General incident handling procedures, escalation, post-mortems |
| [Database Recovery](./db-recovery.md) | Primary failure, connection pool exhaustion, slow queries, data corruption, WAL disk full |
| [Network Partition](./network-partition.md) | Cross-region connectivity loss, WireGuard tunnel failure, split-brain scenarios |
| [Traffic Spike / DDoS](./traffic-spike-ddos.md) | Rate limiting tuning, IP blocking, auto-scaling, emergency circuit breakers, tenant isolation |
| [Redis Failure](./redis-failure.md) | Memory exhaustion, connection failure, data loss, AOF corruption, replication failure |
| [MTA Degradation](./mta-degradation.md) | High bounce rate, SMTP failures, queue backlog, IP reputation damage, DKIM/SPF/DMARC failures |
| [Crypto Incidents](./crypto-incidents.md) | Cryptographic key compromise, certificate or signing-key incidents, DKIM key rotation |
| [System Sender Readiness](./system-sender-readiness.md) | Platform sender bootstrap, DKIM provisioning, DNS verification before enabling mail |

---

## Infrastructure (Planned)

| Runbook | Description | Status |
|---------|-------------|--------|
| Server Failover | Provision replacement Hetzner Cloud ARM server, restore from backup, update DNS | Planned |
| Vertical Scaling | Resize Hetzner server type with minimal downtime | Planned |
| Backup & Restore | PostgreSQL + Redis backup verification and full restore procedure | Planned |
| SSL Certificate Renewal | Manual certificate renewal if Let's Encrypt auto-renewal fails | Planned |
| Disk Space Recovery | Identify and reclaim disk space (logs, Docker images, temp files) | Planned |
| DNS Failover | Update Zone.ee DNS records for IP changes or region migration | Planned |

## Tracking Service (Planned)

| Runbook | Description | Status |
|---------|-------------|--------|
| Tracking Deploy | Standard deployment procedure via Docker Compose | Planned |
| Tracking Rollback | Revert to previous Docker image tags | Planned |
| Tracking Scale | Scale tracking service replicas for high load | Planned |

## Database (Planned)

| Runbook | Description | Status |
|---------|-------------|--------|
| Connection Pool Exhaustion | Diagnose saturation, kill stuck queries, increase limits | Planned |
| Vacuum & Bloat | Manual vacuum for bloated tables, autovacuum tuning | Planned |
| Slow Query Investigation | Identify slow queries via `pg_stat_statements`, add indexes | Planned |
| Point-in-Time Recovery | Restore PostgreSQL to a specific timestamp using WAL archives | Planned |

## Redis (Planned)

| Runbook | Description | Status |
|---------|-------------|--------|
| Memory Exhaustion | Diagnose high memory usage, eviction policy, key analysis | Planned |
| Queue Drain | Manually drain or purge stuck event queues | Planned |
| Redis Restart | Safe Redis restart with data persistence verification | Planned |

## Monitoring & Alerting (Planned)

| Runbook | Description | Status |
|---------|-------------|--------|
| Alert Silence | Silence alerts during maintenance windows via Alertmanager | Planned |
| Dashboard Access | Grafana access, credentials, and dashboard locations | Planned |
| Prometheus Recovery | Restart Prometheus, recover from storage corruption | Planned |
| Log Investigation | Search and analyse application logs for incident investigation | Planned |

---

## Related Documentation

| Document | Location |
|----------|----------|
| On-call rotation guide | [operations/on-call.md](../on-call.md) |
| Monitoring guide | [operations/monitoring.md](../monitoring.md) |
| Disaster recovery | [operations/disaster-recovery.md](../disaster-recovery.md) |
| SLO management | [operations/slo-management.md](../slo-management.md) |
