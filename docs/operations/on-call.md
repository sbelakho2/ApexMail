# On-Call Rotation Guide

> Internal document — Bel Consulting OÜ

## Overview

This document defines the on-call structure, responsibilities, response SLAs, and escalation procedures for the ApexMail platform.

---

## Schedule

| Parameter | Value |
|-----------|-------|
| Rotation period | Weekly (Monday 09:00 UTC → Monday 09:00 UTC) |
| Team size | 2-person teams (primary + secondary) |
| Handoff | Monday at 09:00 UTC with a 30-minute overlap |
| Tool | PagerDuty (schedule: `apexmail-oncall`) |

### Rotation Rules

- Minimum 2-week gap between on-call shifts for the same person.
- No on-call during scheduled PTO — swap with another team member and update PagerDuty.
- Primary responder handles initial triage; secondary is backup if primary doesn't acknowledge within the escalation window.

---

## Response SLAs

| Priority | Description | Acknowledge | Respond / Act | Examples |
|----------|-------------|-------------|---------------|----------|
| **P1 — Critical** | Service down, data loss | 5 min | 15 min | Tracking service unreachable, database down |
| **P2 — Major** | Degraded service, partial outage | 15 min | 1 hour | Elevated error rate, queue backlog |
| **P3 — Minor** | Non-critical degradation | 30 min | 4 hours | Disk usage > 80%, cert expiring |
| **P4 — Low** | Informational, non-urgent | Next business day | Next business day | Staging issues |

---

## Escalation Chain

```
Alert fires
    │
    ▼
Primary on-call (PagerDuty)
    │ no ACK in 5 min
    ▼
Secondary on-call (PagerDuty)
    │ no ACK in 5 min
    ▼
Engineering lead (phone call)
    │ no ACK in 10 min
    ▼
CTO / founder (phone call)
```

For P1 incidents, the engineering lead is **always** notified immediately (in parallel with on-call) as a courtesy page.

---

## PagerDuty & Alert Configuration

### Services

| PagerDuty Service | Source | Escalation Policy |
|-------------------|--------|-------------------|
| `apexmail-tracking` | Prometheus → Alertmanager → PagerDuty | `apexmail-oncall` |
| `apexmail-database` | Prometheus (pg_exporter) → PagerDuty | `apexmail-oncall` |
| `apexmail-infra` | Hetzner monitoring + Prometheus → PagerDuty | `apexmail-oncall` |

### Alert Routing

Alert rules are defined in [deploy/alerting-rules.yml](../../deploy/alerting-rules.yml) and forwarded to PagerDuty via Alertmanager.

- **Critical** alerts → PagerDuty (page immediately).
- **Warning** alerts → Slack `#alerts-warning` (no page).
- **Info** alerts → Slack `#alerts-info` (no page).

---

## Handoff Procedure

At rotation boundary (Monday 09:00 UTC):

1. **Outgoing on-call** posts a handoff summary in `#on-call`:
   - Active incidents or ongoing issues.
   - Alerts that fired during the shift and their resolution.
   - Anything the incoming team should watch.
   - Pending action items from incidents.
2. **Incoming on-call** acknowledges the handoff in the thread.
3. Both teams overlap for 30 minutes to discuss any nuances.
4. PagerDuty schedule automatically transitions.

### Handoff Template

```
## On-Call Handoff — Week of YYYY-MM-DD

**Outgoing:** @name1, @name2
**Incoming:** @name3, @name4

### Active Issues
- None / [describe]

### Alerts This Week
- [Alert name] — [resolution summary]

### Watch Items
- [Anything to monitor]

### Action Items
- [Pending items from incidents]
```

---

## On-Call Compensation

| Item | Detail |
|------|--------|
| Weekly stipend | Fixed amount per on-call week (see employment agreement) |
| Incident response | Additional compensation for P1/P2 incidents resolved outside business hours |
| Time off | On-call engineer may take equivalent time off after a heavy on-call week (manager discretion) |

---

## Common First-Response Actions

### Tracking — High Error Rate

1. Check Prometheus/Grafana dashboard for error distribution.
2. Check tracking logs: `docker compose logs --tail 200 tracking`.
3. Check PostgreSQL connectivity: `pg_isready -h localhost`.
4. Check Redis connectivity: `docker compose exec redis redis-cli ping`.
5. If a recent deploy: consider immediate rollback via image tag revert.

### Tracking — High Latency

1. Check tracking service logs: `docker compose logs --tail 200 tracking`.
2. Verify nginx proxy cache hit rate (should be > 90% for pixel).
3. Check Redis write throughput (event buffering).
4. Check Prometheus metrics: `curl http://localhost:9092/metrics | grep latency`.
5. Restart tracking service if unresponsive: `docker compose restart tracking`.

### Database — High Connection Count

1. Check PgBouncer stats (if using): `psql -p 6432 -U pgbouncer pgbouncer -c 'SHOW POOLS'`.
2. Check for long-running queries: `SELECT * FROM pg_stat_activity WHERE state = 'active' ORDER BY query_start`.
3. Kill stuck queries if needed: `SELECT pg_terminate_backend(pid)`.
4. If pool exhausted, restart postgres: `docker compose restart postgres`.

### Infrastructure — Server Unreachable

1. Check Hetzner Cloud console for server status.
2. Attempt SSH from a different network.
3. If server is truly down, use Hetzner console to restart.
4. If hardware failure, provision replacement Hetzner Cloud ARM server and restore from latest backup.
5. Update DNS in Zone.ee if IP changes.

---

## Runbook Index

See [operations/runbooks/README.md](./runbooks/README.md) for the complete list of operational runbooks organised by category.

---

## Key Contacts

| Role | Contact Method |
|------|---------------|
| Engineering lead | PagerDuty + Slack DM |
| Hetzner support | Cloud console ticket |
| Zone.ee support | Dashboard ticket |
| Stripe support | Dashboard ticket |
| Domain registrar | Provider dashboard |

---

*Last updated: 2026-02-23*
