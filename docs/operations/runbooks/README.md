# Runbook Index

> Internal document — Bel Consulting OÜ

## Overview

This is the central index of all operational runbooks for the ApexMail platform. Runbooks provide step-by-step procedures for common operational tasks and incident response scenarios.

Each runbook should be self-contained, actionable, and usable by any on-call engineer without deep system knowledge. See the [on-call guide](../on-call.md) for alert response context.

---

## Infrastructure

| Runbook | Description | Status |
|---------|-------------|--------|
| [Server Failover](./infra-failover.md) | Provision replacement Hetzner Cloud ARM server, restore from backup, update DNS | Planned |
| [Vertical Scaling](./infra-vertical-scaling.md) | Resize Hetzner server type with minimal downtime | Planned |
| [Horizontal Scaling](./infra-horizontal-scaling.md) | Add application servers, update nginx upstream | Planned |
| [Backup & Restore](./infra-backup-restore.md) | PostgreSQL + Redis backup verification and full restore procedure | Planned |
| [SSL Certificate Renewal](./infra-ssl-renewal.md) | Manual certificate renewal if Let's Encrypt auto-renewal fails | Planned |
| [Disk Space Recovery](./infra-disk-recovery.md) | Identify and reclaim disk space (logs, Docker images, temp files) | Planned |
| [DNS Failover](./infra-dns-failover.md) | Update Zone.ee DNS records for IP changes or region migration | Planned |

## Application

| Runbook | Description | Status |
|---------|-------------|--------|
| [Production Deploy](./app-deploy.md) | Standard deployment procedure via Docker Compose | Planned |
| [Rollback](./app-rollback.md) | Revert to previous Docker image tags and database migration rollback | Planned |
| [Database Migration](./app-migration.md) | Run pending migrations safely, verify, and rollback if needed | Planned |
| [Canary Deploy](./app-canary.md) | Step-by-step canary deployment with nginx traffic splitting | Planned |
| [Emergency Hotfix](./app-hotfix.md) | Fast-track a critical fix to production outside normal release cycle | Planned |
| [Feature Flag Toggle](./app-feature-flags.md) | Enable or disable feature flags for specific tenants or globally | Planned |

## Email & Deliverability

| Runbook | Description | Status |
|---------|-------------|--------|
| [IP Warmup](./email-ip-warmup.md) | Gradual volume ramp for new MTA IP addresses | Planned |
| [Blocklist Removal](./email-blocklist-removal.md) | Identify blocklisting, request delisting, prevent recurrence | Planned |
| [Deliverability Recovery](./email-deliverability-recovery.md) | Diagnose and fix deliverability drops (bounce rate, spam rate) | Planned |
| [DKIM/SPF/DMARC Setup](./email-dns-auth.md) | Configure email authentication DNS records for customer domains | Planned |
| [Bounce Processing](./email-bounce-processing.md) | Investigate and resolve bounce processing failures | Planned |
| [Sending Pause & Resume](./email-sending-control.md) | Emergency pause of all outbound email and controlled resume | Planned |

## Database

| Runbook | Description | Status |
|---------|-------------|--------|
| [Connection Pool Exhaustion](./db-connection-pool.md) | Diagnose PgBouncer saturation, kill stuck queries, increase limits | Planned |
| [Replication Lag](./db-replication-lag.md) | Investigate and resolve PostgreSQL streaming replication delays | Planned |
| [Vacuum & Bloat](./db-vacuum.md) | Manual vacuum for bloated tables, autovacuum tuning | Planned |
| [Slow Query Investigation](./db-slow-queries.md) | Identify slow queries via `pg_stat_statements`, add indexes, optimise | Planned |
| [Point-in-Time Recovery](./db-pitr.md) | Restore PostgreSQL to a specific timestamp using WAL archives | Planned |
| [Emergency Read-Only Mode](./db-read-only.md) | Switch application to read-only mode during database maintenance | Planned |

## Redis

| Runbook | Description | Status |
|---------|-------------|--------|
| [Memory Exhaustion](./redis-memory.md) | Diagnose high memory usage, eviction policy, key analysis | Planned |
| [Queue Drain](./redis-queue-drain.md) | Manually drain or purge stuck BullMQ queues | Planned |
| [Redis Restart](./redis-restart.md) | Safe Redis restart with data persistence verification | Planned |

## Monitoring & Alerting

| Runbook | Description | Status |
|---------|-------------|--------|
| [Alert Silence](./mon-alert-silence.md) | Silence alerts during maintenance windows via Alertmanager | Planned |
| [Dashboard Access](./mon-dashboard-access.md) | Grafana access, credentials, and dashboard locations | Planned |
| [Prometheus Recovery](./mon-prometheus-recovery.md) | Restart Prometheus, recover from storage corruption, re-scrape | Planned |
| [Log Investigation](./mon-log-investigation.md) | Search and analyse application logs for incident investigation | Planned |

## Billing & Compliance

| Runbook | Description | Status |
|---------|-------------|--------|
| [Stripe Webhook Failure](./billing-stripe-webhook.md) | Investigate and replay failed Stripe webhook events | Planned |
| [Subscription Correction](./billing-subscription-fix.md) | Manually correct billing discrepancies between app and Stripe | Planned |
| [GDPR Data Deletion](./compliance-gdpr-deletion.md) | Process data deletion requests per GDPR requirements | Planned |

---

## Cross-References

### Support Playbooks

The [support playbooks](../../support-playbooks/) provide customer-facing troubleshooting guides that complement these runbooks:

- Support playbooks focus on **diagnosing customer-reported issues**.
- Runbooks focus on **operator-level resolution steps**.
- When a support playbook identifies an infrastructure or platform issue, it should reference the appropriate runbook above.

### Related Documentation

| Document | Location |
|----------|----------|
| On-call rotation guide | [operations/on-call.md](../on-call.md) |
| Scaling guide | [operations/scaling.md](../scaling.md) |
| Post-mortem template | [evaluation/post-mortem-template.md](../../evaluation/post-mortem-template.md) |
| Release checklist | [evaluation/release-checklist.md](../../evaluation/release-checklist.md) |
| Canary deployment process | [evaluation/canary-deployment.md](../../evaluation/canary-deployment.md) |
| Alerting rules | [deploy/alerting-rules.yml](../../../deploy/alerting-rules.yml) |

---

## Contributing

When creating a new runbook:

1. Use the naming convention: `<category>-<short-name>.md` (e.g. `db-slow-queries.md`).
2. Include: **When to use**, **Prerequisites**, **Steps** (numbered), **Verification**, **Rollback**.
3. Add the runbook to this index.
4. Link from relevant alert rules in `deploy/alerting-rules.yml`.
5. Test the procedure on staging before marking as "Active".

---

*Last updated: 2026-02-09*
