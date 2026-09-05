# Backup Verification Procedure

> **Rewritten 2026-09-05.** Earlier versions described Kubernetes CronJobs,
> Hetzner S3 buckets, and WAL-archive checks. None of that exists. The real
> deployment is a single Hetzner host; backups are nightly encrypted dumps
> (`postgres-backup`, `clickhouse-backup` compose services) with an offsite
> rsync mirror when `BACKUP_TARGET` is set. See
> [Disaster Recovery](disaster-recovery.md) for the full mechanism.

> **Cadence:** automatic restorability check on every backup; manual restore
> drill monthly; full host-rebuild drill quarterly
> ([DR Testing](disaster-recovery-testing.md))

---

## Table of Contents

- [Automatic Verification (every backup)](#automatic-verification-every-backup)
- [Routine Health Checks](#routine-health-checks)
- [Manual Restore Drill (monthly)](#manual-restore-drill-monthly)
- [RTO/RPO Validation](#rtorpo-validation)
- [Failed-Backup Escalation Procedure](#failed-backup-escalation-procedure)
- [Drill Documentation Template](#drill-documentation-template)
- [Related Documentation](#related-documentation)

---

## Automatic Verification (every backup)

Both backup schedulers (`deploy/hardening/scripts/postgres-backup-encrypt.sh`,
`clickhouse-backup-encrypt.sh`) verify **before deleting the plaintext dump**:

1. The artifact decrypts with the `backup_encryption_key` secret
   (AES-256-CBC + PBKDF2).
2. The decrypted dump is readable — `pg_restore --list` (PostgreSQL) or the
   equivalent archive check (ClickHouse `.tar.enc`).

A backup that fails either check is **not** counted as a good backup and is
not used for retention pruning decisions; check the container logs for the
verification failure.

## Routine Health Checks

Run these on the deploy host (or wire into monitoring):

```bash
# 1. Both backup containers healthy = scheduler alive AND an encrypted
#    artifact exists that is newer than 25 h
docker compose -f docker-compose.yml -f docker-compose.prod.yml --env-file .env \
  ps postgres-backup clickhouse-backup

# 2. Inspect the artifacts and their ages directly (postgres: *.enc; clickhouse: *.tar.enc)
docker run --rm -v apexmail_postgres_backups:/backups:ro alpine \
  sh -c 'ls -lh /backups | tail -10'
docker run --rm -v apexmail_clickhouse_backups:/backups:ro alpine \
  sh -c 'ls -lh /backups | tail -10'

# 3. Confirm the offsite mirror (if BACKUP_TARGET is set) received last night's artifacts
ssh <backup-target-host> 'ls -lh /srv/apexmail-backups | tail -10'

# 4. Tail the scheduler logs for verification/pruning errors
docker compose -f docker-compose.yml -f docker-compose.prod.yml --env-file .env \
  logs --tail 50 postgres-backup
```

Retention defaults: PostgreSQL `BACKUP_KEEP_DAYS=14` / weeks 8 / months 6 /
newest 30; ClickHouse 14 days / 14 artifacts. Offsite mirror retention is
whatever the offsite host's own pruning provides — verify it during drills.

## Manual Restore Drill (monthly)

Purpose: prove a human can actually restore, not just that the script
verified an artifact.

```bash
# 1. Copy the newest encrypted postgres backup out of the volume
NEWEST=$(docker run --rm -v apexmail_postgres_backups:/backups:ro alpine \
  sh -c 'ls -t /backups/*.enc | head -1')
docker run --rm -v apexmail_postgres_backups:/backups:ro alpine cat "$NEWEST" > /tmp/drill.enc

# 2. Decrypt (key from the backup_encryption_key secret value)
openssl enc -d -aes-256-cbc -pbkdf2 -in /tmp/drill.enc -out /tmp/drill.dump \
  -pass file:/path/to/backup_encryption_key

# 3. Restore into a throwaway local postgres
docker run -d --name pg-drill -e POSTGRES_PASSWORD=drill -p 127.0.0.1:55432:5432 postgres:16
sleep 5
docker exec -i pg-drill pg_restore -U postgres -d postgres --no-owner /dev/stdin < /tmp/drill.dump \
  || docker exec -i pg-drill psql -U postgres < /tmp/drill.dump   # format-dependent

# 4. Integrity spot checks
docker exec pg-drill psql -U postgres -c "
  SELECT 'messages', count(*) FROM messages
  UNION ALL SELECT 'contacts', count(*) FROM contacts
  UNION ALL SELECT 'campaigns', count(*) FROM campaigns
  UNION ALL SELECT 'api_keys', count(*) FROM api_keys;"

# 5. Clean up
docker rm -f pg-drill; rm -f /tmp/drill.enc /tmp/drill.dump
```

Repeat quarterly with a ClickHouse `.tar.enc` artifact (decrypt, untar,
check the per-table dumps are non-empty and parseable).

## RTO/RPO Validation

There is no WAL archiving or PITR — these are the honest numbers:

| Metric | Reality | How validated |
|--------|---------|---------------|
| **RPO** | ≤ 24 h (nightly cadence) | Age of newest restorable artifact at drill time |
| **RTO** | Hours — host rebuild dominates; measured, not promised | Quarterly host-rebuild drill ([DR Testing](disaster-recovery-testing.md)) |
| Backup frequency | Nightly (`@daily`) for both postgres and clickhouse | Scheduler logs |
| Backup retention | PostgreSQL 14d/8w/6m/newest-30; ClickHouse 14d/14 | Artifact listing |

## Failed-Backup Escalation Procedure

### Severity Levels

| Situation | Severity | Response Time |
|-----------|----------|---------------|
| Single artifact failed verification but next night succeeded | SEV4 | Ticket, review at next drill |
| Backup container unhealthy (no artifact within 25 h) | SEV2 | 1 hour — backups have stopped |
| 48 h+ with no successful backup | SEV1 | Immediate — data written since the last good backup is at risk |
| Offsite mirror not syncing (`BACKUP_TARGET` rsync failing) | SEV2 | 1 hour — host-loss protection is degraded |
| Manual restore drill failed | SEV2 | 1 hour |

### Escalation Flow

```
Backup failure detected (healthcheck red / drill failure)
        │
        ▼
Check scheduler logs (verification error? encryption key? DB reachable?)
        │
        ├── Transient → confirm next nightly run succeeds
        │
        └── Persistent
                │
                ▼
        Alert on-call operator (SEV1/SEV2)
                │
                ▼
        Fix root cause; trigger a manual backup run to close the gap
        (restart the postgres-backup / clickhouse-backup service)
                │
                ▼
        Verify a fresh encrypted artifact appears and passes verification
        │
        ▼
Post-mortem for SEV1/SEV2 (docs/evaluation/post-mortem-template.md)
```

---

## Drill Documentation Template

```markdown
# Backup Verification Drill — [Month] [Year]

**Date:** YYYY-MM-DD
**Conducted by:** [Name]
**Drill type:** [Postgres restore | ClickHouse restore | Offsite sync check]
**Duration:** [Start] → [End]

## Results

| Metric | Value | Target | Status |
|--------|-------|--------|--------|
| Artifact decrypted | yes/no | yes | |
| Restore completed | yes/no | yes | |
| Row counts plausible | yes/no | yes | |
| Backup age at drill time | [h] | ≤ 24 h | |
| Offsite mirror current | yes/no/n-a | yes (if configured) | |

## Issues Found

1. [Issue] — [Resolution]

## Sign-off

**Verified by:** [Name] — [Date]
```

---

## Related Documentation

- [Disaster Recovery & Backup Procedures](disaster-recovery.md) — the backup mechanism and recovery procedures
- [Disaster Recovery Testing](disaster-recovery-testing.md) — quarterly drills
- [Monitoring Runbook](monitoring.md)
- [Incident Response Runbook](runbooks/incident-response.md)
- [Post-mortem template](../evaluation/post-mortem-template.md)
