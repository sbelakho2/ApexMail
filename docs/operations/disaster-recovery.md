# Disaster Recovery & Backup Procedures

> **Rewritten 2026-09-05.** Earlier versions of this document described a
> two-region HA topology (Finland primary / Germany standby), STONITH fencing,
> WireGuard interconnects, WAL archiving with PITR, and Kubernetes-based DR
> tooling. **None of that exists.** This document now describes the actual
> deployment: a **single Hetzner host in Finland** running the whole stack
> under Docker Compose, protected by encrypted nightly database backups. There
> is **no standby region and no automatic failover** — recovery means host
> rebuild plus backup restore.

## Reality check (what DR actually looks like here)

| Property | Reality |
|---|---|
| Production topology | One Hetzner host (Finland), full stack via `docker-compose.prod.yml` |
| Standby region | **None.** There is no second region, no replication, no region failover |
| PostgreSQL backups | Nightly `pg_dump`, encrypted, restore-verified (see below) |
| ClickHouse backups | Nightly per-table dumps, encrypted, restore-verified |
| Redis backups | **None.** Redis holds cache/queue/challenge state only; after a loss the queue contents and cached state are gone |
| WAL archiving / PITR | **Not implemented.** Recovery point granularity is the last nightly backup (RPO up to ~24 h) |
| Failover automation | None — a host failure is an outage until the host is rebuilt or replaced |
| Deployment | Self-hosted pipeline on the host (`ci/pipeline.sh`); see `deploy/DEPLOYMENT.md` |

Honest objectives (to be validated in drills, not measured yet):

- **RPO:** PostgreSQL and ClickHouse ≤ 24 h (nightly backup cadence). Setting
  `BACKUP_TARGET` (offsite rsync mirror) protects against host loss, not
  against the cadence.
- **RTO:** hours, not minutes — a full recovery involves provisioning/rebuilding
  the host, re-running the bootstrap, rebuilding all images, and restoring the
  databases. Measure it in the quarterly drill and record the real number.

## Backup mechanism

Two compose services implement backups (`docker-compose.prod.yml`):
`postgres-backup` and `clickhouse-backup`. Both run the same contract
(`deploy/hardening/scripts/postgres-backup-encrypt.sh` /
`clickhouse-backup-encrypt.sh`):

1. Dump the data (PostgreSQL `pg_dump`; ClickHouse per-table `SELECT` dumps —
   each table dump is atomic, but the set is **not** a cross-table snapshot;
   acceptable for the append-only OLAP data).
2. Encrypt with AES-256-CBC + PBKDF2 using the `backup_encryption_key` Docker
   secret (`PROD_BACKUP_ENCRYPTION_KEY_FILE`).
3. **Verify restorability before deleting the plaintext** — decrypt the
   artifact and run `pg_restore --list` (or the ClickHouse equivalent check).
   A backup that cannot be decrypted and read is never counted as good.
4. Prune: PostgreSQL keeps `BACKUP_KEEP_DAYS` (14) / weeks (8) / months (6)
   with a newest-`BACKUP_KEEP_COUNT` (30) bound; ClickHouse keeps 14 days /
   14 artifacts.
5. Optionally mirror offsite: when `BACKUP_TARGET` is set (rsync over SSH,
   key at `/var/run/apexmail-backup-ssh/id_ed25519`, pinned `known_hosts`,
   dedicated `apexmail_backup_egress` network), encrypted artifacts are
   copied to the offsite host. Without `BACKUP_TARGET`, backups exist **only
   on the same physical host** as the database — a host-disk failure without
   an offsite mirror can be total data loss. Configure it.

Health monitoring: each backup container's healthcheck requires the scheduler
process to be alive **and** an encrypted artifact newer than 25 h to exist.
A red `postgres-backup`/`clickhouse-backup` in `docker compose ps` means
backups have silently stopped — treat as SEV2.

### What is *not* backed up (known gaps)

- **Redis** — queue contents, rate-limit counters, and KiwiCaptcha challenges
  are lost on Redis loss; in-flight queued email not yet persisted to
  PostgreSQL is gone.
- **Analytics-cold store** — no backup job covers it.
- **Host-local state** under `/opt/apexmail` (`.env`, `secrets/`, TLS certs)
  must be re-rendered during rebuild from `.env.production.example` +
  `deploy/scripts/issue-letsencrypt.sh` (keep an offline copy of the secrets
  — they cannot be regenerated).

## Recovery procedures

### Procedure 1: PostgreSQL data loss / corruption (host survives)

```bash
# 1. Stop the writers
docker compose -f docker-compose.yml -f docker-compose.prod.yml --env-file .env stop api-server worker mta tracking enterprise sales-autopilot billing-service

# 2. Decrypt + restore the latest verified backup
docker compose ... exec postgres-backup sh -c \
  'openssl enc -d -aes-256-cbc -pbkdf2 -in /backups/<latest>.enc -out /backups/restore.dump -pass file:/run/secrets/backup_encryption_key'
docker compose ... exec postgres dropdb -U apexmail apexmail   # data is already lost/corrupt
docker compose ... exec postgres createdb -U apexmail apexmail
docker compose ... exec postgres pg_restore -U apexmail -d apexmail --no-owner /backups/restore.dump

# 3. Restart and verify
docker compose ... up -d
make verify
```

Data written after the last nightly backup is lost (RPO ≤ 24 h).

### Procedure 2: Full host loss (host rebuilt or replaced)

1. **Rebuild the host** — `deploy/scripts/hetzner-bootstrap.sh` (Docker,
   UFW, sshd hardening, `/opt/apexmail`).
2. **Restore the offsite backups** — if `BACKUP_TARGET` was configured, the
   encrypted artifacts exist off-host; rsync them back. If it was **not**
   configured, the backups died with the host: this is a total-loss scenario.
3. **Re-deploy from scratch** — follow *Fresh-host bootstrap* in
   `deploy/DEPLOYMENT.md`: clone the repo, render `.env` from
   `.env.production.example`, re-create all `PROD_*_FILE` secret files,
   `ci/install.sh`, `ci/pipeline.sh run` (builds all images on the host).
4. **Restore databases** — Procedure 1 against the recovered artifacts.
5. **Reissue TLS** — `deploy/scripts/issue-letsencrypt.sh` (certs are not
   backed up).
6. **Verify** — `make verify` plus the deploy verification checklist in
   `deploy/DEPLOYMENT.md`.

### Procedure 3: Single service failure

Restart via compose (`docker compose ... up -d <svc>`); the pipeline's verify
stage output and the per-service healthchecks (`/health/live`, `/health/ready`)
identify what is down. Services are stateless except postgres/redis/clickhouse/
mailstore volumes, so a crashed service recovers with no data action.

## DR testing

See [Disaster Recovery Testing](disaster-recovery-testing.md) for the drill
cadence. The drill that matters most is **Procedure 2 on a scratch host**:
provision a throwaway Hetzner machine, run the bootstrap + pipeline + restore
end-to-end from the offsite mirror, and record the actual RTO. Every backup's
restorability is additionally verified automatically at backup time
(decrypt + `pg_restore --list` before the plaintext is deleted).

## Data retention

Plan-dependent event/analytics retention is defined in
[compliance/data-retention.md](../compliance/data-retention.md) and is
separate from the backup retention above (backup retention is a fixed
operational window, not a plan feature).

## Related documentation

- [deploy/DEPLOYMENT.md](../../deploy/DEPLOYMENT.md) — canonical deployment and fresh-host bootstrap
- [Backup Verification](backup-verification.md)
- [Disaster Recovery Testing](disaster-recovery-testing.md)
- [Runbook: DB recovery](runbooks/db-recovery.md)
- [Runbook: Redis failure](runbooks/redis-failure.md)
