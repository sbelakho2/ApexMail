# Disaster Recovery & Backup Procedures

> Rewritten 2026-09-05; a point-in-time recovery section was added
> 2026-10-25. Earlier versions of this document described a two-region HA
> topology (Finland primary / Germany standby), STONITH fencing, WireGuard
> interconnects, WAL archiving with PITR, and Kubernetes-based DR tooling.
> **None of that exists in production.** This document now describes the
> actual deployment: a **single Hetzner host in Finland** running the whole
> stack under Docker Compose, protected by encrypted nightly database
> backups. There is **no standby region and no automatic failover** —
> recovery means host rebuild plus backup restore. The one 2026-10-25
> addition: the repository ships operator-gated WAL-archiving and
> point-in-time recovery enablement, off until the operator includes the
> override (see below).

## Reality check (what DR actually looks like here)

| Property | Reality |
|---|---|
| Production topology | One Hetzner host (Finland), full stack via `docker-compose.prod.yml` |
| Standby region | **None.** There is no second region, no replication, no region failover |
| PostgreSQL backups | Nightly `pg_dump`, encrypted, restore-verified (see below) |
| ClickHouse backups | Nightly per-table dumps, encrypted, restore-verified |
| Redis backups | **None.** Redis holds cache/queue/challenge state only; after a loss the queue contents and cached state are gone |
| WAL archiving / PITR | **Enablement shipped, off in production.** Nothing archives until the operator sets `WAL_ARCHIVE_TARGET` and boots postgres with `deploy/docker-compose.wal-archive.yml` (checklist below). Until then the recovery point is the last nightly backup. When enabled: segments and the weekly physical base backup are **envelope-encrypted** before offsite transfer, and `archive_timeout` (default 300s) makes the RPO bound deterministic ("minutes") even on a write-idle database |
| Failover automation | None — a host failure is an outage until the host is rebuilt or replaced |
| Deployment | Self-hosted pipeline on the host (`ci/pipeline.sh`); see `deploy/DEPLOYMENT.md` |

Honest objectives (to be validated in drills, not measured yet):

- **RPO:** PostgreSQL and ClickHouse ≤ 24 h logical (nightly backup
  cadence); minutes-with-WAL for PostgreSQL when the operator enables
  archiving, bounded by the archive lag the `apexmail-wal-archive` alerts
  watch. Setting `BACKUP_TARGET` (offsite rsync mirror) protects against
  host loss, not against the cadence.
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
5. Mirror offsite — **mandatory** since 2026-10-26 (durability audit):
   encrypted artifacts are rsynced to the offsite host (rsync over SSH,
   key at `/var/run/apexmail-backup-ssh/id_ed25519`, pinned `known_hosts`,
   dedicated `apexmail_backup_egress` network). The compose service
   refuses an empty `BACKUP_TARGET` (`${VAR:?}`), the backup run fails
   non-zero when the mirror fails, and the healthcheck requires a fresh
   `.last_offsite_ok` stamp — a backup that has not left the host does not
   count as a backup.

Health monitoring: each backup container's healthcheck requires the scheduler
process to be alive **and** an encrypted artifact newer than 25 h to exist.
A red `postgres-backup`/`clickhouse-backup` in `docker compose ps` means
backups have silently stopped — treat as SEV2.

## Point-in-time recovery (WAL archiving, operator-gated)

Encryption: archived WAL segments and the weekly physical base backup are
sealed with the canonical backup envelope (the `backup-envelope.sh` codec,
same as the nightly dumps) before anything is rsynced. SSH protects the
wire, not the object at rest on the archive host, and raw WAL carries
arbitrary page images including personal data. The postgres container
receives the `backup_encryption_key` secret, or a dedicated key through
`WAL_ENCRYPTION_KEY_FILE`. With no key the archiver and the base backup
refuse to run. Recovery decrypts through the same envelope:
`pg-pitr-restore.sh` decrypts the base artifact into its private scratch
directory and runs a decrypting `restore_command`.

Deterministic RPO bound: `archive_timeout` (`WAL_ARCHIVE_TIMEOUT_SECS`,
default 300s) forces a WAL switch on a quiet database. The worst-case
recovery point is then the timeout plus one archive push, a fixed minute
scale rather than a figure that depends on write volume.
`PostgresWALArchiveLagExceeded` warns after 20 minutes without an archived
segment; `PostgresWALArchiveStalled` is critical at 2 hours.

## Point-in-time recovery (WAL archiving, operator-gated)

Since 2026-10-26 the repository ships full WAL-archiving and point-in-time
recovery enablement. It is **off until the operator turns it on**, and the
production deploy step is owner-gated on purpose. The nightly logical dumps
above stay exactly as they are and remain the primary recovery path; WAL
adds replay-to-a-timestamp on top for PostgreSQL. ClickHouse keeps the
nightly cadence either way.

The pieces, and what each does:

- `deploy/hardening/scripts/pg-wal-archive.sh`, the `archive_command`
  helper. It spools each segment locally, rsyncs the batch to
  `WAL_ARCHIVE_TARGET` (rsync over ssh, the same key/known_hosts pattern as
  the backup mirror) and exits 0 only when the segment left the host. A
  failed archive makes postgres retry, which is the designed backpressure.
- `deploy/docker-compose.wal-archive.yml`, the compose override that boots
  postgres with `archive_mode=on` and the helper mounted at
  `/usr/local/bin/pg-wal-archive.sh`, wires the SSH material and refuses to
  render without `WAL_ARCHIVE_TARGET`. It is active only when the operator
  passes `-f deploy/docker-compose.wal-archive.yml`; the canonical
  `docker-compose.prod.yml` deployment is untouched without it.
- `WAL_BASE_BACKUP_ENABLED=1` on the postgres-backup service, which takes a
  weekly physical base backup (`pg_basebackup -F tar -z`) into
  `/backups/wal-base/`, keeps 2 generations and mirrors them offsite.
  Replay needs a physical base; a logical dump cannot serve as one.
- `deploy/hardening/scripts/pg-pitr-restore.sh`, the operator and drill
  tool. It pulls the WAL archive back offsite, builds a scratch data dir
  from a base backup, replays to an RFC3339 timestamp or `latest`, and
  writes a drill-shaped JSON evidence record into `WAL_EVIDENCE_DIR`.
- the `apexmail-wal-archive` alert group (`deploy/alerting-rules.yml`):
  archive failures, a stale archive (more than 2 h since the last segment
  landed) and a documented spool-growth follow-up.

A timed drill makes the quarterly exercise executable evidence instead of
manual timing. `tools/pitr_drill.sh --out drill.json` boots a throwaway
postgres whose archive command ships encrypted segments to a local offsite
directory, writes rows, and seals a physical base backup; it then destroys
the source and measures `pg-pitr-restore.sh` recovering everything from the
offsite ciphertext alone. The JSON it writes records per-phase durations,
the measured `total_rto_s`, the replay LSN, and `verified` true only when
the restored row counts and checksum match the pre-destruction truth. File
it with the drill records; the production cadence stays the quarterly one
defined in [Disaster Recovery Testing](disaster-recovery-testing.md), run
on a scratch host and never against the live cluster.

### Operator enablement checklist

1. Provision an offsite WAL target reachable by rsync over ssh, e.g.
   `backup-user@offsite.example:/srv/apexmail-wal-archive`, and set
   `WAL_ARCHIVE_TARGET` in the deployment `.env`.
2. Provision the SSH key at `/var/run/apexmail-backup-ssh/id_ed25519`
   (or point `WAL_SSH_KEY_FILE` at another host path), register its public
   half in the target's `authorized_keys`, and pre-seed a pinned
   `known_hosts` file for `WAL_SSH_KNOWN_HOSTS_FILE`. The archiver is
   non-interactive; a first-connection host-key prompt fails the archive
   instead of hanging postgres. Reusing the backup mirror's key pair is fine.
3. From the repo root, boot postgres with the override:
   `docker compose -f docker-compose.yml -f docker-compose.prod.yml -f deploy/docker-compose.wal-archive.yml --env-file .env up -d postgres`
   (then re-up the stack so dependents re-resolve). Compose refuses to
   render without `WAL_ARCHIVE_TARGET`.
4. Verify archiving works: `select archived_count, failed_count,
   last_archived_time from pg_stat_archiver;` shows the count rising and
   failures flat, and segment files appear on the target host.
5. Set `WAL_BASE_BACKUP_ENABLED=1` in the `.env` so the next nightly pass
   takes the first weekly physical base backup into `/backups/wal-base/`,
   mirrored offsite with the dumps.
6. Watch the new `apexmail-wal-archive` alerts. Verify once that the
   postgres exporter exposes the `pg_stat_archiver` metrics (see the
   dependency note in `deploy/alerting-rules.yml`).
7. Run `pg-pitr-restore.sh` quarterly (on a scratch instance, not against
   the live cluster) and file the JSON evidence with the drill records in
   [Disaster Recovery Testing](disaster-recovery-testing.md).
8. Until step 3 happens, the honest DR posture stays as documented above:
   nightly logical dumps only.

With archiving on, the PostgreSQL recovery point is "minutes", bounded by
the archive lag the alerts watch, and recovery to any RFC3339 timestamp
inside the retained WAL window becomes possible (Procedure 4).

### Procedure 4: point-in-time recovery (only when enabled above)

```bash
# From the repo root, inside the postgres container (or any host with
# postgres installed), as the postgres OS user:
pg-pitr-restore.sh \
  --base /backups/wal-base/apexmail-wal-base-20261025-010000.tar.gz \
  --target 2026-10-25T08:30:00Z \
  --target-action promote
# Evidence lands in $WAL_EVIDENCE_DIR (pitr-restore-*.json) with the same
# schema the monthly restore drill writes.
```

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

Data written after the last nightly backup is lost (RPO ≤ 24 h). With WAL
archiving on, Procedure 4 instead recovers to a chosen timestamp.

### Procedure 2: Full host loss (host rebuilt or replaced)

1. **Rebuild the host** — `deploy/scripts/hetzner-bootstrap.sh` (Docker,
   UFW, sshd hardening, `/opt/apexmail`).
2. **Restore the offsite backups** — encrypted artifacts exist off-host
   (the mirror is mandatory; the healthcheck refuses a local-only state);
   rsync them back.
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
cadence. Two automated exercises run continuously since 2026-10-26:
every backup is verified at backup time (decrypt + `pg_restore --list`
before the plaintext is deleted), and the `postgres-restore-drill`
compose service restores the newest backup into a scratch database on a
cadence, runs integrity probes, drops the scratch database and writes a
JSON evidence record (`backup_at`, `recovery_started_at`,
`recovered_at`, measured `rpo_seconds` / `rto_seconds`, integrity
counts) under `/backups/drill-evidence/`. A drill that never succeeds
turns the container unhealthy. The manual **Procedure 2 on a scratch
host** remains the drill that matters most: provision a throwaway
Hetzner machine, run the bootstrap + pipeline + restore end-to-end from
the offsite mirror, and record the actual RTO.

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
