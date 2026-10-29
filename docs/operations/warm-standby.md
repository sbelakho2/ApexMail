# Warm Standby Runbook

> **Added 2026-10-28, repo-side preparation.** The repository ships a warm
> streaming-standby overlay for PostgreSQL. It is **off by default**: a
> standby exists only while the operator includes
> `deploy/docker-compose.standby.yml` and sets the `STANDBY_*` environment
> documented (commented) in `.env.production.example`. Until that happens
> production stays a single-host deployment, and the recovery paths in
> [disaster-recovery.md](disaster-recovery.md) are the whole story.

**Cadence:** standby lag checked during the daily backup-verification pass
**Related:** [disaster-recovery.md](disaster-recovery.md),
[backup-verification.md](backup-verification.md)

## What this protects, honestly

A warm standby is a second postgres holding a streaming replica of the
primary, kept warm by physical replication. Promoted in minutes, it turns a
postgres-level incident (corruption, a destructive migration, an operator
error that kills the data dir) into a short outage instead of a restore.

Two limits matter:

- A standby on the **same host** as the primary survives only postgres-level
  loss. When the host dies, both copies die with it; the encrypted offsite
  backups remain the last line of defense.
- A standby on a **second host** (point `STANDBY_PRIMARY_HOST` at the
  primary across the network) also covers host loss. That is the topology
  this overlay prepares for; standing it up is an owner decision involving a
  second machine, its own compose deployment, and network reachability
  between the two.

The standby is read-only while in recovery. Anything that needs to write
goes through the primary until a promotion happens.

## Bootstrap

Prerequisites on the **primary**, once:

1. Create a replication role (superuser psql on the primary):

   ```bash
   docker compose -f docker-compose.yml -f docker-compose.prod.yml --env-file .env \
     exec postgres psql -U apexmail -d postgres \
     -c "CREATE ROLE replicator WITH REPLICATION LOGIN PASSWORD '<standby-password>';"
   ```

2. Permit replication connections from the standby in the primary's
   `pg_hba.conf` (inside the `postgres_data` volume), then reload it. A
   same-host standby connects from the `apexmail_data_internal` bridge:

   ```text
   host replication replicator 172.21.0.0/16 scram-sha-256
   ```

   ```sql
   SELECT pg_reload_conf();
   ```

3. Put the matching password in a file on the standby host, mode 0600, and
   set `STANDBY_REPL_PASSWORD_FILE` to its path (see
   `.env.production.example`).

Then boot the standby from the repo root:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
  -f deploy/docker-compose.standby.yml --env-file .env up -d postgres-standby
```

The entrypoint runs `deploy/hardening/scripts/pg-standby-bootstrap.sh`,
which waits for the primary to accept the credentials (retrying loudly
until `STANDBY_BOOTSTRAP_TIMEOUT_SECS`), takes ONE
`pg_basebackup -R -X stream -C -S apexmail_standby` into the standby data
volume, and starts postgres with `hot_standby=on`.

Idempotency: a standby data dir that already carries `standby.signal`
skips the basebackup on every restart and rejoins streaming replication. A
data dir holding a cluster that lacks `standby.signal` makes the bootstrap
refuse to start (it never overwrites a primary); wiping the
`postgres_standby_data` volume starts a fresh clone.

Verify streaming on both sides:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
  -f deploy/docker-compose.standby.yml --env-file .env \
  exec postgres-standby psql -U apexmail -d postgres \
  -c "SELECT pg_is_in_recovery(), pg_last_wal_receive_lsn(), pg_last_wal_replay_lsn();"
```

On the primary, `pg_stat_replication` must show the standby with state
`streaming`, and `pg_replication_slots` must list `apexmail_standby` as
active.

## Second-host transport requirement (seventh external audit)

The production data network is `internal: true`: it cannot carry traffic to
a primary on another physical machine. A second-failure-domain standby must
join the dedicated `apexmail_replication` network this overlay declares:

1. Create the network on both hosts attached to the restricted peer path
   (WireGuard/Tailscale or a dedicated replication interface), never a
   public bridge: `docker network create --attachable apexmail_replication`.
2. Expose PostgreSQL only to that peer (firewall the port to the peer
   address; do not open it broadly).
3. Set `STANDBY_PRIMARY_HOST` to the address reachable through that peer.

Same-host operation needs none of this: the data network already reaches
the primary. The promotion gate below additionally refuses a promotion
when freshness evidence is missing.

## Lag SLO

The quantity the standby itself can measure is the **replay lag**: WAL the
standby has already received but has not applied yet. Everything received
is applied during a promotion, so this is the in-flight window the standby
controls. Check it any time:

```sql
SELECT pg_wal_lsn_diff(pg_last_wal_receive_lsn(), pg_last_wal_replay_lsn());
```

SLO: replay lag stays under `STANDBY_MAX_LAG_BYTES` (default 1048576, one
MiB). The promotion tool enforces exactly this bound.

The honest caveat: WAL the primary never shipped cannot be measured from
the standby. While the primary is alive, read `pg_stat_replication` on it;
once it is gone, the `apexmail-wal-archive` alerts bound the archiving gap
when archiving is enabled. A promotion decision therefore combines the
measured standby lag with an operator judgment on that unmeasured
remainder.

## Promote procedure

1. Check the lag (query above) and confirm the standby is in recovery.

2. Promote, guarded:

   ```bash
   docker compose -f docker-compose.yml -f docker-compose.prod.yml \
     -f deploy/docker-compose.standby.yml --env-file .env \
     exec postgres-standby sh /usr/local/bin/pg-standby-promote.sh
   ```

3. The tool prints the measured lag and the cap, promotes via
   `pg_promote()`, verifies the instance left recovery, and exits 0 on
   success. Above the cap it refuses and exits 1; `--force` promotes
   anyway, recording that an operator accepted the loss window.

4. Repoint the stack's database clients at the promoted instance (compose
   wiring change on the host) and restart the writers.

5. File the incident per [first-response-slo.md](first-response-slo.md)
   with the measured lag at promotion time.

## Failback

Failback is manual and always a re-bootstrap. A promoted instance cannot be
demoted back into a standby, and the old primary must never resume writes
on its own. After the incident:

1. Decide which instance now holds the canonical data (usually the
   promoted standby).
2. Stop the writers, wipe the non-canonical side's data volume, and
   bootstrap a fresh standby against the canonical instance with this same
   overlay.
3. Promote back only through the same guarded procedure, with a human
   checking the lag first.

With no standby running, the recovery paths that always exist (nightly
encrypted backups, and point-in-time recovery when archiving is enabled)
remain exactly as described in
[disaster-recovery.md](disaster-recovery.md); the daily verification pass
for both is [backup-verification.md](backup-verification.md).
