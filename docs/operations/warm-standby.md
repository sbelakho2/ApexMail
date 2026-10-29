# Warm Standby Runbook

> **Added 2026-10-28, repo-side preparation.** The repository ships a warm
> streaming-standby overlay for PostgreSQL. It is **off by default**: a
> standby exists only while the operator includes one of the standby
> overlays and sets the `STANDBY_*` environment documented in
> `.env.production.example` and in the overlay headers. Until that happens
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
- A standby on a **second host** also covers host loss. That is the remote
  topology below; standing it up is an owner decision involving a second
  machine, its own compose deployment, and network reachability between the
  two.

The standby is read-only while in recovery. Anything that needs to write
goes through the primary until a promotion happens.

## Two topologies, two overlays

The same-host and remote topologies are separate compose files (they used to
share one overlay that both depended on the local `postgres` service and
declared the second-host transport — neither can be true at once):

**Same-host** (`deploy/docker-compose.standby.yml`) is run on the primary
host. The standby joins only `apexmail_data_internal` (the primary's own
compose network); there is no external network stanza:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
  -f deploy/docker-compose.standby.yml --env-file .env up -d postgres-standby
```

**Remote** (`deploy/docker-compose.standby-remote.yml`) is run on the
standby host, with this repo checked out there and a `.env` in place. It
defines the standby standalone: no `depends_on`/reference of any local
`postgres` service, and the only network is the dedicated external
replication transport. Preconditions:

1. Pre-create the network on the standby host, attached to the restricted
   peer path: a WireGuard or Tailscale interface, or a dedicated replication
   interface on a private network segment, never a public bridge. Expose the
   primary's replication listener to its peer on the primary host the same
   way:

   ```bash
   docker network create --attachable apexmail_replication
   ```

2. Point `STANDBY_PRIMARY_HOST` at the address reachable through that peer
   and firewall the primary's port to the peer address.
3. Boot: `up -d postgres-standby` starts only the standby (no local
   postgres exists on this host, and the overlay references none):

```bash
docker compose -f docker-compose.yml \
  -f deploy/docker-compose.standby-remote.yml --env-file .env up -d postgres-standby
```

(`docker-compose.yml` is listed first only to anchor the project directory;
none of its services are started by this command.)

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
   same-host standby connects from the `apexmail_data_internal` bridge; a
   remote standby connects from the replication peer path:

   ```text
   host replication replicator <standby-subnet-or-peer-address> scram-sha-256
   ```

   ```sql
   SELECT pg_reload_conf();
   ```

3. Put the matching password in a file on the standby host, mode 0600, and
   set `STANDBY_REPL_PASSWORD_FILE` to its path (see
   `.env.production.example`).

4. Enable the replication heartbeat on the primary (see next section):
   include `deploy/docker-compose.wal-archive.yml` and start the
   `postgres-heartbeat` runner.

The entrypoint runs `deploy/hardening/scripts/pg-standby-bootstrap.sh`,
which waits for the primary to accept the credentials, retrying loudly
until `STANDBY_BOOTSTRAP_TIMEOUT_SECS`. On a remote host it is this retry
loop, not a compose dependency, that orders the boot. The bootstrap then
takes one `pg_basebackup -R -X stream -C -S apexmail_standby` into the
standby data volume and starts postgres with `hot_standby=on`.

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

## The replication heartbeat (freshness evidence)

The replay position a standby reports describes only what it has already
received. A disconnected standby's byte lag reads 0 while the primary keeps
committing WAL the standby never sees — the primary's unshipped tail is
invisible from the standby by construction. The end-to-end proof that the
standby is still hearing from the primary is therefore written traffic, not
a timestamp the standby mints itself:

- The `postgres-heartbeat` runner (wal-archive overlay, or
  `docker compose ... exec postgres sh /usr/local/bin/pg-replication-heartbeat.sh`)
  inserts one row every `HEARTBEAT_INTERVAL_SECONDS` (default 15) into
  `apexmail_ops.replication_heartbeat (primary_clock, primary_lsn)` on the
  primary.
- Physical replication carries the rows to the standby, so the newest row
  on the standby proves the standby applied something from the primary
  within that window.

`pg-standby-promote.sh` reads exactly that: heartbeat age over
`STANDBY_MAX_HEARTBEAT_AGE_SECONDS` (default 90) refuses promotion, and a
missing/empty heartbeat table is *unproven freshness* (the runner never
deployed), which refuses as well. `--accept-unknown-loss` is the only
override. The heartbeat is the primary evidence;
`pg_last_xact_replay_timestamp()` (`STANDBY_MAX_RECEIVE_AGE_SECS`, default
30) stays as the second gate. The replay timestamp alone is not "recently
heard from the primary": it freezes when replication stops, reading
identically on a live-primary standby and a dead one.

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
once it is gone, the only positions anyone holds are the standby's replay
position and the offsite archive's, and the archive check below proves only
that the *first* covers the *second*.

## Promote procedure

The promotion gate has three tiers; every refusal names its gate and the
measured evidence:

1. The replay-lag byte cap (`STANDBY_MAX_LAG_BYTES`), overridden by
   `--force` and nothing else.
2. The freshness gates, overridden by `--accept-unknown-loss` and nothing
   else: the replication heartbeat age
   (`STANDBY_MAX_HEARTBEAT_AGE_SECONDS`), the replay age
   (`STANDBY_MAX_RECEIVE_AGE_SECS`) and, when `STANDBY_WAL_ARCHIVE_DIR` is
   set, archive continuity. `--force` never touches them.
3. The not-a-standby guard, overridden by nothing.

About the archive gate, precisely: it proves *the offsite archive covers
the standby's replay position*, meaning the newest archived segment is at
least the last segment the standby received. It can never prove the dead
primary had shipped, let alone committed, everything it held; unshipped
primary WAL exists in no place this check can look. Proof complete means a
guarded promotion; proof incomplete means `--accept-unknown-loss`, an
operator decision to accept that unmeasured remainder, recorded in the
tool's output.

1. Confirm the standby is in recovery and the heartbeat is flowing, with
   the heartbeat age well under 90:

   ```sql
   SELECT extract(epoch from clock_timestamp() - max(primary_clock))
     FROM apexmail_ops.replication_heartbeat;
   ```

2. Promote, guarded:

   ```bash
   docker compose -f docker-compose.yml -f docker-compose.prod.yml \
     -f deploy/docker-compose.standby.yml --env-file .env \
     exec postgres-standby sh /usr/local/bin/pg-standby-promote.sh
   ```

3. The tool prints the measured evidence (lag bytes, heartbeat seconds,
   replay seconds, archive segments), promotes via `pg_promote()`, verifies
   the instance left recovery, and exits 0 on success. A failed gate
   refuses and exits 1: `--force` accepts only the byte-cap breach;
   `--accept-unknown-loss` accepts only unproven freshness; both together
   print which gate each flag covered.

4. Repoint the stack's database clients at the promoted instance (compose
   wiring change on the host) and restart the writers.

5. File the incident per [first-response-slo.md](first-response-slo.md)
   with the measured evidence at promotion time.

## Failback

Failback is manual and always a re-bootstrap. A promoted instance cannot be
demoted back into a standby, and the old primary must never resume writes
on its own. After the incident:

1. Decide which instance now holds the canonical data (usually the
   promoted standby).
2. Stop the writers, wipe the non-canonical side's data volume, and
   bootstrap a fresh standby against the canonical instance with the same
   overlay.
3. Promote back only through the same guarded procedure, with a human
   checking the evidence first.

With no standby running, the recovery paths that always exist (nightly
encrypted backups, and point-in-time recovery when archiving is enabled)
remain exactly as described in
[disaster-recovery.md](disaster-recovery.md); the daily verification pass
for both is [backup-verification.md](backup-verification.md).
