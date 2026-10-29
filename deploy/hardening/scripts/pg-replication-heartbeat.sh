#!/bin/sh
# =============================================================================
# pg-replication-heartbeat.sh — replicated heartbeat writer for the PRIMARY.
# =============================================================================
# Eighth external audit (DR wave, "pg_last_xact_replay_timestamp is the age
# of the last replayed transaction, not 'recently heard from the primary'"):
# the standby-side freshness gates need evidence the standby is STILL
# applying what the primary commits, end to end. This writer inserts one row
# every HEARTBEAT_INTERVAL_SECONDS (default 15) into
#
#   apexmail_ops.replication_heartbeat (primary_clock, primary_lsn)
#
# on the primary; PHYSICAL replication carries the rows to every standby, so
# pg-standby-promote.sh measures the age of the newest row ON THE STANDBY:
# if the standby has applied nothing from the primary for longer than
# STANDBY_MAX_HEARTBEAT_AGE_SECONDS, promotion is refused (unproven
# freshness) unless the operator passes --accept-unknown-loss. The replay
# timestamp alone cannot serve this role: it freezes when replication stops,
# reading identically on a live-primary standby and a dead one.
#
# Deployment (deploy/docker-compose.wal-archive.yml wires the runner as a
# second container next to the primary postgres):
#
#   docker compose -f docker-compose.yml -f docker-compose.prod.yml \
#     -f deploy/docker-compose.wal-archive.yml up -d postgres-heartbeat
#
# It can also be exec'd by hand INSIDE the primary container (the local
# socket trusts the postgres OS user's peers):
#
#   docker compose ... exec postgres sh /usr/local/bin/pg-replication-heartbeat.sh
#
# Connection: plain libpq env vars. As the compose sidecar the overlay sets
# PGHOST/PGUSER/PGDATABASE and mounts the postgres_password secret
# (PGPASSWORD_FILE); inside the primary container PGUSER defaults to
# POSTGRES_USER over the trusted socket. The exact write is the brief's:
#
#   psql -d postgres -v ON_ERROR_STOP=1 -c "INSERT INTO ..."
#
# The table is created idempotently before the loop; the schema and rows
# replicate to standbys as ordinary WAL. The loop is restart-tolerant: a
# failed insert (primary restarting, migration not applied yet) is logged
# loudly and retried on the next tick, and `restart: unless-stopped` covers
# a crashed writer. Rows older than 24h are pruned hourly so the table (and
# max(primary_clock) on the standby) stays small without touching the
# freshness window.
#
# Environment: HEARTBEAT_INTERVAL_SECONDS (default 15), POSTGRES_USER (psql
# role fallback inside the primary container, default apexmail), PGUSER /
# PGHOST / PGDATABASE / PGPASSWORD / PGPASSWORD_FILE (standard libpq; the
# compose sidecar sets them).
# =============================================================================

set -eu

HEARTBEAT_INTERVAL_SECONDS="${HEARTBEAT_INTERVAL_SECONDS:-15}"
HEARTBEAT_DB_USER="${PGUSER:-${POSTGRES_USER:-apexmail}}"
HEARTBEAT_PRUNE_KEEP_HOURS="${HEARTBEAT_PRUNE_KEEP_HOURS:-24}"
HEARTBEAT_PRUNE_EVERY_TICKS="${HEARTBEAT_PRUNE_EVERY_TICKS:-240}"

case $HEARTBEAT_INTERVAL_SECONDS in
    ''|*[!0-9]*) printf '[replication-heartbeat] FATAL: HEARTBEAT_INTERVAL_SECONDS must be numeric (got %s)\n' "'$HEARTBEAT_INTERVAL_SECONDS'" >&2; exit 1 ;;
esac
[ "$HEARTBEAT_INTERVAL_SECONDS" -ge 1 ] 2>/dev/null \
    || { echo '[replication-heartbeat] FATAL: HEARTBEAT_INTERVAL_SECONDS must be >= 1' >&2; exit 1; }

export PGUSER="$HEARTBEAT_DB_USER"
export PGDATABASE="${PGDATABASE:-postgres}"
# The compose sidecar bridges the postgres_password secret to PGPASSWORD;
# inside the primary container the local socket is trusted and this is a no-op.
if [ -n "${PGPASSWORD_FILE:-}" ] && [ -r "$PGPASSWORD_FILE" ]; then
    PGPASSWORD="$(tr -d '\r\n' < "$PGPASSWORD_FILE")"
    export PGPASSWORD
fi

hb_log() { printf '%s [replication-heartbeat] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
hb_err() { printf '%s [replication-heartbeat] ERROR: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }

command -v psql >/dev/null 2>&1 \
    || { hb_err "psql not on PATH — run inside a postgres container (the postgres-wal image bakes it)"; exit 1; }

# Idempotent bootstrap of the heartbeat table. Physical replication carries
# the schema and the rows to every standby — no standby-side DDL exists.
ensure_heartbeat_table() {
    psql -d postgres -v ON_ERROR_STOP=1 -q <<'SQL'
CREATE SCHEMA IF NOT EXISTS apexmail_ops;
CREATE TABLE IF NOT EXISTS apexmail_ops.replication_heartbeat (
    id bigint generated always as identity primary key,
    primary_clock timestamptz not null default now(),
    primary_lsn pg_lsn not null
);
SQL
}

until ensure_heartbeat_table; do
    hb_err "could not create apexmail_ops.replication_heartbeat (is the primary up and accepting this role?); retrying in ${HEARTBEAT_INTERVAL_SECONDS}s"
    sleep "$HEARTBEAT_INTERVAL_SECONDS"
done
hb_log "heartbeat table ready; writing every ${HEARTBEAT_INTERVAL_SECONDS}s (pruning rows older than ${HEARTBEAT_PRUNE_KEEP_HOURS}h every ${HEARTBEAT_PRUNE_EVERY_TICKS} ticks)"

_tick=0
while :; do
    if ! psql -d postgres -v ON_ERROR_STOP=1 \
        -c "INSERT INTO apexmail_ops.replication_heartbeat (primary_clock, primary_lsn) VALUES (now(), pg_current_wal_lsn())" >/dev/null 2>&1; then
        hb_err "heartbeat INSERT failed — the standby freshness gates will age out (apexmail_ops.replication_heartbeat); will retry next tick"
    fi
    _tick=$((_tick + 1))
    if [ "$_tick" -ge "$HEARTBEAT_PRUNE_EVERY_TICKS" ]; then
        _tick=0
        psql -d postgres -v ON_ERROR_STOP=1 -q \
            -c "DELETE FROM apexmail_ops.replication_heartbeat WHERE primary_clock < now() - ($HEARTBEAT_PRUNE_KEEP_HOURS || ' hours')::interval" 2>/dev/null \
            || hb_err "heartbeat prune failed (non-fatal; retried next window)"
    fi
    sleep "$HEARTBEAT_INTERVAL_SECONDS"
done
