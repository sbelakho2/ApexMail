#!/bin/sh
# =============================================================================
# pg-standby-bootstrap.sh — warm-standby entrypoint bootstrap.
# =============================================================================
# External audit 6 remediation #14 (repo-side preparation; the owner runs
# production). Deployed by deploy/docker-compose.standby.yml as the
# postgres-standby `command:` — the image entrypoint (docker-entrypoint.sh)
# execs THIS script because its first argument is not `postgres`, and this
# script execs the entrypoint BACK with `postgres` once PGDATA is a standby
# clone, so the image's own init path (gosu drop, socket dir, perms) is
# preserved.
#
# What it does, exactly once per data dir:
#   (a) waits for the primary to accept this standby's replication
#       credentials (STANDBY_PRIMARY_HOST/PORT, STANDBY_REPL_USER,
#       STANDBY_REPL_PASSWORD_FILE) — the bootstrap retries until
#       STANDBY_BOOTSTRAP_TIMEOUT_SECS because the primary may still be
#       booting, its pg_hba may not permit replication yet, or the role may
#       not exist; every failed attempt logs the reason,
#   (b) takes ONE physical base backup:
#         pg_basebackup -R -X stream -C -S $STANDBY_SLOT
#       into PGDATA. -R writes standby.signal + primary_conninfo (slot
#       included); -C creates the physical replication slot idempotently
#       (a pre-existing slot from an earlier attempt is detected and reused
#       instead of failing the retry),
#   (c) execs postgres in standby mode (hot_standby=on) via the image
#       entrypoint.
#
# IDEMPOTENT: an existing PGDATA that already carries standby.signal skips
# the basebackup entirely — a restarted standby container rejoins streaming
# replication from its own data dir. A PGDATA with a cluster but NO
# standby.signal is refused: this entrypoint must never overwrite a primary
# (or an initdb'd empty cluster) with a fresh basebackup.
#
# Run as root via the compose overlay (the entrypoint drops privileges when
# it execs postgres); `docker compose exec postgres-standby` works for
# inspection. No --self-test here: the script is a straight-line bootstrap
# whose pieces (pg_basebackup, the entrypoint) only run against a live
# primary — see docs/operations/warm-standby.md.
# =============================================================================

set -eu

STANDBY_PRIMARY_HOST="${STANDBY_PRIMARY_HOST:-}"
STANDBY_PRIMARY_PORT="${STANDBY_PRIMARY_PORT:-5432}"
STANDBY_REPL_USER="${STANDBY_REPL_USER:-replicator}"
STANDBY_REPL_PASSWORD_FILE="${STANDBY_REPL_PASSWORD_FILE:-}"
STANDBY_SLOT="${STANDBY_SLOT:-apexmail_standby}"
STANDBY_BOOTSTRAP_TIMEOUT_SECS="${STANDBY_BOOTSTRAP_TIMEOUT_SECS:-600}"
STANDBY_BOOTSTRAP_POLL_SECS="${STANDBY_BOOTSTRAP_POLL_SECS:-5}"
PGDATA="${PGDATA:-/var/lib/postgresql/data}"

log() { printf '%s [standby-bootstrap] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
err() { printf '%s [standby-bootstrap] ERROR: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }

for _tool in pg_basebackup psql; do
    command -v "$_tool" >/dev/null 2>&1 \
        || { err "$_tool not on PATH — this script must run inside the postgres-wal image"; exit 1; }
done
command -v docker-entrypoint.sh >/dev/null 2>&1 \
    || { err "docker-entrypoint.sh not on PATH — the postgres image entrypoint is required"; exit 1; }

[ -n "$STANDBY_PRIMARY_HOST" ] || { err "STANDBY_PRIMARY_HOST is not set"; exit 1; }
[ -n "$STANDBY_REPL_PASSWORD_FILE" ] || { err "STANDBY_REPL_PASSWORD_FILE is not set"; exit 1; }
[ -r "$STANDBY_REPL_PASSWORD_FILE" ] || { err "cannot read $STANDBY_REPL_PASSWORD_FILE — mount it read-only into the standby container"; exit 1; }
case $STANDBY_PRIMARY_PORT in
    ''|*[!0-9]*) err "STANDBY_PRIMARY_PORT must be numeric (got '$STANDBY_PRIMARY_PORT')"; exit 1 ;;
esac
case $STANDBY_BOOTSTRAP_TIMEOUT_SECS in
    ''|*[!0-9]*) err "STANDBY_BOOTSTRAP_TIMEOUT_SECS must be numeric (got '$STANDBY_BOOTSTRAP_TIMEOUT_SECS')"; exit 1 ;;
esac
case $STANDBY_BOOTSTRAP_POLL_SECS in
    ''|*[!0-9]*) STANDBY_BOOTSTRAP_POLL_SECS=5 ;;
esac

# Idempotent fast path: already a standby — rejoin, never re-clone.
if [ -f "$PGDATA/standby.signal" ]; then
    log "PGDATA already carries standby.signal — skipping the basebackup, rejoining primary ${STANDBY_PRIMARY_HOST}:${STANDBY_PRIMARY_PORT}"
    exec docker-entrypoint.sh postgres -c hot_standby=on
fi
if [ -e "$PGDATA/PG_VERSION" ]; then
    err "$PGDATA holds a cluster without standby.signal — refusing to basebackup over it (wipe the postgres_standby_data volume to re-bootstrap)"
    exit 1
fi

# slot_exists — a slot left by an earlier attempt must be REUSED: pg_basebackup -C
# fails when the slot already exists, which would make the retry loop livelock.
# An unreachable primary answers "unknown", and the -C attempt then fails with
# the connection error and retries as intended.
slot_exists() {
    _se_out=$(psql -h "$STANDBY_PRIMARY_HOST" -p "$STANDBY_PRIMARY_PORT" \
        -U "$STANDBY_REPL_USER" -d postgres -tAc \
        "SELECT count(*) FROM pg_replication_slots WHERE slot_name = '$STANDBY_SLOT'" 2>/dev/null) \
        || return 1
    # A probe that printed something other than a number answers "unknown".
    case $_se_out in
        ''|*[!0-9]*) return 1 ;;
    esac
    [ "$_se_out" -ge 1 ]
}

PGPASSWORD="$(tr -d '\r\n' < "$STANDBY_REPL_PASSWORD_FILE")"
export PGPASSWORD

_deadline=$(( $(date +%s) + STANDBY_BOOTSTRAP_TIMEOUT_SECS ))
while :; do
    log "attempting pg_basebackup from ${STANDBY_REPL_USER}@${STANDBY_PRIMARY_HOST}:${STANDBY_PRIMARY_PORT} into $PGDATA (slot $STANDBY_SLOT)"
    # Positional assembly keeps the conditional -C legible under set -eu.
    set -- pg_basebackup \
        -h "$STANDBY_PRIMARY_HOST" -p "$STANDBY_PRIMARY_PORT" \
        -U "$STANDBY_REPL_USER" -D "$PGDATA" \
        -R -X stream -c fast -S "$STANDBY_SLOT" --no-password
    if ! slot_exists; then
        set -- "$@" -C
    fi
    if "$@" >/tmp/standby-basebackup.log 2>&1; then
        break
    fi
    # A torn attempt must not leave a half-written PGDATA behind: the next
    # try starts from an empty dir (the guard var keeps a stray empty PGDATA
    # from ever expanding the glob against /).
    rm -rf "${PGDATA:?}"/* 2>/dev/null || true
    if [ "$(date +%s)" -ge "$_deadline" ]; then
        err "primary ${STANDBY_PRIMARY_HOST}:${STANDBY_PRIMARY_PORT} did not accept replication within ${STANDBY_BOOTSTRAP_TIMEOUT_SECS}s — last pg_basebackup output:"
        sed 's/^/  /' /tmp/standby-basebackup.log >&2 || true
        exit 1
    fi
    log "primary not ready yet (retrying every ${STANDBY_BOOTSTRAP_POLL_SECS}s):"
    sed 's/^/  /' /tmp/standby-basebackup.log || true
    sleep "$STANDBY_BOOTSTRAP_POLL_SECS"
done
unset PGPASSWORD

[ -f "$PGDATA/standby.signal" ] || { err "pg_basebackup -R did not write standby.signal"; exit 1; }
log "basebackup complete — starting postgres in standby mode (hot_standby=on), following ${STANDBY_PRIMARY_HOST}:${STANDBY_PRIMARY_PORT}"
# The entrypoint takes it from here: PGDATA is non-empty so initdb is
# skipped, ownership is fixed up, and postgres execs as the postgres user.
exec docker-entrypoint.sh postgres -c hot_standby=on
