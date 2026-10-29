#!/bin/sh
# =============================================================================
# pg-standby-promote.sh — LAG-GUARDED promotion of the warm standby.
# =============================================================================
# External audit 6 remediation #14 (repo-side preparation). Runs INSIDE the
# standby container (pg-standby-bootstrap.sh's sibling, bind-mounted by
# deploy/docker-compose.standby.yml):
#
#   docker compose -f docker-compose.yml -f docker-compose.prod.yml \
#     -f deploy/docker-compose.standby.yml exec postgres-standby \
#     sh /usr/local/bin/pg-standby-promote.sh [--force]
#
# Guard rails:
#   * refuses on anything that is not currently a standby (in recovery),
#   * measures the replay lag in bytes
#     (pg_wal_lsn_diff(pg_last_wal_receive_lsn(), pg_last_wal_replay_lsn()) —
#     the WAL the standby already received but has not applied yet, the
#     promotion-relevant quantity: everything received is replayed before
#     the promotion completes, so this is the in-flight loss window the
#     standby itself controls),
#   * prints the measured lag and the cap, refuses above STANDBY_MAX_LAG_BYTES
#     (default 1 MiB) unless --force,
#   * promotes via pg_promote(wait => true) and verifies the instance left
#     recovery before reporting success.
#
# The lag the standby CANNOT measure from inside is the primary's
# not-yet-shipped WAL; that gap needs the primary alive (pg_stat_replication
# on the primary) or the archiving alerts — see docs/operations/warm-standby.md
# for the honest SLO statement.
#
# After a promotion there is no way back to standby mode on this data dir:
# failback means a fresh bootstrap (wipe the volume, restart the overlay).
#
# --self-test proves the lag decision and the usage contract WITHOUT docker
# (the decision function is pure; the psql probes are the only live part).
# =============================================================================

set -eu

STANDBY_MAX_LAG_BYTES="${STANDBY_MAX_LAG_BYTES:-1048576}"
STANDBY_PSQL_USER="${POSTGRES_USER:-apexmail}"
STANDBY_PSQL_HOST="${STANDBY_PSQL_HOST:-/var/run/postgresql}"

log() { printf '%s [standby-promote] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
err() { printf '%s [standby-promote] ERROR: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }

usage() {
    cat >&2 <<'EOF'
usage: pg-standby-promote.sh [--force]

  Promotes THIS standby to a primary after checking the replay lag against
  STANDBY_MAX_LAG_BYTES (default 1048576 = 1 MiB). Above the cap the
  promotion is REFUSED unless --force is given (an operator decision to
  accept the data loss).

Environment: STANDBY_MAX_LAG_BYTES, POSTGRES_USER (psql superuser of the
cloned cluster), STANDBY_PSQL_HOST (unix socket dir, default
/var/run/postgresql).
EOF
}

PROMOTE_FORCE=0

parse_args() {
    while [ $# -gt 0 ]; do
        case $1 in
            --force) PROMOTE_FORCE=1; shift ;;
            --help|-h)
                usage; return 0 ;;
            *)
                err "unknown argument: $1"; usage; return 2 ;;
        esac
    done
    return 0
}

# promotion_decision <lag-bytes|''> <cap-bytes> <force 0|1> — pure decision,
# printed then returned: 0 = promote, 1 = refuse, 2 = bad configuration.
# lag '' means "unmeasurable" (standby unreachable/psql failed): refusing is
# the honest default — an unknown lag is not a small lag.
promotion_decision() {
    _pd_lag=$1
    _pd_cap=$2
    _pd_force=$3
    case $_pd_cap in
        ''|*[!0-9]*)
            printf 'bad-config: STANDBY_MAX_LAG_BYTES must be numeric (got %s)\n' "'$_pd_cap'"
            return 2 ;;
    esac
    if [ "$_pd_force" = "1" ]; then
        printf 'force: promoting regardless of lag (cap %s bytes)\n' "$_pd_cap"
        return 0
    fi
    case $_pd_lag in
        ''|*[!0-9]*)
            printf 'refuse: replay lag is unmeasurable (%s) — refusing with an unknown lag\n' "'${_pd_lag:-empty}'"
            return 1 ;;
    esac
    if [ "$_pd_lag" -gt "$_pd_cap" ]; then
        printf 'refuse: replay lag %s bytes exceeds STANDBY_MAX_LAG_BYTES (%s bytes) — pass --force to accept the loss\n' "$_pd_lag" "$_pd_cap"
        return 1
    fi
    printf 'allow: replay lag %s bytes is within STANDBY_MAX_LAG_BYTES (%s bytes)\n' "$_pd_lag" "$_pd_cap"
    return 0
}

standby_psql() {
    psql -h "$STANDBY_PSQL_HOST" -U "$STANDBY_PSQL_USER" -d postgres -tAc "$1"
}

run_promote() {
    command -v psql >/dev/null 2>&1 \
        || { err "psql not on PATH — run inside the postgres-standby container"; return 1; }

    _rp_inrec=$(standby_psql 'SELECT pg_is_in_recovery()' 2>/dev/null) || _rp_inrec=""
    if [ "$_rp_inrec" != "t" ]; then
        err "this instance is NOT in recovery (pg_is_in_recovery() = '${_rp_inrec:-unreachable}') — there is nothing to promote; refusing"
        return 1
    fi

    _rp_lag=$(standby_psql \
        'SELECT coalesce(pg_wal_lsn_diff(pg_last_wal_receive_lsn(), pg_last_wal_replay_lsn())::bigint::text, $$0$$)' \
        2>/dev/null) || _rp_lag=""
    log "measured replay lag: ${_rp_lag:-unmeasurable} bytes (cap ${STANDBY_MAX_LAG_BYTES})"

    _rp_decision=$(promotion_decision "${_rp_lag:-}" "$STANDBY_MAX_LAG_BYTES" "$PROMOTE_FORCE") \
        || { _pd_rc=$?; printf '%s [standby-promote] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$_rp_decision" >&2; err "promotion REFUSED"; return "$_pd_rc"; }
    log "$_rp_decision"

    _rp_ok=$(standby_psql 'SELECT pg_promote(true, 60)' 2>/dev/null) || _rp_ok="f"
    if [ "$_rp_ok" != "t" ]; then
        err "pg_promote() did not succeed (got '$_rp_ok')"
        return 1
    fi
    _rp_after=$(standby_psql 'SELECT pg_is_in_recovery()' 2>/dev/null) || _rp_after="t"
    if [ "$_rp_after" != "f" ]; then
        err "promotion returned success but the instance still reports in recovery"
        return 1
    fi
    log "PROMOTED — this instance is now a primary. Failback is NOT automatic: re-bootstrap it as a standby (docs/operations/warm-standby.md)"
    return 0
}

# ── Self-test: lag decision + usage contract, no docker ──────────────────────
standby_promote_self_test() {
    _st_fail=0

    # 1. Usage contract (recursive invocation; parse_args fails before psql).
    if sh "$0" --definitely-not-a-flag >/dev/null 2>&1; then
        echo "[standby-promote] self-test FAILED: unknown flag must exit non-zero" >&2
        _st_fail=1
    fi
    sh "$0" --help >/dev/null 2>&1 || {
        echo "[standby-promote] self-test FAILED: --help must exit 0" >&2
        _st_fail=1
    }

    # 2. Decision table: below/at/over the cap, force, unmeasurable, bad cap.
    _st_out=$(promotion_decision 4096 1048576 0) || {
        echo "[standby-promote] self-test FAILED: small lag must be allowed" >&2
        _st_fail=1
    }
    case $_st_out in allow:*) : ;;
        *) echo "[standby-promote] self-test FAILED: small lag decision was '$_st_out'" >&2; _st_fail=1 ;;
    esac
    # Boundary: lag equal to the cap is allowed ("above the cap" refuses).
    _st_out=$(promotion_decision 1048576 1048576 0) || {
        echo "[standby-promote] self-test FAILED: lag == cap must be allowed" >&2
        _st_fail=1
    }
    case $_st_out in allow:*) : ;;
        *) echo "[standby-promote] self-test FAILED: boundary decision was '$_st_out'" >&2; _st_fail=1 ;;
    esac
    _st_out=$(promotion_decision 1048577 1048576 0) && {
        echo "[standby-promote] self-test FAILED: lag above the cap must be refused" >&2
        _st_fail=1
    }
    _st_rc=0
    _st_out=$(promotion_decision 2097152 1048576 0) || _st_rc=$?
    [ "$_st_rc" -eq 1 ] || {
        echo "[standby-promote] self-test FAILED: over-cap refusal must exit 1 (got $_st_rc)" >&2
        _st_fail=1
    }
    case $_st_out in refuse:*exceeds*) : ;;
        *) echo "[standby-promote] self-test FAILED: over-cap message must name the cap and the measured lag" >&2; _st_fail=1 ;;
    esac
    _st_out=$(promotion_decision 2097152 1048576 1) || {
        echo "[standby-promote] self-test FAILED: --force must allow an over-cap promotion" >&2
        _st_fail=1
    }
    case $_st_out in force:*) : ;;
        *) echo "[standby-promote] self-test FAILED: forced decision was '$_st_out'" >&2; _st_fail=1 ;;
    esac
    # Unmeasurable lag refuses (unknown lag is not a small lag).
    _st_rc=0
    _st_out=$(promotion_decision "" 1048576 0) || _st_rc=$?
    [ "$_st_rc" -eq 1 ] || {
        echo "[standby-promote] self-test FAILED: unmeasurable lag must refuse (got $_st_rc)" >&2
        _st_fail=1
    }
    case $_st_out in refuse:*unmeasurable*) : ;;
        *) echo "[standby-promote] self-test FAILED: unmeasurable decision was '$_st_out'" >&2; _st_fail=1 ;;
    esac
    # A non-numeric cap is a configuration error, exit 2, never a promote.
    _st_rc=0
    _st_out=$(promotion_decision 5 1MiB 0) || _st_rc=$?
    [ "$_st_rc" -eq 2 ] || {
        echo "[standby-promote] self-test FAILED: bad cap must exit 2 (got $_st_rc)" >&2
        _st_fail=1
    }
    case $_st_out in bad-config:*) : ;;
        *) echo "[standby-promote] self-test FAILED: bad-cap decision was '$_st_out'" >&2; _st_fail=1 ;;
    esac

    if [ "$_st_fail" -ne 0 ]; then
        echo "[standby-promote] self-test FAILED" >&2
        return 1
    fi
    echo "[standby-promote] self-test OK: usage contract, decision table (below/at/over the cap, over-cap with --force, unmeasurable lag refused, non-numeric cap rejected) with exit codes 0/1/2. NOTE: the psql probes and pg_promote() run only inside a live standby container (docs/operations/warm-standby.md)"
    return 0
}

if [ "${1:-}" = "--self-test" ]; then
    standby_promote_self_test
    exit $?
fi

case "${1:-}" in
    --help|-h) usage; exit 0 ;;
esac

# Under set -e a failing parse_args exits with its own status (2 on usage
# errors) — the same deliberate shape pg-pitr-restore.sh documents.
parse_args "$@"
run_promote
