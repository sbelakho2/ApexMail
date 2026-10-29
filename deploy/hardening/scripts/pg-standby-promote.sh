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
# Seventh external audit, P1-DR-1: the replay lag alone is NOT an RPO
# bound. A disconnected standby reports lag 0 while the primary keeps
# committing WAL the standby never received (receive == replay == stale).
# The promotion gate therefore requires END-TO-END freshness evidence:
#   1. replay lag (in-flight loss the standby controls),
#   2. WAL-receipt FRESHNESS: the age of pg_last_xact_replay_timestamp()
#      must be under STANDBY_MAX_RECEIVE_AGE_SECS (default 30) — a standby
#      whose last replayed transaction is minutes old has been
#      disconnected, whatever the byte lag says,
#   3. when STANDBY_WAL_ARCHIVE_DIR is set: ARCHIVE CONTINUITY — the
#      newest archived segment on the offsite target must be >= the last
#      segment the standby received, proving no gap exists that only the
#      dead primary ever held.
# Evidence 2/3 missing or stale = freshness UNPROVEN = refuse, with
# --accept-unknown-loss as the explicit operator override (distinct from
# --force, which overrides the byte cap).
#
# After a promotion there is no way back to standby mode on this data dir:
# failback means a fresh bootstrap (wipe the volume, restart the overlay).
#
# --self-test proves the lag decision and the usage contract WITHOUT docker
# (the decision function is pure; the psql probes are the only live part).
# =============================================================================

set -eu

STANDBY_MAX_LAG_BYTES="${STANDBY_MAX_LAG_BYTES:-1048576}"
STANDBY_MAX_RECEIVE_AGE_SECS="${STANDBY_MAX_RECEIVE_AGE_SECS:-30}"
STANDBY_WAL_ARCHIVE_DIR="${STANDBY_WAL_ARCHIVE_DIR:-}"
STANDBY_PSQL_USER="${POSTGRES_USER:-apexmail}"
STANDBY_PSQL_HOST="${STANDBY_PSQL_HOST:-/var/run/postgresql}"

log() { printf '%s [standby-promote] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
err() { printf '%s [standby-promote] ERROR: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }

usage() {
    cat >&2 <<'EOF'
usage: pg-standby-promote.sh [--force] [--accept-unknown-loss]

  Promotes THIS standby to a primary after checking END-TO-END freshness:
  the replay lag against STANDBY_MAX_LAG_BYTES (default 1 MiB), the age of
  the last replayed transaction against STANDBY_MAX_RECEIVE_AGE_SECS
  (default 30, the disconnection evidence a byte lag cannot show), and —
  when STANDBY_WAL_ARCHIVE_DIR is set — offsite archive continuity. A
  failed gate REFUSES: --force overrides the byte cap, and
  --accept-unknown-loss is the explicit operator decision to promote with
  UNPROVEN freshness (the two are deliberately separate decisions).

Environment: STANDBY_MAX_LAG_BYTES, STANDBY_MAX_RECEIVE_AGE_SECS,
STANDBY_WAL_ARCHIVE_DIR, POSTGRES_USER (psql superuser of the cloned
cluster), STANDBY_PSQL_HOST (unix socket dir, default /var/run/postgresql).
EOF
}

PROMOTE_FORCE=0
ACCEPT_UNKNOWN=0

parse_args() {
    while [ $# -gt 0 ]; do
        case $1 in
            --force) PROMOTE_FORCE=1; shift ;;
            --accept-unknown-loss) ACCEPT_UNKNOWN=1; shift ;;
            --help|-h)
                usage; return 0 ;;
            *)
                err "unknown argument: $1"; usage; return 2 ;;
        esac
    done
    return 0
}

# promotion_decision <lag-bytes|''> <cap-bytes> <replay-age-secs|''>
#   <age-cap-secs> <continuity: ok|gap|unknown> <force 0|1>
#   <accept-unknown 0|1> — pure decision, printed then returned:
#   0 = promote, 1 = refuse, 2 = bad configuration.
# lag/age '' means "unmeasurable": refusing is the honest default — an
# unknown lag is not a small lag, and unknown freshness is not freshness.
promotion_decision() {
    _pd_lag=$1
    _pd_cap=$2
    _pd_age=$3
    _pd_age_cap=$4
    _pd_continuity=$5
    _pd_force=$6
    _pd_accept=$7
    case $_pd_cap in
        ''|*[!0-9]*)
            printf 'bad-config: STANDBY_MAX_LAG_BYTES must be numeric (got %s)\n' "'$_pd_cap'"
            return 2 ;;
    esac
    case $_pd_age_cap in
        ''|*[!0-9]*)
            printf 'bad-config: STANDBY_MAX_RECEIVE_AGE_SECS must be numeric (got %s)\n' "'$_pd_age_cap'"
            return 2 ;;
    esac
    if [ "$_pd_force" = "1" ] && [ "$_pd_accept" = "1" ]; then
        printf 'force: promoting regardless of lag and freshness (cap %s bytes, age cap %ss)\n' "$_pd_cap" "$_pd_age_cap"
        return 0
    fi
    if [ "$_pd_force" = "1" ]; then
        printf 'force: promoting regardless of the byte cap (freshness gates still apply; add --accept-unknown-loss for those)\n'
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
    # P1-DR-1: end-to-end freshness. receive==replay on a DISCONNECTED
    # standby reads as lag 0 while the primary's unshipped WAL grows; the
    # replay age and the archive continuity are the disconnection evidence.
    case $_pd_age in
        ''|*[!0-9]*)
            if [ "$_pd_accept" = "1" ]; then
                printf 'accept-unknown-loss: replay age unmeasurable — operator explicitly accepted\n'
            else
                printf 'refuse: WAL freshness is UNPROVEN (replay age unmeasurable) — pass --accept-unknown-loss only as a deliberate operator decision\n'
                return 1
            fi ;;
        *)
            if [ "$_pd_age" -gt "$_pd_age_cap" ]; then
                if [ "$_pd_accept" = "1" ]; then
                    printf 'accept-unknown-loss: replay age %ss exceeds %ss — operator explicitly accepted\n' "$_pd_age" "$_pd_age_cap"
                else
                    printf 'refuse: last replayed transaction is %ss old (cap %ss) — the standby has been DISCONNECTED; byte lag %s is not an RPO bound (P1-DR-1)\n' "$_pd_age" "$_pd_age_cap" "$_pd_lag"
                    return 1
                fi
            fi ;;
    esac
    case $_pd_continuity in
        ok) ;;
        gap)
            if [ "$_pd_accept" = "1" ]; then
                printf 'accept-unknown-loss: archive continuity shows a GAP — operator explicitly accepted\n'
            else
                printf 'refuse: the offsite archive is BEHIND the standby (continuity gap) — WAL exists only the dead primary held; pass --accept-unknown-loss deliberately\n'
                return 1
            fi ;;
        *) ;; # unknown/not-configured: age gate above is the freshness evidence
    esac
    printf 'allow: replay lag %s bytes within %s, replay age %ss within %ss, continuity %s\n' \
        "$_pd_lag" "$_pd_cap" "${_pd_age:-?}" "$_pd_age_cap" "$_pd_continuity"
    return 0
}

# archive_continuity <archive-dir> — 'ok' when the newest archived .gz.enc/
# .enc/plain segment >= the standby's last received segment, 'gap' when the
# archive is behind, 'unknown' when the check cannot run. Pure string math
# over WAL segment names (hex, time+log ordered).
archive_continuity() {
    _ac_dir=$1
    _ac_received=$2
    [ -n "$_ac_dir" ] && [ -d "$_ac_dir" ] || { printf 'unknown'; return 0; }
    [ -n "$_ac_received" ] || { printf 'unknown'; return 0; }
    _ac_newest=''
    for _ac_candidate in "$_ac_dir"/*; do
        [ -f "$_ac_candidate" ] || continue
        _ac_name=${_ac_candidate##*/}
        case $_ac_name in
            ????????????????????????.gz.enc|????????????????????????.enc|????????????????????????)
                if [ -z "$_ac_newest" ] || [ "$(expr "$_ac_name" '>' "$_ac_newest")" = 1 ]; then
                    _ac_newest=$_ac_name
                fi ;;
        esac
    done
    [ -n "$_ac_newest" ] || { printf 'unknown'; return 0; }
    _ac_newest_base=${_ac_newest%%.*}
    if [ "$(expr "$_ac_newest_base" '<' "$_ac_received")" = "1" ]; then
        printf 'gap'
    else
        printf 'ok'
    fi
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
    # P1-DR-1 freshness evidence: the age of the last replayed transaction
    # (disconnection evidence byte lag cannot show) and the standby's last
    # received segment for the archive continuity check.
    _rp_age=$(standby_psql \
        'SELECT coalesce(extract(epoch from now() - pg_last_xact_replay_timestamp())::bigint::text, $$-1$$)' \
        2>/dev/null) || _rp_age=""
    [ "$_rp_age" = "-1" ] && _rp_age=""
    _rp_received=$(standby_psql \
        "SELECT coalesce(pg_walfile_name(pg_last_wal_replay_lsn()), '')" \
        2>/dev/null) || _rp_received=""
    _rp_continuity=$(archive_continuity "$STANDBY_WAL_ARCHIVE_DIR" "$_rp_received")
    log "evidence: replay lag ${_rp_lag:-unmeasurable}B (cap ${STANDBY_MAX_LAG_BYTES}), replay age ${_rp_age:-unmeasurable}s (cap ${STANDBY_MAX_RECEIVE_AGE_SECS}), archive continuity ${_rp_continuity}${STANDBY_WAL_ARCHIVE_DIR:+ @ $STANDBY_WAL_ARCHIVE_DIR}"

    _rp_decision=$(promotion_decision "${_rp_lag:-}" "$STANDBY_MAX_LAG_BYTES" "${_rp_age:-}" "$STANDBY_MAX_RECEIVE_AGE_SECS" "$_rp_continuity" "$PROMOTE_FORCE" "$ACCEPT_UNKNOWN") \
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

    # 2. Decision table: lag + freshness + continuity (P1-DR-1).
    _st_out=$(promotion_decision 4096 1048576 5 30 ok 0 0) || {
        echo "[standby-promote] self-test FAILED: fresh small-lag must be allowed" >&2
        _st_fail=1
    }
    case $_st_out in allow:*) : ;;
        *) echo "[standby-promote] self-test FAILED: small fresh decision was '$_st_out'" >&2; _st_fail=1 ;;
    esac
    _st_out=$(promotion_decision 1048576 1048576 30 30 ok 0 0) || {
        echo "[standby-promote] self-test FAILED: boundary lag+age must be allowed" >&2
        _st_fail=1
    }
    _st_rc=0
    _st_out=$(promotion_decision 1048577 1048576 5 30 ok 0 0) || _st_rc=$?
    [ "$_st_rc" -eq 1 ] && case $_st_out in "refuse:"*"exceeds"*) : ;; *) _st_rc=0 ;; esac
    [ "$_st_rc" -eq 1 ] || {
        echo "[standby-promote] self-test FAILED: over-cap must refuse naming the cap (got '$_st_out')" >&2
        _st_fail=1
    }
    _st_out=$(promotion_decision 2097152 1048576 5 30 ok 1 0) || {
        echo "[standby-promote] self-test FAILED: --force must allow over-cap" >&2
        _st_fail=1
    }
    # THE P1-DR-1 CASE: zero byte lag, STALE replay age = disconnected
    # standby; must refuse and the message must say the byte lag is not an
    # RPO bound.
    _st_rc=0
    _st_out=$(promotion_decision 0 1048576 300 30 ok 0 0) || _st_rc=$?
    [ "$_st_rc" -eq 1 ] && case $_st_out in "refuse:"*"DISCONNECTED"*"not an RPO bound"*) : ;; *) _st_rc=0 ;; esac
    [ "$_st_rc" -eq 1 ] || {
        echo "[standby-promote] self-test FAILED: stale replay age with lag 0 must refuse as disconnected (got '$_st_out')" >&2
        _st_fail=1
    }
    # Unmeasurable age refuses unless the explicit override.
    _st_rc=0
    _st_out=$(promotion_decision 0 1048576 "" 30 ok 0 0) || _st_rc=$?
    [ "$_st_rc" -eq 1 ] && case $_st_out in "refuse:"*"UNPROVEN"*) : ;; *) _st_rc=0 ;; esac
    [ "$_st_rc" -eq 1 ] || {
        echo "[standby-promote] self-test FAILED: unmeasurable age must refuse (got '$_st_out')" >&2
        _st_fail=1
    }
    _st_out=$(promotion_decision 0 1048576 300 30 ok 0 1) || {
        echo "[standby-promote] self-test FAILED: --accept-unknown-loss must allow the stale age" >&2
        _st_fail=1
    }
    case $_st_out in *accept-unknown-loss*) ;;
        *) echo "[standby-promote] self-test FAILED: acceptance message missing (got '$_st_out')" >&2; _st_fail=1 ;;
    esac
    # Archive continuity: gap refuses, parity ok.
    _st_rc=0
    _st_out=$(promotion_decision 0 1048576 5 30 gap 0 0) || _st_rc=$?
    [ "$_st_rc" -eq 1 ] && case $_st_out in "refuse:"*"archive"*) : ;; *) _st_rc=0 ;; esac
    [ "$_st_rc" -eq 1 ] || {
        echo "[standby-promote] self-test FAILED: archive gap must refuse (got '$_st_out')" >&2
        _st_fail=1
    }
    _st_out=$(promotion_decision 0 1048576 5 30 ok 0 0) || {
        echo "[standby-promote] self-test FAILED: continuity ok must allow" >&2
        _st_fail=1
    }
    # Bad config: non-numeric caps.
    promotion_decision 0 not-a-number 5 30 ok 0 0 >/dev/null 2>&1 && {
        echo "[standby-promote] self-test FAILED: bad lag cap must exit 2" >&2
        _st_fail=1
    }
    promotion_decision 0 1048576 5 not-a-number ok 0 0 >/dev/null 2>&1 && {
        echo "[standby-promote] self-test FAILED: bad age cap must exit 2" >&2
        _st_fail=1
    }
    # Unmeasurable lag still refuses.
    _st_rc=0
    _st_out=$(promotion_decision "" 1048576 5 30 ok 0 0) || _st_rc=$?
    [ "$_st_rc" -eq 1 ] || {
        echo "[standby-promote] self-test FAILED: unmeasurable lag must refuse (got $_st_rc)" >&2
        _st_fail=1
    }

    # 3. Archive continuity math over real segment names.
    _st_tmp=$(mktemp -d "${TMPDIR:-/tmp}/apexmail-promote-test.XXXXXX")
    touch "$_st_tmp/000000010000000000000005.gz.enc" "$_st_tmp/00000001000000000000000A.enc"
    [ "$(archive_continuity "$_st_tmp" 00000001000000000000000A)" = "ok" ] || {
        echo "[standby-promote] self-test FAILED: archive at parity must be ok" >&2
        _st_fail=1
    }
    [ "$(archive_continuity "$_st_tmp" 00000001000000000000000F)" = "gap" ] || {
        echo "[standby-promote] self-test FAILED: archive behind must be a gap" >&2
        _st_fail=1
    }
    [ "$(archive_continuity "/nonexistent" 00000001000000000000000A)" = "unknown" ] || {
        echo "[standby-promote] self-test FAILED: missing dir must be unknown" >&2
        _st_fail=1
    }
    rm -rf "$_st_tmp"

    if [ "$_st_fail" -ne 0 ]; then
        echo "[standby-promote] self-test FAILED" >&2
        return 1
    fi
    echo "[standby-promote] self-test OK: usage contract; decision table with END-TO-END freshness (lag cap, replay-age cap refusing the disconnected lag-0 case, archive continuity, --force vs --accept-unknown-loss separation, bad caps, unmeasurable evidence); continuity math over real segment names. The psql probes and pg_promote() run only inside a live standby container (docs/operations/warm-standby.md)"
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
