#!/bin/sh
# =============================================================================
# pg-standby-promote.sh — GATE-GUARDED promotion of the warm standby.
# =============================================================================
# External audit 6 remediation #14 (repo-side preparation). Runs INSIDE the
# standby container (pg-standby-bootstrap.sh's sibling, bind-mounted by
# deploy/docker-compose.standby.yml / deploy/docker-compose.standby-remote.yml):
#
#   docker compose -f docker-compose.yml -f docker-compose.prod.yml \
#     -f deploy/docker-compose.standby.yml exec postgres-standby \
#     sh /usr/local/bin/pg-standby-promote.sh
#
# THE THREE-TIER CONTRACT (eighth external audit, DR + control plane:
# the old "--force bypassed more than its documentation claims"):
#
#   Tier 1 — replay-lag byte cap (STANDBY_MAX_LAG_BYTES, default 1 MiB):
#     the WAL the standby already received but has not applied — the
#     in-flight loss window the standby itself controls. Overridden by
#     --force and NOTHING else.
#   Tier 2 — freshness gates (overridden ONLY by --accept-unknown-loss;
#     --force NEVER touches them):
#       * replication HEARTBEAT (the PRIMARY evidence, P1-DR-2): the age of
#         the newest row in apexmail_ops.replication_heartbeat — written on
#         the primary by pg-replication-heartbeat.sh and carried to this
#         standby by physical replication. Age > STANDBY_MAX_HEARTBEAT_AGE_SECONDS
#         (default 90) = the standby has applied NOTHING from the primary
#         for that long. A missing/empty/unmeasurable heartbeat table means
#         freshness is UNPROVEN (the heartbeat runner never deployed) — this
#         is a refusal, never a silent fallback to the replay timestamp.
#       * replay age (the SECOND evidence): pg_last_xact_replay_timestamp()
#         age vs STANDBY_MAX_RECEIVE_AGE_SECS (default 30). The heartbeat is
#         the end-to-end "recently heard from the primary" proof; the replay
#         timestamp alone is NOT (it freezes when replication stops, so a
#         stale value reads identically on a dead primary).
#       * archive continuity (when STANDBY_WAL_ARCHIVE_DIR is set): the
#         newest archived segment must be >= the last segment the standby
#         received. This proves THE OFFSITE ARCHIVE COVERS THE STANDBY'S
#         REPLAY POSITION — it can NEVER prove the dead primary had shipped
#         (let alone committed) everything it held: unshipped primary WAL
#         exists in no place this check can look. A gap, or a check that
#         cannot run, is unproven freshness = refuse.
#   Every refusal/override line names the gate and the measured evidence
#   (lag bytes, heartbeat seconds, replay seconds, archive segments), and
#   says exactly which flag would override that gate. Both flags together:
#   --force covers the byte cap, --accept-unknown-loss covers freshness —
#   the report prints the override map.
#
# Guard rails:
#   * refuses on anything that is not currently a standby (in recovery),
#   * promotes via pg_promote(wait => true) and verifies the instance left
#     recovery before reporting success.
#
# After a promotion there is no way back to standby mode on this data dir:
# failback means a fresh bootstrap (wipe the volume, restart the overlay).
#
# --self-test proves the decision table and the usage contract WITHOUT
# docker (the decision function is pure; the psql probes are the only live
# part).
# =============================================================================

set -eu

STANDBY_MAX_LAG_BYTES="${STANDBY_MAX_LAG_BYTES:-1048576}"
STANDBY_MAX_HEARTBEAT_AGE_SECONDS="${STANDBY_MAX_HEARTBEAT_AGE_SECONDS:-90}"
STANDBY_MAX_RECEIVE_AGE_SECS="${STANDBY_MAX_RECEIVE_AGE_SECS:-30}"
STANDBY_WAL_ARCHIVE_DIR="${STANDBY_WAL_ARCHIVE_DIR:-}"
PROMOTE_PSQL_USER="${POSTGRES_USER:-apexmail}"
STANDBY_PSQL_HOST="${STANDBY_PSQL_HOST:-/var/run/postgresql}"

log() { printf '%s [standby-promote] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
err() { printf '%s [standby-promote] ERROR: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }

usage() {
    cat >&2 <<'EOF'
usage: pg-standby-promote.sh [--force] [--accept-unknown-loss]

  Promotes THIS standby to a primary after three gate tiers, each printed
  with its measured evidence:

    1. replay-lag byte cap (STANDBY_MAX_LAG_BYTES, default 1 MiB)
         — overridden by --force ONLY;
    2. freshness gates (heartbeat age vs STANDBY_MAX_HEARTBEAT_AGE_SECONDS,
       replay age vs STANDBY_MAX_RECEIVE_AGE_SECS, offsite archive
       continuity when STANDBY_WAL_ARCHIVE_DIR is set)
         — overridden by --accept-unknown-loss ONLY;
    3. the not-a-standby guard — overridden by nothing.

  A failed gate REFUSES. --force ignores only the byte cap; the freshness
  gates still run and can still refuse. --accept-unknown-loss is the
  explicit operator decision to promote with UNPROVEN freshness (unmeasurable
  or stale heartbeat/replay age, or a broken/gapped archive check) — it does
  not lift the byte cap. The two are deliberately separate decisions, and a
  promotion with both flags prints which gate each flag covered.

Environment: STANDBY_MAX_LAG_BYTES, STANDBY_MAX_HEARTBEAT_AGE_SECONDS,
STANDBY_MAX_RECEIVE_AGE_SECS, STANDBY_WAL_ARCHIVE_DIR, POSTGRES_USER (psql
superuser of the cloned cluster), STANDBY_PSQL_HOST (unix socket dir,
default /var/run/postgresql).
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

# promotion_decision <lag-bytes|''> <cap-bytes>
#   <heartbeat-age-secs|''> <heartbeat-age-cap-secs>
#   <replay-age-secs|''> <replay-age-cap-secs>
#   <continuity-evidence> <force 0|1> <accept-unknown 0|1>
#   — pure decision, printed then returned:
#   0 = promote, 1 = refuse, 2 = bad configuration.
#
# lag/heartbeat/age '' means "unmeasurable": refusing is the honest default
# — an unknown lag is not a small lag, and unknown freshness is not
# freshness. <continuity-evidence> is one of:
#   ok <newest-segment>        — the archive covers the standby replay position
#   gap <newest> <received>    — the archive is BEHIND the standby
#   broken <reason>            — configured but unmeasurable
#   unknown                    — not configured (no archive dir)
# Every refusal names its gate and evidence; every applied override names
# the flag and the gate it covers.
promotion_decision() {
    _pd_lag=$1
    _pd_cap=$2
    _pd_hb=$3
    _pd_hb_cap=$4
    _pd_age=$5
    _pd_age_cap=$6
    _pd_continuity=$7
    _pd_force=$8
    _pd_accept=$9
    case $_pd_cap in
        ''|*[!0-9]*)
            printf 'bad-config: STANDBY_MAX_LAG_BYTES must be numeric (got %s)\n' "'$_pd_cap'"
            return 2 ;;
    esac
    case $_pd_hb_cap in
        ''|*[!0-9]*)
            printf 'bad-config: STANDBY_MAX_HEARTBEAT_AGE_SECONDS must be numeric (got %s)\n' "'$_pd_hb_cap'"
            return 2 ;;
    esac
    case $_pd_age_cap in
        ''|*[!0-9]*)
            printf 'bad-config: STANDBY_MAX_RECEIVE_AGE_SECS must be numeric (got %s)\n' "'$_pd_age_cap'"
            return 2 ;;
    esac

    # ── Tier 1: replay-lag byte cap. --force covers THIS gate only. ────────
    case $_pd_lag in
        ''|*[!0-9]*)
            printf 'refuse: replay-lag byte-cap gate: replay lag is unmeasurable (%s) — the in-flight loss window cannot be bounded; no flag overrides an unmeasurable lag\n' "'${_pd_lag:-empty}'"
            return 1 ;;
    esac
    if [ "$_pd_lag" -gt "$_pd_cap" ]; then
        if [ "$_pd_force" = "1" ]; then
            printf 'override: --force covers the replay-lag byte-cap gate (replay lag %s bytes > STANDBY_MAX_LAG_BYTES %s bytes); the freshness gates still apply\n' "$_pd_lag" "$_pd_cap"
        else
            printf 'refuse: replay-lag byte-cap gate: replay lag %s bytes exceeds STANDBY_MAX_LAG_BYTES (%s bytes) — pass --force to accept exactly this cap\n' "$_pd_lag" "$_pd_cap"
            return 1
        fi
    fi

    # ── Tier 2a: replication heartbeat — the PRIMARY freshness evidence. ───
    # A disconnected standby's byte lag reads 0 while the primary's unshipped
    # WAL grows (P1-DR-1); the heartbeat is the end-to-end proof the standby
    # is STILL applying what the primary commits.
    case $_pd_hb in
        ''|*[!0-9]*)
            if [ "$_pd_accept" = "1" ]; then
                printf 'override: --accept-unknown-loss covers the replication-heartbeat gate (heartbeat age UNPROVEN: apexmail_ops.replication_heartbeat is missing, empty or unmeasurable on this standby)\n'
            else
                printf 'refuse: replication-heartbeat gate: freshness UNPROVEN (no measurable apexmail_ops.replication_heartbeat age — the heartbeat runner never deployed on the primary, or the standby applies nothing) — pass --accept-unknown-loss only as a deliberate operator decision\n'
                return 1
            fi ;;
        *)
            if [ "$_pd_hb" -gt "$_pd_hb_cap" ]; then
                if [ "$_pd_accept" = "1" ]; then
                    printf 'override: --accept-unknown-loss covers the replication-heartbeat gate (heartbeat age %ss > STANDBY_MAX_HEARTBEAT_AGE_SECONDS %ss — the standby has applied nothing from the primary for that long)\n' "$_pd_hb" "$_pd_hb_cap"
                else
                    printf 'refuse: replication-heartbeat gate: heartbeat age %ss exceeds STANDBY_MAX_HEARTBEAT_AGE_SECONDS (%ss) — the standby has not applied anything from the primary for that long; --force does not cover freshness, pass --accept-unknown-loss deliberately\n' "$_pd_hb" "$_pd_hb_cap"
                    return 1
                fi
            fi ;;
    esac

    # ── Tier 2b: replay age — the SECOND freshness evidence. ───────────────
    case $_pd_age in
        ''|*[!0-9]*)
            if [ "$_pd_accept" = "1" ]; then
                printf 'override: --accept-unknown-loss covers the replay-age gate (last replayed transaction age unmeasurable — WAL freshness UNPROVEN)\n'
            else
                printf 'refuse: replay-age gate: WAL freshness is UNPROVEN (replay age unmeasurable) — pass --accept-unknown-loss only as a deliberate operator decision\n'
                return 1
            fi ;;
        *)
            if [ "$_pd_age" -gt "$_pd_age_cap" ]; then
                if [ "$_pd_accept" = "1" ]; then
                    printf 'override: --accept-unknown-loss covers the replay-age gate (last replayed transaction %ss old > STANDBY_MAX_RECEIVE_AGE_SECS %ss)\n' "$_pd_age" "$_pd_age_cap"
                else
                    printf 'refuse: replay-age gate: last replayed transaction is %ss old (cap %ss) — the standby has been DISCONNECTED; byte lag %s is not an RPO bound (P1-DR-1) — pass --accept-unknown-loss deliberately\n' "$_pd_age" "$_pd_age_cap" "$_pd_lag"
                    return 1
                fi
            fi ;;
    esac

    # ── Tier 2c: archive continuity. Proves ONLY that the offsite archive
    # covers the standby's replay position — never that the dead primary
    # shipped everything it held (unshipped WAL is in no place this check
    # can look). ────────────────────────────────────────────────────────────
    case $_pd_continuity in
        ok*) ;;
        unknown) ;; # not configured: the heartbeat + replay-age gates carry freshness
        gap*)
            if [ "$_pd_accept" = "1" ]; then
                printf 'override: --accept-unknown-loss covers the archive-continuity gate (the offsite archive is BEHIND the standby replay position: %s — the archive covers less than the standby has already replayed)\n' "$_pd_continuity"
            else
                printf 'refuse: archive-continuity gate: the offsite archive is BEHIND the standby replay position (%s) — WAL exists that only the dead primary ever held; this check proves archive coverage of the standby replay position, it cannot recover primary-only WAL — pass --accept-unknown-loss deliberately\n' "$_pd_continuity"
                return 1
            fi ;;
        broken*)
            if [ "$_pd_accept" = "1" ]; then
                printf 'override: --accept-unknown-loss covers the archive-continuity gate (the archive check cannot run: %s — coverage of the standby replay position is UNPROVEN)\n' "$_pd_continuity"
            else
                printf 'refuse: archive-continuity gate: the archive check cannot run (%s) — that the offsite archive covers the standby replay position is UNPROVEN — pass --accept-unknown-loss deliberately\n' "$_pd_continuity"
                return 1
            fi ;;
        *)
            printf 'bad-config: archive-continuity evidence must start with ok|gap|broken|unknown (got %s)\n' "'$_pd_continuity'"
            return 2 ;;
    esac

    if [ "$_pd_force" = "1" ] && [ "$_pd_accept" = "1" ]; then
        printf 'override map: --force covers ONLY the replay-lag byte cap; --accept-unknown-loss covers the freshness gates (heartbeat age, replay age, archive continuity) — the two are separate decisions\n'
    fi
    printf 'allow: replay lag %s bytes within %s; heartbeat age %ss within %ss; replay age %ss within %ss; archive continuity %s\n' \
        "$_pd_lag" "$_pd_cap" "${_pd_hb:-?}" "$_pd_hb_cap" "${_pd_age:-?}" "$_pd_age_cap" "$_pd_continuity"
    return 0
}

# archive_continuity <archive-dir> <received-segment> — prints ONE of:
#   ok <newest-archived-segment>
#   gap <newest-archived-segment> <received-segment>
#   unknown
# 'ok' when the newest archived .gz.enc/.enc/plain segment >= the standby's
# last received segment, 'gap' when the archive is behind, 'unknown' when
# the check cannot run. Pure string math over WAL segment names (hex,
# time+log ordered).
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
        printf 'gap %s %s' "$_ac_newest_base" "$_ac_received"
    else
        printf 'ok %s' "$_ac_newest_base"
    fi
    return 0
}

# continuity_evidence <archive-dir|''> <received-segment> — the evidence
# string promotion_decision consumes. Not configured (empty dir) prints
# "unknown" (the freshness rests on the heartbeat + replay-age gates). A
# configured check delegates to archive_continuity; a configured-but-
# unmeasurable result is a BROKEN check — unproven freshness, never a pass.
continuity_evidence() {
    _ce_dir=$1
    _ce_received=$2
    if [ -z "$_ce_dir" ]; then
        printf 'unknown'
        return 0
    fi
    _ce_result=$(archive_continuity "$_ce_dir" "$_ce_received")
    case $_ce_result in
        ok*|gap*) printf '%s' "$_ce_result" ;;
        *)
            case $_ce_received in
                '') printf 'broken (the standby replay position is unmeasurable — no last-received segment)' ;;
                *)  printf 'broken (no archived segment readable at %s)' "$_ce_dir" ;;
            esac ;;
    esac
    return 0
}

standby_psql() {
    psql -h "$STANDBY_PSQL_HOST" -U "$PROMOTE_PSQL_USER" -d postgres -tAc "$1"
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
    # P1-DR-2 freshness evidence, HEARTBEAT FIRST: the age of the newest
    # replicated heartbeat row (written on the primary every
    # HEARTBEAT_INTERVAL_SECONDS and carried here by physical replication).
    # A missing/empty table is UNPROVEN freshness — the heartbeat runner
    # never deployed; there is no silent fallback to the replay timestamp.
    _rp_hb=$(standby_psql \
        'SELECT extract(epoch from (clock_timestamp() - max(primary_clock)))::bigint::text FROM apexmail_ops.replication_heartbeat' \
        2>/dev/null) || _rp_hb=""
    # A heartbeat age can be marginally negative when the standby's clock
    # trails the primary's (the row's clock is the primary's now()): that is
    # maximally fresh, not unmeasurable.
    case $_rp_hb in
        -*) _rp_hb=0 ;;
    esac
    case $_rp_hb in
        ''|*[!0-9]*) _rp_hb="" ;;
    esac
    # Second freshness evidence: the age of the last replayed transaction
    # (disconnection evidence a byte lag cannot show), and the standby's
    # last received segment for the archive continuity check.
    _rp_age=$(standby_psql \
        'SELECT coalesce(extract(epoch from now() - pg_last_xact_replay_timestamp())::bigint::text, $$-1$$)' \
        2>/dev/null) || _rp_age=""
    [ "$_rp_age" = "-1" ] && _rp_age=""
    case $_rp_age in
        -*) _rp_age=0 ;;
    esac
    case $_rp_age in
        ''|*[!0-9]*) _rp_age="" ;;
    esac
    _rp_received=$(standby_psql \
        "SELECT coalesce(pg_walfile_name(pg_last_wal_replay_lsn()), '')" \
        2>/dev/null) || _rp_received=""
    _rp_continuity=$(continuity_evidence "$STANDBY_WAL_ARCHIVE_DIR" "$_rp_received")
    log "evidence: replay lag ${_rp_lag:-unmeasurable}B (cap ${STANDBY_MAX_LAG_BYTES}), heartbeat age ${_rp_hb:-unproven}s (cap ${STANDBY_MAX_HEARTBEAT_AGE_SECONDS}), replay age ${_rp_age:-unmeasurable}s (cap ${STANDBY_MAX_RECEIVE_AGE_SECS}), archive continuity ${_rp_continuity}${STANDBY_WAL_ARCHIVE_DIR:+ @ $STANDBY_WAL_ARCHIVE_DIR}"

    _rp_decision=$(promotion_decision "${_rp_lag:-}" "$STANDBY_MAX_LAG_BYTES" \
        "${_rp_hb:-}" "$STANDBY_MAX_HEARTBEAT_AGE_SECONDS" \
        "${_rp_age:-}" "$STANDBY_MAX_RECEIVE_AGE_SECS" \
        "$_rp_continuity" "$PROMOTE_FORCE" "$ACCEPT_UNKNOWN") \
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

# ── Self-test: decision table + usage contract, no docker ────────────────────
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

    # 2. Decision table: tier-1 lag cap, tier-2 freshness (heartbeat FIRST,
    #    then replay age, then archive continuity). Argument order:
    #    lag cap hb hb-cap age age-cap continuity force accept.
    _st_out=$(promotion_decision 4096 1048576 5 90 5 30 ok 0 0) || {
        echo "[standby-promote] self-test FAILED: healthy evidence must be allowed" >&2
        _st_fail=1
    }
    case $_st_out in allow:*) : ;;
        *) echo "[standby-promote] self-test FAILED: healthy decision was '$_st_out'" >&2; _st_fail=1 ;;
    esac
    _st_out=$(promotion_decision 1048576 1048576 90 90 30 30 ok 0 0) || {
        echo "[standby-promote] self-test FAILED: boundary lag+heartbeat+age must be allowed" >&2
        _st_fail=1
    }
    _st_rc=0
    _st_out=$(promotion_decision 1048577 1048576 5 90 5 30 ok 0 0) || _st_rc=$?
    [ "$_st_rc" -eq 1 ] && case $_st_out in "refuse: replay-lag byte-cap gate:"*"exceeds"*) : ;; *) _st_rc=0 ;; esac
    [ "$_st_rc" -eq 1 ] || {
        echo "[standby-promote] self-test FAILED: over-cap must refuse naming the gate and the cap (got '$_st_out')" >&2
        _st_fail=1
    }
    _st_out=$(promotion_decision 2097152 1048576 5 90 5 30 ok 1 0) || {
        echo "[standby-promote] self-test FAILED: --force must allow over-cap" >&2
        _st_fail=1
    }
    case $_st_out in *"--force covers the replay-lag byte-cap gate"*) : ;;
        *) echo "[standby-promote] self-test FAILED: --force override must name its gate (got '$_st_out')" >&2; _st_fail=1 ;;
    esac
    # THE P1-DR-1 CASE: zero byte lag, STALE replay age = disconnected
    # standby; must refuse and the message must say the byte lag is not an
    # RPO bound.
    _st_rc=0
    _st_out=$(promotion_decision 0 1048576 5 90 300 30 ok 0 0) || _st_rc=$?
    [ "$_st_rc" -eq 1 ] && case $_st_out in "refuse: replay-age gate:"*"DISCONNECTED"*"not an RPO bound"*) : ;; *) _st_rc=0 ;; esac
    [ "$_st_rc" -eq 1 ] || {
        echo "[standby-promote] self-test FAILED: stale replay age with lag 0 must refuse as disconnected (got '$_st_out')" >&2
        _st_fail=1
    }
    # Unmeasurable replay age refuses unless the explicit override.
    _st_rc=0
    _st_out=$(promotion_decision 0 1048576 5 90 "" 30 ok 0 0) || _st_rc=$?
    [ "$_st_rc" -eq 1 ] && case $_st_out in "refuse: replay-age gate:"*"UNPROVEN"*) : ;; *) _st_rc=0 ;; esac
    [ "$_st_rc" -eq 1 ] || {
        echo "[standby-promote] self-test FAILED: unmeasurable replay age must refuse (got '$_st_out')" >&2
        _st_fail=1
    }
    # THREE-TIER TEETH (audit: "--force bypasses more than its documentation
    # claims"): the freshness gates STILL refuse under --force.
    _st_rc=0
    _st_out=$(promotion_decision 4096 1048576 5 90 300 30 ok 1 0) || _st_rc=$?
    [ "$_st_rc" -eq 1 ] && case $_st_out in "refuse: replay-age gate:"*) : ;; *) _st_rc=0 ;; esac
    [ "$_st_rc" -eq 1 ] || {
        echo "[standby-promote] self-test FAILED: force+stale replay age must still refuse at the replay-age gate (got '$_st_out')" >&2
        _st_fail=1
    }
    _st_rc=0
    _st_out=$(promotion_decision 4096 1048576 5 90 "" 30 ok 1 0) || _st_rc=$?
    [ "$_st_rc" -eq 1 ] && case $_st_out in "refuse: replay-age gate:"*"UNPROVEN"*) : ;; *) _st_rc=0 ;; esac
    [ "$_st_rc" -eq 1 ] || {
        echo "[standby-promote] self-test FAILED: force+unmeasurable replay age must still refuse (got '$_st_out')" >&2
        _st_fail=1
    }
    # --accept-unknown-loss allows the stale/unproven replay age.
    _st_out=$(promotion_decision 0 1048576 5 90 300 30 ok 0 1) || {
        echo "[standby-promote] self-test FAILED: --accept-unknown-loss must allow the stale replay age" >&2
        _st_fail=1
    }
    case $_st_out in *"--accept-unknown-loss covers the replay-age gate"*) ;;
        *) echo "[standby-promote] self-test FAILED: replay-age acceptance must name flag+gate (got '$_st_out')" >&2; _st_fail=1 ;;
    esac
    # HEARTBEAT gate (the primary freshness evidence):
    # missing/empty table = UNPROVEN = refuse, force or not.
    _st_rc=0
    _st_out=$(promotion_decision 4096 1048576 "" 90 5 30 ok 0 0) || _st_rc=$?
    [ "$_st_rc" -eq 1 ] && case $_st_out in "refuse: replication-heartbeat gate:"*"UNPROVEN"*) : ;; *) _st_rc=0 ;; esac
    [ "$_st_rc" -eq 1 ] || {
        echo "[standby-promote] self-test FAILED: missing heartbeat must refuse as UNPROVEN (got '$_st_out')" >&2
        _st_fail=1
    }
    _st_rc=0
    _st_out=$(promotion_decision 4096 1048576 "" 90 5 30 ok 1 0) || _st_rc=$?
    [ "$_st_rc" -eq 1 ] && case $_st_out in "refuse: replication-heartbeat gate:"*) : ;; *) _st_rc=0 ;; esac
    [ "$_st_rc" -eq 1 ] || {
        echo "[standby-promote] self-test FAILED: force must NOT cover a missing heartbeat (got '$_st_out')" >&2
        _st_fail=1
    }
    _st_out=$(promotion_decision 4096 1048576 "" 90 5 30 ok 0 1) || {
        echo "[standby-promote] self-test FAILED: --accept-unknown-loss must allow the missing heartbeat" >&2
        _st_fail=1
    }
    case $_st_out in *"--accept-unknown-loss covers the replication-heartbeat gate"*) ;;
        *) echo "[standby-promote] self-test FAILED: heartbeat acceptance must name flag+gate (got '$_st_out')" >&2; _st_fail=1 ;;
    esac
    # Stale heartbeat (the standby applies nothing from the primary) refuses;
    # --force does not cover it, --accept-unknown-loss does.
    _st_rc=0
    _st_out=$(promotion_decision 0 1048576 300 90 5 30 ok 0 0) || _st_rc=$?
    [ "$_st_rc" -eq 1 ] && case $_st_out in "refuse: replication-heartbeat gate:"*"300"*"90"*) : ;; *) _st_rc=0 ;; esac
    [ "$_st_rc" -eq 1 ] || {
        echo "[standby-promote] self-test FAILED: stale heartbeat must refuse naming gate+evidence (got '$_st_out')" >&2
        _st_fail=1
    }
    _st_rc=0
    _st_out=$(promotion_decision 0 1048576 300 90 5 30 ok 1 0) || _st_rc=$?
    [ "$_st_rc" -eq 1 ] || {
        echo "[standby-promote] self-test FAILED: force must NOT cover a stale heartbeat (got '$_st_out')" >&2
        _st_fail=1
    }
    _st_out=$(promotion_decision 0 1048576 300 90 5 30 ok 0 1) || {
        echo "[standby-promote] self-test FAILED: --accept-unknown-loss must allow the stale heartbeat" >&2
        _st_fail=1
    }
    # Archive continuity: gap refuses (naming the segments), parity ok, and
    # the both-flags case allows with BOTH overrides named.
    _st_rc=0
    _st_out=$(promotion_decision 0 1048576 5 90 5 30 "gap 000000010000000000000005 00000001000000000000000F" 0 0) || _st_rc=$?
    [ "$_st_rc" -eq 1 ] && case $_st_out in "refuse: archive-continuity gate:"*"000000010000000000000005"*) : ;; *) _st_rc=0 ;; esac
    [ "$_st_rc" -eq 1 ] || {
        echo "[standby-promote] self-test FAILED: archive gap must refuse naming the gate and segments (got '$_st_out')" >&2
        _st_fail=1
    }
    _st_out=$(promotion_decision 0 1048576 5 90 5 30 "ok 00000001000000000000000A" 0 0) || {
        echo "[standby-promote] self-test FAILED: continuity ok must allow" >&2
        _st_fail=1
    }
    # A configured-but-unmeasurable archive check is unproven freshness.
    _st_rc=0
    _st_out=$(promotion_decision 0 1048576 5 90 5 30 "broken (no archived segment readable at /mnt/archive)" 0 0) || _st_rc=$?
    [ "$_st_rc" -eq 1 ] && case $_st_out in "refuse: archive-continuity gate:"*"UNPROVEN"*) : ;; *) _st_rc=0 ;; esac
    [ "$_st_rc" -eq 1 ] || {
        echo "[standby-promote] self-test FAILED: broken archive check must refuse as UNPROVEN (got '$_st_out')" >&2
        _st_fail=1
    }
    # THE BOTH-FLAGS CASE: --force covers the cap, --accept-unknown-loss
    # covers freshness; the report names which gate each flag covered.
    _st_out=$(promotion_decision 2097152 1048576 300 90 5 30 "gap 000000010000000000000005 00000001000000000000000F" 1 1) || {
        echo "[standby-promote] self-test FAILED: force+accept-unknown-loss with an archive gap must allow" >&2
        _st_fail=1
    }
    case $_st_out in
        *"--force covers the replay-lag byte-cap gate"*"--accept-unknown-loss covers the archive-continuity gate"*"override map: --force covers ONLY"*) : ;;
        *) echo "[standby-promote] self-test FAILED: both-flags report must name each gate's flag (got '$_st_out')" >&2; _st_fail=1 ;;
    esac
    # Not-configured archive (unknown) still allows on the strength of the
    # heartbeat + replay-age gates.
    _st_out=$(promotion_decision 4096 1048576 5 90 5 30 unknown 0 0) || {
        echo "[standby-promote] self-test FAILED: archive not configured must allow on heartbeat+replay evidence" >&2
        _st_fail=1
    }
    # Unmeasurable lag still refuses (no flag covers it).
    _st_rc=0
    _st_out=$(promotion_decision "" 1048576 5 90 5 30 ok 0 0) || _st_rc=$?
    [ "$_st_rc" -eq 1 ] || {
        echo "[standby-promote] self-test FAILED: unmeasurable lag must refuse (got $_st_rc)" >&2
        _st_fail=1
    }
    # Bad config: non-numeric caps.
    promotion_decision 0 not-a-number 5 90 5 30 ok 0 0 >/dev/null 2>&1 && {
        echo "[standby-promote] self-test FAILED: bad lag cap must exit 2" >&2
        _st_fail=1
    }
    promotion_decision 0 1048576 5 not-a-number 5 30 ok 0 0 >/dev/null 2>&1 && {
        echo "[standby-promote] self-test FAILED: bad heartbeat cap must exit 2" >&2
        _st_fail=1
    }
    promotion_decision 0 1048576 5 90 5 not-a-number ok 0 0 >/dev/null 2>&1 && {
        echo "[standby-promote] self-test FAILED: bad replay-age cap must exit 2" >&2
        _st_fail=1
    }

    # 3. Archive continuity math over real segment names.
    _st_tmp=$(mktemp -d "${TMPDIR:-/tmp}/apexmail-promote-test.XXXXXX")
    touch "$_st_tmp/000000010000000000000005.gz.enc" "$_st_tmp/00000001000000000000000A.enc"
    _st_cc=$(archive_continuity "$_st_tmp" 00000001000000000000000A)
    case $_st_cc in
        "ok 00000001000000000000000A") : ;;
        *) echo "[standby-promote] self-test FAILED: archive at parity must be ok with the segment named (got '$_st_cc')" >&2; _st_fail=1 ;;
    esac
    _st_cc=$(archive_continuity "$_st_tmp" 00000001000000000000000F)
    case $_st_cc in
        "gap 00000001000000000000000A 00000001000000000000000F") : ;;
        *) echo "[standby-promote] self-test FAILED: archive behind must be a gap naming both segments (got '$_st_cc')" >&2; _st_fail=1 ;;
    esac
    _st_cc=$(archive_continuity "/nonexistent" 00000001000000000000000A)
    [ "$_st_cc" = "unknown" ] || {
        echo "[standby-promote] self-test FAILED: missing dir must be unknown" >&2
        _st_fail=1
    }

    # 4. Continuity evidence mapping (the run_promote input): a healthy or
    #    gapped configured archive passes through with its segments, a
    #    configured-but-unmeasurable check becomes a BROKEN refusal, and an
    #    unconfigured archive stays "unknown".
    _st_tmp2=$(mktemp -d "${TMPDIR:-/tmp}/apexmail-promote-test.XXXXXX")
    touch "$_st_tmp2/000000010000000000000007.enc"
    _st_ce=$(continuity_evidence "$_st_tmp2" 000000010000000000000007)
    case $_st_ce in
        "ok 000000010000000000000007") : ;;
        *) echo "[standby-promote] self-test FAILED: a healthy configured archive must stay ok (got '$_st_ce')" >&2; _st_fail=1 ;;
    esac
    _st_ce=$(continuity_evidence "$_st_tmp2" 00000001000000000000000F)
    case $_st_ce in
        "gap 000000010000000000000007 00000001000000000000000F") : ;;
        *) echo "[standby-promote] self-test FAILED: a gapped configured archive must stay a gap (got '$_st_ce')" >&2; _st_fail=1 ;;
    esac
    _st_ce=$(continuity_evidence "/nonexistent" 00000001000000000000000A)
    case $_st_ce in
        "broken (no archived segment readable at /nonexistent)") : ;;
        *) echo "[standby-promote] self-test FAILED: a configured-but-unmeasurable archive must be broken (got '$_st_ce')" >&2; _st_fail=1 ;;
    esac
    _st_ce=$(continuity_evidence "$_st_tmp2" "")
    case $_st_ce in
        "broken (the standby replay position is unmeasurable"*) : ;;
        *) echo "[standby-promote] self-test FAILED: an unmeasurable replay position must be broken (got '$_st_ce')" >&2; _st_fail=1 ;;
    esac
    _st_ce=$(continuity_evidence "" 00000001000000000000000A)
    [ "$_st_ce" = "unknown" ] || {
        echo "[standby-promote] self-test FAILED: an unconfigured archive must be unknown (got '$_st_ce')" >&2
        _st_fail=1
    }
    rm -rf "$_st_tmp2"

    if [ "$_st_fail" -ne 0 ]; then
        echo "[standby-promote] self-test FAILED" >&2
        return 1
    fi
    echo "[standby-promote] self-test OK: usage contract; THREE-TIER decision table (--force covers only the replay-lag byte cap; heartbeat age + replay age + archive continuity refuse under --force and yield only to --accept-unknown-loss; missing heartbeat = UNPROVEN; both-flags report names each gate's flag; bad caps; unmeasurable lag); continuity math over real segment names. The psql probes and pg_promote() run only inside a live standby container (docs/operations/warm-standby.md)"
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
