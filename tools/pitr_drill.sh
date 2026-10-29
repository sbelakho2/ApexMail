#!/bin/sh
# =============================================================================
# tools/pitr_drill.sh — timed DESTRUCTIVE point-in-time-recovery drill.
# =============================================================================
# External audit 6 remediation #13 (repo side; the owner runs production):
# the PITR tooling shipped with deploy/docker-compose.wal-archive.yml was
# proven only by plumbing self-tests — no run had ever measured how long a
# full recovery from the offsite ciphertext actually takes. This drill makes
# that evidence executable:
#
#   1. boots a THROWAWAY source postgres (the pinned postgres-wal image,
#      built from deploy/hardening/postgres-wal/Dockerfile) with the real
#      archive machinery: archive_command runs pg-wal-archive.sh with
#      WAL_ARCHIVE_TARGET pointed at a LOCAL "offsite" directory, so segments
#      really flow through the encrypted spool (backup-envelope.sh, key
#      generated for this run),
#   2. writes rows, forces a segment switch (CHECKPOINT; pg_switch_wal()),
#      takes the encrypted physical base backup the same way
#      postgres-backup-encrypt.sh's wal-base path does (pg_basebackup -F tar
#      -z -X stream sealed by the SAME envelope helper — reuse, no fork),
#      writes MORE rows and switches again, so replay must go beyond the
#      base backup through decrypting restore_command,
#   3. DESTRUCTIVE step: stops and REMOVES the source container and its data
#      dir, leaving nothing but the offsite ciphertext + the sealed base,
#   4. measures pg-pitr-restore.sh (deploy/hardening/scripts/pg-pitr-restore.sh)
#      performing the full restore+replay into a scratch container —
#      monotonic clock start/end per phase — then restarts the recovered
#      data dir and VERIFIES the row count and md5 checksum against the
#      pre-destruction truth,
#   5. writes the timings as JSON to --out:
#      {phase_durations_s, total_rto_s, restore_lsn, target_time, verified}
#      and exits 0 ONLY when verified. A trap removes every container and
#      the work dir (--keep preserves them for inspection).
#
# total_rto_s is measured from the destructive step (the "loss event") to a
# verified recovered instance — the honest definition, not just the restore
# command's wall time.
#
# Usage: tools/pitr_drill.sh --out drill.json [--keep]
# Env:   PITR_DRILL_IMAGE (default apexmail/postgres-wal:16.8-r1),
#        PITR_DRILL_WORK_ROOT, PITR_DRILL_PORT, PITR_DRILL_BOOT_TIMEOUT,
#        PITR_DRILL_ARCHIVE_TIMEOUT, PITR_DRILL_REPLAY_TIMEOUT_SECS.
# Needs: docker (daemon + build/pull), openssl on the host (key generation).
#
# --self-test is HERMETIC (no docker): it proves the usage contract, the
# verification evaluator (zero-verified rejected, checksum mismatch
# rejected, replay-beyond-base required), the monotonic-clock/duration
# helpers, and the JSON evidence shape. The live round trip above is the
# operator's timed drill — the self-test says so honestly.
# =============================================================================

set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
SCRIPTS_DIR=$ROOT/deploy/hardening/scripts
PG_PITR_RESTORE=$SCRIPTS_DIR/pg-pitr-restore.sh
PG_WAL_ARCHIVE=$SCRIPTS_DIR/pg-wal-archive.sh
ENVELOPE_LIB=$SCRIPTS_DIR/backup-envelope.sh
WAL_DOCKERFILE=$ROOT/deploy/hardening/postgres-wal/Dockerfile

DRILL_IMAGE=${PITR_DRILL_IMAGE:-apexmail/postgres-wal:16.8-r1}
DRILL_WORK_ROOT=${PITR_DRILL_WORK_ROOT:-${TMPDIR:-/tmp}}
DRILL_PORT=${PITR_DRILL_PORT:-55432}
DRILL_BOOT_TIMEOUT=${PITR_DRILL_BOOT_TIMEOUT:-180}
DRILL_ARCHIVE_TIMEOUT=${PITR_DRILL_ARCHIVE_TIMEOUT:-120}
DRILL_REPLAY_TIMEOUT=${PITR_DRILL_REPLAY_TIMEOUT_SECS:-600}
DRILL_SRC_PASSWORD=pitr-drill-throwaway
DRILL_TABLE=pitr_drill_log
DRILL_PRE_ROWS=50
DRILL_POST_ROWS=25

log() { printf '%s [pitr-drill] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
err() { printf '%s [pitr-drill] ERROR: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }

usage() {
    cat >&2 <<'EOF'
usage: pitr_drill.sh --out <drill.json> [--keep]

  --out   path the JSON timing/verification record is written to
          ({phase_durations_s, total_rto_s, restore_lsn, target_time,
          verified}); exit 0 only when verified is true
  --keep  keep the throwaway containers' work dir for inspection

Environment: PITR_DRILL_IMAGE (default apexmail/postgres-wal:16.8-r1,
built from deploy/hardening/postgres-wal/Dockerfile when absent),
PITR_DRILL_WORK_ROOT, PITR_DRILL_PORT, PITR_DRILL_BOOT_TIMEOUT,
PITR_DRILL_ARCHIVE_TIMEOUT, PITR_DRILL_REPLAY_TIMEOUT_SECS.

DESTRUCTIVE by design: the throwaway SOURCE container and its data dir are
destroyed mid-run (never touches anything outside the fresh work dir).
EOF
}

DRILL_OUT=""
DRILL_KEEP=0

parse_args() {
    while [ $# -gt 0 ]; do
        case $1 in
            --out)
                [ $# -ge 2 ] || { err "--out needs a value"; usage; return 2; }
                DRILL_OUT=$2; shift 2 ;;
            --keep) DRILL_KEEP=1; shift ;;
            --help|-h)
                usage; exit 0 ;;
            *)
                err "unknown argument: $1"; usage; return 2 ;;
        esac
    done
    [ -n "$DRILL_OUT" ] || { err "--out is required (the drill writes its JSON evidence there)"; usage; return 2; }
    return 0
}

# ── Monotonic clock + duration math ───────────────────────────────────────────
# mono_now prints seconds as a float off a monotonic clock: python3's
# time.monotonic() when available, then /proc/uptime (the Linux deploy
# host), then a documented epoch-seconds fallback (wall clock, the last
# resort on an exotic host with neither).
mono_now() {
    if [ -r /proc/uptime ]; then
        awk '{printf "%.3f\n", $1}' /proc/uptime
        return 0
    fi
    if command -v python3 >/dev/null 2>&1; then
        python3 -c 'import time; print("%.3f" % time.monotonic())' 2>/dev/null && return 0
    fi
    date +%s
}

# dur_s <start> <end> — float seconds between two mono_now readings.
dur_s() {
    awk -v a="$1" -v b="$2" 'BEGIN { printf "%.3f", b - a }'
}

# ── Verification evaluator (pure; self-testable) ─────────────────────────────
# verify_drill_result <expected_count> <expected_md5> <rows_at_base>
#                     <actual_count> <actual_md5>
# Passes (exit 0) ONLY when both counts are positive (a zero-verified drill
# proves nothing), they match, the checksums match, and the restored count
# EXCEEDS the row count already inside the base backup — the last condition
# is what proves WAL replay beyond the base instead of a bare base restore.
verify_drill_result() {
    _vd_ec=$1; _vd_em=$2; _vd_base=$3; _vd_ac=$4; _vd_am=$5
    case $_vd_ec in ''|*[!0-9]*) err "verifier: expected row count is not a number: '$_vd_ec'"; return 1 ;; esac
    case $_vd_ac in ''|*[!0-9]*) err "verifier: restored row count is not a number: '$_vd_ac'"; return 1 ;; esac
    if [ "$_vd_ec" -le 0 ]; then
        err "verifier: expected row count is $_vd_ec — a drill that verifies ZERO rows proves nothing (rejected)"
        return 1
    fi
    if [ "$_vd_ac" -le 0 ]; then
        err "verifier: restored row count is $_vd_ac — zero-verified result rejected"
        return 1
    fi
    if [ "$_vd_ac" != "$_vd_ec" ]; then
        err "verifier: row count mismatch — restored $_vd_ac, expected $_vd_ec"
        return 1
    fi
    if [ -z "$_vd_em" ] || [ -z "$_vd_am" ]; then
        err "verifier: checksum missing (expected '$_vd_em', restored '$_vd_am')"
        return 1
    fi
    if [ "$_vd_am" != "$_vd_em" ]; then
        err "verifier: row checksum mismatch — restored '$_vd_am', expected '$_vd_em'"
        return 1
    fi
    if [ "$_vd_ac" -le "$_vd_base" ]; then
        err "verifier: restored rows ($_vd_ac) do not exceed the base backup's rows ($_vd_base) — WAL replay beyond the base was NOT proven"
        return 1
    fi
    log "verifier: OK — $_vd_ac rows, checksum $_vd_am, replay proven beyond the base ($_vd_base rows)"
    return 0
}

# ── JSON evidence (the brief's shape: phase_durations_s, total_rto_s,
#    restore_lsn, target_time, verified) ──────────────────────────────────────
# Filled by drill_run; the duration/verified variables default so a failed
# phase still renders valid JSON with verified:false.
write_drill_json() {
    cat > "$1" <<EOF
{"recorded_at":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","drill":"pitr-restore","image":"$DRILL_IMAGE","phase_durations_s":{"source_boot":${PH_BOOT:-0.000},"writes":${PH_WRITES:-0.000},"base_backup":${PH_BASE:-0.000},"source_teardown":${PH_TEARDOWN:-0.000},"pitr_restore":${PH_RESTORE:-0.000},"verify":${PH_VERIFY:-0.000}},"total_rto_s":${TOTAL_RTO:-0.000},"restore_target":"latest","restore_lsn":"${RESTORE_LSN:-not-reached}","target_time":"${REPLAY_TS:-none}","wal_segments_offsite":${WAL_COUNT:-0},"rows_at_base":${ROWS_AT_BASE:-0},"expected_rows":${EXPECTED_COUNT:-0},"restored_rows":${ACTUAL_COUNT:-0},"row_checksum":"${EXPECTED_MD5:-none}","verified":${VERIFIED_LITERAL:-false}}
EOF
}

# ── Drill machinery (docker-gated) ───────────────────────────────────────────
WORK_DIR=""
SRC_NAME=""
RESTORE_NAME=""
VERIFY_NAME=""
CLEANED=0

drill_teardown() {
    _dt_rc=$?
    [ "$CLEANED" = 1 ] && return "$_dt_rc"
    CLEANED=1
    for _dt_c in "$SRC_NAME" "$RESTORE_NAME" "$VERIFY_NAME"; do
        [ -n "$_dt_c" ] && docker rm -f "$_dt_c" >/dev/null 2>&1 || true
    done
    if [ -n "$WORK_DIR" ] && [ -d "$WORK_DIR" ] && [ "$DRILL_KEEP" = 0 ]; then
        rm -rf "$WORK_DIR"
    elif [ -n "$WORK_DIR" ] && [ "$DRILL_KEEP" = 1 ]; then
        log "--keep set — work dir preserved: $WORK_DIR"
    fi
    return "$_dt_rc"
}

ensure_image() {
    if docker image inspect "$DRILL_IMAGE" >/dev/null 2>&1; then
        log "image present: $DRILL_IMAGE"
        return 0
    fi
    log "building $DRILL_IMAGE from $WAL_DOCKERFILE (pinned postgres:16.8-alpine base + rsync/openssh)"
    docker build -t "$DRILL_IMAGE" -f "$WAL_DOCKERFILE" "$ROOT" >/dev/null
}

wait_source_ready() {
    _wr_waited=0
    while :; do
        if docker exec "$SRC_NAME" pg_isready -U postgres -d postgres -q >/dev/null 2>&1; then
            return 0
        fi
        if [ "$(docker inspect -f '{{.State.Running}}' "$SRC_NAME" 2>/dev/null || echo false)" != "true" ]; then
            err "source postgres container died before accepting connections — last log lines:"
            docker logs --tail 30 "$SRC_NAME" >&2 || true
            return 1
        fi
        if [ "$_wr_waited" -ge "$DRILL_BOOT_TIMEOUT" ]; then
            err "source postgres not ready within ${DRILL_BOOT_TIMEOUT}s — last log lines:"
            docker logs --tail 30 "$SRC_NAME" >&2 || true
            return 1
        fi
        sleep 2
        _wr_waited=$((_wr_waited + 2))
    done
}

# wait_archived <segment-name> — block until archive_command pushed the
# segment offsite (pg_stat_archiver.last_archived_wal). This is what makes
# the later `--target latest` replay able to reach every row we wrote.
wait_archived() {
    _wa_seg=$1
    _wa_waited=0
    log "waiting for segment $_wa_seg to reach the offsite archive"
    while :; do
        _wa_last=$(docker exec "$SRC_NAME" psql -U postgres -d postgres \
            -tAc 'SELECT last_archived_wal FROM pg_stat_archiver' 2>/dev/null || echo '')
        # "at or beyond": if another worker archived a newer segment in the
        # meantime, ours still landed. WAL names sort lexicographically
        # within a timeline; awk does the string compare POSIX sh lacks.
        if [ -n "$_wa_last" ] \
            && awk -v last="$_wa_last" -v seg="$_wa_seg" 'BEGIN { exit !(last >= seg) }'; then
            log "segment $_wa_seg archived (encrypted, offsite)"
            return 0
        fi
        _wa_fail=$(docker exec "$SRC_NAME" psql -U postgres -d postgres \
            -tAc 'SELECT failed_count FROM pg_stat_archiver' 2>/dev/null || echo 0)
        if [ "${_wa_fail:-0}" -gt 0 ]; then
            err "archive_command reported $_wa_fail failures — the encrypted archive path is broken in this drill"
            return 1
        fi
        if [ "$_wa_waited" -ge "$DRILL_ARCHIVE_TIMEOUT" ]; then
            err "segment $_wa_seg was not archived within ${DRILL_ARCHIVE_TIMEOUT}s"
            return 1
        fi
        sleep 2
        _wa_waited=$((_wa_waited + 2))
    done
}

# switch_and_wait — force one WAL switch and wait for the old segment's
# encrypted artifact to land offsite.
switch_and_wait() {
    _sw_seg=$(docker exec "$SRC_NAME" psql -U postgres -d postgres \
        -tAc 'SELECT pg_walfile_name(pg_switch_wal())' 2>/dev/null) || return 1
    wait_archived "$_sw_seg"
}

# row_facts — "<count>|<md5>" of the drill table, the verification truth.
row_facts() {
    docker exec "$SRC_NAME" psql -U postgres -d postgres -tAc \
        "SELECT count(*) || '|' || coalesce(md5(string_agg(id::text || ':' || note, ',' ORDER BY id)), 'none') FROM $DRILL_TABLE"
}

drill_run() {
    [ -f "$PG_PITR_RESTORE" ] && [ -f "$PG_WAL_ARCHIVE" ] && [ -f "$ENVELOPE_LIB" ] && [ -f "$WAL_DOCKERFILE" ] \
        || { err "missing sibling under $SCRIPTS_DIR (pg-pitr-restore.sh / pg-wal-archive.sh / backup-envelope.sh) or the postgres-wal Dockerfile"; return 1; }
    command -v docker >/dev/null 2>&1 || { err "docker is required for the drill (the hermetic --self-test needs none)"; return 1; }
    command -v openssl >/dev/null 2>&1 || { err "openssl is required (drill key generation)"; return 1; }
    docker info >/dev/null 2>&1 || { err "docker daemon unreachable"; return 1; }
    ensure_image

    WORK_DIR=$(mktemp -d "$DRILL_WORK_ROOT/apexmail-pitr-drill.XXXXXX")
    SRC_NAME=apexmail-pitr-drill-src-$$
    RESTORE_NAME=apexmail-pitr-drill-restore-$$
    VERIFY_NAME=apexmail-pitr-drill-verify-$$
    mkdir -p "$WORK_DIR/offsite/wal-archive" "$WORK_DIR/offsite/wal-base" \
        "$WORK_DIR/keys" "$WORK_DIR/restore-scratch" "$WORK_DIR/restore-evidence" "$WORK_DIR/src-pgdata"
    # The source's archive_command runs as the container's postgres OS user
    # (uid 70) while the restore container runs as the invoking host user:
    # the throwaway mktemp parent stays 0700, but the SHARED dirs inside it
    # are opened up so both container uids can read/write the drill spool.
    chmod 0777 "$WORK_DIR/offsite/wal-archive" "$WORK_DIR/src-pgdata"
    chmod 0755 "$WORK_DIR/keys"
    # Throwaway envelope key for THIS drill only (real envelope encryption:
    # the archive and the restore resolve the very same key file).
    openssl rand -base64 32 > "$WORK_DIR/keys/wal.key"
    chmod 0644 "$WORK_DIR/keys/wal.key"
    log "work dir: $WORK_DIR (local 'offsite' stands in for the rsync target)"

    # Phase 1 — throwaway source with the real encrypted archive machinery.
    _t0=$(mono_now)
    log "phase 1/6: booting throwaway source postgres ($DRILL_IMAGE) with archive_command -> $PG_WAL_ARCHIVE"
    docker run -d --name "$SRC_NAME" \
        -e POSTGRES_USER=postgres \
        -e POSTGRES_PASSWORD="$DRILL_SRC_PASSWORD" \
        -e POSTGRES_DB=postgres \
        -e WAL_ARCHIVE_TARGET=/offsite/wal-archive \
        -e WAL_SPOOL_DIR=/tmp/wal-spool \
        -e WAL_ENCRYPTION_KEY_FILE=/keys/wal.key \
        -e WAL_RSYNC_TIMEOUT=60 \
        -v "$PG_WAL_ARCHIVE":/usr/local/bin/pg-wal-archive.sh:ro \
        -v "$ENVELOPE_LIB":/usr/local/lib/backup-envelope.sh:ro \
        -v "$WORK_DIR/offsite/wal-archive":/offsite/wal-archive \
        -v "$WORK_DIR/keys":/keys:ro \
        -v "$WORK_DIR/src-pgdata":/var/lib/postgresql/data \
        "$DRILL_IMAGE" \
        postgres -c archive_mode=on \
                 -c archive_command='/usr/local/bin/pg-wal-archive.sh %p %f' \
                 -c archive_timeout=60 >/dev/null
    wait_source_ready
    # Half-tooled image refusal (same guard the wal-archive overlay boots
    # with): the drill needs the encrypting archive path, not a bare db.
    docker exec "$SRC_NAME" sh -c \
        'command -v rsync >/dev/null && command -v ssh >/dev/null && command -v openssl >/dev/null && command -v pg_basebackup >/dev/null' \
        || { err "the drill image lacks rsync/ssh/openssl/pg_basebackup — rebuild $DRILL_IMAGE"; return 1; }
    PH_BOOT=$(dur_s "$_t0" "$(mono_now)")

    # Phase 2 — writes + a forced switch so segments really flow through
    # the encrypted spool, then the sealed base backup (wal-base shape).
    _t0=$(mono_now)
    log "phase 2/6: writes + encrypted base backup"
    docker exec "$SRC_NAME" psql -U postgres -d postgres -v ON_ERROR_STOP=1 >/dev/null \
        -c "CREATE TABLE $DRILL_TABLE (id serial PRIMARY KEY, note text, written_at timestamptz DEFAULT now())" \
        -c "INSERT INTO $DRILL_TABLE (note) SELECT 'pre-base-' || g FROM generate_series(1, $DRILL_PRE_ROWS) g"
    docker exec "$SRC_NAME" psql -U postgres -d postgres -tAc 'CHECKPOINT' >/dev/null
    switch_and_wait
    BASE_LABEL=$(docker exec -e PGPASSWORD="$DRILL_SRC_PASSWORD" "$SRC_NAME" sh -c '
        set -eu
        ts=$(date -u +%Y%m%d-%H%M%S)
        label="apexmail-wal-base-${ts}"
        spool=$(mktemp -d /tmp/pitr-drill-base.XXXXXX)
        pg_basebackup -h 127.0.0.1 -U postgres -D "$spool" -F tar -z -X stream -c fast \
            --label="$label" --no-password
        [ -s "$spool/base.tar.gz" ] || { echo "pg_basebackup produced no base.tar.gz" >&2; exit 1; }
        # Seal with the SAME envelope helper the wal-base path of
        # postgres-backup-encrypt.sh uses (reuse, no fork): artifacts leave
        # the private spool only as ciphertext, paired by the timestamp.
        . /usr/local/lib/backup-envelope.sh
        BACKUP_ENCRYPTION_KEY_FILE=/keys/wal.key
        backup_envelope_key
        backup_envelope_encrypt "$spool/base.tar.gz" "/offsite/wal-base/${label}.tar.gz.enc"
        if [ -s "$spool/pg_wal.tar.gz" ]; then
            backup_envelope_encrypt "$spool/pg_wal.tar.gz" "/offsite/wal-base/${label}.pg_wal.tar.gz.enc"
        fi
        rm -rf "$spool"
        printf "%s\n" "$label"') || return 1
    BASE_ART=$WORK_DIR/offsite/wal-base/$BASE_LABEL.tar.gz.enc
    [ -s "$BASE_ART" ] || { err "sealed base backup missing: $BASE_ART"; return 1; }
    if ls "$WORK_DIR"/offsite/wal-base/*.tar.gz >/dev/null 2>&1; then
        err "a PLAINTEXT base artifact exists in the offsite dir — the drill must publish ciphertext only"
        return 1
    fi
    ROWS_AT_BASE=$(docker exec "$SRC_NAME" psql -U postgres -d postgres -tAc \
        "SELECT count(*) FROM $DRILL_TABLE")
    log "sealed base backup: $BASE_LABEL.tar.gz.enc (+ pg_wal sibling), rows at base: $ROWS_AT_BASE"
    # Post-base writes: replay has to go PAST the base through decrypting
    # restore_command for the verify to pass.
    docker exec "$SRC_NAME" psql -U postgres -d postgres -v ON_ERROR_STOP=1 >/dev/null \
        -c "INSERT INTO $DRILL_TABLE (note) SELECT 'post-base-' || g FROM generate_series(1, $DRILL_POST_ROWS) g"
    docker exec "$SRC_NAME" psql -U postgres -d postgres -tAc 'CHECKPOINT' >/dev/null
    switch_and_wait
    EXPECTED_FACTS=$(row_facts)
    EXPECTED_COUNT=${EXPECTED_FACTS%%|*}
    EXPECTED_MD5=${EXPECTED_FACTS##*|}
    PH_WRITES=$(dur_s "$_t0" "$(mono_now)")
    WAL_COUNT=$(find "$WORK_DIR/offsite/wal-archive" -type f -name '*.gz.enc' | wc -l | tr -d ' ')
    log "expected truth: $EXPECTED_COUNT rows, checksum $EXPECTED_MD5; $WAL_COUNT encrypted segments offsite"

    # Phase 3 — DESTRUCTIVE: the source and its data dir are GONE. Only the
    # offsite ciphertext + the sealed base remain as recovery inputs.
    _rto0=$(mono_now)
    _t0=$(mono_now)
    log "phase 3/6: DESTRUCTIVE — removing source container + data dir"
    docker rm -f "$SRC_NAME" >/dev/null
    SRC_NAME=""
    rm -rf "$WORK_DIR/src-pgdata"
    [ -s "$BASE_ART" ] || { err "sealed base vanished before the restore"; return 1; }
    [ "$WAL_COUNT" -gt 0 ] || { err "no encrypted WAL segments survived — nothing to replay"; return 1; }
    PH_TEARDOWN=$(dur_s "$_t0" "$(mono_now)")
    log "source destroyed; recovery inputs are ciphertext only"

    # Phase 4 — timed PITR restore by the production tool, unmodified.
    _t0=$(mono_now)
    log "phase 4/6: pg-pitr-restore.sh full restore + replay (target latest, monotonic clock)"
    _restore_rc=0
    docker run --rm --name "$RESTORE_NAME" \
        --user "$(id -u):$(id -g)" \
        -e WAL_ARCHIVE_TARGET=/work/offsite/wal-archive \
        -e WAL_ENCRYPTION_KEY_FILE=/work/keys/wal.key \
        -e BACKUP_ENCRYPTION_KEY_FILE=/work/keys/wal.key \
        -e WAL_EVIDENCE_DIR=/work/restore-evidence \
        -e PITR_SCRATCH_ROOT=/work/restore-scratch \
        -e PITR_KEEP_SCRATCH=1 \
        -e PITR_PORT="$DRILL_PORT" \
        -e PITR_POLL_SECS=2 \
        -e PITR_REPLAY_TIMEOUT_SECS="$DRILL_REPLAY_TIMEOUT" \
        -v "$PG_PITR_RESTORE":/usr/local/bin/pg-pitr-restore.sh:ro \
        -v "$ENVELOPE_LIB":/usr/local/lib/backup-envelope.sh:ro \
        -v "$WORK_DIR":/work \
        "$DRILL_IMAGE" \
        sh /usr/local/bin/pg-pitr-restore.sh \
            --base "/work/offsite/wal-base/$BASE_LABEL.tar.gz.enc" \
            --target latest --target-action promote || _restore_rc=$?
    PH_RESTORE=$(dur_s "$_t0" "$(mono_now)")
    if [ "$_restore_rc" -ne 0 ]; then
        err "pg-pitr-restore.sh failed (exit $_restore_rc) — drill NOT verified"
        TOTAL_RTO=$(dur_s "$_rto0" "$(mono_now)")
        VERIFIED_LITERAL=false
        return 1
    fi
    RESTORE_DATA=$(ls -d "$WORK_DIR"/restore-scratch/apexmail-pitr.*/data 2>/dev/null | tail -n 1)
    [ -n "$RESTORE_DATA" ] || { err "PITR_KEEP_SCRATCH=1 but no scratch data dir survived"; TOTAL_RTO=$(dur_s "$_rto0" "$(mono_now)"); VERIFIED_LITERAL=false; return 1; }
    log "restore+replay done in ${PH_RESTORE}s (scratch kept at $RESTORE_DATA)"

    # Phase 5 — verify: boot the RECOVERED data dir and compare against the
    # pre-destruction truth. pg-pitr-restore already promoted and stopped it.
    _t0=$(mono_now)
    log "phase 5/6: verifying the recovered data"
    _rel_data=${RESTORE_DATA#"$WORK_DIR"}
    docker run -d --name "$VERIFY_NAME" \
        --user "$(id -u):$(id -g)" \
        -v "$WORK_DIR":/work \
        "$DRILL_IMAGE" \
        postgres -D "/work$_rel_data" -k /tmp -p "$DRILL_PORT" -c listen_addresses='' >/dev/null
    _vr_waited=0
    until docker exec "$VERIFY_NAME" pg_isready -h /tmp -p "$DRILL_PORT" -q >/dev/null 2>&1; do
        if [ "$(docker inspect -f '{{.State.Running}}' "$VERIFY_NAME" 2>/dev/null || echo false)" != "true" ]; then
            err "recovered postgres died on restart — last log lines:"
            docker logs --tail 30 "$VERIFY_NAME" >&2 || true
            TOTAL_RTO=$(dur_s "$_rto0" "$(mono_now)"); VERIFIED_LITERAL=false
            return 1
        fi
        [ "$_vr_waited" -ge 120 ] && { err "recovered postgres not ready within 120s"; TOTAL_RTO=$(dur_s "$_rto0" "$(mono_now)"); VERIFIED_LITERAL=false; return 1; }
        sleep 2
        _vr_waited=$((_vr_waited + 2))
    done
    ACTUAL_FACTS=$(docker exec "$VERIFY_NAME" psql -h /tmp -p "$DRILL_PORT" -U postgres -d postgres -tAc \
        "SELECT count(*) || '|' || coalesce(md5(string_agg(id::text || ':' || note, ',' ORDER BY id)), 'none') FROM $DRILL_TABLE" \
        2>/dev/null) || ACTUAL_FACTS="0|none"
    ACTUAL_COUNT=${ACTUAL_FACTS%%|*}
    ACTUAL_MD5=${ACTUAL_FACTS##*|}
    RESTORE_LSN=$(docker exec "$VERIFY_NAME" psql -h /tmp -p "$DRILL_PORT" -U postgres -d postgres -tAc \
        "SELECT coalesce(pg_last_wal_replay_lsn()::text, 'none')" 2>/dev/null || echo none)
    REPLAY_TS=$(docker exec "$VERIFY_NAME" psql -h /tmp -p "$DRILL_PORT" -U postgres -d postgres -tAc \
        "SELECT coalesce(pg_last_xact_replay_timestamp()::text, 'none')" 2>/dev/null || echo none)
    _in_rec=$(docker exec "$VERIFY_NAME" psql -h /tmp -p "$DRILL_PORT" -U postgres -d postgres -tAc \
        'SELECT pg_is_in_recovery()' 2>/dev/null || echo t)
    PH_VERIFY=$(dur_s "$_t0" "$(mono_now)")
    if [ "$_in_rec" = "t" ]; then
        err "recovered instance is still in recovery — the promote step did not complete"
        TOTAL_RTO=$(dur_s "$_rto0" "$(mono_now)")
        VERIFIED_LITERAL=false
        return 1
    fi
    if verify_drill_result "$EXPECTED_COUNT" "$EXPECTED_MD5" "$ROWS_AT_BASE" "$ACTUAL_COUNT" "$ACTUAL_MD5"; then
        VERIFIED_LITERAL=true
    else
        VERIFIED_LITERAL=false
        return 1
    fi
    TOTAL_RTO=$(dur_s "$_rto0" "$(mono_now)")
    log "phase 6/6: drill VERIFIED — total RTO ${TOTAL_RTO}s, restore_lsn $RESTORE_LSN, target_time $REPLAY_TS"
    return 0
}

# ── Self-test: hermetic evaluator + usage contract (no docker) ───────────────
pitr_drill_self_test() {
    _st_fail=0
    _st_tmp=$(mktemp -d "${TMPDIR:-/tmp}/apexmail-pitr-drill-test.XXXXXX") || return 1

    # 1. Usage contract (recursive invocation; nothing docker-shaped runs
    #    because parse_args fails before any tooling check).
    if sh "$0" >/dev/null 2>&1; then
        echo "[pitr-drill] self-test FAILED: bare invocation must exit non-zero" >&2; _st_fail=1
    fi
    if sh "$0" --out >/dev/null 2>&1; then
        echo "[pitr-drill] self-test FAILED: --out without a value must exit non-zero" >&2; _st_fail=1
    fi
    if sh "$0" --definitely-not-a-flag x >/dev/null 2>&1; then
        echo "[pitr-drill] self-test FAILED: unknown flag must exit non-zero" >&2; _st_fail=1
    fi
    sh "$0" --help >/dev/null 2>&1 || {
        echo "[pitr-drill] self-test FAILED: --help must exit 0" >&2; _st_fail=1
    }

    # 2. Evaluator: the verified shape passes; every degraded shape fails.
    if ! verify_drill_result 75 abc0123 50 75 abc0123 >/dev/null; then
        echo "[pitr-drill] self-test FAILED: a matching positive result must verify" >&2; _st_fail=1
    fi
    if verify_drill_result 75 abc0123 50 74 abc0123 >/dev/null 2>&1; then
        echo "[pitr-drill] self-test FAILED: row-count mismatch must be rejected" >&2; _st_fail=1
    fi
    if verify_drill_result 75 abc0123 50 75 zz9999 >/dev/null 2>&1; then
        echo "[pitr-drill] self-test FAILED: checksum mismatch must be rejected" >&2; _st_fail=1
    fi
    if verify_drill_result 75 abc0123 50 0 none >/dev/null 2>&1; then
        echo "[pitr-drill] self-test FAILED: zero restored rows must be rejected" >&2; _st_fail=1
    fi
    if verify_drill_result 0 none 0 0 none >/dev/null 2>&1; then
        echo "[pitr-drill] self-test FAILED: zero-EXPECTED drill must be rejected" >&2; _st_fail=1
    fi
    if verify_drill_result 75 abc0123 75 75 abc0123 >/dev/null 2>&1; then
        echo "[pitr-drill] self-test FAILED: result not exceeding the base rows must be rejected (replay unproven)" >&2; _st_fail=1
    fi
    if verify_drill_result 75 abc0123 50 seventy-five abc0123 >/dev/null 2>&1; then
        echo "[pitr-drill] self-test FAILED: non-numeric count must be rejected" >&2; _st_fail=1
    fi

    # 3. Clock + duration math.
    _st_a=$(mono_now) || { echo "[pitr-drill] self-test FAILED: mono_now errored" >&2; _st_fail=1; }
    sleep 1
    _st_b=$(mono_now)
    case $(dur_s "$_st_a" "$_st_b") in
        *.*) : ;;
        *) echo "[pitr-drill] self-test FAILED: dur_s did not render a float" >&2; _st_fail=1 ;;
    esac
    _st_d=$(dur_s 1.500 2.250)
    [ "$_st_d" = "0.750" ] || { echo "[pitr-drill] self-test FAILED: dur_s(1.500, 2.250) gave '$_st_d'" >&2; _st_fail=1; }
    _st_e=$(dur_s 3.000 3.000)
    [ "$_st_e" = "0.000" ] || { echo "[pitr-drill] self-test FAILED: dur_s(3,3) gave '$_st_e'" >&2; _st_fail=1; }

    # 4. JSON evidence shape (both verdicts; every phase key present).
    PH_BOOT=1.500; PH_WRITES=2.250; PH_BASE=3.000; PH_TEARDOWN=0.500
    PH_RESTORE=9.000; PH_VERIFY=1.000; TOTAL_RTO=10.500
    RESTORE_LSN=0/3000190; REPLAY_TS=2026-10-28T12:00:00+00
    WAL_COUNT=4; ROWS_AT_BASE=50; EXPECTED_COUNT=75; ACTUAL_COUNT=75
    EXPECTED_MD5=abc0123; VERIFIED_LITERAL=true
    write_drill_json "$_st_tmp/verified.json"
    for _st_key in '"phase_durations_s"' '"total_rto_s":10.500' '"restore_lsn":"0/3000190"' \
        '"target_time"' '"verified":true' '"source_boot":1.500' '"writes":2.250' \
        '"base_backup":3.000' '"source_teardown":0.500' '"pitr_restore":9.000' '"verify":1.000'; do
        grep -q "$_st_key" "$_st_tmp/verified.json" || {
            echo "[pitr-drill] self-test FAILED: JSON missing $_st_key" >&2; _st_fail=1
        }
    done
    VERIFIED_LITERAL=false
    write_drill_json "$_st_tmp/failed.json"
    grep -q '"verified":false' "$_st_tmp/failed.json" || {
        echo "[pitr-drill] self-test FAILED: failed verdict not rendered" >&2; _st_fail=1
    }
    # Unset phase variables must still render valid JSON (defaults).
    unset PH_BOOT PH_WRITES PH_BASE PH_TEARDOWN PH_RESTORE PH_VERIFY TOTAL_RTO \
        RESTORE_LSN REPLAY_TS WAL_COUNT ROWS_AT_BASE EXPECTED_COUNT ACTUAL_COUNT \
        EXPECTED_MD5 VERIFIED_LITERAL 2>/dev/null || true
    write_drill_json "$_st_tmp/defaulted.json"
    grep -q '"pitr_restore":0.000' "$_st_tmp/defaulted.json" || {
        echo "[pitr-drill] self-test FAILED: defaulted phase durations not rendered" >&2; _st_fail=1
    }

    rm -rf "$_st_tmp"
    if [ "$_st_fail" -ne 0 ]; then
        echo "[pitr-drill] self-test FAILED" >&2
        return 1
    fi
    echo "[pitr-drill] self-test OK: usage contract, verifier (positive match, count/checksum mismatch, zero-verified both directions, replay-beyond-base required, non-numeric rejected), monotonic clock + duration math, JSON evidence shape for both verdicts and the defaulted form. NOTE: no docker round trip runs here — the timed destructive restore is the operator drill itself (docs/operations/disaster-recovery.md)"
    return 0
}

if [ "${1:-}" = "--self-test" ]; then
    pitr_drill_self_test
    exit $?
fi

case "${1:-}" in
    --help|-h) usage; exit 0 ;;
esac

trap drill_teardown EXIT
trap 'drill_teardown; exit 130' INT TERM HUP
# Under set -e a failing parse_args exits with its own status (2 on usage
# errors) — the same deliberate shape pg-pitr-restore.sh documents.
parse_args "$@"
if drill_run; then
    DRILL_STATUS=0
else
    DRILL_STATUS=1
    [ -n "${VERIFIED_LITERAL:-}" ] || VERIFIED_LITERAL=false
fi
DRILL_PARENT=$(dirname -- "$DRILL_OUT")
mkdir -p "$DRILL_PARENT" 2>/dev/null || true
write_drill_json "$DRILL_OUT"
log "drill JSON written: $DRILL_OUT (verified=$VERIFIED_LITERAL)"
if [ "$DRILL_STATUS" -ne 0 ]; then
    err "drill NOT verified — see $DRILL_OUT and the log above"
fi
exit "$DRILL_STATUS"
