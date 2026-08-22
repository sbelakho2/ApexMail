#!/bin/sh
# =============================================================================
# ci/stages/notify.sh — stage 9: failure reporting + housekeeping.
# =============================================================================
# Replaces every GitHub notifications surface (workflow failure emails, the
# red X in the GitHub UI, PR comments). Mechanism, in order:
#   1. ci/.last-failure marker — a machine-readable file the status command
#      and any external monitoring can poll.
#   2. systemd journal / syslog when available (systemd-cat or logger).
#   3. EMAIL THROUGH THE PLATFORM ITSELF: on failure (and only on failure) an
#      email is enqueued by INSERTING A ROW INTO email_queue via the stack's
#      own postgres (`docker compose exec -T postgres psql`). The outbound
#      worker then delivers it through the exact production email path
#      (MTA/SES) — zero external dependencies, and it doubles as a canary:
#      if the notification email never arrives, outbound delivery is broken.
#      Rate-limited: at most one notification email per CI_NOTIFY_COOLDOWN
#      seconds (default 1800) so a red pipeline polling every 5 minutes
#      cannot flood the queue.
#   4. Always: prune old run dirs + cap history (ci_prune_runs) so ci/runs
#      never grows unbounded.
# =============================================================================
set -eu

. "${CI_ROOT:-$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)}/lib.sh"

# Determine the run outcome from the manifest: any stage with status
# fail|timeout (advisory-fail does not page) means the run failed.
run_outcome() {
    if command -v jq >/dev/null 2>&1 && [ -f "$RUN_DIR/manifest.json" ]; then
        _bad=$(jq -r '[.stages[] | select(.status == "fail" or .status == "timeout")] | length' \
            "$RUN_DIR/manifest.json" 2>/dev/null || printf 0)
        [ "${_bad:-0}" -gt 0 ] && { printf 'fail'; return; }
        printf 'ok'
        return
    fi
    printf 'unknown'
}

failed_stage_name() {
    if command -v jq >/dev/null 2>&1 && [ -f "$RUN_DIR/manifest.json" ]; then
        jq -r '[.stages[] | select(.status == "fail" or .status == "timeout")][0].name // "unknown"' \
            "$RUN_DIR/manifest.json" 2>/dev/null || printf 'unknown'
    else
        printf 'unknown'
    fi
}

write_failure_marker() {
    _fm_stage=$1
    cat >"$CI_DIR_MARKER" <<EOF
run_id=$CI_RUN_ID
time=$(_ci_ts)
ref=$CI_REF
sha=$CI_SHA
stage=$_fm_stage
run_dir=$RUN_DIR
EOF
    chmod 644 "$CI_DIR_MARKER" 2>/dev/null || true
}

journal_log() {
    # Prefer the systemd journal (deploy host); fall back to syslog; neither
    # is fatal when absent (dev machines).
    if command -v systemd-cat >/dev/null 2>&1; then
        printf 'apexmail-pipeline run %s FAILED at stage %s (%s)\n' \
            "$CI_RUN_ID" "$1" "$RUN_DIR" | systemd-cat -p err -t apexmail-ci 2>/dev/null || true
    elif command -v logger >/dev/null 2>&1; then
        logger -t apexmail-ci -p user.err \
            "run $CI_RUN_ID FAILED at stage $1 ($RUN_DIR)" 2>/dev/null || true
    fi
}

cooldown_active() {
    _cd_file=$RUNS_DIR/.notify-cooldown
    _cd_now=$(date +%s)
    if [ -f "$_cd_file" ]; then
        _cd_last=$(cat "$_cd_file" 2>/dev/null || printf 0)
        case $_cd_last in
            ''|*[!0-9]*) _cd_last=0 ;;
        esac
        [ $(( _cd_now - _cd_last )) -lt "${CI_NOTIFY_COOLDOWN:-1800}" ] && return 0
    fi
    return 1
}

mark_notified() {
    date +%s >"$RUNS_DIR/.notify-cooldown"
}

enqueue_failure_email() {
    _ne_stage=$1
    if ! ci_on_deploy_host; then
        ci_info "not on the deploy host — email notification skipped (marker + journal only)"
        return "$CI_EXIT_OK"
    fi
    if cooldown_active; then
        ci_info "notification cooldown active — email suppressed (marker + journal still written)"
        return "$CI_EXIT_OK"
    fi
    cd "$CI_DEPLOY_DIR"
    _ne_log=$RUN_DIR/stages/$_ne_stage.log
    _ne_tail=$(tail -c 4000 "$_ne_log" 2>/dev/null | tr -d '\0' | sed "s/'/''/g" || true)
    _ne_subject="ApexMail pipeline FAILED: $_ne_stage (run $CI_RUN_ID)"
    _ne_body="The ApexMail CI pipeline failed at stage '$_ne_stage'.
Run:    $CI_RUN_ID
Ref:    $CI_REF
SHA:    $CI_SHA
Run dir: $RUN_DIR

Stage log tail:
$_ne_tail

This email was enqueued through the platform's own email_queue by
ci/stages/notify.sh — delivery itself proves outbound mail works."

    # Insert straight into the platform's outbound queue (schema:
    # 001_initial_schema.sql email_queue). Single-quoted values are escaped
    # above; array literal cast keeps psql happy.
    if docker compose -f docker-compose.yml -f docker-compose.prod.yml --env-file .env \
        exec -T postgres psql -U "${POSTGRES_USER:-apexmail}" -d "${POSTGRES_DB:-apexmail}" \
        -v ON_ERROR_STOP=1 >>"$CI_STAGE_LOG" 2>&1 <<SQL
INSERT INTO email_queue
    (from_address, to_addresses, subject, text_body, status, priority, tags)
VALUES
    ('${CI_NOTIFY_FROM:-ci@apexmail.ee}',
     ARRAY['${CI_NOTIFY_TO:-admin@apexmail.ee}']::text[],
     '${_ne_subject}',
     \$body\$${_ne_body}\$body\$,
     'pending', 100, ARRAY['ci-notification']::text[]);
SQL
    then
        mark_notified
        ci_info "failure notification enqueued into email_queue (platform delivery path)"
        return "$CI_EXIT_OK"
    fi
    ci_warn "email_queue insert failed (stack postgres unreachable?) — marker + journal only"
    return "$CI_EXIT_OK"
}

stage_main() {
    CI_DIR_MARKER=$CI_ROOT/.last-failure

    _outcome=$(run_outcome)
    if [ "$_outcome" = fail ]; then
        _stage=$(failed_stage_name)
        write_failure_marker "$_stage"
        journal_log "$_stage"
        enqueue_failure_email "$_stage"
    else
        ci_info "run outcome: $_outcome — no failure notification needed"
        rm -f "$CI_DIR_MARKER" 2>/dev/null || true
    fi

    # Housekeeping: bounded history.
    ci_prune_runs "${CI_KEEP_RUNS:-30}"
    ci_info "notify: run dirs pruned to newest ${CI_KEEP_RUNS:-30}"
    return "$CI_EXIT_OK"
}

stage_main
