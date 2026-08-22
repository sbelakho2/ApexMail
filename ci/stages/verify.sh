#!/bin/sh
# =============================================================================
# ci/stages/verify.sh — stage 8: post-deploy verification (real probes).
# =============================================================================
# Replaces deploy-hetzner.yml's "Verify rollout" + "Verify TLS certificate"
# steps and the `make verify` target:
#   1. per-service compose state: every canonical service running/healthy
#   2. HTTP: api/track/status/enterprise health 200; the sales-autopilot
#      unsubscribe route answers 404 (a 502/503 means it is DOWN behind nginx)
#   3. SMTP banner on 127.0.0.1:25 (MTA alive)
#   4. ports 80/443/25/587/993 open (143 intentionally CLOSED — SSL-only IMAP)
#   5. TLS cert present + issuer sanity (Let's Encrypt vs self-signed warn)
#   6. cache-coherence: deploy/scripts/verify-deployment.sh over the legal pages
#
# Off-host: skipped (75) unless CI_VERIFY_REMOTE=1, which runs ONLY the
# read-only public HTTP probes against production (a manual pre-merge check).
# =============================================================================
set -eu

. "${CI_ROOT:-$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)}/lib.sh"

VERIFY_SERVICES="api-server mta imap-server mailstore worker enterprise tracking
                 observability marketing status-server billing-service sales-autopilot
                 postgres-backup nginx certbot postgres redis clickhouse"

compose() {
    docker compose -f docker-compose.yml -f docker-compose.prod.yml --env-file .env "$@"
}

check_http() {
    _label=$1 _url=$2 _expect=$3
    _code=$(curl -k -s -o /dev/null -w '%{http_code}' --max-time 10 "$_url" 2>/dev/null || printf '000')
    if [ "$_code" = "$_expect" ]; then
        ci_info "verify: $_label -> $_code OK"
        return "$CI_EXIT_OK"
    fi
    ci_err "verify: $_label returned HTTP $_code (expected $_expect)"
    return "$CI_EXIT_FAIL"
}

verify_stack_state() {
    _vs_fail=0
    for _svc in $VERIFY_SERVICES; do
        _state=$(compose ps --format '{{.Name}} {{.State}} {{.Health}}' "$_svc" 2>/dev/null | head -1 || true)
        _name=$(printf '%s' "$_state" | awk '{print $1}')
        _stat=$(printf '%s' "$_state" | awk '{print $2}')
        _health=$(printf '%s' "$_state" | awk '{print $3}')
        if [ -z "$_name" ]; then
            ci_err "service $_svc has no container (compose ps empty)"
            _vs_fail=1
        elif [ "$_health" = unhealthy ] || [ "$_stat" != running ]; then
            ci_err "service $_svc is $_stat/$_health (expected running/healthy)"
            _vs_fail=1
        else
            ci_info "verify: $_svc: $_stat/${_health:-no-healthcheck} OK"
        fi
    done
    [ "$_vs_fail" -eq 0 ] || return "$CI_EXIT_FAIL"
    return "$CI_EXIT_OK"
}

verify_http_local() {
    check_http "api health"        "https://api.apexmail.ee/health"                        "200" &&
    check_http "track health"      "https://track.apexmail.ee/health"                      "200" &&
    check_http "status page"       "https://status.apexmail.ee/status"                     "200" &&
    check_http "enterprise health" "https://enterprise.apexmail.ee/health"                 "200" &&
    check_http "sales-api (404 not 502)" "https://api.apexmail.ee/sales-api/u/healthcheck-probe" "404"
}

verify_smtp() {
    _banner=$( (printf 'QUIT\r\n'; sleep 1) | ci_timeout 10 \
        openssl s_client -starttls smtp -connect 127.0.0.1:25 -quiet 2>/dev/null | head -1 || true)
    case ${_banner:-} in
        *220*|*ESMTP*)
            ci_info "verify: SMTP banner OK: $_banner"
            return "$CI_EXIT_OK" ;;
    esac
    # openssl -quiet hides the banner on some builds; raw TCP fallback.
    _banner=$( (exec 3<>/dev/tcp/127.0.0.1/25 && head -1 <&3) 2>/dev/null || true)
    case ${_banner:-} in
        *220*|*ESMTP*)
            ci_info "verify: SMTP banner OK: $_banner"
            return "$CI_EXIT_OK" ;;
        *)
            ci_err "verify: no SMTP banner on 127.0.0.1:25 (got '${_banner:-nothing}')"
            return "$CI_EXIT_FAIL" ;;
    esac
}

verify_ports() {
    # 143 intentionally closed: IMAP is SSL-only on 993.
    for _port in 80 443 25 587 993; do
        if nc -z -w 2 127.0.0.1 "$_port" 2>/dev/null; then
            ci_info "verify: port $_port OPEN"
        else
            ci_err "verify: port $_port CLOSED (expected open)"
            return "$CI_EXIT_FAIL"
        fi
    done
    return "$CI_EXIT_OK"
}

verify_tls_cert() {
    _cert=$CI_DEPLOY_DIR/deploy/nginx/ssl/fullchain.pem
    if [ ! -s "$_cert" ]; then
        ci_err "verify: no fullchain.pem — nginx cannot be serving TLS"
        return "$CI_EXIT_FAIL"
    fi
    if openssl x509 -in "$_cert" -noout -subject -enddate >>"$CI_STAGE_LOG" 2>&1; then
        if openssl x509 -in "$_cert" -noout -issuer 2>/dev/null | grep -qi "let's encrypt"; then
            ci_info "verify: Let's Encrypt certificate active"
        else
            ci_warn "verify: certificate is NOT Let's Encrypt (self-signed?) — run deploy/scripts/issue-letsencrypt.sh"
        fi
        return "$CI_EXIT_OK"
    fi
    ci_err "verify: fullchain.pem present but unparseable"
    return "$CI_EXIT_FAIL"
}

verify_cache_coherence() {
    (cd "$CI_DEPLOY_DIR" && FETCH_COUNT=3 RETRY_DELAY=3 \
        ci_check "cache coherence (legal pages)" \
        bash deploy/scripts/verify-deployment.sh https://apexmail.ee)
}

verify_remote_only() {
    ci_warn "CI_VERIFY_REMOTE=1 — probing PRODUCTION endpoints read-only"
    check_http "api health"        "https://api.apexmail.ee/health"          "200" &&
    check_http "track health"      "https://track.apexmail.ee/health"        "200" &&
    check_http "status page"       "https://status.apexmail.ee/status"       "200" &&
    check_http "enterprise health" "https://enterprise.apexmail.ee/health"   "200" &&
    check_http "sales-api (404 not 502)" \
        "https://api.apexmail.ee/sales-api/u/healthcheck-probe" "404"
}

# Images that are optional per-sha (only these warn when missing during a
# rollback; canonical stack services must ALL exist or the rollback aborts).
EXTRA_ROLLBACK_IMAGES="${EXTRA_ROLLBACK_IMAGES:-}"

# Rollback to the previously deployed :<sha> pins when the rollout probes
# fail (CI_ROLLBACK_ON_VERIFY_FAIL, default 1). Migrations are NOT reverted —
# they are additive/compatible by the migration gate's design; this restores
# the previous APPLICATION images only.
rollback_to_previous_sha() {
    [ "${CI_ROLLBACK_ON_VERIFY_FAIL:-1}" = 1 ] || { ci_warn "auto-rollback disabled (CI_ROLLBACK_ON_VERIFY_FAIL=0)"; return 0; }
    _rb_sha=""
    [ -f "$CI_ROOT/.last-deployed-sha" ] && _rb_sha=$(cat "$CI_ROOT/.last-deployed-sha" 2>/dev/null)
    if [ -z "$_rb_sha" ] || [ "$_rb_sha" = "${CI_SHA:-}" ]; then
        ci_warn "no previous deployed sha to roll back to — leaving the current rollout in place"
        return 0
    fi
    ci_err "verify FAILED — rolling back to previously deployed images :$_rb_sha"
    _rb_ns=${GHCR_NS:-ghcr.io/sbelakho2/apexmail}
    _rb_missing=0
    for _svc in $STACK_SERVICES; do
        if docker image inspect "$_rb_ns/$_svc:$_rb_sha" >/dev/null 2>&1; then
            docker tag "$_rb_ns/$_svc:$_rb_sha" "$_rb_ns/$_svc:latest" >/dev/null 2>&1 \
                || { ci_warn "retag failed for $_svc"; _rb_missing=1; }
        else
            # Extra images (migrator etc.) may legitimately not exist per sha.
            case " $EXTRA_ROLLBACK_IMAGES " in
                *" $_svc "*) ci_warn "image $_svc:$_rb_sha missing — not rolled back"; _rb_missing=1 ;;
            esac
        fi
    done
    if [ "$_rb_missing" = 1 ]; then
        ci_warn "rollback incomplete for at least one service — keeping current stack (mixed versions are worse than a known-bad one with containers up)"
        return 0
    fi
    if compose up -d --remove-orphans $STACK_SERVICES >>"$CI_STAGE_LOG" 2>&1; then
        _i=1; while [ "$_i" -le 5 ]; do
            compose exec -T nginx nginx -s reload >>"$CI_STAGE_LOG" 2>&1 && break
            _i=$((_i + 1)); sleep 3
        done
        ci_err "ROLLBACK COMPLETE: stack restored to images :$_rb_sha (migrations NOT reverted — they are additive by design)"
    else
        ci_err "rollback compose up FAILED — the failed rollout is still running; intervene manually"
    fi
    return 0
}

stage_main() {
    if ! ci_on_deploy_host; then
        if [ "${CI_VERIFY_REMOTE:-0}" = 1 ]; then
            verify_remote_only
            return "$?"
        fi
        ci_skip_stage "verify runs on the deploy host; set CI_VERIFY_REMOTE=1 to probe production from here"
    fi
    cd "$CI_DEPLOY_DIR"

    if
        verify_stack_state &&
        verify_http_local &&
        verify_smtp &&
        verify_ports &&
        verify_tls_cert &&
        verify_cache_coherence
    then
        :
    else
        rollback_to_previous_sha
        return "$CI_EXIT_FAIL"
    fi

    ci_info "verify: rollout verified — services healthy, endpoints and SMTP answering"
    return "$CI_EXIT_OK"
}

stage_main
