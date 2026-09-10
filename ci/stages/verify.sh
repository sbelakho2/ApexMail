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
#   7. CONTENT SMOKE (verify_http_content): the infra probes above answer
#      "is it up"; these answer "do the deployed pages actually render" —
#      the app console login/signup/forgot-password forms, the anonymous
#      dashboard redirect, the api /health JSON body, and the marketing
#      homepage/pricing/docs pages, each asserting status + content-type +
#      in-body markers. Strictly read-only GETs: no form POSTs, no account
#      creation on production, ever.
#
# Off-host: skipped (75) unless CI_VERIFY_REMOTE=1, which runs ONLY the
# read-only public HTTP probes against production (a manual pre-merge check).
# =============================================================================
set -eu

. "${CI_ROOT:-$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)}/lib.sh"

VERIFY_SERVICES="api-server mta imap-server mailstore worker enterprise tracking
                 observability marketing status-server billing-service sales-autopilot
                 compliance analytics-worker pdf-renderer ai-service
                 postgres-backup clickhouse-backup nginx certbot postgres redis clickhouse
                 prometheus grafana loki alertmanager tempo otel-collector
                 node-exporter blackbox-exporter postgres-exporter redis-exporter
                 clickhouse-exporter synthetic-monitor"

# FIX (audit): rollback_to_previous_sha iterated $STACK_SERVICES, which was
# never defined in this script (each stage runs as its own process — the
# deploy stage's variable does not carry over), so the rollback loop was
# EMPTY and a failed verify would "roll back" nothing. Mirror the deploy
# stage's canonical service list (incl. the monitoring slice) here.
STACK_SERVICES="$VERIFY_SERVICES"

compose() {
    # --profile monitoring: keep the profiled monitoring services part of the
    # active project set during rollback (see ci/stages/deploy.sh).
    docker compose -f docker-compose.yml -f docker-compose.prod.yml --env-file .env \
        --profile monitoring "$@"
}

check_http() {
    # _expect may be a single code ("200") or a pipe alternation ("400|404").
    _label=$1 _url=$2 _expect=$3
    _code=$(curl -k -s -o /dev/null -w '%{http_code}' --max-time 10 "$_url" 2>/dev/null || printf '000')
    _ok=0
    case "|$_expect|" in
        *"|$_code|"*) _ok=1 ;;
    esac
    if [ "$_ok" -eq 1 ]; then
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
    check_http "sales-api served (400|404 not 502)" "https://api.apexmail.ee/sales-api/u/healthcheck-probe" "400|404"
}

# --- content smoke (post-deploy) -------------------------------------------------
# Infrastructure probes answer "is it up"; these answer "does it render".
# Same host/port style as verify_http_local: the app console
# (app.apexmail.ee) is the api-server's SSR console behind the local nginx;
# marketing (apexmail.ee) is the marketing container behind the same nginx.

# content_probe <url> <expect_codes> <ctype_substring> [probe-string...]
#   expect_codes: a single HTTP code ("200") or pipe alternation
#   ("302|303"). ctype_substring: what the Content-Type must contain
#   ("text/html"); "-" skips that check. Every remaining argument is a
#   fixed string the response body must contain (case-insensitive, so the
#   probe survives both dev and minified markup). Prints a diagnostic on
#   failure; returns 1.
content_probe() {
    _cp_url=$1 _cp_expect=$2 _cp_ctype=$3
    shift 3
    _cp_tmp=$(mktemp "${TMPDIR:-/tmp}/apexmail-verify.XXXXXX")
    _cp_meta=$(curl -k -s -o "$_cp_tmp" -w '%{http_code} %{content_type}' --max-time 10 "$_cp_url" 2>/dev/null || printf '000 ')
    _cp_code=${_cp_meta%% *}
    _cp_ct=${_cp_meta#* }
    _cp_err=''
    case "|$_cp_expect|" in
        *"|$_cp_code|"*) ;;
        *) _cp_err="HTTP $_cp_code (expected $_cp_expect)" ;;
    esac
    if [ -z "$_cp_err" ] && [ "$_cp_ctype" != "-" ]; then
        case "$_cp_ct" in
            *"$_cp_ctype"*) ;;
            *) _cp_err="content-type '$_cp_ct' (expected to contain '$_cp_ctype')" ;;
        esac
    fi
    if [ -z "$_cp_err" ]; then
        for _cp_str in "$@"; do
            if ! grep -qiF -- "$_cp_str" "$_cp_tmp" 2>/dev/null; then
                _cp_err="body missing probe string: '$_cp_str'"
                break
            fi
        done
    fi
    rm -f "$_cp_tmp"
    if [ -n "$_cp_err" ]; then
        printf 'content probe %s: %s\n' "$_cp_url" "$_cp_err" >&2
        return "$CI_EXIT_FAIL"
    fi
    return "$CI_EXIT_OK"
}

# redirect_probe <url> <expect_codes> <location_prefix> — the UN-followed
# response must redirect (302/303 by default) to a Location that starts
# with the given prefix; proves the auth wall, not just a status code.
# curl's %{redirect_url} resolves relative Locations to absolute
# (Location: /login?next=… → https://app.apexmail.ee/login?next=…), so the
# scheme+host are stripped before the prefix match.
redirect_probe() {
    _rp_url=$1 _rp_expect=$2 _rp_prefix=$3
    _rp_meta=$(curl -k -s -o /dev/null -w '%{http_code} %{redirect_url}' --max-time 10 "$_rp_url" 2>/dev/null || printf '000 ')
    _rp_code=${_rp_meta%% *}
    _rp_loc=${_rp_meta#* }
    _rp_loc=$(printf '%s' "$_rp_loc" | sed -E 's|^[a-zA-Z]+://[^/]+||')
    _rp_err=''
    case "|$_rp_expect|" in
        *"|$_rp_code|"*) ;;
        *) _rp_err="HTTP $_rp_code (expected $_rp_expect)" ;;
    esac
    if [ -z "$_rp_err" ]; then
        case "$_rp_loc" in
            "$_rp_prefix"*) ;;
            *) _rp_err="redirects to '$_rp_loc' (expected to start with '$_rp_prefix')" ;;
        esac
    fi
    if [ -n "$_rp_err" ]; then
        printf 'redirect probe %s: %s\n' "$_rp_url" "$_rp_err" >&2
        return "$CI_EXIT_FAIL"
    fi
    return "$CI_EXIT_OK"
}

verify_http_content() {
    _vhc_fail=0

    # App console (app.apexmail.ee → api-server SSR, via the local nginx —
    # the same vhost verify_http_local already probes for other subdomains).
    ci_check "content: app console /login renders" \
        content_probe "https://app.apexmail.ee/login" "200" "text/html" \
        "Welcome back" 'action="/web/auth/login"' "data-kiwi-widget" || _vhc_fail=1
    ci_check "content: app console /signup renders" \
        content_probe "https://app.apexmail.ee/signup" "200" "text/html" \
        'id="signup-name"' 'id="signup-password"' "data-kiwi-widget" || _vhc_fail=1
    ci_check "content: app console /forgot-password renders" \
        content_probe "https://app.apexmail.ee/forgot-password" "200" "text/html" \
        'action="/web/auth/forgot-password"' || _vhc_fail=1
    ci_check "content: app console /dashboard redirects anonymous users to login" \
        redirect_probe "https://app.apexmail.ee/dashboard" "302|303" "/login" || _vhc_fail=1

    # API health body (the status probe above only checked the code).
    ci_check "content: api /health returns status JSON" \
        content_probe "https://api.apexmail.ee/health" "200" "json" "status" || _vhc_fail=1

    # Marketing site (apexmail.ee → marketing container, via the same nginx).
    ci_check "content: marketing / renders" \
        content_probe "https://apexmail.ee/" "200" "text/html" "ApexMail" || _vhc_fail=1
    ci_check "content: marketing /pricing/ renders" \
        content_probe "https://apexmail.ee/pricing/" "200" "text/html" "pricing" || _vhc_fail=1
    ci_check "content: marketing /docs/api/ renders" \
        content_probe "https://apexmail.ee/docs/api/" "200" "text/html" "ApexMail" || _vhc_fail=1
    # Unknown path: underscores deliberately do NOT match the edge vhost's
    # trailing-slash canonicalisation regex ([a-z0-9-]+ only), so this falls
    # through to the marketing container's try_files =404 and must come back
    # as a real 404 (a 200 here would mean the SPA-style fallback regressed).
    ci_check "content: marketing unknown path answers 404" \
        content_probe "https://apexmail.ee/ci_content_smoke_404" "404" "text/html" || _vhc_fail=1

    [ "$_vhc_fail" -eq 0 ] || return "$CI_EXIT_FAIL"
    ci_info "verify: content smoke green — console, api and marketing pages render"
    return "$CI_EXIT_OK"
}

verify_smtp() {
    # Raw banner first — /dev/tcp is a BASH-ism (stages run dash on Debian),
    # so the read runs under an explicit bash -c.
    _banner=$(bash -c 'exec 3<>/dev/tcp/127.0.0.1/25 && head -1 <&3' 2>/dev/null || true)
    case ${_banner:-} in
        *220*|*ESMTP*)
            ci_info "verify: SMTP banner OK: $_banner"
            return "$CI_EXIT_OK" ;;
    esac
    # STARTTLS leg via openssl when the raw read failed (also proves TLS).
    _banner=$( (printf 'QUIT\r\n'; sleep 1) | ci_timeout 10 \
        openssl s_client -starttls smtp -connect 127.0.0.1:25 -quiet 2>/dev/null | head -1 || true)
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
    check_http "sales-api served (400|404 not 502)" \
        "https://api.apexmail.ee/sales-api/u/healthcheck-probe" "400|404"
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
            # Read-only production probes (incl. the content smoke) for a
            # manual pre-merge check from a dev machine.
            verify_remote_only && verify_http_content
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
        verify_cache_coherence &&
        verify_http_content
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
