#!/bin/sh
# =============================================================================
# ci/units/webhook-handler.sh — socket-activated webhook receiver.
# =============================================================================
# systemd hands each accepted connection on 127.0.0.1:8088 to this script as
# stdin/stdout (Accept=yes socket activation). It:
#   1. reads ONE HTTP request with a hard 10s / 8KB budget,
#   2. requires the shared secret:  curl -H 'X-ApexMail-Token: <token>' \
#         -d '{"ref":"main"}' http://127.0.0.1:8088/hooks/pipeline
#      where <token> is /etc/apexmail/webhook-token (0600, root-only),
#   3. answers 202 and starts apexmail-pipeline.service (queued behind the
#      pipeline's own lock if a run is already going).
#
# Deliberately minimal: no JSON parsing beyond a ref allow-list, no external
# dependencies, no writes outside journald.
# =============================================================================
set -eu

CI_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
# shellcheck source=lib.sh
. "$CI_DIR/lib.sh"

TOKEN_FILE=${APEXMAIL_WEBHOOK_TOKEN_FILE:-/etc/apexmail/webhook-token}

respond() { # <status> <reason>
    printf 'HTTP/1.1 %s %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s\n' \
        "$1" "$2" "$((${#2} + 1))" "$2"
}

main() {
    # Read the request head + small body under a deadline.
    _req=$(ci_timeout 10 sh -c 'head -c 8192' 2>/dev/null || printf '')
    [ -n "$_req" ] || { respond 408 "empty request"; return 0; }

    _path=$(printf '%s\n' "$_req" | head -n 1 | awk '{print $2}')
    case $_path in
        /hooks/pipeline) ;;
        *) respond 404 "not found"; return 0 ;;
    esac

    if [ ! -r "$TOKEN_FILE" ]; then
        ci_err "webhook: token file $TOKEN_FILE missing/unreadable (create via ci/install.sh webhook-token)"
        respond 500 "server misconfigured"
        return 0
    fi
    _want_token=$(head -n 1 "$TOKEN_FILE" | tr -d '[:space:]')
    _got_token=$(printf '%s\n' "$_req" | tr -d '\r' | sed -n 's/^X-Apexmail-Token:[[:space:]]*//Ip' | head -n 1 | tr -d '[:space:]')
    if [ -z "$_want_token" ] || [ "$_got_token" != "$_want_token" ]; then
        ci_warn "webhook: bad token from connection"
        respond 403 "forbidden"
        return 0
    fi

    # Optional ref in a tiny JSON body; only allow-listed refs are honoured.
    _ref=$(printf '%s\n' "$_req" | sed -n 's/.*"ref"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)
    [ -n "$_ref" ] || _ref=${CI_REF:-main}
    case $_ref in
        main|master|develop) ;;
        *) ci_warn "webhook: ref '$_ref' not allow-listed; using ${CI_REF:-main}"; _ref=${CI_REF:-main} ;;
    esac

    # Queue the run; systemd serialises oneshot starts, the pipeline's own
    # lock collapses redundant ones.
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl start --no-block apexmail-pipeline.service >/dev/null 2>&1; then
            ci_info "webhook: pipeline queued (ref=$_ref)"
            respond 202 "pipeline run queued"
        else
            respond 500 "failed to queue pipeline"
        fi
        return 0
    fi
    # No systemd (tests): start the runner detached.
    "$CI_DIR/pipeline.sh" run --ref "$_ref" >/dev/null 2>&1 &
    respond 202 "pipeline run queued (no systemd)"
}

main
