#!/bin/sh
# =============================================================================
# ci/stages/deploy.sh — stage 7: recreate the stack.
# =============================================================================
# Replaces deploy-hetzner.yml's "Apply stack" + "Reload nginx" (+ deploy.sh
# Steps 4/6/7/8): TLS material refresh, `docker compose up -d` over the
# canonical service set, and a retried graceful nginx reload so upstream
# container IPs are re-resolved.
#
# Deploy decision (see ci/README.md): deploy/scripts/deploy.sh is NOT invoked
# for the up-step because it has no "up without rebuilding and without
# re-running the migrator" flag — this pipeline already ran build (images
# stage) and the migration gate (migrate stage), so re-running deploy.sh
# --no-build would repeat the migrator and its cleanup passes. The four
# commands below replicate deploy.sh Steps 4/6/8 and the Hetzner workflow's
# Apply/Reload steps exactly; the images stage reuses deploy.sh's build
# verbatim.
#
# Skips (exit 75) off-host.
# =============================================================================
set -eu

. "${CI_ROOT:-$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)}/lib.sh"

# Canonical production service set (deploy-hetzner.yml "Apply stack" order).
# FIX (audit): the monitoring services (prometheus, grafana, loki,
# alertmanager, exporters, tempo, otel-collector, synthetic-monitor) live
# behind the `monitoring` compose profile and were absent from this list —
# production therefore ran WITHOUT its own observability stack, and
# `up --remove-orphans` over the non-monitoring list could even reap
# manually-started profile containers. They are now enumerated explicitly
# AND the profile is activated in compose() below. Both are needed: an
# explicit service list keeps `up` starting exactly the canonical set
# regardless of profile semantics, while `--profile monitoring` makes the
# profiled services part of the project's active set so `--remove-orphans`
# can never treat their containers as orphans (a long-standing compose v2
# quirk with inactive-profile services).
STACK_SERVICES="api-server mta imap-server mailstore worker enterprise tracking
                observability marketing status-server billing-service sales-autopilot
                compliance
                postgres-backup clickhouse-backup nginx certbot postgres redis clickhouse
                prometheus grafana loki alertmanager tempo otel-collector
                node-exporter blackbox-exporter postgres-exporter redis-exporter
                clickhouse-exporter synthetic-monitor"

compose() {
    docker compose -f docker-compose.yml -f docker-compose.prod.yml --env-file .env \
        --profile monitoring "$@"
}

# deploy.sh Step 4: publish the live LE cert at the ssl tree root nginx reads.
publish_tls_certs() {
    _live=$CI_DEPLOY_DIR/deploy/nginx/ssl/live/apexmail.ee
    _root=$CI_DEPLOY_DIR/deploy/nginx/ssl
    if [ -f "$_live/fullchain.pem" ] && [ -f "$_live/privkey.pem" ]; then
        install -m 644 "$_live/fullchain.pem" "$_root/fullchain.pem"
        install -m 600 "$_live/privkey.pem" "$_root/privkey.pem"
        [ -f "$_live/chain.pem" ] && install -m 644 "$_live/chain.pem" "$_root/ca-chain.pem"
        chown :101 "$_root/privkey.pem" 2>/dev/null || true
        chmod 640 "$_root/privkey.pem"
        ci_info "TLS certificates published from live/apexmail.ee"
    else
        ci_info "no live/ LE cert yet — keeping existing certs (certbot will populate)"
    fi
}

stage_main() {
    if ! ci_on_deploy_host; then
        ci_skip_stage "deploy stage runs only on the deploy host ($CI_DEPLOY_DIR)"
    fi
    cd "$CI_DEPLOY_DIR"

    # --- 0. digest manifest verification (images-stage tamper guard) ----------------
    # The images stage recorded exactly what it built and gated. Refuse to
    # bring up anything whose local image no longer matches that manifest
    # (rebuilt/retagged/removed out-of-band between stages).
    if [ -f "$RUN_DIR/image-digests.txt" ] && [ -n "${CI_SHA:-}" ]; then
        _ns_d=${GHCR_NS:-ghcr.io/sbelakho2/apexmail}
        _dig_err=0
        while IFS=' ' read -r _svc _digests; do
            [ -n "${_svc:-}" ] || continue
            _now=$(docker image inspect "$_ns_d/$_svc:$CI_SHA" \
                --format '{{.Id}}' 2>/dev/null) || _now=""
            if [ "$_now" != "$_digests" ]; then
                ci_err "image digest mismatch for $_svc:$CI_SHA — rebuilt or altered since the images stage; refusing to deploy"
                _dig_err=1
            fi
        done <"$RUN_DIR/image-digests.txt"
        [ "$_dig_err" -eq 0 ] || return "$CI_EXIT_FAIL"
        if [ -f "$RUN_DIR/SHA256SUMS.images" ] && command -v sha256sum >/dev/null 2>&1; then
            ( cd "$RUN_DIR" && sha256sum -c SHA256SUMS.images >/dev/null 2>&1 ) \
                || { ci_err "image-digests.txt fails its SHA256SUMS.images signature"; return "$CI_EXIT_FAIL"; }
        fi
        ci_info "image digests match the images-stage manifest"
    else
        ci_warn "no image-digests.txt in this run (images stage skipped?) — deploying unverified digests"
    fi

    publish_tls_certs

    ci_info "docker compose up -d --remove-orphans (canonical service set)"
    if ! ci_run_logged compose up -d --remove-orphans $STACK_SERVICES; then
        ci_err "docker compose up failed — see log; previous containers keep running"
        return "$CI_EXIT_FAIL"
    fi

    # Graceful reload, retried: nginx caches upstream DNS at worker start and
    # recreated backends get new container IPs (deploy-hetzner.yml Reload step).
    ci_info "reloading nginx (re-resolve upstreams)"
    _reloaded=0
    _i=1
    while [ "$_i" -le 5 ]; do
        if compose exec -T nginx nginx -s reload >>"$CI_STAGE_LOG" 2>&1; then
            ci_info "nginx reload OK (attempt $_i)"
            _reloaded=1
            break
        fi
        ci_warn "nginx reload attempt $_i failed (nginx may still be starting); retrying"
        _i=$((_i + 1))
        sleep 3
    done
    [ "$_reloaded" = 1 ] || { ci_err "nginx did not reload after 5 attempts"; return "$CI_EXIT_FAIL"; }

    # deploy.sh Step 7: drop dangling images left by the rebuild.
    docker image prune -f >/dev/null 2>&1 || true

    # Record what is now live so a failed verify stage can roll back to the
    # PREVIOUS sha (written only after a fully successful deploy).
    if [ -n "${CI_SHA:-}" ]; then
        printf '%s\n' "$CI_SHA" >"$CI_ROOT/.last-deployed-sha"
    fi

    ci_info "deploy: stack recreated, nginx reloaded"
    return "$CI_EXIT_OK"
}

stage_main
