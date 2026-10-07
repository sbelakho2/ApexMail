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
# FIX (audit P2): redis-backup and analytics-backup are default-profile
# services in docker-compose.prod.yml and are built/scanned/pinned by the
# images stage, but were absent from this list — `up -d $STACK_SERVICES` only
# acts on named services, so the Redis snapshot scheduler and the cold
# analytics archiver were never started or recreated on a pipeline-led host.
# ci/stages/validate.sh now asserts every *-backup compose service stays in
# this list AND in ci/stages/verify.sh VERIFY_SERVICES.
STACK_SERVICES="api-server mta imap-server mailstore worker enterprise tracking
                 observability marketing status-server billing-service sales-autopilot
                 compliance analytics-worker pdf-renderer ai-service
                 postgres-backup clickhouse-backup redis-backup analytics-backup
                 nginx certbot postgres redis clickhouse
                prometheus grafana loki alertmanager tempo otel-collector
                node-exporter blackbox-exporter postgres-exporter redis-exporter
                clickhouse-exporter synthetic-monitor"

# Digest override applied to EVERY compose call (external audit item 5):
# ci/stages/images.sh renders $RUN_DIR/docker-compose.digest-override.yml
# pinning every first-party service to the exact content this run built and
# gated (see release-manifest.json). Set in stage_main before the first
# compose() call; empty (override absent) only when images did not run.
COMPOSE_PIN_ARGS=''

compose() {
    # shellcheck disable=SC2086  # COMPOSE_PIN_ARGS is the word pair
    #                            # "-f <path>"; RUN_DIR paths have no spaces.
    docker compose -f docker-compose.yml -f docker-compose.prod.yml \
        $COMPOSE_PIN_ARGS --env-file .env --profile monitoring "$@"
}

# First-party images the images stage builds (CANONICAL_SERVICES + EXTRA_IMAGES
# in ci/stages/images.sh — keep the two lists in lockstep; ci/stages/images.sh
# is the authority). Used ONLY by the partial-run fallback renderer below; a
# full run reuses the override the images stage rendered for its exact digests.
PIN_SERVICE_IMAGES="api-server mta imap-server mailstore worker enterprise observability
                    status-server billing-service sales-autopilot compliance analytics-worker
                    pdf-renderer ai-service migrator marketing tracking-service
                    postgres-backup clickhouse-backup redis-backup analytics-backup"

# Compose service key for an image name — mirrors image_compose_key() in
# ci/stages/images.sh (the one divergence: image `tracking-service` ↔
# compose key `tracking`).
image_compose_key() {
    case "$1" in
        tracking-service) printf 'tracking' ;;
        *)                printf '%s' "$1" ;;
    esac
}

# render_pin_fallback — partial runs (`--stages deploy`/`migrate,deploy,verify`)
# have no fresh images-stage rendering: pin to the current `:<sha>` rollback
# tags instead of letting `up` resolve the mutable :latest tag. Services whose
# :<sha> image is absent are left un-pinned — the live pinning gate below then
# refuses the deploy if they are first-party (fail closed).
render_pin_fallback() {
    _rf_ns=${GHCR_NS:-ghcr.io/sbelakho2/apexmail}
    _rf_out="$RUN_DIR/docker-compose.digest-override.yml"
    {
        printf '# GENERATED by ci/stages/deploy.sh (partial-run fallback) — do not edit, do not commit.\n'
        printf '# Pins first-party services to the current :<git-sha> rollback tags (no fresh\n'
        printf '# images-stage rendering in this run; content is re-verified by the digest\n'
        printf '# check above when this run has a manifest).\nservices:\n'
    } >"$_rf_out"
    _rf_pinned=0
    for _svc in $PIN_SERVICE_IMAGES; do
        if docker image inspect "$_rf_ns/$_svc:$CI_SHA" >/dev/null 2>&1; then
            printf '  %s:\n    image: %s\n' "$(image_compose_key "$_svc")" \
                "$_rf_ns/$_svc:$CI_SHA" >>"$_rf_out"
            _rf_pinned=$((_rf_pinned + 1))
        else
            ci_warn "no :$CI_SHA image for $_svc — left on the compose tag (the live pinning gate will refuse a first-party float)"
        fi
    done
    COMPOSE_PIN_ARGS="-f $_rf_out"
    ci_info "fallback digest override rendered ($_rf_pinned services pinned): $_rf_out"
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
    COMPOSE_PIN_ARGS=''

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

    # --- 0b. immutable-pins override + live gate (external audit item 5) ------------
    # The images stage rendered docker-compose.digest-override.yml for the
    # exact content this run built (release-manifest.json). APPLY it to every
    # compose() call — the `up` below must recreate containers on pinned
    # content, never on the mutable :latest tag a manual invocation would
    # resolve — then prove the pinning on the LIVE rendering before anything
    # is brought up (tools/check_image_pinning.py, allowlist for third-party
    # images; deploy/DEPLOYMENT.md § "Immutable deployment artifacts").
    if [ -f "$RUN_DIR/docker-compose.digest-override.yml" ]; then
        COMPOSE_PIN_ARGS="-f $RUN_DIR/docker-compose.digest-override.yml"
        ci_info "digest override applied: $RUN_DIR/docker-compose.digest-override.yml"
    elif [ -n "${CI_SHA:-}" ]; then
        ci_warn "no digest override from this run (images stage skipped?) — rendering rollback-tag pins from the live images"
        render_pin_fallback
    else
        ci_warn "no CI_SHA in this run — digest override not applied (the live pinning gate below decides)"
    fi

    if command -v python3 >/dev/null 2>&1; then
        ci_info "rendering the live compose config for the immutable-pins gate"
        _pins_rc=0
        compose config --format json >"$RUN_DIR/compose-resolved.json" 2>>"$CI_STAGE_LOG" || _pins_rc=$?
        if [ "$_pins_rc" -ne 0 ]; then
            ci_err "could not render the compose config for the pinning gate (see log)"
            return "$CI_EXIT_FAIL"
        fi
        ci_check "immutable image pins (live compose config)" \
            python3 "$REPO_ROOT/tools/check_image_pinning.py" \
                "$RUN_DIR/compose-resolved.json" \
                --namespace "${GHCR_NS:-ghcr.io/sbelakho2/apexmail}" \
                --only-services "$STACK_SERVICES" \
            || { ci_err "the live compose config floats mutable images — refusing to deploy"; return "$CI_EXIT_FAIL"; }
        # Audit-3 #1: the SECURITY-CONTROL policy decisions must also be
        # explicit in the LIVE rendering — no implicit false defaults, and
        # the managed-baseline inspection controls must be active.
        ci_check "security posture (live compose config)" \
            python3 "$REPO_ROOT/tools/check_security_posture.py" \
                --resolved-json "$RUN_DIR/compose-resolved.json" \
            || { ci_err "the live compose config disagrees with the managed security profile — refusing to deploy"; return "$CI_EXIT_FAIL"; }
    else
        ci_warn "python3 missing — the live immutable-pins gate was NOT enforced (audit item 5)"
    fi

    publish_tls_certs

    ci_info "docker compose up -d --remove-orphans (canonical service set)"
    if ! ci_run_logged compose up -d --remove-orphans $STACK_SERVICES; then
        ci_err "docker compose up failed — see log; previous containers keep running"
        return "$CI_EXIT_FAIL"
    fi

    # nginx: recreate FIRST when the on-disk conf changed, then reload.
    # A bind-mounted FILE pins the inode it was created with: git replacing
    # deploy/nginx/nginx.conf leaves the container reading the OLD inode,
    # and `nginx -s reload` faithfully reloads stale bytes (observed on the
    # 2026-09-05 deploy: new default_server/headers lived on disk but never
    # served). Compare the mounted file's md5 against the host file and
    # restart the container when they differ — a one-second blip for the
    # static proxy, and only on conf-changing deploys.
    _reloaded=0
    _host_conf="$CI_DEPLOY_DIR/deploy/nginx/nginx.conf"
    if [ -f "$_host_conf" ]; then
        _host_md5=$(md5sum "$_host_conf" 2>/dev/null | cut -d" " -f1)
        _ctr_md5=$(compose exec -T nginx md5sum /etc/nginx/nginx.conf 2>/dev/null | cut -d" " -f1)
        if [ -n "$_host_md5" ] && [ "$_host_md5" != "$_ctr_md5" ]; then
            ci_info "nginx.conf changed on disk (inode replaced) — restarting nginx to re-bind the mount"
            compose exec -T nginx nginx -t >>"$CI_STAGE_LOG" 2>&1 \
                || { ci_err "new nginx.conf fails nginx -t — restarting anyway is unsafe; fix the conf"; return "$CI_EXIT_FAIL"; }
            if compose restart nginx >>"$CI_STAGE_LOG" 2>&1; then
                ci_info "nginx restarted on the new conf — upstream re-resolution covered by the restart; reload skipped"
                _reloaded=1
            else
                ci_err "nginx restart on new conf failed"
                return "$CI_EXIT_FAIL"
            fi
        fi
    fi

    # Graceful reload, retried: nginx caches upstream DNS at worker start and
    # recreated backends get new container IPs (deploy-hetzner.yml Reload step).
    ci_info "reloading nginx (re-resolve upstreams)"
    _i=1
    while [ "$_reloaded" = 0 ] && [ "$_i" -le 5 ]; do
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

    # Record the state the verify stage needs — NOT by overwriting
    # .last-deployed-sha with the NEW sha, which made the auto-rollback
    # trigger dead in every full run (audit P1): verify read the file, saw
    # its own sha and bailed "nothing to roll back to".
    #   * pre-deploy-sha — the sha that WAS verified live before this deploy;
    #     verify.sh rolls back to exactly this when the probes fail.
    #   * deployed-sha   — the sha this run just brought up; verify.sh
    #     advances .last-deployed-sha to it ONLY after every probe passes,
    #     so .last-deployed-sha always names a VERIFIED rollout.
    record_deploy_state
    ci_info "deploy: stack recreated, nginx reloaded"
    return "$CI_EXIT_OK"
}

# record_deploy_state — capture the rollback target + this run's rollout sha
# for the verify stage (see the call site). Split out so
# ci/tests/rollback-selftest.sh can exercise the real capture logic against a
# synthetic state without bringing anything up.
record_deploy_state() {
    [ -n "${CI_SHA:-}" ] || { ci_warn "CI_SHA unset — rollback state not recorded"; return "$CI_EXIT_OK"; }
    [ -n "${RUN_DIR:-}" ] || { ci_warn "RUN_DIR unset — rollback state not recorded"; return "$CI_EXIT_OK"; }
    _rds_prev=''
    if [ -f "$CI_ROOT/.last-deployed-sha" ]; then
        _rds_prev=$(tr -d '[:space:]' <"$CI_ROOT/.last-deployed-sha" 2>/dev/null || true)
    fi
    if [ -n "$_rds_prev" ] && [ "$_rds_prev" != "$CI_SHA" ]; then
        printf '%s\n' "$_rds_prev" >"$RUN_DIR/pre-deploy-sha"
        ci_info "previous verified sha $_rds_prev recorded (verify-stage rollback target)"
    else
        ci_warn "no previous VERIFIED sha on $(basename "$CI_ROOT")/.last-deployed-sha — a verify failure has no earlier image set to roll back to"
    fi
    printf '%s\n' "$CI_SHA" >"$RUN_DIR/deployed-sha"
    return "$CI_EXIT_OK"
}

# Test hook (ci/tests/rollback-selftest.sh): exercise ONLY the rollback-state
# capture against a synthetic CI_ROOT/RUN_DIR — no docker, no infra. Never
# part of a real run: gated on an explicit env flag.
if [ "${CI_DEPLOY_STATE_SELFTEST:-0}" = 1 ]; then
    record_deploy_state
    exit "$CI_EXIT_OK"
fi

stage_main
