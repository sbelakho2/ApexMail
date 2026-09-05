#!/bin/sh
# =============================================================================
# ci/stages/images.sh — stage 5: build ALL service images on the host.
# =============================================================================
# Replaces deploy.yml's "Build & Push Docker Images" job, minus the registry:
# nothing is pushed (the host deploys from its local images), so there is no
# GHCR dependency at all.
#
# Implementation: deploy/scripts/deploy.sh IS the single build implementation
# (its Step 2/3 build the Rust workspace + every service image from the same
# Dockerfile targets the GitHub workflow used). This stage invokes it with
# --build-only, then:
#   * tags every canonical image with :<sha> in addition to :latest
#     (rollback pins — deploy/DEPLOYMENT.md § Rollback expects :<sha> tags)
#   * runs the post-build Trivy gate on EVERY runtime image the compose
#     files define (the scan list is derived from the merged compose
#     config — audit §2: the old gate scanned only api-server + mta, 2 of
#     ~20 built images)
#   * writes SPDX SBOMs for runtime images (advisory, like the Syft step)
#   * prunes :<sha> tags older than CI_KEEP_SHAS (default 5) per service so
#     image storage cannot grow without bound
#
# Skips (exit 75) when not on the deploy host (no $CI_DEPLOY_DIR/.env) —
# e.g. a developer machine or the selftest.
# =============================================================================
set -eu

. "${CI_ROOT:-$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)}/lib.sh"

CANONICAL_SERVICES="api-server mta imap-server mailstore worker enterprise observability
                    status-server billing-service sales-autopilot compliance analytics-worker pdf-renderer ai-service migrator"
# Images with their own Dockerfiles, built by deploy.sh's separate loop:
# marketing + tracking + the four backup sidecars (postgres / clickhouse /
# redis / analytics-cold).
EXTRA_IMAGES="marketing tracking-service postgres-backup clickhouse-backup redis-backup analytics-backup"

stage_main() {
    if ! ci_on_deploy_host; then
        ci_skip_stage "images stage runs only on the deploy host ($CI_DEPLOY_DIR) — local/docker builds happen there"
    fi
    cd "$CI_DEPLOY_DIR"

    # --- 1. build everything through deploy.sh (the single implementation) -------
    ci_info "building all images via deploy/scripts/deploy.sh --build-only"
    # The pipeline holds the deploy flock for the whole run; deploy.sh would
    # try to flock the SAME file as a child and refuse (self-deadlock — the
    # first end-to-end images run hit exactly this). The flag makes deploy.sh
    # inherit the parent's lock instead of re-acquiring it; standalone
    # manual deploy.sh runs are unaffected.
    APEXMAIL_DEPLOY_LOCK_INHERITED=1 ci_exec bash deploy/scripts/deploy.sh --build-only \
        || { ci_err "deploy.sh --build-only failed"; return "$CI_EXIT_FAIL"; }

    # --- 2. tag :<sha> rollback pins ------------------------------------------------
    _ns=${GHCR_NS:-ghcr.io/sbelakho2/apexmail}
    ci_info "tagging images with sha $CI_SHA"
    for _svc in $CANONICAL_SERVICES $EXTRA_IMAGES; do
        if docker image inspect "$_ns/$_svc:latest" >/dev/null 2>&1; then
            ci_exec docker tag "$_ns/$_svc:latest" "$_ns/$_svc:$CI_SHA" \
                || { ci_err "failed to tag $_ns/$_svc:$CI_SHA"; return "$CI_EXIT_FAIL"; }
        else
            ci_err "expected image missing after build: $_ns/$_svc:latest"
            return "$CI_EXIT_FAIL"
        fi
    done

    # --- 3. post-build Trivy gate — EVERY runtime image the compose files define
    # Audit §2 (Trivy scanned only 2 of ~20 images): the scan list is now
    # DERIVED from the merged compose config (base + prod overlay + the
    # monitoring/migrate profiles the deploy activates) instead of a
    # hardcoded api-server+mta pair. Every service whose resolved image is
    # one of OUR builds — the GHCR_NS namespace deploy.sh tags into, or the
    # apexmail/* namespace of the monitoring sidecars — is gated. Stock
    # third-party images (postgres, redis, nginx, certbot, prometheus, ...)
    # are pulled, not built by this pipeline, and stay outside the gate.
    # The ignore policy (.trivyignore) is unchanged.
    if command -v trivy >/dev/null 2>&1; then
        _scan_refs=$(docker compose -f docker-compose.yml -f docker-compose.prod.yml \
                --profile monitoring --profile migrate config --format json 2>>"$CI_STAGE_LOG" \
            | jq -r --arg ns "$_ns" '.services | to_entries[]
                | select(.value.image != null)
                | select(.value.image | startswith($ns + "/") or startswith("apexmail/"))
                | .value.image' | sort -u || true)
        if [ -z "$_scan_refs" ]; then
            ci_err "derived an EMPTY trivy scan list from the compose config — refusing to silently skip the gate (check the compose config output above)"
            return "$CI_EXIT_FAIL"
        fi
        for _ref in $_scan_refs; do
            # Prefer the :<sha> rollback pin (byte-identical to :latest and
            # exactly what the digest manifest below records).
            _scan_img="$_ref"
            case "$_ref" in
                "$_ns"/*:latest)
                    if docker image inspect "${_ref%:latest}:$CI_SHA" >/dev/null 2>&1; then
                        _scan_img="${_ref%:latest}:$CI_SHA"
                    fi
                    ;;
            esac
            if ! docker image inspect "$_scan_img" >/dev/null 2>&1; then
                # Not built by this pipeline (e.g. a monitoring sidecar
                # pinned to a date tag) — advisory skip, matching the fact
                # that deploy.sh never builds it.
                ci_warn "image $_scan_img (from compose config) not built by this pipeline — trivy scan skipped (advisory)"
                continue
            fi
            ci_check "trivy gate $_scan_img" \
                trivy image --ignorefile "$REPO_ROOT/.trivyignore" --severity "$CI_TRIVY_SEVERITY" --exit-code 1 --quiet "$_scan_img" \
                || { ci_err "Trivy gate FAILED for $_scan_img — fix vulnerabilities before deploying"; return "$CI_EXIT_FAIL"; }
            _sbom_name=$(printf '%s' "$_scan_img" | tr '/:' '__')
            trivy image --format spdx-json --output "$RUN_DIR/sbom-$_sbom_name.spdx.json" \
                "$_scan_img" >>"$CI_STAGE_LOG" 2>&1 \
                && ci_info "SBOM: $RUN_DIR/sbom-$_sbom_name.spdx.json" \
                || ci_warn "SBOM generation failed for $_scan_img (advisory)"
        done
    else
        ci_warn "trivy missing — post-build vulnerability gate skipped (install with ci/install.sh)"
    fi

    # --- 4. digest manifest (deploy-stage tamper guard) ------------------------------
    # Record the exact image content IDs the deploy will bring up. The deploy
    # stage re-inspects the images and refuses to continue on any mismatch —
    # nothing runs in production that this run did not build and gate.
    ci_info "recording image digest manifest"
    : >"$RUN_DIR/image-digests.txt"
    for _svc in $CANONICAL_SERVICES $EXTRA_IMAGES; do
        _digest=$(docker image inspect "$_ns/$_svc:$CI_SHA" \
            --format '{{.Id}}' 2>/dev/null) || _digest=""
        if [ -n "$_digest" ]; then
            printf '%s %s\n' "$_svc" "$_digest" >>"$RUN_DIR/image-digests.txt"
        else
            ci_err "cannot inspect $_ns/$_svc:$CI_SHA for the digest manifest"
            return "$CI_EXIT_FAIL"
        fi
    done
    ( cd "$RUN_DIR" && sha256sum image-digests.txt > SHA256SUMS.images 2>/dev/null ) \
        || ci_warn "sha256sum unavailable — digest manifest left unsigned (advisory)"

    # --- 5. bounded :<sha> history ---------------------------------------------------
    _keep=${CI_KEEP_SHAS:-5}
    ci_info "pruning :<sha> image tags beyond the newest $_keep per service"
    for _svc in $CANONICAL_SERVICES $EXTRA_IMAGES; do
        docker images "$_ns/$_svc" --format '{{.Tag}} {{.ID}}' 2>/dev/null \
            | grep -E '^[0-9a-f]{7,40} ' | grep -v "^${CI_SHA:-} " | head -n -"$_keep" | while IFS=' ' read -r _tag _id; do
                [ -n "$_tag" ] || continue
                ci_info "removing old sha tag $_svc:$_tag"
                docker rmi "$_ns/$_svc:$_tag" >/dev/null 2>&1 || true
            done
    done
    docker image prune -f >/dev/null 2>&1 || true

    ci_info "images: all canonical images built, sha-tagged and gated"
    return "$CI_EXIT_OK"
}

stage_main
