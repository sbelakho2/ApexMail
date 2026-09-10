#!/usr/bin/env bash
#
# deploy.sh — ApexMail manual deployment script (emergency/hotfix path only).
#
# ⚠️  CANONICAL deployment is the self-hosted pipeline (ci/pipeline.sh on the
#     deploy host): it builds every image LOCALLY (nothing is pushed to or
#     pulled from GHCR — the registry-publishing GitHub workflows are gone),
#     gates them (trivy/digest manifest), runs the migrator and brings the
#     stack up. See deploy/DEPLOYMENT.md and ci/README.md.
#     This script is the SAME local-build path used for manual hotfixes: it
#     builds images locally and tags them with the canonical
#     ghcr.io/sbelakho2/apexmail/<service> names so compose resolves them;
#     the tags exist ONLY on the host.
#
# Usage (from developer machine via Makefile):
#   make deploy              — full deploy: sync all code + rebuild all images
#   make deploy-service S=api-server  — partial: sync only changed code,
#                                        rebuild only the specified service,
#                                        remove old files/images/binaries
#
# Usage (on the server directly):
#   ./deploy/scripts/deploy.sh                      # full rebuild + deploy
#   ./deploy/scripts/deploy.sh --service api-server # rebuild one service only
#   ./deploy/scripts/deploy.sh --service mta,imap-server  # rebuild multiple
#   ./deploy/scripts/deploy.sh --build-only         # build without restarting
#   ./deploy/scripts/deploy.sh --no-build            # just restart existing images
#
# What this script does:
#   1. Cleans old files/binaries/containers/images
#   2. Builds the Rust workspace (full or partial) in Docker
#   3. Builds service images (all or selected)
#   4. Removes orphaned containers (created by docker run, not compose)
#   5. Deploys TLS certs
#   6. docker compose up -d (recreates changed services)
#   7. Cleans dangling Docker images
#   8. Reloads nginx + verifies
#
# Partial deploys (--service):
#   Only the specified service(s) are rebuilt and restarted. The Rust workspace
#   is still compiled as a whole (cargo uses incremental compilation), but only
#   the changed service images are rebuilt and only those containers are recreated.
#   Old images for rebuilt services are pruned automatically.
#
set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────
DEPLOY_DIR="/opt/apexmail"
MAIL_SERVER_DIR="${DEPLOY_DIR}/services/mail-server"
COMPOSE_FILES="-f docker-compose.yml -f docker-compose.prod.yml"
# The Dockerfile expects the REPO ROOT as build context (COPY paths are
# services/mail-server/..., packages/kiwicaptcha/..., apps/marketing-zola/...)
BUILD_CONTEXT="${DEPLOY_DIR}"
DOCKERFILE="${MAIL_SERVER_DIR}/Dockerfile"
ENV_FILE="${DEPLOY_DIR}/.env"
NGINX_SSL_DIR="${DEPLOY_DIR}/deploy/nginx/ssl"
CERT_SRC="${NGINX_SSL_DIR}/live/apexmail.ee"
CERT_DIR="${DEPLOY_DIR}/certs"
GHCR_NS="${GHCR_NS:-ghcr.io/sbelakho2/apexmail}"

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()   { echo -e "${GREEN}[deploy]${NC} $*"; }
warn()  { echo -e "${YELLOW}[warn]${NC} $*"; }
error() { echo -e "${RED}[error]${NC} $*" >&2; }
step()  { echo -e "\n${CYAN}━━━ $* ━━━${NC}"; }

# ── Parse arguments ──────────────────────────────────────────────────────────
SERVICES_TO_BUILD=""
BUILD_ONLY=false
NO_BUILD=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --service)   SERVICES_TO_BUILD="$2"; shift 2 ;;
        --build-only) BUILD_ONLY=true; shift ;;
        --no-build)   NO_BUILD=true; shift ;;
        *) error "Unknown argument: $1"; exit 1 ;;
    esac
done

# All services that can be built from the mail-server Dockerfile
ALL_SERVICES=(api-server mta imap-server mailstore worker enterprise observability status-server billing-service sales-autopilot compliance analytics-worker pdf-renderer ai-service migrator)
# Dockerfile targets that differ from the canonical image/service name.
# status-server is built from the `auth-server` stage (the binary inside the
# image is auth-server); the IMAGE name follows the compose service key.
declare -A BUILD_TARGETS=(
    [status-server]=auth-server
)
ALL_IMAGES="${GHCR_NS}/marketing:latest ${GHCR_NS}/tracking-service:latest
            ${GHCR_NS}/postgres-backup:latest ${GHCR_NS}/clickhouse-backup:latest
            ${GHCR_NS}/redis-backup:latest ${GHCR_NS}/analytics-backup:latest"
for s in "${ALL_SERVICES[@]}"; do ALL_IMAGES+=" ${GHCR_NS}/${s}:latest"; done


# Determine which services to build
if [[ -n "$SERVICES_TO_BUILD" ]]; then
    IFS=',' read -ra BUILD_LIST <<< "$SERVICES_TO_BUILD"
else
    BUILD_LIST=("${ALL_SERVICES[@]}")
fi

# ── Step 0: Verify environment ───────────────────────────────────────────────
step "Step 0: Verify environment"

[[ -d "$DEPLOY_DIR" ]] || { error "$DEPLOY_DIR does not exist."; exit 1; }
[[ -f "$ENV_FILE" ]]   || { error ".env not found at $ENV_FILE"; exit 1; }

# ── Concurrency lock (audit fix + F5) ────────────────────────────────────────
# THE SAME LOCK the CI pipeline takes (ci/pipeline.sh): two overlapping
# deploys — one manual, one pipeline — race the build, the migrator and
# `compose up`, and can interleave image tags. Canonical path:
# /opt/apexmail/.deploy.lock (APEXMAIL_DEPLOY_LOCK overrides both sides);
# ci/pipeline.sh acquires exactly this file before running its stages.
LOCK_FILE="${APEXMAIL_DEPLOY_LOCK:-${DEPLOY_DIR}/.deploy.lock}"
mkdir -p "$(dirname "$LOCK_FILE")" 2>/dev/null || true
if [ "${APEXMAIL_DEPLOY_LOCK_INHERITED:-0}" = "1" ]; then
    # Invoked BY the CI pipeline, which already holds the deploy flock for
    # this run — re-acquiring it here would self-deadlock (different open
    # file description, same file). Mutual exclusion vs manual runs is
    # provided by the pipeline's lock.
    log "Deploy lock inherited from the CI pipeline (${LOCK_FILE})."
elif command -v flock >/dev/null 2>&1; then
    exec 9>"$LOCK_FILE"
    if ! flock -n 9; then
        error "another deploy.sh run holds ${LOCK_FILE} — refusing to start (concurrent deploys corrupt image tags)"
        exit 1
    fi
else
    # mkdir fallback (atomic on POSIX); a lock whose owning PID is gone is stale.
    if ! mkdir "${LOCK_FILE}.dir" 2>/dev/null; then
        _lock_pid="$(cat "${LOCK_FILE}.dir/pid" 2>/dev/null || true)"
        if [[ -n "$_lock_pid" ]] && ! kill -0 "$_lock_pid" 2>/dev/null; then
            warn "removing stale deploy lock (pid $_lock_pid gone)"
            rm -rf "${LOCK_FILE}.dir"
            mkdir "${LOCK_FILE}.dir"
        else
            error "another deploy.sh run holds ${LOCK_FILE}.dir — refusing to start"
            exit 1
        fi
    fi
    printf '%s\n' $$ >"${LOCK_FILE}.dir/pid"
    trap 'rm -rf "${LOCK_FILE}.dir"' EXIT
fi
log "Deploy lock acquired."

cd "$DEPLOY_DIR"
log "Deploy: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
if [[ -n "$SERVICES_TO_BUILD" ]]; then
    log "Partial deploy: $SERVICES_TO_BUILD"
else
    log "Full deploy: all services"
fi

# ── Step 1: Clean old artifacts ──────────────────────────────────────────────
step "Step 1: Clean old artifacts"

# Remove stray host-built binaries (we use Docker images now, not bind-mounts)
rm -f "${DEPLOY_DIR}/api-server" "${DEPLOY_DIR}/api-server-new" 2>/dev/null || true
rm -f "${DEPLOY_DIR}/"*.log 2>/dev/null || true

# Remove old target/ binaries that are no longer bind-mounted
log "Removing stale host binaries..."
rm -f "${MAIL_SERVER_DIR}/target/release/api-server" 2>/dev/null || true
rm -f "${MAIL_SERVER_DIR}/target/release/mta-server" 2>/dev/null || true
rm -f "${MAIL_SERVER_DIR}/target/release/imap-server" 2>/dev/null || true
rm -f "${MAIL_SERVER_DIR}/target/release/mailstore" 2>/dev/null || true

# Remove orphaned containers (not compose-managed)
for name in apexmail-imap apexmail-mta apexmail-mailstore; do
    if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "^${name}$"; then
        if ! docker inspect "$name" --format '{{.Config.Labels}}' 2>/dev/null | grep -q "compose"; then
            warn "Removing orphaned container: $name"
            docker rm -f "$name" 2>/dev/null || true
        fi
    fi
done

# Disable stale systemd units
systemctl disable --now apexmail-imap apexmail-mta apexmail-status 2>/dev/null || true
rm -f /etc/systemd/system/apexmail-*.service 2>/dev/null || true

log "Cleanup complete."

# ── Step 1.5: Snapshot current images (rollback baseline) ───────────────────
step "Step 1.5: Snapshot current images (rollback baseline)"

# Audit fix (no rollback on the manual path): tag every locally-present
# canonical image as :pre-deploy BEFORE the rebuild overwrites :latest. If
# post-deploy verification fails, Step 8b retags :pre-deploy back to
# :latest and re-creates the stack — minimal tag-before-upgrade /
# retag-on-failure, no registry round-trip.
ROLLBACK_BASELINE=0
for img in $ALL_IMAGES; do
    if docker image inspect "$img" >/dev/null 2>&1; then
        docker tag "$img" "${img%:latest}:pre-deploy" \
            && ROLLBACK_BASELINE=1 \
            || warn "could not snapshot $img for rollback"
    fi
done
if [[ "$ROLLBACK_BASELINE" -eq 1 ]]; then
    log "Rollback baseline captured (:pre-deploy tags)."
else
    warn "No previous images found — this looks like a first deploy; no rollback baseline exists."
fi

# ── Step 1.7: TLS renewal auto-restart watcher (systemd path unit) ───────────
step "Step 1.7: TLS renewal auto-restart watcher"

# Audit 1.9 (cert renewal gap): mta + imap-server load certs at startup
# only. The certbot loop drops renewal-restart-flag after each renewal;
# this systemd path-unit watcher restarts the two containers exactly once
# per renewal (see deploy/hardening/tls-renew-restart.sh). Installed here —
# not in hetzner-bootstrap.sh — because the unit files live in the repo
# tree that is synced to the deploy dir. Non-fatal for non-root/manual runs
# (the certbot loop still logs the manual restart command as before).
if [[ $EUID -eq 0 ]] && command -v systemctl >/dev/null 2>&1; then
    TLS_RENEW_FLAG="${NGINX_SSL_DIR}/renewal-restart-flag"
    install -m 0755 "${DEPLOY_DIR}/deploy/hardening/tls-renew-restart.sh" \
        /usr/local/sbin/apexmail-tls-renew-restart.sh
    for _unit in apexmail-tls-renew-restart.service apexmail-tls-renew-restart.path; do
        sed -e "s|@FLAG_PATH@|${TLS_RENEW_FLAG}|g" \
            -e "s|@DEPLOY_DIR@|${DEPLOY_DIR}|g" \
            "${DEPLOY_DIR}/deploy/hardening/${_unit}" \
            > "/etc/systemd/system/${_unit}"
    done
    systemctl daemon-reload
    systemctl enable --now apexmail-tls-renew-restart.path
    log "TLS renewal auto-restart watcher active (watching ${TLS_RENEW_FLAG})."
else
    warn "not root / no systemd — TLS renewal auto-restart watcher NOT installed."
    warn "Renewals will log the manual restart command instead (audit 1.9 regression)."
fi

# ── Step 2: Build Rust workspace ─────────────────────────────────────────────
if ! $NO_BUILD; then
    step "Step 2: Build Rust workspace"

    log "Building full workspace in Docker (incremental via Docker layer cache)..."
    docker build \
        --target builder \
        --tag apexmail-builder:latest \
        -f "$DOCKERFILE" \
        "$BUILD_CONTEXT" 2>&1 | tail -5

    log "Workspace build complete."

    # ── Step 3: Build service images ──────────────────────────────────────
    step "Step 3: Build service images"

    for svc in "${BUILD_LIST[@]}"; do
        image="${GHCR_NS}/${svc}:latest"
        target="${BUILD_TARGETS[${svc}]:-$svc}"
        log "Building: $image (Dockerfile target: $target)"
        docker build \
            --target "$target" \
            --tag "$image" \
            -f "$DOCKERFILE" \
            "$BUILD_CONTEXT" 2>&1 | tail -2
    done

    # Build services with separate Dockerfiles (marketing, tracking,
    # backup sidecars).
    for separate_svc in marketing tracking-service postgres-backup clickhouse-backup redis-backup analytics-backup; do
        should_build=false
        if [[ -z "$SERVICES_TO_BUILD" ]] || echo "$SERVICES_TO_BUILD" | grep -q "$separate_svc"; then
            should_build=true
        fi

        if $should_build; then
            case "$separate_svc" in
                marketing)
                    log "Building: ${GHCR_NS}/marketing:latest"
                    docker build --tag "${GHCR_NS}/marketing:latest" \
                        "${DEPLOY_DIR}/apps/marketing-zola" 2>&1 | tail -2
                    ;;
                tracking-service)
                    if [[ -f "${DEPLOY_DIR}/deploy/Dockerfile.tracking" ]]; then
                        log "Building: ${GHCR_NS}/tracking-service:latest"
                        docker build --tag "${GHCR_NS}/tracking-service:latest" \
                            -f "${DEPLOY_DIR}/deploy/Dockerfile.tracking" \
                            "${DEPLOY_DIR}" 2>&1 | tail -2
                    fi
                    ;;
                postgres-backup)
                    log "Building: ${GHCR_NS}/postgres-backup:latest"
                    docker build --tag "${GHCR_NS}/postgres-backup:latest" \
                        -f "${DEPLOY_DIR}/deploy/hardening/Dockerfile.postgres-backup" \
                        "${DEPLOY_DIR}/deploy/hardening" 2>&1 | tail -2
                    ;;
                clickhouse-backup)
                    log "Building: ${GHCR_NS}/clickhouse-backup:latest"
                    docker build --tag "${GHCR_NS}/clickhouse-backup:latest" \
                        -f "${DEPLOY_DIR}/deploy/hardening/Dockerfile.clickhouse-backup" \
                        "${DEPLOY_DIR}/deploy/hardening" 2>&1 | tail -2
                    ;;
                redis-backup)
                    log "Building: ${GHCR_NS}/redis-backup:latest"
                    docker build --tag "${GHCR_NS}/redis-backup:latest" \
                        -f "${DEPLOY_DIR}/deploy/hardening/Dockerfile.redis-backup" \
                        "${DEPLOY_DIR}/deploy/hardening" 2>&1 | tail -2
                    ;;
                analytics-backup)
                    log "Building: ${GHCR_NS}/analytics-backup:latest"
                    docker build --tag "${GHCR_NS}/analytics-backup:latest" \
                        -f "${DEPLOY_DIR}/deploy/hardening/Dockerfile.analytics-backup" \
                        "${DEPLOY_DIR}/deploy/hardening" 2>&1 | tail -2
                    ;;
            esac
        fi
    done
else
    step "Step 2-3: Skipped (--no-build)"
fi

if $BUILD_ONLY; then
    log "Build-only mode — skipping deployment."
    exit 0
fi

# ── Step 4: Deploy TLS certs ─────────────────────────────────────────────────
step "Step 4: Deploy TLS certificates"

# The certbot service maintains the cert tree under deploy/nginx/ssl
# (NGINX_SSL_DIR); live/<domain>/ holds the current LE cert. Copy it to the
# tree root where nginx reads it (same layout as the certbot deploy-hook).
# The legacy host /etc/letsencrypt tree is NOT used (see deploy/DEPLOYMENT.md).
if [[ -f "${CERT_SRC}/fullchain.pem" && -f "${CERT_SRC}/privkey.pem" ]]; then
    mkdir -p "$NGINX_SSL_DIR" "$CERT_DIR"
    install -m 644 "${CERT_SRC}/fullchain.pem" "${NGINX_SSL_DIR}/fullchain.pem"
    install -m 600 "${CERT_SRC}/privkey.pem"   "${NGINX_SSL_DIR}/privkey.pem"
    install -m 644 "${CERT_SRC}/chain.pem"     "${NGINX_SSL_DIR}/ca-chain.pem"
    # The nginx container runs as uid 101 (nginx). A root-owned 600 key makes
    # every nginx reload fail with BIO_new_file Permission denied, so the
    # private key must be readable by gid 101 (group-read; not world-readable).
    chown :101 "${NGINX_SSL_DIR}/privkey.pem" 2>/dev/null || true
    chmod 640 "${NGINX_SSL_DIR}/privkey.pem"
    for name in apexmail.crt apexmail.key mta.crt mta.key fullchain.pem privkey.pem; do
        case "$name" in
            *.crt|fullchain.pem) cp "${CERT_SRC}/fullchain.pem" "${CERT_DIR}/${name}" ;;
            *.key|privkey.pem)   cp "${CERT_SRC}/privkey.pem"   "${CERT_DIR}/${name}" ;;
        esac
    done
    log "Certs deployed."
else
    warn "Let's Encrypt cert not found — using existing certs."
fi

# ── Step 5: Run database migrations (gate before up) ────────────────────────
step "Step 5: Run database migrations (migrator one-shot job)"

# P0 — the deploy-time migration gate. The migrator applies the sqlx chain
# embedded in its image and exits; `up -d` below only runs when it succeeds
# (the same gate the pipeline migrate stage runs). Profile `migrate` +
# restart: no keep it out of the long-running stack.
log "Running migrator (docker compose run --rm migrator)..."
docker compose $COMPOSE_FILES --env-file "$ENV_FILE" --profile migrate run --rm migrator

log "Migrations up to date."

# ── Step 6: Docker Compose up ────────────────────────────────────────────────
step "Step 6: Deploy services via Docker Compose"

log "Starting services..."
# FIX (audit): activate the `monitoring` compose profile so the observability
# stack (prometheus, grafana, loki, alertmanager, exporters, tempo,
# otel-collector, synthetic-monitor) starts with the deployment. Without the
# flag, `up -d` only starts default-profile services — production ran blind,
# and --remove-orphans could even reap manually-started monitoring containers
# (inactive-profile services are treated as orphans by some compose v2
# versions). pdf-renderer (dev profile) and migrator (migrate profile) stay
# excluded. CI does the same — see ci/stages/deploy.sh.
docker compose $COMPOSE_FILES --env-file "$ENV_FILE" \
    --profile monitoring up -d --remove-orphans 2>&1

log "Services started."

# ── Step 7: Clean dangling images ────────────────────────────────────────────
step "Step 7: Clean old Docker images"

# Remove dangling images (<none>:<none>) left from rebuilds. NOTE: the
# per-service non-:latest tag removal (incl. the :pre-deploy rollback
# baseline) moved to Step 9 — it may only run AFTER verification succeeded.
log "Pruning dangling images..."
docker image prune -f 2>/dev/null | grep -v "Total" || true

log "Image cleanup complete."

# ── Step 8: Reload nginx + verify (+ rollback on failure) ───────────────────
step "Step 8: Reload nginx + verify"

sleep 3
NGINX_NAME=$(docker ps --format '{{.Names}}' | grep nginx | head -1)
if [[ -n "$NGINX_NAME" ]]; then
    docker exec "$NGINX_NAME" nginx -s reload 2>&1 || true
    log "Nginx reloaded."
fi

# verify_stack — essentials of ci/stages/verify.sh: every canonical service
# container RUNNING and the core ports answering. Retries for up to ~60s
# because containers need a moment to settle after `up -d`.
verify_stack() {
    local services="api-server mta imap-server mailstore worker enterprise tracking
                    observability marketing status-server billing-service sales-autopilot
                    compliance
                    postgres-backup clickhouse-backup redis-backup analytics-backup
                    nginx certbot postgres redis clickhouse
                    prometheus grafana loki alertmanager tempo otel-collector
                    node-exporter blackbox-exporter postgres-exporter redis-exporter
                    clickhouse-exporter synthetic-monitor"
    local attempt svc state fail
    for attempt in 1 2 3; do
        fail=0
        for svc in $services; do
            state=$(docker compose $COMPOSE_FILES --env-file "$ENV_FILE" ps --format '{{.State}}' "$svc" 2>/dev/null | head -1)
            if [[ "$state" != "running" ]]; then
                error "verify: service $svc is '${state:-missing}' (expected running)"
                fail=1
            fi
        done
        for port in 80 443 25; do
            nc -z -w2 127.0.0.1 "$port" 2>/dev/null \
                || { error "verify: port $port not answering"; fail=1; }
        done
        [[ "$fail" -eq 0 ]] && return 0
        warn "verify attempt $attempt failed — settling 20s before retry"
        sleep 20
    done
    return 1
}

# rollback_images — retag the :pre-deploy baseline back onto :latest and
# recreate the stack (tag-before-upgrade / retag-on-failure, Step 1.5).
# Migrations are NOT reverted: the migrate gate only ships additive,
# compatible migrations by design.
rollback_images() {
    if [[ "$ROLLBACK_BASELINE" -ne 1 ]]; then
        warn "no rollback baseline (first deploy?) — leaving the current stack in place"
        return 0
    fi
    error "verify FAILED — rolling back to the pre-deploy images (:pre-deploy -> :latest)"
    local missing=0 img pre
    for img in $ALL_IMAGES; do
        pre="${img%:latest}:pre-deploy"
        if docker image inspect "$pre" >/dev/null 2>&1; then
            docker tag "$pre" "$img" || { warn "retag failed for $img"; missing=1; }
        else
            warn "no :pre-deploy baseline for $img — it stays on the new image"
        fi
    done
    if [[ "$missing" -eq 1 ]]; then
        warn "rollback incomplete for at least one image — keeping the current stack (mixed versions are worse)"
        return 0
    fi
    if docker compose $COMPOSE_FILES --env-file "$ENV_FILE" \
        --profile monitoring up -d --remove-orphans 2>&1; then
        sleep 3
        [[ -n "$NGINX_NAME" ]] && docker exec "$NGINX_NAME" nginx -s reload 2>&1 || true
        error "ROLLBACK COMPLETE: stack restored to the pre-deploy images (migrations NOT reverted — additive by design)"
    else
        error "rollback compose up FAILED — the failed rollout is still running; intervene manually"
    fi
    return 0
}

sleep 5
log "Container status:"
docker compose $COMPOSE_FILES --env-file "$ENV_FILE" ps --format "table {{.Name}}\t{{.Status}}" 2>/dev/null || \
    docker ps --format "table {{.Names}}\t{{.Status}}"

echo ""
log "Port checks:"
# 143 is intentionally CLOSED — IMAP is SSL-only on 993 (see commit
# "fix(mail): close port 143, SSL-only autoconfig").
for port in 80 443 25 587 993; do
    nc -z -w2 127.0.0.1 "$port" 2>/dev/null && echo "  :${port} ${GREEN}OPEN${NC}" || echo "  :${port} ${RED}CLOSED${NC}"
done

echo ""
if echo "Q" | timeout 5 openssl s_client -connect 127.0.0.1:993 2>/dev/null | grep -q "verify return:1"; then
    log "IMAPS TLS: ${GREEN}VALID${NC}"
else
    warn "IMAPS TLS: ${RED}CHECK NEEDED${NC}"
fi

if verify_stack; then
    log "Verify: all canonical services running, core ports answering."
else
    rollback_images
    error "Deploy FAILED verification — see above (rollback attempted)."
    exit 1
fi

# ── Step 9: Post-success tag cleanup ─────────────────────────────────────────
step "Step 9: Remove rollback baseline + stale tags"

# Only on a VERIFIED deploy may the previous image generation be dropped.
for img in $ALL_IMAGES; do
    docker rmi "${img%:latest}:pre-deploy" 2>/dev/null || true
done
if [[ -n "$SERVICES_TO_BUILD" ]]; then
    # F6 — NEVER rmi the :<sha> rollback pins the CI verify stage depends on.
    # ci/stages/verify.sh rolls a failed rollout back to the tags recorded in
    # ci/.last-deployed-sha (written by ci/stages/deploy.sh after a green
    # deploy). Read the SAME file/format here and exclude that tag (plus
    # `latest`) from the prune list.
    LAST_DEPLOYED_SHA=""
    if [[ -f "${DEPLOY_DIR}/ci/.last-deployed-sha" ]]; then
        LAST_DEPLOYED_SHA="$(tr -d '[:space:]' < "${DEPLOY_DIR}/ci/.last-deployed-sha")"
    fi
    if [[ -n "$LAST_DEPLOYED_SHA" ]]; then
        log "Preserving rollback pin :${LAST_DEPLOYED_SHA} (ci/.last-deployed-sha) from tag cleanup."
    fi
    for svc in "${BUILD_LIST[@]}"; do
        docker images "${GHCR_NS}/${svc}" --format '{{.Tag}}' 2>/dev/null | \
            grep -v "^latest$" | \
            { [[ -n "$LAST_DEPLOYED_SHA" ]] && grep -v "^${LAST_DEPLOYED_SHA}$" || cat; } | \
            while read -r old_tag; do
                warn "Removing old image: ${GHCR_NS}/${svc}:${old_tag}"
                docker rmi "${GHCR_NS}/${svc}:${old_tag}" 2>/dev/null || true
            done
    done
fi

log "Deploy complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
