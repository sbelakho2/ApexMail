#!/usr/bin/env bash
#
# deploy.sh — ApexMail manual deployment script (emergency/hotfix path only).
#
# ⚠️  CANONICAL deployment is CI/CD: deploy.yml builds + pushes images to GHCR,
#     deploy-hetzner.yml pulls + `docker compose up -d` on the host.
#     See deploy/DEPLOYMENT.md — the single source of truth.
#     This script builds images LOCALLY and tags them with GHCR-style names;
#     they are NEVER pushed to GHCR. Use it only for manual hotfixes.
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
GHCR_NS="ghcr.io/sbelakho2/apexmail"

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
ALL_SERVICES=(api-server mta imap-server mailstore worker enterprise observability status-server)
# Dockerfile targets that differ from the canonical image/service name.
# status-server is built from the `auth-server` stage (the binary inside the
# image is auth-server); the IMAGE name follows the compose service key.
declare -A BUILD_TARGETS=(
    [status-server]=auth-server
)
ALL_IMAGES="${GHCR_NS}/marketing:latest ${GHCR_NS}/tracking-service:latest"
for s in "${ALL_SERVICES[@]}"; do ALL_IMAGES+=" ${GHCR_NS}/${s}:latest"; done

# Services with separate Dockerfiles
declare -A SEPARATE_DOCKERFILES=(
    [marketing]="${DEPLOY_DIR}/apps/marketing-zola/Dockerfile"
    [tracking-service]="${DEPLOY_DIR}/deploy/Dockerfile.tracking"
)

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

    # Build services with separate Dockerfiles (marketing, tracking).
    # NOTE: pdf-renderer is dev-profile-only (docker-compose.yml profiles:
    # ["dev","full-stack"]), is NOT part of the production stack, and its
    # Dockerfile is not buildable from this context — skip it here.
    for separate_svc in marketing tracking-service; do
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

# ── Step 5: Docker Compose up ────────────────────────────────────────────────
step "Step 5: Deploy services via Docker Compose"

log "Starting services..."
docker compose $COMPOSE_FILES --env-file "$ENV_FILE" up -d --remove-orphans 2>&1

log "Services started."

# ── Step 6: Clean dangling images ────────────────────────────────────────────
step "Step 6: Clean old Docker images"

# Remove dangling images (<none>:<none>) left from rebuilds
log "Pruning dangling images..."
docker image prune -f 2>/dev/null | grep -v "Total" || true

# For partial deploys, remove old images for the rebuilt services that aren't :latest
if [[ -n "$SERVICES_TO_BUILD" ]]; then
    for svc in "${BUILD_LIST[@]}"; do
        # Remove any non-:latest tags for this service
        docker images "${GHCR_NS}/${svc}" --format '{{.Tag}}' 2>/dev/null | \
            grep -v "^latest$" | while read -r old_tag; do
            warn "Removing old image: ${GHCR_NS}/${svc}:${old_tag}"
            docker rmi "${GHCR_NS}/${svc}:${old_tag}" 2>/dev/null || true
        done
    done
fi

log "Image cleanup complete."

# ── Step 7: Reload nginx + verify ────────────────────────────────────────────
step "Step 7: Reload nginx + verify"

sleep 3
NGINX_NAME=$(docker ps --format '{{.Names}}' | grep nginx | head -1)
if [[ -n "$NGINX_NAME" ]]; then
    docker exec "$NGINX_NAME" nginx -s reload 2>&1 || true
    log "Nginx reloaded."
fi

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

log "Deploy complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
