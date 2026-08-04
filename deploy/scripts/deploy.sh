#!/usr/bin/env bash
#
# deploy.sh — ApexMail unified deployment script.
#
# This is the SINGLE source of truth for deployments. No GitHub Actions,
# no ad-hoc Makefile targets, no manual docker run. One script, one command,
# fully reproducible.
#
# Usage:
#   ./deploy/scripts/deploy.sh           # deploy from current repo state
#   ./deploy/scripts/deploy.sh --pull    # git pull first, then deploy
#   ./deploy/scripts/deploy.sh --build-only   # build images without restarting
#
# What this script does (in order):
#   1. Verify prerequisites (running on the server, /opt/apexmail exists)
#   2. Optionally pull latest code from origin/main
#   3. Build ALL Rust binaries in a Docker container (full workspace)
#   4. Build ALL service images from the Dockerfile
#   5. Stop orphaned containers (created by docker run, not compose)
#   6. Deploy TLS certs to all service paths
#   7. docker compose up -d (recreates all services from new images)
#   8. Reload nginx to pick up new upstreams
#   9. Verify all services are healthy
#
# The script is idempotent — running it twice produces the same result.
#

set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────
DEPLOY_DIR="/opt/apexmail"
MAIL_SERVER_DIR="${DEPLOY_DIR}/services/mail-server"
COMPOSE_FILES="-f docker-compose.yml -f docker-compose.prod.yml"
ENV_FILE="${DEPLOY_DIR}/.env"
GIT_REMOTE="origin"
GIT_BRANCH="main"

# Cert source (Let's Encrypt live cert)
CERT_SRC="/etc/letsencrypt/live/apexmail.ee"
# Cert destinations (multiple services read from different paths)
CERT_DIR="${DEPLOY_DIR}/certs"
NGINX_SSL_DIR="${DEPLOY_DIR}/deploy/nginx/ssl"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

log()   { echo -e "${GREEN}[deploy]${NC} $*"; }
warn()  { echo -e "${YELLOW}[warn]${NC} $*"; }
error() { echo -e "${RED}[error]${NC} $*" >&2; }
step()  { echo -e "\n${CYAN}━━━ $* ━━━${NC}"; }

# ── Parse arguments ──────────────────────────────────────────────────────────
DO_PULL=false
BUILD_ONLY=false
for arg in "$@"; do
    case "$arg" in
        --pull)        DO_PULL=true ;;
        --build-only)  BUILD_ONLY=true ;;
        *) error "Unknown argument: $arg"; exit 1 ;;
    esac
done

# ── Step 0: Verify we're on the server ───────────────────────────────────────
step "Step 0: Verify environment"

if [[ ! -d "$DEPLOY_DIR" ]]; then
    error "Deploy directory $DEPLOY_DIR does not exist."
    error "This script must be run on the production server."
    exit 1
fi

if [[ ! -f "$ENV_FILE" ]]; then
    error ".env file not found at $ENV_FILE"
    exit 1
fi

# Fix git safe.directory (directory may be owned by a different uid due to rsync)
git config --global --add safe.directory "$DEPLOY_DIR" 2>/dev/null || true

cd "$DEPLOY_DIR"
log "Working directory: $(pwd)"
log "Current commit: $(git log -1 --oneline 2>/dev/null || echo 'unknown')"

# ── Step 1: Pull latest code ─────────────────────────────────────────────────
if $DO_PULL; then
    step "Step 1: Pull latest code from $GIT_REMOTE/$GIT_BRANCH"
    git fetch "$GIT_REMOTE" "$GIT_BRANCH"
    git reset --hard "${GIT_REMOTE}/${GIT_BRANCH}"
    log "Now at: $(git log -1 --oneline)"
else
    step "Step 1: Using current code (pass --pull to fetch latest)"
    log "At: $(git log -1 --oneline 2>/dev/null || echo 'no git history')"
fi

# ── Step 2: Build ALL Rust binaries via Docker ───────────────────────────────
step "Step 2: Build Rust workspace (all binaries)"

# The Dockerfile's `builder` stage runs `cargo build --release` for the entire
# workspace, producing every binary (api-server, mta-server, imap-server,
# mailstore, worker, enterprise, etc.) in one reproducible build.
log "Building full workspace in Docker (this may take several minutes)..."

docker build \
    --target builder \
    --tag apexmail-builder:latest \
    --build-arg BUILDKIT_INLINE_CACHE=1 \
    "$MAIL_SERVER_DIR" 2>&1 | tail -5

log "Workspace build complete."

# ── Step 3: Build ALL service images ─────────────────────────────────────────
step "Step 3: Build service images"

# Tag images with the EXACT names the compose file references so Docker finds
# them locally and doesn't try to pull from GHCR.
GHCR_NS="ghcr.io/sbelakho2/apexmail"

# Each service image is a thin layer on top of runtime-base that COPYs its
# binary from the builder stage. Building them all ensures every service
# has a dedicated image with its own binary baked in.
declare -A SERVICES=(
    [api-server]=api-server
    [mta]=mta
    [imap-server]=imap-server
    [mailstore]=mailstore
    [worker]=worker
    [enterprise]=enterprise
    [observability]=observability
)

for stage_name in "${!SERVICES[@]}"; do
    image_name="${GHCR_NS}/${stage_name}:latest"
    log "Building: $image_name (stage: $stage_name)"
    docker build \
        --target "$stage_name" \
        --tag "$image_name" \
        "$MAIL_SERVER_DIR" 2>&1 | tail -2
done

# Marketing image (built from its own Dockerfile)
log "Building: ${GHCR_NS}/marketing:latest"
docker build \
    --tag "${GHCR_NS}/marketing:latest" \
    "${DEPLOY_DIR}/apps/marketing-zola" 2>&1 | tail -2

# Tracking service (built from its own Dockerfile)
if [[ -f "${DEPLOY_DIR}/deploy/Dockerfile.tracking" ]]; then
    log "Building: ${GHCR_NS}/tracking-service:latest"
    docker build \
        --tag "${GHCR_NS}/tracking-service:latest" \
        -f "${DEPLOY_DIR}/deploy/Dockerfile.tracking" \
        "${DEPLOY_DIR}" 2>&1 | tail -2
fi

if $BUILD_ONLY; then
    log "Build-only mode — skipping deployment."
    log "Images built: ${SERVICES[*]} marketing tracking-service"
    exit 0
fi

# ── Step 4: Stop orphaned containers ─────────────────────────────────────────
step "Step 4: Stop orphaned containers"

# Remove containers that were created by `docker run` (not compose-managed).
# These have no compose labels and will conflict with `docker compose up`.
ORPHANS=("apexmail-imap" "apexmail-mta" "apexmail-mailstore")
for name in "${ORPHANS[@]}"; do
    if docker ps -a --format '{{.Names}}' | grep -q "^${name}$"; then
        # Check if it has compose labels — if not, it's an orphan
        if ! docker inspect "$name" --format '{{.Config.Labels}}' 2>/dev/null | grep -q "compose"; then
            warn "Stopping orphaned container: $name (not compose-managed)"
            docker rm -f "$name" 2>/dev/null || true
        else
            log "Container $name is compose-managed — will be handled by compose up"
        fi
    fi
done

# ── Step 5: Deploy TLS certs ─────────────────────────────────────────────────
step "Step 5: Deploy TLS certificates"

if [[ -f "${CERT_SRC}/fullchain.pem" && -f "${CERT_SRC}/privkey.pem" ]]; then
    log "Copying Let's Encrypt cert to all service paths..."

    # Docker nginx SSL path
    mkdir -p "$NGINX_SSL_DIR"
    cp "${CERT_SRC}/fullchain.pem" "${NGINX_SSL_DIR}/fullchain.pem"
    cp "${CERT_SRC}/privkey.pem"   "${NGINX_SSL_DIR}/privkey.pem"

    # Mail services cert path
    mkdir -p "$CERT_DIR"
    for name in apexmail.crt apexmail.key mta.crt mta.key fullchain.pem privkey.pem; do
        case "$name" in
            *.crt|fullchain.pem) cp "${CERT_SRC}/fullchain.pem" "${CERT_DIR}/${name}" ;;
            *.key|privkey.pem)   cp "${CERT_SRC}/privkey.pem"   "${CERT_DIR}/${name}" ;;
        esac
    done

    log "Certs deployed."
else
    warn "Let's Encrypt cert not found at ${CERT_SRC} — services will use existing certs."
fi

# ── Step 6: Docker Compose up ────────────────────────────────────────────────
step "Step 6: Deploy all services via Docker Compose"

log "Pulling infrastructure images (postgres, redis, clickhouse, nginx, certbot)..."
docker compose $COMPOSE_FILES --env-file "$ENV_FILE" pull 2>&1 | grep -v "Pull complete\|Already exists\|Digest\|Status" || true

log "Starting all services..."
docker compose $COMPOSE_FILES --env-file "$ENV_FILE" up -d --remove-orphans 2>&1

log "All services started."

# ── Step 7: Reload nginx ─────────────────────────────────────────────────────
step "Step 7: Reload nginx"

sleep 3  # Give containers a moment to start
if docker ps --format '{{.Names}}' | grep -q "nginx"; then
    docker exec "$(docker ps --format '{{.Names}}' | grep nginx | head -1)" nginx -s reload 2>&1 || true
    log "Nginx reloaded."
else
    warn "Nginx container not found — skipping reload."
fi

# ── Step 8: Verify ───────────────────────────────────────────────────────────
step "Step 8: Verify deployment"

sleep 5  # Give services time to initialize

log "Container status:"
docker compose $COMPOSE_FILES --env-file "$ENV_FILE" ps --format "table {{.Name}}\t{{.Status}}" 2>/dev/null || \
    docker ps --format "table {{.Names}}\t{{.Status}}"

echo ""
log "Port checks:"
for port in 80 443 25 587 143 993; do
    if nc -z -w2 127.0.0.1 "$port" 2>/dev/null; then
        echo "  Port $port: ${GREEN}OPEN${NC}"
    else
        echo "  Port $port: ${RED}CLOSED${NC}"
    fi
done

echo ""
log "TLS check (IMAPS 993):"
if echo "Q" | timeout 5 openssl s_client -connect 127.0.0.1:993 2>/dev/null | grep -q "verify return:1"; then
    echo "  IMAPS TLS: ${GREEN}VALID${NC}"
else
    echo "  IMAPS TLS: ${RED}FAILED${NC}"
fi

echo ""
log "Deployed commit: $(git log -1 --oneline)"
log "Deployment complete."
