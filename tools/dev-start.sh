#!/usr/bin/env bash
# =============================================================================
# Local Development Startup Script
# =============================================================================
# Starts all required services for local ApexMail development:
# - Docker containers (PostgreSQL + Redis)
# - Rust API server (port 3001)
# - Rust web surface via 127.0.0.1 host mapping
# - Rust control-plane surface via localhost host mapping
# - Marketing routes via marketing.localhost host mapping
# =============================================================================

set -euo pipefail
cd "$(dirname "$0")/.."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[dev-start]${NC} $1"; }
warn() { echo -e "${YELLOW}[dev-start]${NC} $1"; }
error() { echo -e "${RED}[dev-start]${NC} $1"; exit 1; }

needs_rebuild() {
    local output="$1"
    shift

    if [[ ! -e "$output" ]]; then
        return 0
    fi

    local newer_input
    newer_input="$(find "$@" -type f -newer "$output" -print -quit 2>/dev/null || true)"
    [[ -n "$newer_input" ]]
}

build_rust_ui_css() {
    local tailwind_cli="apps/marketing-zola/tailwindcss"
    local config="services/mail-server/crates/ui-foundation/tailwind.config.js"
    local input="services/mail-server/crates/ui-foundation/assets/globals.input.css"
    local output="services/mail-server/crates/ui-foundation/assets/globals.css"

    if ! needs_rebuild "$output" "$config" "$input" "services/mail-server/crates/ui-foundation/src"; then
        return
    fi

    [[ -x "$tailwind_cli" ]] || error "Tailwind CLI not found at $tailwind_cli"
    log "Building Rust UI stylesheet..."
    "$tailwind_cli" -c "$config" -i "$input" -o "$output"
}

build_marketing_static_site() {
    local tailwind_cli="apps/marketing-zola/tailwindcss"
    local css_input="apps/marketing-zola/static/css/input.css"
    local css_output="apps/marketing-zola/static/css/styles.css"

    if needs_rebuild "$css_output" \
        "apps/marketing-zola/tailwind.config.js" \
        "$css_input" \
        "apps/marketing-zola/templates" \
        "apps/marketing-zola/content" \
        "apps/marketing-zola/static/js"; then
        [[ -x "$tailwind_cli" ]] || error "Tailwind CLI not found at $tailwind_cli"
        log "Building marketing stylesheet..."
        "$tailwind_cli" -c apps/marketing-zola/tailwind.config.js -i "$css_input" -o "$css_output" --minify
    fi

    if needs_rebuild "apps/marketing-zola/public/index.html" \
        "apps/marketing-zola/config.toml" \
        "apps/marketing-zola/templates" \
        "apps/marketing-zola/content" \
        "apps/marketing-zola/static"; then
        command -v zola >/dev/null 2>&1 || error "Zola is required to refresh apps/marketing-zola/public"
        log "Building marketing static export..."
        zola --root apps/marketing-zola build
    fi
}

generate_secret() {
    local bytes="${1:-32}"
    openssl rand -hex "$bytes" 2>/dev/null || error "Failed to generate secret material"
}

load_or_seed_secret() {
    local path="$1"
    local bytes="${2:-32}"

    mkdir -p "$(dirname "$path")"

    if [[ -s "$path" ]]; then
        tr -d '\r\n' < "$path"
        return
    fi

    local secret_value
    secret_value="$(generate_secret "$bytes")"
    printf '%s' "$secret_value" > "$path"
    chmod 600 "$path"
    printf '%s' "$secret_value"
}

resolve_secret() {
    local env_name="$1"
    local path="$2"
    local bytes="${3:-32}"
    local existing_value="${!env_name:-}"

    if [[ -n "$existing_value" ]]; then
        printf '%s' "$existing_value"
        return
    fi

    load_or_seed_secret "$path" "$bytes"
}

# -----------------------------------------------------------------------------
# Export local defaults required during compose interpolation
# -----------------------------------------------------------------------------
export POSTGRES_USER=apexmail
mkdir -p secrets

POSTGRES_PASSWORD="$(resolve_secret POSTGRES_PASSWORD secrets/postgres_password.txt 32)"
export POSTGRES_PASSWORD
export POSTGRES_DB=apexmail
REDIS_PASSWORD="$(resolve_secret REDIS_PASSWORD secrets/redis_password.txt 32)"
export REDIS_PASSWORD
TRACKING_SECRET_KEY="$(resolve_secret TRACKING_SECRET_KEY secrets/tracking_secret_key.txt 32)"
export TRACKING_SECRET_KEY
CLICKHOUSE_PASSWORD="$(resolve_secret CLICKHOUSE_PASSWORD secrets/clickhouse_password.txt 32)"
export CLICKHOUSE_PASSWORD
INTERNAL_SERVICE_TOKEN="$(resolve_secret INTERNAL_SERVICE_TOKEN secrets/internal_service_token.txt 32)"
export INTERNAL_SERVICE_TOKEN
JWT_SECRET="$(resolve_secret JWT_SECRET secrets/jwt_secret.txt 32)"
export JWT_SECRET
export GRAFANA_USER=admin
GRAFANA_PASSWORD="$(resolve_secret GRAFANA_PASSWORD secrets/grafana_password.txt 24)"
export GRAFANA_PASSWORD

chmod 600 secrets/*.txt

HOST_POSTGRES_PORT=5432
if lsof -nP -iTCP:5432 -sTCP:LISTEN >/dev/null 2>&1; then
    warn "Port 5432 is already in use; remapping local Postgres to 55432"
    export POSTGRES_PORT=127.0.0.1:55432
    HOST_POSTGRES_PORT=55432
else
    export POSTGRES_PORT=127.0.0.1:5432
fi

HOST_REDIS_PORT=6379
if lsof -nP -iTCP:6379 -sTCP:LISTEN >/dev/null 2>&1; then
    warn "Port 6379 is already in use; remapping local Redis to 56379"
    export REDIS_PORT=127.0.0.1:56379
    HOST_REDIS_PORT=56379
else
    export REDIS_PORT=127.0.0.1:6379
fi

# -----------------------------------------------------------------------------
# Refresh generated browser assets before serving or embedding them
# -----------------------------------------------------------------------------
build_rust_ui_css
build_marketing_static_site

# -----------------------------------------------------------------------------
# Start Docker containers
# -----------------------------------------------------------------------------
log "Starting Docker containers..."
docker compose up -d postgres redis

# Wait for postgres to be ready
log "Waiting for PostgreSQL..."
until docker exec apexmail-postgres pg_isready -U apexmail -d apexmail >/dev/null 2>&1; do
    sleep 1
done
log "PostgreSQL ready"

escaped_postgres_password=${POSTGRES_PASSWORD//\'/\'\'}
docker exec apexmail-postgres sh -lc "psql -v ON_ERROR_STOP=1 -U \"$POSTGRES_USER\" -d \"$POSTGRES_DB\" -c \"ALTER USER \\\"$POSTGRES_USER\\\" WITH PASSWORD '$escaped_postgres_password';\"" >/dev/null

# -----------------------------------------------------------------------------
# Apply schema patches required for the live signup → MFA → login E2E flow.
# Migration 055 is fully idempotent (ADD COLUMN IF NOT EXISTS / ALTER ...).
# This is a stop-gap until a full sqlx migration runner is wired in; see
# faults.md for the broader migration audit and per-file fixes still required.
# -----------------------------------------------------------------------------
schema_patch="services/mail-server/migrations/055_e2e_schema_fixes.sql"
if [[ -f "$schema_patch" ]]; then
    log "Applying live-DB schema patches (migration 055)..."
    # Pipe via stdin (avoid `docker cp` because the postgres container has a
    # read-only rootfs in this compose stack — only declared tmpfs mounts are
    # writable, and /tmp is not necessarily one of them).
    docker exec -i -e PGPASSWORD="$POSTGRES_PASSWORD" apexmail-postgres \
        psql -v ON_ERROR_STOP=0 -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
        < "$schema_patch" >/dev/null 2>&1 || \
        log "Schema patch returned non-zero (likely tables not yet created; will retry on next start)"
fi

# Wait for redis
log "Waiting for Redis..."
until docker exec apexmail-redis redis-cli -a "$REDIS_PASSWORD" ping >/dev/null 2>&1; do
    sleep 1
done
log "Redis ready"

# -----------------------------------------------------------------------------
# Generate JWT keys if needed
# -----------------------------------------------------------------------------
if [[ ! -f /tmp/jwt_private.pem ]]; then
    log "Generating development JWT keys..."
    umask 077
    openssl genrsa 2048 2>/dev/null > /tmp/jwt_private.pem
    openssl rsa -in /tmp/jwt_private.pem -pubout 2>/dev/null > /tmp/jwt_public.pem
    umask 022
fi

# -----------------------------------------------------------------------------
# Export environment variables
# -----------------------------------------------------------------------------
export PORT=3001
export HOST=0.0.0.0
export BASE_URL=http://localhost:3001
export ENVIRONMENT=development
export DB_HOST=localhost
export DB_PORT=${HOST_POSTGRES_PORT}
export DB_NAME=${POSTGRES_DB}
export DB_USER=${POSTGRES_USER}
export DB_PASSWORD=${POSTGRES_PASSWORD}
export REDIS_HOST=localhost
export REDIS_PORT=${HOST_REDIS_PORT}
API_KEY_HASH_SECRET="$(resolve_secret API_KEY_HASH_SECRET secrets/api_key_hash_secret.txt 32)"
export API_KEY_HASH_SECRET
WEBHOOK_SIGNING_SECRET="$(resolve_secret WEBHOOK_SIGNING_SECRET secrets/webhook_signing_secret.txt 32)"
export WEBHOOK_SIGNING_SECRET
export AWS_REGION=us-east-1
JWT_PRIVATE_KEY_PEM="$(cat /tmp/jwt_private.pem)"
export JWT_PRIVATE_KEY_PEM
JWT_PUBLIC_KEY_PEM="$(cat /tmp/jwt_public.pem)"
export JWT_PUBLIC_KEY_PEM
export UI_MARKETING_HOSTS="${UI_MARKETING_HOSTS:-apexmail.ee,www.apexmail.ee,marketing.localhost}"

# -----------------------------------------------------------------------------
# Build API if needed
# -----------------------------------------------------------------------------
if needs_rebuild services/mail-server/target/release/api-server \
    services/mail-server/Cargo.toml \
    services/mail-server/Cargo.lock \
    services/mail-server/crates \
    apps/marketing-zola/public; then
    log "Building Rust API server..."
    cd services/mail-server
    cargo build --package api-server --release
    cd ../..
fi

# -----------------------------------------------------------------------------
# Start API server in background
# -----------------------------------------------------------------------------
log "Starting API server on port 3001..."
pkill -f "api-server" 2>/dev/null || true
nohup services/mail-server/target/release/api-server > /tmp/api-server.log 2>&1 &
sleep 2

# Check API is running
if curl -sf http://localhost:3001/health/live >/dev/null 2>&1; then
    log "API server running at http://localhost:3001"
else
    error "Failed to start API server. Check /tmp/api-server.log"
fi

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
echo ""
log "Development environment ready!"
echo ""
echo "  API Server:     http://localhost:3001/health/live"
echo "  Web Surface:    http://127.0.0.1:3001 (Rust SSR via api-server host map)"
echo "  Control Plane:  http://localhost:3001 (Rust SSR via api-server host map)"
echo "  Marketing:      http://marketing.localhost:3001 (exported marketing routes via api-server host map)"
echo ""
