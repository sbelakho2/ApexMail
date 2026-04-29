#!/usr/bin/env bash
# =============================================================================
# Local Development Startup Script
# =============================================================================
# Starts all required services for local ApexMail development:
# - Docker containers (PostgreSQL + Redis)
# - Rust API server (port 3001)
# - Rust web surface via 127.0.0.1 host mapping
# - Rust control-plane surface via localhost host mapping
# - Marketing routes served by the Rust web surface (port 3001)
# =============================================================================

set -eu
cd "$(dirname "$0")/.."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[dev-start]${NC} $1"; }
warn() { echo -e "${YELLOW}[dev-start]${NC} $1"; }
error() { echo -e "${RED}[dev-start]${NC} $1"; exit 1; }

load_or_seed_secret() {
    local path="$1"
    local default_value="$2"

    if [[ -s "$path" ]]; then
        tr -d '\r\n' < "$path"
        return
    fi

    printf '%s' "$default_value" > "$path"
    chmod 600 "$path"
    printf '%s' "$default_value"
}

# -----------------------------------------------------------------------------
# Export local defaults required during compose interpolation
# -----------------------------------------------------------------------------
export POSTGRES_USER=apexmail
mkdir -p secrets

export POSTGRES_PASSWORD="$(load_or_seed_secret secrets/postgres_password.txt dev-postgres-password-minimum-32)"
export POSTGRES_DB=apexmail
export REDIS_PASSWORD="$(load_or_seed_secret secrets/redis_password.txt dev-redis-password-minimum-32-chars)"
export TRACKING_SECRET_KEY="dev-tracking-secret-key-minimum-32"
export CLICKHOUSE_PASSWORD="$(load_or_seed_secret secrets/clickhouse_password.txt dev-clickhouse-password-minimum-32)"
export INTERNAL_SERVICE_TOKEN="dev-internal-service-token-minimum-32"
export JWT_SECRET="dev-jwt-secret-minimum-32-chars"
export GRAFANA_USER=admin
export GRAFANA_PASSWORD=adminadmin

chmod 600 secrets/postgres_password.txt secrets/redis_password.txt secrets/clickhouse_password.txt

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
export API_KEY_HASH_SECRET="dev-api-key-secret-minimum-32-chars"
export WEBHOOK_SIGNING_SECRET="dev-webhook-signing-secret-minimum-32"
export AWS_REGION=us-east-1
export JWT_PRIVATE_KEY_PEM="$(cat /tmp/jwt_private.pem)"
export JWT_PUBLIC_KEY_PEM="$(cat /tmp/jwt_public.pem)"

# -----------------------------------------------------------------------------
# Build API if needed
# -----------------------------------------------------------------------------
if [[ ! -f services/mail-server/target/release/api-server ]]; then
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
echo "  Marketing:      http://127.0.0.1:3001 (exported marketing routes via api-server)"
echo ""
echo "  Test user:      aaron / &&Pw20354491"
echo ""
