#!/usr/bin/env bash
# =============================================================================
# Local Development Startup Script
# =============================================================================
# Starts all required services for local ApexMail development:
# - Docker containers (PostgreSQL + Redis)
# - Rust API server (port 3001)
# - Web console (port 3010)
# - Control Plane (port 3020)
# - Marketing site (port 1111)
# =============================================================================

set -e
cd "$(dirname "$0")/.."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[dev-start]${NC} $1"; }
warn() { echo -e "${YELLOW}[dev-start]${NC} $1"; }
error() { echo -e "${RED}[dev-start]${NC} $1"; exit 1; }

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

# Wait for redis
log "Waiting for Redis..."
until docker exec apexmail-redis redis-cli -a devredis123 ping >/dev/null 2>&1; do
    sleep 1
done
log "Redis ready"

# -----------------------------------------------------------------------------
# Generate JWT keys if needed
# -----------------------------------------------------------------------------
if [[ ! -f /tmp/jwt_private.pem ]]; then
    log "Generating development JWT keys..."
    openssl genrsa 2048 2>/dev/null > /tmp/jwt_private.pem
    openssl rsa -in /tmp/jwt_private.pem -pubout 2>/dev/null > /tmp/jwt_public.pem
fi

# -----------------------------------------------------------------------------
# Export environment variables
# -----------------------------------------------------------------------------
export PORT=3001
export HOST=0.0.0.0
export BASE_URL=http://localhost:3001
export ENVIRONMENT=development
export DB_HOST=localhost
export DB_PORT=5432
export DB_NAME=apexmail
export DB_USER=apexmail
export DB_PASSWORD=devpass123
export REDIS_HOST=localhost
export REDIS_PORT=6379
export REDIS_PASSWORD=devredis123
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
echo "  Web Console:    cd apps/web && pnpm dev (port 3010)"
echo "  Control Plane:  cd apps/control-plane && pnpm dev (port 3020)"
echo "  Marketing:      cd apps/marketing-zola && zola serve (port 1111)"
echo ""
echo "  Test user:      aaron / &&Pw20354491"
echo ""
