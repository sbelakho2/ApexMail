#!/usr/bin/env bash
# =============================================================================
# ApexMail Load Test Environment Setup
# =============================================================================
# Provisions the full load test environment: PostgreSQL, Redis, Mailpit,
# and runs schema migration + seed data.
#
# Usage:
#   ./deploy/load-test-infra/setup.sh               # Start environment
#   ./deploy/load-test-infra/setup.sh --reset        # Reset + start fresh
#   ./deploy/load-test-infra/setup.sh --only-db      # Database only
#   ./deploy/load-test-infra/setup.sh --status       # Check status
#   ./deploy/load-test-infra/setup.sh down           # Tear down
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"

# ── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

log_info()  { echo -e "${CYAN}[INFO]${NC}  $1"; }
log_ok()    { echo -e "${GREEN}[OK]${NC}    $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# ── Helpers ─────────────────────────────────────────────────────────────────
check_docker() {
  if ! command -v docker &>/dev/null; then
    log_error "Docker is not installed. Please install Docker Desktop or Docker Engine."
    exit 1
  fi
  if ! docker compose version &>/dev/null; then
    log_error "Docker Compose v2 is required. Please upgrade Docker."
    exit 1
  fi
}

wait_for_services() {
  log_info "Waiting for PostgreSQL to be ready..."
  until docker compose -f "$COMPOSE_FILE" exec -T postgres pg_isready -U apexmail -d apexmail_loadtest &>/dev/null; do
    sleep 2
  done
  log_ok "PostgreSQL is ready"

  log_info "Waiting for Redis to be ready..."
  until docker compose -f "$COMPOSE_FILE" exec -T redis redis-cli ping | grep -q PONG; do
    sleep 1
  done
  log_ok "Redis is ready"

  log_info "Waiting for Mailpit to be ready..."
  until curl -sf http://localhost:8025/api/v1/info &>/dev/null; do
    sleep 2
  done
  log_ok "Mailpit is ready"
}

run_migrations() {
  log_info "Running database migrations..."
  docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U apexmail -d apexmail_loadtest < "$SCRIPT_DIR/init-db.sql"
  log_ok "Database migrations complete"
}

# ── Commands ────────────────────────────────────────────────────────────────
case "${1:-up}" in
  up)
    check_docker
    log_info "Starting load test environment..."
    docker compose -f "$COMPOSE_FILE" up -d postgres redis mailpit
    wait_for_services
    run_migrations
    log_ok "Load test environment is ready!"
    echo ""
    echo "  ┌──────────────────────────────────────────────────────────┐"
    echo "  │  Service        │  Address                              │"
    echo "  ├──────────────────────────────────────────────────────────┤"
    echo "  │  PostgreSQL     │  localhost:5432                       │"
    echo "  │                 │  apexmail / apexmail / apexmail       │"
    echo "  │  Redis          │  localhost:6379                       │"
    echo "  │  Mailpit SMTP   │  localhost:1025                       │"
    echo "  │  Mailpit Web UI │  http://localhost:8025                │"
    echo "  └──────────────────────────────────────────────────────────┘"
    echo ""
    echo "  Run load tests:  cargo test -p load-tests --release"
    echo "  Run k6 tests:    cd services/mail-server/crates/load-tests/tests/k6 && k6 run api-load-test.js"
    echo "  Tear down:       $0 down"
    ;;

  down)
    check_docker
    log_info "Stopping load test environment..."
    docker compose -f "$COMPOSE_FILE" down -v
    log_ok "Load test environment stopped"
    ;;

  --reset)
    check_docker
    log_info "Resetting load test environment..."
    docker compose -f "$COMPOSE_FILE" down -v
    docker compose -f "$COMPOSE_FILE" up -d postgres redis mailpit
    wait_for_services
    run_migrations
    log_ok "Load test environment reset complete"
    ;;

  --only-db)
    check_docker
    log_info "Starting database services only..."
    docker compose -f "$COMPOSE_FILE" up -d postgres redis
    wait_for_services
    run_migrations
    log_ok "Database services ready"
    ;;

  --status)
    check_docker
    echo "─── Load Test Environment Status ───────────────────────────────"
    docker compose -f "$COMPOSE_FILE" ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}"
    ;;

  --help)
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  up          Start environment (default)"
    echo "  down        Stop and remove environment"
    echo "  --reset     Reset and restart fresh"
    echo "  --only-db   Start only PostgreSQL and Redis"
    echo "  --status    Show service status"
    echo "  --help      Show this help"
    ;;

  *)
    log_error "Unknown command: $1"
    echo "Usage: $0 [up|down|--reset|--only-db|--status|--help]"
    exit 1
    ;;
esac
