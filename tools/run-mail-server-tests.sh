#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

log() {
  echo "[mail-server-tests] $*"
}

error() {
  echo "[mail-server-tests] ERROR: $*" >&2
  exit 1
}

require_command() {
  local command_name="$1"
  command -v "$command_name" >/dev/null 2>&1 || error "Missing required command: $command_name"
}

db_ready() {
  local database_url="$1"
  PGCONNECT_TIMEOUT=2 psql "$database_url" -tAc 'SELECT 1' >/dev/null 2>&1
}

select_database_url() {
  local host="${DB_HOST:-${POSTGRES_HOST:-127.0.0.1}}"
  local port="${DB_PORT:-${POSTGRES_PORT:-5432}}"
  local name="${DB_NAME:-${POSTGRES_DB:-apexmail}}"
  local user="${DB_USER:-${POSTGRES_USER:-apexmail}}"
  local password="${DB_PASSWORD:-${POSTGRES_PASSWORD:-}}"
  local candidate=""
  local -a candidates=()

  # Build candidate from explicit env vars (preferred — no hardcoded secrets)
  if [[ -n "$password" ]]; then
    candidates+=("postgres://${user}:${password}@${host}:${port}/${name}")
  fi

  # Fallback: try local unix socket with peer/auth or pgpass-based connection
  # (no password on command line — relies on pg_hba.conf trust/peer or ~/.pgpass)
  candidates+=(
    "postgres://${user}@127.0.0.1:5432/${name}?sslmode=disable"
    "postgres://${user}@127.0.0.1:55432/${name}?sslmode=disable"
    "postgres://${user}@127.0.0.1:5435/${name}?sslmode=disable"
  )

  for candidate in "${candidates[@]}"; do
    if db_ready "$candidate"; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  return 1
}

if [[ $# -eq 0 ]]; then
  error "Usage: $0 <cargo args...>"
fi

require_command cargo
require_command psql

if [[ -z "${DATABASE_URL:-}" ]]; then
  DATABASE_URL="$(select_database_url)" || error "DATABASE_URL is not set and no reachable local Postgres default was detected"
  log "Auto-selected reachable local DATABASE_URL"
fi

TEST_DATABASE_URL="${TEST_DATABASE_URL:-$DATABASE_URL}"

if ! db_ready "$DATABASE_URL"; then
  error "DATABASE_URL is not reachable: $DATABASE_URL"
fi

if ! db_ready "$TEST_DATABASE_URL"; then
  error "TEST_DATABASE_URL is not reachable: $TEST_DATABASE_URL"
fi

export DATABASE_URL
export TEST_DATABASE_URL

cd "$PROJECT_ROOT"
log "Running cargo $*"
cargo "$@"