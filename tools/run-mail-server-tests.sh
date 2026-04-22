#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DEFAULT_DATABASE_URL="postgres://apexmail:apexmail@127.0.0.1:5435/apexmail"

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

if [[ $# -eq 0 ]]; then
  error "Usage: $0 <cargo args...>"
fi

require_command cargo
require_command psql

DATABASE_URL="${DATABASE_URL:-$DEFAULT_DATABASE_URL}"
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