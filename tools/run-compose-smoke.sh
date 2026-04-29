#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BASE_COMPOSE="$PROJECT_ROOT/docker-compose.yml"
PROD_COMPOSE="$PROJECT_ROOT/docker-compose.prod.yml"
SMOKE_DIR="${SMOKE_DIR:-$PROJECT_ROOT/target/apexmail-smoke}"
SMOKE_SSL_DIR="$SMOKE_DIR/ssl"
SMOKE_ALERT_NAME="smoke_alertmanager_delivery"

log() {
  echo "[compose-smoke] $*"
}

error() {
  echo "[compose-smoke] ERROR: $*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage: tools/run-compose-smoke.sh <command>

Commands:
  up       Bring up monitoring plus the prod smoke subset.
  verify   Verify monitoring, nginx, API, and tracking endpoints.
  alert    Inject a synthetic alert into Alertmanager and verify delivery to Observability.
  down     Stop and remove the smoke-test containers and delete target/apexmail-smoke.
  full     Run up, verify, and alert in sequence.

Environment overrides:
  POSTGRES_PASSWORD
  REDIS_PASSWORD
  CLICKHOUSE_PASSWORD
  JWT_SECRET
  TRACKING_SECRET_KEY
  INTERNAL_SERVICE_TOKEN
  TLS_CERT_DIR
  SMOKE_DIR

This script intentionally keeps TLS material under the repo-local target/ tree so
Docker Desktop on macOS can mount it reliably.
EOF
}

require_command() {
  local command_name="$1"
  command -v "$command_name" >/dev/null 2>&1 || error "Missing required command: $command_name"
}

compose() {
  (
    cd "$PROJECT_ROOT"
    docker compose -f "$BASE_COMPOSE" -f "$PROD_COMPOSE" --profile monitoring "$@"
  )
}

existing_postgres_password() {
  local secret_file="$PROJECT_ROOT/secrets/postgres_password.txt"
  if [[ -f "$secret_file" ]]; then
    tr -d '\r\n' < "$secret_file"
  fi
}

existing_internal_service_token() {
  docker inspect apexmail-observability --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null \
    | sed -n 's/^INTERNAL_SERVICE_TOKEN=//p' \
    | head -n 1
}

resolved_postgres_password() {
  if [[ -n "${POSTGRES_PASSWORD:-}" ]]; then
    printf '%s\n' "$POSTGRES_PASSWORD"
    return 0
  fi

  local detected_password=""
  detected_password="$(existing_postgres_password || true)"
  if [[ -n "$detected_password" ]]; then
    printf '%s\n' "$detected_password"
    return 0
  fi

  printf '%s\n' 'dev-postgres-password-minimum-32'
}

ensure_smoke_assets() {
  mkdir -p "$SMOKE_SSL_DIR"

  if [[ ! -f "$SMOKE_DIR/jwt-private.pem" ]]; then
    openssl genrsa -out "$SMOKE_DIR/jwt-private.pem" 2048 >/dev/null 2>&1
  fi

  if [[ ! -f "$SMOKE_DIR/jwt-public.pem" ]]; then
    openssl rsa -in "$SMOKE_DIR/jwt-private.pem" -pubout -out "$SMOKE_DIR/jwt-public.pem" >/dev/null 2>&1
  fi

  if [[ ! -f "$SMOKE_SSL_DIR/fullchain.pem" || ! -f "$SMOKE_SSL_DIR/privkey.pem" ]]; then
    openssl req -x509 -nodes -newkey rsa:2048 \
      -keyout "$SMOKE_SSL_DIR/privkey.pem" \
      -out "$SMOKE_SSL_DIR/fullchain.pem" \
      -days 1 \
      -subj '/CN=localhost' >/dev/null 2>&1
  fi

  chmod 0644 "$SMOKE_SSL_DIR/fullchain.pem" "$SMOKE_SSL_DIR/privkey.pem"
}

export_smoke_env() {
  ensure_smoke_assets

  local detected_internal_service_token=""
  detected_internal_service_token="$(existing_internal_service_token || true)"

  export POSTGRES_PASSWORD="$(resolved_postgres_password)"
  mkdir -p "$PROJECT_ROOT/secrets"
  printf '%s' "$POSTGRES_PASSWORD" > "$PROJECT_ROOT/secrets/postgres_password.txt"
  chmod 600 "$PROJECT_ROOT/secrets/postgres_password.txt"
  export REDIS_PASSWORD="${REDIS_PASSWORD:-$(<"$PROJECT_ROOT/secrets/redis_password.txt")}"
  export CLICKHOUSE_PASSWORD="${CLICKHOUSE_PASSWORD:-clickhouse-password-smoke-1234567890}"
  export JWT_SECRET="${JWT_SECRET:-enterprise-jwt-secret-smoke-1234567890123456}"
  export GRAFANA_USER="${GRAFANA_USER:-smoke-admin}"
  export GRAFANA_PASSWORD="${GRAFANA_PASSWORD:-smoke-grafana-password-123456}"
  export TRACKING_SECRET_KEY="${TRACKING_SECRET_KEY:-tracking-secret-key-smoke-12345678901234567890}"
  export BASE_URL="${BASE_URL:-https://api.apexmail.ee}"
  export OAUTH_REDIRECT_BASE_URL="${OAUTH_REDIRECT_BASE_URL:-https://app.apexmail.ee/auth/callback}"
  export API_KEY_HASH_SECRET="${API_KEY_HASH_SECRET:-api-key-hash-secret-smoke-123456789012345}"
  export WEBHOOK_SIGNING_SECRET="${WEBHOOK_SIGNING_SECRET:-webhook-signing-secret-smoke-1234567890}"
  export SESSION_SECRET="${SESSION_SECRET:-session-secret-smoke-12345678901234567890}"
  export IMPERSONATION_SECRET="${IMPERSONATION_SECRET:-impersonation-secret-smoke-1234567890123}"
  export CSRF_SECRET="${CSRF_SECRET:-csrf-secret-smoke-123456789012345678901234}"
  export INTERNAL_SERVICE_TOKEN="${detected_internal_service_token:-${INTERNAL_SERVICE_TOKEN:-smoke-internal-service-token-32chars}}"
  export ENTERPRISE_BASE_URL="${ENTERPRISE_BASE_URL:-https://api.apexmail.ee}"
  export TRACKING_BASE_URL="${TRACKING_BASE_URL:-https://track.apexmail.ee}"
  export BILLING_COMPANY_IBAN="${BILLING_COMPANY_IBAN:-EE381010220123456789}"
  export BILLING_COMPANY_PHONE="${BILLING_COMPANY_PHONE:-+3726000000}"
  export TLS_CERT_DIR="${TLS_CERT_DIR:-$SMOKE_SSL_DIR}"
  export JWT_PRIVATE_KEY_PEM="$(<"$SMOKE_DIR/jwt-private.pem")"
  export JWT_PUBLIC_KEY_PEM="$(<"$SMOKE_DIR/jwt-public.pem")"
  export DOCKER_BUILDKIT="${DOCKER_BUILDKIT:-0}"
  export COMPOSE_DOCKER_CLI_BUILD="${COMPOSE_DOCKER_CLI_BUILD:-0}"
}

wait_for_container_health() {
  local container_name="$1"
  local timeout_secs="$2"
  local deadline=$((SECONDS + timeout_secs))
  local status=""

  while (( SECONDS < deadline )); do
    status="$(docker inspect "$container_name" --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' 2>/dev/null || true)"
    if [[ "$status" == "healthy" ]]; then
      log "$container_name is healthy"
      return 0
    fi
    if [[ "$status" == "exited" || "$status" == "dead" ]]; then
      docker logs "$container_name" --tail 80 >&2 || true
      error "$container_name failed before becoming healthy"
    fi
    sleep 2
  done

  docker inspect "$container_name" --format '{{json .State}}' >&2 || true
  docker logs "$container_name" --tail 80 >&2 || true
  error "$container_name did not become healthy within ${timeout_secs}s"
}

wait_for_curl_contains() {
  local label="$1"
  local expected_fragment="$2"
  local timeout_secs="$3"
  shift 3

  local deadline=$((SECONDS + timeout_secs))
  local output=""

  while (( SECONDS < deadline )); do
    if output="$(curl "$@" 2>/dev/null)"; then
      if [[ "$output" == *"$expected_fragment"* ]]; then
        log "$label OK"
        printf '%s\n' "$output"
        return 0
      fi
    fi
    sleep 2
  done

  error "$label did not return the expected content: $expected_fragment"
}

observability_alerts_raw() {
  docker exec -e INTERNAL_SERVICE_TOKEN="$INTERNAL_SERVICE_TOKEN" apexmail-observability sh -lc '
    printf "GET /alerts HTTP/1.1\r\nHost: localhost\r\nx-api-key: %s\r\nConnection: close\r\n\r\n" "$INTERNAL_SERVICE_TOKEN" | nc 127.0.0.1 4400
  '
}

print_status_summary() {
  docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' \
    | grep 'apexmail-nginx-1\|apexmail-api-1\|apexmail-api-2\|apexmail-enterprise-1\|apexmail-enterprise-2\|apexmail-tracking-1\|apexmail-tracking-2\|apexmail-clickhouse\|apexmail-observability\|apexmail-prometheus\|apexmail-alertmanager\|NAME' || true
}

bring_up_stack() {
  export_smoke_env
  compose config >/dev/null

  log "Starting monitoring slice"
  compose up -d --force-recreate observability prometheus alertmanager

  log "Starting prod smoke subset"
  compose up -d --build --force-recreate nginx api enterprise tracking postgres redis clickhouse
}

verify_stack() {
  export_smoke_env

  wait_for_container_health apexmail-observability 90
  wait_for_curl_contains "Prometheus readiness" 'Ready' 60 -fsS http://127.0.0.1:9090/-/ready >/dev/null
  wait_for_curl_contains "Alertmanager readiness" 'OK' 60 -fsS http://127.0.0.1:9093/-/ready >/dev/null

  wait_for_container_health apexmail-clickhouse 120
  wait_for_container_health apexmail-api-1 120
  wait_for_container_health apexmail-api-2 120
  wait_for_container_health apexmail-enterprise-1 120
  wait_for_container_health apexmail-enterprise-2 120
  wait_for_container_health apexmail-tracking-1 120
  wait_for_container_health apexmail-tracking-2 120
  wait_for_container_health apexmail-nginx-1 120

  wait_for_curl_contains "nginx health" 'OK' 30 -fsS http://127.0.0.1/nginx-health >/dev/null
  wait_for_curl_contains "API TLS health" '"status":"ok"' 30 -kfsS --resolve api.apexmail.ee:443:127.0.0.1 https://api.apexmail.ee/health >/dev/null
  wait_for_curl_contains "Tracking TLS health" '"status":"healthy"' 30 -kfsS --resolve track.apexmail.ee:443:127.0.0.1 https://track.apexmail.ee/health >/dev/null

  print_status_summary
}

verify_alert_delivery() {
  export_smoke_env

  local starts_at
  local payload
  local alerts_response
  local deadline

  starts_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  payload=$(cat <<EOF
[
  {
    "labels": {
      "alertname": "$SMOKE_ALERT_NAME",
      "severity": "critical",
      "source": "compose_smoke"
    },
    "annotations": {
      "summary": "Compose smoke Alertmanager delivery",
      "description": "Synthetic alert that verifies Alertmanager webhook delivery into Observability"
    },
    "startsAt": "$starts_at",
    "endsAt": "2099-01-01T00:00:00Z",
    "generatorURL": "https://apexmail.ee/smoke"
  }
]
EOF
)

  log "Posting synthetic alert to Alertmanager"
  curl -fsS -X POST http://127.0.0.1:9093/api/v2/alerts \
    -H 'Content-Type: application/json' \
    --data "$payload" >/dev/null

  deadline=$((SECONDS + 90))
  while (( SECONDS < deadline )); do
    alerts_response="$(observability_alerts_raw || true)"
    if [[ "$alerts_response" == *"\"rule_name\":\"$SMOKE_ALERT_NAME\""* ]]; then
      log "Observed synthetic alert in Observability"
      printf '%s\n' "$alerts_response"
      return 0
    fi
    sleep 5
  done

  error "Synthetic alert did not reach Observability within 90 seconds"
}

tear_down_stack() {
  export_smoke_env

  local -a services=(
    nginx
    api
    enterprise
    tracking
    postgres
    redis
    clickhouse
    observability
    prometheus
    alertmanager
  )

  log "Stopping smoke-test services"
  compose stop "${services[@]}" >/dev/null 2>&1 || true
  compose rm -fs "${services[@]}" >/dev/null 2>&1 || true

  rm -rf "$SMOKE_DIR"
  log "Removed smoke assets from $SMOKE_DIR"
}

main() {
  local command="${1:-full}"

  require_command docker
  require_command openssl
  require_command curl

  case "$command" in
    up)
      bring_up_stack
      ;;
    verify)
      verify_stack
      ;;
    alert)
      verify_alert_delivery
      ;;
    down)
      tear_down_stack
      ;;
    full)
      bring_up_stack
      verify_stack
      verify_alert_delivery
      ;;
    -h|--help|help)
      usage
      ;;
    *)
      usage
      error "Unknown command: $command"
      ;;
  esac
}

main "$@"