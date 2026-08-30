#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BASE_COMPOSE="$PROJECT_ROOT/docker-compose.yml"
PROD_COMPOSE="$PROJECT_ROOT/docker-compose.prod.yml"
SMOKE_DIR="${SMOKE_DIR:-$PROJECT_ROOT/target/apexmail-smoke}"
SMOKE_SSL_DIR="$SMOKE_DIR/ssl"
SMOKE_ALERT_NAME="smoke_alertmanager_delivery"

# Audit P — rm -rf guard: SMOKE_DIR must be an absolute path nested under
# /tmp or the repository root (never "/", never an arbitrary absolute path
# that a stray env var could point at).
validate_smoke_dir() {
  if [[ -z "$SMOKE_DIR" || "$SMOKE_DIR" == "/" ]]; then
    error "SMOKE_DIR must be a non-root directory (got '${SMOKE_DIR}')"
  fi
  case "$SMOKE_DIR" in
    "$PROJECT_ROOT"/*|/tmp/*)
      ;;
    *)
      error "SMOKE_DIR must be absolute and located under /tmp or ${PROJECT_ROOT} (got '${SMOKE_DIR}')"
      ;;
  esac
}

log() {
  echo "[compose-smoke] $*"
}

error() {
  echo "[compose-smoke] ERROR: $*" >&2
  exit 1
}

generate_secret() {
  local bytes="${1:-32}"
  openssl rand -hex "$bytes" 2>/dev/null || error "Failed to generate secret material"
}

load_or_seed_secret() {
  local secret_file="$1"
  local bytes="${2:-32}"

  mkdir -p "$(dirname "$secret_file")"
  if [[ -s "$secret_file" ]]; then
    tr -d '\r\n' < "$secret_file"
    return 0
  fi

  local secret_value
  secret_value="$(generate_secret "$bytes")"
  printf '%s' "$secret_value" > "$secret_file"
  chmod 600 "$secret_file"
  printf '%s' "$secret_value"
}

resolve_env_or_seed_secret() {
  local env_name="$1"
  local secret_file="$2"
  local bytes="${3:-32}"
  local current_value="${!env_name:-}"

  if [[ -n "$current_value" ]]; then
    printf '%s' "$current_value"
    return 0
  fi

  load_or_seed_secret "$secret_file" "$bytes"
}

resolve_env_or_generate_secret() {
  local env_name="$1"
  local bytes="${2:-32}"
  local current_value="${!env_name:-}"

  if [[ -n "$current_value" ]]; then
    printf '%s' "$current_value"
    return 0
  fi

  generate_secret "$bytes"
}

usage() {
  cat <<'EOF'
Usage: tools/run-compose-smoke.sh <command>

Commands:
  up       Bring up monitoring plus the prod smoke subset (api-server,
           enterprise, tracking, sales-autopilot, billing-service, nginx,
           postgres, redis, clickhouse).
  verify   Verify monitoring, nginx, API, tracking, and sales endpoints.
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

Container names are discovered dynamically via `docker compose ps -q <svc>`
(single-replica reality); nothing here depends on hardcoded container names.

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

# Resolve the (single) container of a compose service at runtime. Compose
# naming has drifted over time (apexmail-api-1 vs apexmail-api-server-1,
# explicit container_name for the datastores) — asking compose itself is the
# only name-proof way.
service_container() {
  local svc="$1"
  compose ps -q "$svc" 2>/dev/null | head -1
}

existing_internal_service_token() {
  local cid
  cid="$(service_container observability || true)"
  [[ -n "$cid" ]] || return 0
  docker inspect "$cid" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null \
    | sed -n 's/^INTERNAL_SERVICE_TOKEN=//p' \
    | head -n 1
}

resolved_postgres_password() {
  resolve_env_or_seed_secret POSTGRES_PASSWORD "$PROJECT_ROOT/secrets/postgres_password.txt" 32
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

  # nginx.conf references ca-chain.pem for OCSP stapling
  # (ssl_trusted_certificate) — a self-signed chain equals the cert itself.
  if [[ ! -f "$SMOKE_SSL_DIR/ca-chain.pem" ]]; then
    cp "$SMOKE_SSL_DIR/fullchain.pem" "$SMOKE_SSL_DIR/ca-chain.pem"
  fi

  # Audit P deviation: the throwaway privkey stays 0644 ON PURPOSE. The prod
  # overlay runs nginx as uid 101, and Docker Desktop bind mounts do not map
  # host ownership into the container (verified: uid 101 gets EACCES on a
  # 0600 host file), so 0600 would prevent the smoke nginx from loading its
  # TLS key. Production perms are enforced by deploy-hetzner.yml (privkey
  # 0640 root-owned-by-101); this file is an ephemeral 1-day localhost cert
  # inside a throwaway smoke directory.
  chmod 0644 "$SMOKE_SSL_DIR/privkey.pem"
  chmod 0644 "$SMOKE_SSL_DIR/fullchain.pem" "$SMOKE_SSL_DIR/ca-chain.pem"
}

export_smoke_env() {
  ensure_smoke_assets

  local detected_internal_service_token=""
  detected_internal_service_token="$(existing_internal_service_token || true)"

  export POSTGRES_PASSWORD="$(resolved_postgres_password)"
  export REDIS_PASSWORD="$(resolve_env_or_seed_secret REDIS_PASSWORD "$PROJECT_ROOT/secrets/redis_password.txt" 32)"
  export CLICKHOUSE_PASSWORD="$(resolve_env_or_seed_secret CLICKHOUSE_PASSWORD "$PROJECT_ROOT/secrets/clickhouse_password.txt" 32)"
  export JWT_SECRET="$(resolve_env_or_generate_secret JWT_SECRET 32)"
  # Grafana admin credentials — the names docker-compose.yml actually reads
  # (GF_SECURITY_ADMIN_USER directly, GRAFANA_ADMIN_PASSWORD interpolated into
  # GF_SECURITY_ADMIN_PASSWORD). The old GRAFANA_USER/GRAFANA_PASSWORD exports
  # were read by nothing.
  export GF_SECURITY_ADMIN_USER="${GF_SECURITY_ADMIN_USER:-smoke-admin}"
  export GRAFANA_ADMIN_PASSWORD="$(resolve_env_or_generate_secret GRAFANA_ADMIN_PASSWORD 24)"
  export TRACKING_SECRET_KEY="$(resolve_env_or_generate_secret TRACKING_SECRET_KEY 32)"
  export BASE_URL="${BASE_URL:-https://api.apexmail.ee}"
  export OAUTH_REDIRECT_BASE_URL="${OAUTH_REDIRECT_BASE_URL:-https://app.apexmail.ee/auth/callback}"
  export API_KEY_HASH_SECRET="$(resolve_env_or_generate_secret API_KEY_HASH_SECRET 32)"
  export WEBHOOK_SIGNING_SECRET="$(resolve_env_or_generate_secret WEBHOOK_SIGNING_SECRET 32)"
  export SESSION_SECRET="$(resolve_env_or_generate_secret SESSION_SECRET 32)"
  export IMPERSONATION_SECRET="$(resolve_env_or_generate_secret IMPERSONATION_SECRET 32)"
  export CSRF_SECRET="$(resolve_env_or_generate_secret CSRF_SECRET 32)"
  if [[ -n "$detected_internal_service_token" ]]; then
    export INTERNAL_SERVICE_TOKEN="$detected_internal_service_token"
  else
    export INTERNAL_SERVICE_TOKEN="$(resolve_env_or_generate_secret INTERNAL_SERVICE_TOKEN 32)"
  fi
  export ENTERPRISE_BASE_URL="${ENTERPRISE_BASE_URL:-https://api.apexmail.ee}"
  export TRACKING_BASE_URL="${TRACKING_BASE_URL:-https://track.apexmail.ee}"
  export BILLING_COMPANY_IBAN="${BILLING_COMPANY_IBAN:-EE381010220123456789}"
  export BILLING_COMPANY_PHONE="${BILLING_COMPANY_PHONE:-+3726000000}"
  export TLS_CERT_DIR="${TLS_CERT_DIR:-$SMOKE_SSL_DIR}"
  export JWT_PRIVATE_KEY_PEM="$(<"$SMOKE_DIR/jwt-private.pem")"
  export JWT_PUBLIC_KEY_PEM="$(<"$SMOKE_DIR/jwt-public.pem")"
  # Audit B — the production overlay requires APEXMAIL_API_KEY (:? guard).
  export APEXMAIL_API_KEY="$(resolve_env_or_generate_secret APEXMAIL_API_KEY 32)"
  export KIWI_SECRET_KEY="$(resolve_env_or_generate_secret KIWI_SECRET_KEY 32)"
  export DKIM_PRIVATE_KEY_ENCRYPTION_KEY="$(resolve_env_or_seed_secret DKIM_PRIVATE_KEY_ENCRYPTION_KEY "$PROJECT_ROOT/secrets/dkim_private_key_encryption_key.txt" 32)"
  # Required by ${VAR:?} guards in docker-compose.prod.yml for the services in
  # the smoke set (api-server placement engine, sales-autopilot dispatcher).
  export PLACEMENT_ENCRYPTION_SECRET="$(resolve_env_or_generate_secret PLACEMENT_ENCRYPTION_SECRET 32)"
  export SALES_CAMPAIGN_FROM_EMAIL="${SALES_CAMPAIGN_FROM_EMAIL:-smoke@apexmail.ee}"
  export SALES_UNSUBSCRIBE_SECRET="$(resolve_env_or_generate_secret SALES_UNSUBSCRIBE_SECRET 32)"
  export DOCKER_BUILDKIT="${DOCKER_BUILDKIT:-0}"
  export COMPOSE_DOCKER_CLI_BUILD="${COMPOSE_DOCKER_CLI_BUILD:-0}"
  seed_prod_secret_files
}

# Audit B/G/I/E — the production overlay declares every secret with a
# ${PROD_*_FILE:?} guard, so `docker compose config` (and `up`) requires an
# env var AND an existing file for each. Seed local throwaway files and
# export the matching PROD_*_FILE variables so the smoke stack renders.
seed_prod_secret_files() {
  seed_prod_secret_file POSTGRES_PASSWORD        postgres_password.txt      "$(resolved_postgres_password)"
  seed_prod_secret_file REDIS_PASSWORD           redis_password.txt         "$REDIS_PASSWORD"
  # redis-exporter prod auth: the exporter only accepts a JSON MAP file
  # ({"redis://addr":"password"}); same password as redis_password.txt.
  seed_prod_secret_file REDIS_PASSWORD_MAP        redis_password_map.json     "{\"redis://redis:6379\":\"$REDIS_PASSWORD\"}"
  seed_prod_secret_file CLICKHOUSE_PASSWORD      clickhouse_password.txt    "$CLICKHOUSE_PASSWORD"
  seed_prod_secret_file CLICKHOUSE_ADMIN_PASSWORD clickhouse_admin_password.txt "$(resolve_env_or_generate_secret CLICKHOUSE_ADMIN_PASSWORD 32)"
  seed_prod_secret_file API_KEY_HASH_SECRET      api_key_hash_secret.txt    "$API_KEY_HASH_SECRET"
  seed_prod_secret_file WEBHOOK_SIGNING_SECRET   webhook_signing_secret.txt "$WEBHOOK_SIGNING_SECRET"
  seed_prod_secret_file TRACKING_SECRET_KEY      tracking_secret_key.txt    "$TRACKING_SECRET_KEY"
  seed_prod_secret_file INTERNAL_SERVICE_TOKEN   internal_service_token.txt "$INTERNAL_SERVICE_TOKEN"
  seed_prod_secret_file JWT_SECRET               jwt_secret.txt             "$JWT_SECRET"
  seed_prod_secret_file SESSION_SECRET           session_secret.txt         "$SESSION_SECRET"
  seed_prod_secret_file IMPERSONATION_SECRET     impersonation_secret.txt   "$IMPERSONATION_SECRET"
  seed_prod_secret_file CSRF_SECRET              csrf_secret.txt            "$CSRF_SECRET"
  seed_prod_secret_file DKIM_PRIVATE_KEY_ENCRYPTION_KEY dkim_private_key_encryption_key.txt "$DKIM_PRIVATE_KEY_ENCRYPTION_KEY"
  seed_prod_secret_file KIWI_SECRET_KEY          kiwi_secret_key.txt        "$KIWI_SECRET_KEY"
  seed_prod_secret_file STRIPE_SECRET_KEY        stripe_secret_key.txt      "$(resolve_env_or_generate_secret STRIPE_SECRET_KEY 32)"
  seed_prod_secret_file STRIPE_WEBHOOK_SECRET    stripe_webhook_secret.txt  "$(resolve_env_or_generate_secret STRIPE_WEBHOOK_SECRET 32)"
  seed_prod_secret_file AWS_ACCESS_KEY_ID        aws_access_key_id.txt      "${AWS_ACCESS_KEY_ID:-}"
  seed_prod_secret_file AWS_SECRET_ACCESS_KEY    aws_secret_access_key.txt  "${AWS_SECRET_ACCESS_KEY:-}"
  seed_prod_secret_file SMTP_USERNAME            smtp_username.txt          "${SMTP_USERNAME:-}"
  seed_prod_secret_file SMTP_PASSWORD            smtp_password.txt          "${SMTP_PASSWORD:-}"
  seed_prod_secret_file BACKUP_ENCRYPTION_KEY    backup_encryption_key.txt  "$(resolve_env_or_generate_secret BACKUP_ENCRYPTION_KEY 32)"
  # sales-autopilot unsubscribe HMAC key (prod secret sales_unsubscribe_secret).
  seed_prod_secret_file SALES_UNSUBSCRIBE_SECRET sales_unsubscribe_secret.txt "$SALES_UNSUBSCRIBE_SECRET"
  # JWT key material is PEM — point straight at the generated key files.
  export PROD_JWT_PRIVATE_KEY_FILE="$SMOKE_DIR/jwt-private.pem"
  export PROD_JWT_PUBLIC_KEY_FILE="$SMOKE_DIR/jwt-public.pem"
}

seed_prod_secret_file() {
  local value_name="$1"
  local file_name="$2"
  local value="$3"
  local target="$PROJECT_ROOT/secrets/$file_name"

  mkdir -p "$PROJECT_ROOT/secrets"
  if [[ ! -s "$target" ]]; then
    printf '%s' "$value" > "$target"
    chmod 600 "$target"
  fi
  export "PROD_${value_name}_FILE=$target"
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

# Wait for a compose SERVICE (container resolved dynamically) to be healthy.
wait_for_service_health() {
  local svc="$1"
  local timeout_secs="$2"
  local cid
  cid="$(service_container "$svc")"
  if [[ -z "$cid" ]]; then
    error "service '$svc' has no container — did the smoke 'up' run?"
  fi
  wait_for_container_health "$cid" "$timeout_secs"
}

observability_alerts_raw() {
  local cid
  cid="$(service_container observability)"
  docker exec -e INTERNAL_SERVICE_TOKEN="$INTERNAL_SERVICE_TOKEN" "$cid" sh -lc '
    printf "GET /alerts HTTP/1.1\r\nHost: localhost\r\nx-api-key: %s\r\nConnection: close\r\n\r\n" "$INTERNAL_SERVICE_TOKEN" | nc 127.0.0.1 4400
  '
}

print_status_summary() {
  compose ps --format 'table {{.Name}}\t{{.Status}}' 2>/dev/null || \
    docker ps --format 'table {{.Names}}\t{{.Status}}' | grep apexmail || true
}

bring_up_stack() {
  export_smoke_env
  compose config >/dev/null

  log "Starting monitoring slice"
  compose up -d --force-recreate observability prometheus alertmanager

  log "Starting prod smoke subset"
  # billing-service/pdf-renderer carry the dev/full-stack profiles in the
  # base compose file; naming them explicitly on the command line activates
  # them WITHOUT enabling those profiles (mailpit stays out of the smoke).
  # pdf-renderer: billing-service renders every invoice through it.
  # analytics-worker: events compaction/retention (no healthcheck — a
  # running state is its healthy state).
  compose up -d --build --force-recreate \
    nginx api-server enterprise tracking sales-autopilot billing-service \
    pdf-renderer analytics-worker \
    postgres redis clickhouse
}

verify_stack() {
  export_smoke_env

  wait_for_service_health observability 90
  wait_for_curl_contains "Prometheus readiness" 'Ready' 60 -fsS http://127.0.0.1:9090/-/ready >/dev/null
  wait_for_curl_contains "Alertmanager readiness" 'OK' 60 -fsS http://127.0.0.1:9093/-/ready >/dev/null

  wait_for_service_health clickhouse 120
  wait_for_service_health api-server 120
  wait_for_service_health enterprise 120
  wait_for_service_health tracking 120
  wait_for_service_health sales-autopilot 120
  wait_for_service_health billing-service 120
  wait_for_service_health pdf-renderer 120
  # analytics-worker has no healthcheck (cron loop): running == healthy.
  _aw_cid="$(service_container analytics-worker)"
  _aw_deadline=$((SECONDS + 90))
  while (( SECONDS < _aw_deadline )); do
    if [[ "$(docker inspect "$_aw_cid" --format '{{.State.Status}}' 2>/dev/null || true)" == "running" ]]; then
      log "analytics-worker is running"
      break
    fi
    sleep 3
  done
  if [[ "$(docker inspect "$_aw_cid" --format '{{.State.Status}}' 2>/dev/null || true)" != "running" ]]; then
    docker logs "$_aw_cid" --tail 80 >&2 || true
    error "analytics-worker failed to reach running state"
  fi
  wait_for_service_health nginx 120

  wait_for_curl_contains "nginx health" 'OK' 30 -fsS http://127.0.0.1/nginx-health >/dev/null
  wait_for_curl_contains "API TLS health" '"status":"ok"' 30 -kfsS --resolve api.apexmail.ee:443:127.0.0.1 https://api.apexmail.ee/health >/dev/null
  wait_for_curl_contains "Tracking TLS health" '"status":"healthy"' 30 -kfsS --resolve track.apexmail.ee:443:127.0.0.1 https://track.apexmail.ee/health >/dev/null
  # The unsubscribe route with a bogus token must 404 (route matched, token
  # invalid). A 502/503 means sales-autopilot is down behind nginx.
  local sales_code
  sales_code="$(curl -ks -o /dev/null -w '%{http_code}' --resolve api.apexmail.ee:443:127.0.0.1 https://api.apexmail.ee/sales-api/u/smoke-probe || echo 000)"
  if [[ "$sales_code" == "404" ]]; then
    log "sales-api /u/ -> 404 OK (sales-autopilot answering behind nginx)"
  else
    error "sales-api /u/ returned $sales_code (expected 404; 502/503 = sales-autopilot down)"
  fi

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
    api-server
    enterprise
    tracking
    sales-autopilot
    billing-service
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

  validate_smoke_dir
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