#!/usr/bin/env bash
# ApexMail atomic deployment — server-side (SINGLE CANONICAL DEPLOY PATH)
# ==========================================================================
# This is the ONLY deployment tool for the ApexMail production server.
# Do NOT deploy via GitHub Actions, Docker Compose, manual rsync, or any
# other mechanism. All deploys MUST go through this script or the local
# `make` commands that invoke it.
#
# Usage: deploy.sh <marketing|auth-server|nginx|mta|all|rollback-marketing>
#
# Guarantees:
#   - Atomic swap (mv on same filesystem — never partial)
#   - Immediate rollback via snapshot
#   - Old staging/snapshot dirs cleaned after success
#   - No orphan files from prior deploys
#   - Registry code scan (blocks deploy if old codes found)
#   - Template leak scan (blocks deploy if raw {% found)
#   - Content verification (proves page is not SPA fallback)
#   - Status API health check
#   - All actions logged with timestamps

set -euo pipefail
IFS=$'\n\t'

# ── Immutable config ──
readonly DEPLOY_BASE="/opt/apexmail"
readonly LOG_DIR="${DEPLOY_BASE}/logs"
readonly LOG_FILE="${LOG_DIR}/deploy.log"
readonly NGINX_ROOT="/var/www/apexmail.ee"
readonly NGINX_PREV="/var/www/.apexmail.ee.prev"
readonly NGINX_NEXT="/var/www/.apexmail.ee.next"
readonly NGINX_PROTECTED="/var/www/.apexmail.ee.protected"
readonly STATUS_URL="https://apexmail.ee/api/status-data"
readonly TIMESTAMP="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

# Directories inside NGINX_ROOT that belong to OTHER apps (NOT marketing).
# These must survive marketing deploys.
readonly PROTECTED_DIRS=(
  login dashboard analytics home signup forgot-password reset-password verify-email
  campaigns contacts domains events lists reports settings templates
  admin assets
  css js fonts images
)

# ── Helpers ──
log() { echo "[deploy ${TIMESTAMP}] $*" | tee -a "${LOG_FILE}"; }
die() { log "FATAL: $*"; exit 1; }
ok()  { log "OK: $*"; }

health_http() {
  local url="$1" expect="${2:-200}" code
  code="$(curl -skL -o /dev/null -w '%{http_code}' -m 10 "${url}" 2>/dev/null || echo '000')"
  [ "${code}" = "${expect}" ] || die "Health check failed: ${url} returned ${code}, expected ${expect}"
  ok "${url} → ${code}"
}

health_status_api() {
  local status json
  json="$(curl -sk -m 10 "${STATUS_URL}" 2>/dev/null || echo '{}')"
  status="$(echo "${json}" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("status","missing"))' 2>/dev/null || echo 'missing')"
  case "${status}" in
    operational|degraded|outage) ok "status API: ${status}" ;;
    *) die "status API returned unexpected: ${status}" ;;
  esac
}

verify_no_conflicting_docker() {
  # The Docker apexmail-nginx container MUST NOT be running — we use bare-metal nginx.
  if docker ps --format '{{.Names}}' 2>/dev/null | grep -q 'apexmail-nginx'; then
    die "CONFLICT: Docker container 'apexmail-nginx' is running — it conflicts with bare-metal nginx. Stop it: docker stop apexmail-nginx && docker rm apexmail-nginx"
  fi
  ok "No conflicting Docker nginx container"
}

verify_deployed_content() {
  # Ensure the deployed directory has expected pages (not empty, not SPA-only)
  local root="${1:-${NGINX_ROOT}}"
  local required=("index.html" "pricing/index.html" "features/index.html" "security/index.html" "de/index.html" "fr/index.html" "es/index.html")
  for f in "${required[@]}"; do
    [ -f "${root}/${f}" ] || die "Missing required file: ${root}/${f}"
  done
  ok "All required pages present (${#required[@]} checked)"

  # Content fingerprint: pricing page must contain unique content
  if ! grep -q "Frequently Asked Questions" "${root}/pricing/index.html" 2>/dev/null; then
    die "Content verification failed: pricing/index.html missing expected text"
  fi
  ok "Content fingerprint verified"

  # No old registry codes (scan staging only — protected console dirs may have JS with curly braces)
  if grep -rq '16942833\|16192499' "${NGINX_NEXT}"; then
    die "OLD REGISTRY CODES (16942833 / 16192499) DETECTED in staged marketing build!"
  fi
  ok "Registry code scan clean"

  # No raw Zola template syntax (scan staging only)
  if grep -rq '{% if\|{% for\|{% include' "${NGINX_NEXT}"; then
    die "RAW TEMPLATE SYNTAX DETECTED in staged marketing build!"
  fi
  ok "Template syntax scan clean"
}

cleanup_orphans() {
  # Remove staging dir (consumed by atomic swap)
  if [ -d "${NGINX_NEXT}" ]; then
    rm -rf "${NGINX_NEXT}"
    ok "Cleaned staging dir: ${NGINX_NEXT}"
  fi

  # Remove protected dir temp (should always be cleaned by deploy, but just in case)
  rm -rf "${NGINX_PROTECTED}" 2>/dev/null || true

  # Remove old atomic-swap temp dir if somehow left behind
  rm -rf "${NGINX_ROOT}.old" 2>/dev/null || true
  rm -rf "${NGINX_ROOT}.rollback" 2>/dev/null || true

  # Expire snapshots older than 7 days (keep only latest)
  if [ -d "${NGINX_PREV}" ]; then
    local prev_age
    prev_age="$(find "${NGINX_PREV}" -maxdepth 1 -name 'index.html' -printf '%T@' 2>/dev/null || echo 0)"
    local cutoff
    cutoff="$(date -d '7 days ago' +%s 2>/dev/null || echo 0)"
    if [ "${prev_age%.*}" -lt "${cutoff}" ] 2>/dev/null; then
      rm -rf "${NGINX_PREV}"
      ok "Expired old snapshot (>7 days)"
    fi
  fi
}

# ── Deploy: marketing ──
deploy_marketing() {
  log "=== Deploying marketing site ==="

  verify_no_conflicting_docker

  if [ ! -f "${NGINX_NEXT}/index.html" ]; then
    die "${NGINX_NEXT}/index.html not found — stage files first with: make push-marketing"
  fi

  # Pre-flight verification on staging
  log "Pre-flight checks on staging..."
  verify_deployed_content "${NGINX_NEXT}"

  local before_count after_count
  before_count="$(find "${NGINX_ROOT}" -type f 2>/dev/null | wc -l)"
  after_count="$(find "${NGINX_NEXT}" -type f | wc -l)"
  log "File counts: current=${before_count} next=${after_count}"

  # ── Save protected non-marketing directories ──
  log "Saving protected directories: ${PROTECTED_DIRS[*]}"
  rm -rf "${NGINX_PROTECTED}"
  mkdir -p "${NGINX_PROTECTED}"
  local saved=0
  for dir in "${PROTECTED_DIRS[@]}"; do
    if [ -d "${NGINX_ROOT}/${dir}" ]; then
      cp -a "${NGINX_ROOT}/${dir}" "${NGINX_PROTECTED}/${dir}"
      ok "Saved: ${dir} ($(find "${NGINX_ROOT}/${dir}" -type f | wc -l) files)"
      saved=$((saved + 1))
    else
      log "Note: ${dir}/ not found (may not exist yet)"
    fi
  done

  # ── Snapshot current prod → prev for rollback ──
  if [ -d "${NGINX_ROOT}" ] && [ "$(ls -A "${NGINX_ROOT}" 2>/dev/null)" ]; then
    rm -rf "${NGINX_PREV}"
    cp -a "${NGINX_ROOT}" "${NGINX_PREV}"
    ok "Snapshot saved: ${NGINX_PREV} (${before_count} files)"
  fi

  # ── Atomic swap of marketing files ──
  rm -rf "${NGINX_ROOT}.old" 2>/dev/null || true
  if [ -d "${NGINX_ROOT}" ]; then
    mv "${NGINX_ROOT}" "${NGINX_ROOT}.old"
  fi
  mv "${NGINX_NEXT}" "${NGINX_ROOT}"
  rm -rf "${NGINX_ROOT}.old"
  log "Atomic swap complete"

  # ── Restore protected directories ──
  for dir in "${PROTECTED_DIRS[@]}"; do
    if [ -d "${NGINX_PROTECTED}/${dir}" ]; then
      cp -a "${NGINX_PROTECTED}/${dir}" "${NGINX_ROOT}/${dir}"
      ok "Restored: ${dir}"
    fi
  done
  rm -rf "${NGINX_PROTECTED}"

  # ── Verify protected dirs survived ──
  for dir in "${PROTECTED_DIRS[@]}"; do
    if [ ! -d "${NGINX_ROOT}/${dir}" ]; then
      die "Protected directory ${dir}/ was NOT restored — aborting before nginx reload"
    fi
  done
  ok "All protected directories verified present"

  # Reload nginx
  nginx -t 2>&1 | tail -1
  nginx -s reload
  ok "nginx reloaded"

  # Post-deploy verification
  health_http "https://apexmail.ee" "200"
  health_http "https://apexmail.ee/de/" "200"
  health_http "https://apexmail.ee/fr/" "200"
  health_http "https://apexmail.ee/es/" "200"
  health_http "https://app.apexmail.ee/" "200"
  health_http "https://admin.apexmail.ee/" "200"
  verify_deployed_content "${NGINX_ROOT}"
  health_status_api

  # Cleanup
  cleanup_orphans

  log "=== Marketing deploy complete ==="
}

# ── Deploy: auth-server ──
deploy_auth() {
  log "=== Deploying auth-server ==="

  if ! systemctl is-enabled auth-server &>/dev/null; then
    die "auth-server systemd unit not installed."
  fi

  # Check binary exists
  if [ ! -f /opt/apexmail/auth-server/target/release/auth-server ]; then
    die "auth-server binary not found — build first: make deploy-auth"
  fi

  systemctl restart auth-server
  sleep 2

  if ! systemctl is-active --quiet auth-server; then
    log "Last 20 log lines:"
    journalctl -u auth-server --no-pager -n 20 2>/dev/null | tee -a "${LOG_FILE}"
    die "auth-server failed to start"
  fi
  ok "auth-server restarted"

  # Wait for readiness (up to 15s)
  for i in $(seq 1 15); do
    if curl -sk http://127.0.0.1:3000/status/api -m 2 >/dev/null 2>&1; then
      ok "auth-server ready after ${i}s"
      break
    fi
    [ "${i}" -eq 15 ] && die "auth-server not ready after 15s"
    sleep 1
  done

  health_status_api
  log "=== Auth-server deploy complete ==="
}

# ── Deploy: nginx ──
deploy_nginx() {
  log "=== Deploying nginx config ==="

  local CONFIG_SRC="/opt/apexmail/nginx/apexmail.conf"
  local CONFIG_DST="/etc/nginx/sites-enabled/apexmail.conf"

  if [ ! -f "${CONFIG_SRC}" ]; then
    die "${CONFIG_SRC} not found — push config first: make push-nginx"
  fi

  # Diff before deploying
  if [ -f "${CONFIG_DST}" ]; then
    local diff_count
    diff_count="$(diff "${CONFIG_DST}" "${CONFIG_SRC}" | wc -l)"
    if [ "${diff_count}" -eq 0 ]; then
      log "nginx config unchanged — skipping deploy"
      return 0
    fi
    log "nginx config diff: ${diff_count} lines changed"
  fi

  # Backup current
  local backup="${CONFIG_DST}.prev-$(date +%s)"
  cp "${CONFIG_DST}" "${backup}" 2>/dev/null || true
  cp "${CONFIG_SRC}" "${CONFIG_DST}"

  if ! nginx -t 2>&1; then
    mv "${backup}" "${CONFIG_DST}" 2>/dev/null || true
    die "nginx -t failed — config rolled back"
  fi

  nginx -s reload
  ok "nginx config deployed and reloaded"

  # Verify
  sleep 1
  health_http "https://apexmail.ee" "200"
  health_status_api

  # Clean old backups (keep last 5)
  ls -t "${CONFIG_DST}.prev-"* 2>/dev/null | tail -n +6 | xargs rm -f 2>/dev/null || true

  log "=== Nginx deploy complete ==="
}

# ── Deploy: mta ──
deploy_mta() {
  log "=== Deploying MTA ==="

  if ! systemctl is-enabled apexmail-mta &>/dev/null; then
    die "apexmail-mta systemd unit not found"
  fi

  systemctl restart apexmail-mta
  sleep 2
  if ! systemctl is-active --quiet apexmail-mta; then
    journalctl -u apexmail-mta --no-pager -n 10 | tee -a "${LOG_FILE}"
    die "apexmail-mta failed to restart"
  fi
  ok "MTA restarted"
  log "=== MTA deploy complete ==="
}

# ── Deploy: all ──
deploy_all() {
  deploy_auth
  deploy_marketing
  deploy_nginx
  deploy_mta
}

# ── Rollback: marketing ──
rollback_marketing() {
  log "=== Rolling back marketing ==="
  if [ ! -d "${NGINX_PREV}" ] || [ ! -f "${NGINX_PREV}/index.html" ]; then
    die "No previous deployment found at ${NGINX_PREV}"
  fi

  # Save protected dirs from CURRENT root before rollback
  rm -rf "${NGINX_PROTECTED}"
  mkdir -p "${NGINX_PROTECTED}"
  for dir in "${PROTECTED_DIRS[@]}"; do
    if [ -d "${NGINX_ROOT}/${dir}" ]; then
      cp -a "${NGINX_ROOT}/${dir}" "${NGINX_PROTECTED}/${dir}"
    fi
  done

  # Atomic rollback swap
  rm -rf "${NGINX_ROOT}.rollback" 2>/dev/null || true
  mv "${NGINX_ROOT}" "${NGINX_ROOT}.rollback" 2>/dev/null || true
  mv "${NGINX_PREV}" "${NGINX_ROOT}"
  rm -rf "${NGINX_ROOT}.rollback"

  # Restore protected dirs
  for dir in "${PROTECTED_DIRS[@]}"; do
    if [ -d "${NGINX_PROTECTED}/${dir}" ]; then
      cp -a "${NGINX_PROTECTED}/${dir}" "${NGINX_ROOT}/${dir}"
    fi
  done
  rm -rf "${NGINX_PROTECTED}"

  nginx -s reload
  ok "Rollback complete"
  health_http "https://apexmail.ee" "200"
  health_http "https://app.apexmail.ee/" "200"
}

# ── Clean: remove ALL deployment artifacts (use before fresh deploy) ──
deploy_clean() {
  log "=== Cleaning deployment artifacts ==="
  rm -rf "${NGINX_NEXT}" "${NGINX_PREV}" "${NGINX_ROOT}.old" "${NGINX_ROOT}.rollback"
  ok "All deployment temp dirs removed"

  # Expire nginx config backups older than 30 days
  find /etc/nginx/sites-enabled/ -name 'apexmail.conf.prev-*' -mtime +30 -delete 2>/dev/null || true
  ok "Old nginx config backups expired"

  log "=== Clean complete ==="
}

# ── Main ──
mkdir -p "${LOG_DIR}"
touch "${LOG_FILE}"
chmod 600 "${LOG_FILE}" 2>/dev/null || true

COMPONENT="${1:-}"
case "${COMPONENT}" in
  marketing)          deploy_marketing ;;
  auth-server)        deploy_auth ;;
  nginx)              deploy_nginx ;;
  mta)                deploy_mta ;;
  all)                deploy_all ;;
  rollback-marketing) rollback_marketing ;;
  clean)              deploy_clean ;;
  --help|-h)
    echo "ApexMail deploy.sh — SINGLE CANONICAL DEPLOYMENT TOOL"
    echo "======================================================"
    echo "Usage: deploy.sh <component>"
    echo ""
    echo "Components:"
    echo "  marketing           Deploy Zola static site (atomic swap + verify)"
    echo "  auth-server         Restart auth-server via systemd"
    echo "  nginx               Deploy nginx config from /opt/apexmail/nginx/"
    echo "  mta                 Restart MTA via systemd"
    echo "  all                 Deploy everything in dependency order"
    echo "  rollback-marketing  Instant rollback to previous snapshot"
    echo "  clean               Remove all staging/snapshot/temp dirs"
    echo ""
    echo "This is the ONLY deployment mechanism. Do NOT rsync directly."
    echo "Do NOT use GitHub Actions for deployment. Do NOT use Docker Compose."
    echo "Deploy from your workstation with:  make deploy-marketing"
    ;;
  *) die "Unknown component '${COMPONENT}'. Use --help." ;;
esac

log "Deploy finished successfully."
