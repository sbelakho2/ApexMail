#!/usr/bin/env bash
# =============================================================================
# ApexMail — TLS renewal auto-restart for mta + imap-server (host-side)
# =============================================================================
# Cert-renewal gap (audit 1.9): the mta and imap-server load their TLS certs
# ONCE at startup, so every successful Let's Encrypt renewal left them
# serving the OLD certificate until someone restarted them by hand. The
# certbot renewal loop (deploy/scripts/certbot-renew-loop.sh) cannot restart
# them itself: its container deliberately does NOT mount
# /var/run/docker.sock (a root container with the engine socket is
# host-root-equivalent — see the audit note on the certbot service in
# docker-compose.prod.yml) and ships no docker CLI. Instead the loop drops
# the renewal-restart-flag into the shared cert tree, and THIS script —
# installed on the host as a systemd path-unit watcher by deploy.sh
# (apexmail-tls-renew-restart.path) — performs the restart.
#
# Guard: the flag file's mtime is compared against the last-handled state;
# each successful renewal `touch`es the flag (new mtime), so exactly ONE
# restart happens per renewal no matter how often systemd re-fires.
#
# Toggle: APEXMAIL_TLS_AUTO_RESTART=0 disables the restart (the flag is
# still consumed so the watcher does not re-fire; the manual command is
# logged loudly). Default ON — reasoning: an automated ~monthly restart of
# two mail containers, each with a 90s stop_grace_period drain for in-flight
# SMTP/IMAP transactions, is far cheaper than silently serving an expired
# certificate for up to 90 days on :25/:587/:465/:993.
# =============================================================================
set -euo pipefail

DEPLOY_DIR="${DEPLOY_DIR:-/opt/apexmail}"
COMPOSE_FILES="-f docker-compose.yml -f docker-compose.prod.yml"
# The certbot container's TLS_RELOAD_FLAG lands on the host at
# ${TLS_CERT_DIR}/renewal-restart-flag (TLS_CERT_DIR defaults to
# ./deploy/nginx/ssl relative to the compose project dir = DEPLOY_DIR).
FLAG_FILE="${FLAG_FILE:-${DEPLOY_DIR}/deploy/nginx/ssl/renewal-restart-flag}"
STATE_FILE="${STATE_FILE:-/var/lib/apexmail/tls-renew-restart.state}"
AUTO_RESTART="${APEXMAIL_TLS_AUTO_RESTART:-1}"

log()  { printf '[tls-renew-restart] %s\n' "$*"; }
warn() { printf '[tls-renew-restart] WARNING: %s\n' "$*" >&2; }

# Sanitize to a non-negative integer so the arithmetic guard below can
# never explode on a corrupted/empty state file.
mtime_of() {
  local value=0
  if [[ -f "$1" ]]; then
    value="$(stat -c %Y "$1" 2>/dev/null || echo 0)"
  fi
  [[ "$value" =~ ^[0-9]+$ ]] || value=0
  printf '%s' "$value"
}

content_of() {
  local value
  value="$(cat "$1" 2>/dev/null || true)"
  [[ "$value" =~ ^[0-9]+$ ]] || value=0
  printf '%s' "$value"
}

main() {
  local mtime handled
  mtime="$(mtime_of "$FLAG_FILE")"
  handled="$(content_of "$STATE_FILE")"

  if (( mtime <= handled )); then
    # The guard against restarting more than once per renewal: systemd path
    # units re-fire on ANY modification of the watched file.
    log "renewal flag already handled (flag mtime ${mtime}, last handled ${handled}) — nothing to do"
    return 0
  fi

  log "certificate renewal detected (${FLAG_FILE} mtime ${mtime})"
  log "mta + imap-server load TLS certs at startup only — restarting them now"
  log "(in-flight SMTP/IMAP transactions drain for up to 90s via stop_grace_period)"

  if [[ "$AUTO_RESTART" != "1" ]]; then
    warn "APEXMAIL_TLS_AUTO_RESTART != 1 — automatic restart DISABLED."
    warn "Run on the host: cd ${DEPLOY_DIR} && docker compose ${COMPOSE_FILES} restart mta imap-server"
    printf '%s\n' "$mtime" > "$STATE_FILE" # consume the flag anyway
    return 0
  fi

  if (cd "$DEPLOY_DIR" && docker compose ${COMPOSE_FILES} restart mta imap-server); then
    printf '%s\n' "$mtime" > "$STATE_FILE"
    log "restart complete — mta + imap-server now serve the renewed certificate"
  else
    warn "docker compose restart FAILED — the mail containers still serve the OLD certificate."
    warn "Run on the host: cd ${DEPLOY_DIR} && docker compose ${COMPOSE_FILES} restart mta imap-server"
    warn "(the state file was NOT updated, so the next flag touch retries)"
    return 1
  fi
}

main "$@"
