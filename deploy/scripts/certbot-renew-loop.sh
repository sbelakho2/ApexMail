#!/bin/sh
# =============================================================================
# certbot renewal loop (runs inside the certbot service container as root).
# =============================================================================
# Every 12h: attempt renewal. On successful renewal (detected by comparing the
# fullchain.pem hash before/after — `certbot renew` exits 0 even when nothing
# was due), the deploy-hook copies fullchain / privkey / chain into the path
# the front nginx container reads via its read-only bind mount, and this loop
# then:
#   1. reloads nginx (graceful — picks up the new cert files), and
#   2. restarts the mta and imap-server containers, which load the certs ONCE
#      at startup (see the notes on their TLS bind mounts in
#      docker-compose.prod.yml).
#
# The container has the docker socket bind-mounted read-only
# (/var/run/docker.sock — see the certbot service in docker-compose.prod.yml)
# and installs the docker CLI at startup, so it talks to the engine directly
# by container name. `docker compose ... exec` cannot be used from here: the
# compose files and .env (with their ${VAR:?required} interpolation) are not
# mounted into this container. Compose v2 default names are
# <project>-<service>-1; the project is "apexmail" (deployed from /opt/apexmail).
#
# If the docker CLI or socket is unavailable the renewal is still installed —
# services then pick it up on the next deploy / manual restart, and a warning
# is logged so the operator can act.
# =============================================================================
set -eu

LIVE_DIR="/etc/letsencrypt/live/apexmail.ee"
OUT_DIR="/etc/letsencrypt"
# The nginx container runs as uid 101 (nginx); the certbot container runs as
# root, so install with mode 600 owned by uid 101 — owner-only read (SEC-107)
# while remaining readable by the nginx master process.
NGINX_UID=101
# Compose v2 container names (project "apexmail" from the /opt/apexmail dir).
NGINX_CONTAINER="apexmail-nginx-1"
MAIL_CONTAINERS="apexmail-mta-1 apexmail-imap-server-1"

# --- Best-effort docker CLI bootstrap ----------------------------------------
# certbot/certbot is Alpine-based; install the CLI so renewals can act on the
# sibling containers. Non-fatal on failure (offline image pulls etc.).
if ! command -v docker >/dev/null 2>&1; then
  apk add --no-cache docker-cli >/dev/null 2>&1 || \
    echo "[certbot] WARN: could not install docker CLI — renewed certs will only be picked up on the next deploy/restart"
fi

has_docker() {
  command -v docker >/dev/null 2>&1 && docker version >/dev/null 2>&1
}

# --- Reload nginx + restart the mail containers after a renewal --------------
reload_services() {
  if ! has_docker; then
    echo "[certbot] WARN: docker unavailable — reload nginx and restart ${MAIL_CONTAINERS} manually"
    return 0
  fi
  if docker exec "$NGINX_CONTAINER" nginx -s reload; then
    echo "[certbot] nginx reloaded (${NGINX_CONTAINER})"
  else
    echo "[certbot] WARN: nginx reload failed on ${NGINX_CONTAINER}"
  fi
  # mta / imap-server read the certs once at startup — restart to pick them up.
  if docker restart $MAIL_CONTAINERS; then
    echo "[certbot] restarted: ${MAIL_CONTAINERS}"
  else
    echo "[certbot] WARN: failed to restart ${MAIL_CONTAINERS} — TLS certs reload only after a manual restart"
  fi
}

cat > /usr/local/bin/apexmail-deploy-hook.sh <<HOOK
#!/bin/sh
set -eu
LIVE_DIR="/etc/letsencrypt/live/apexmail.ee"
OUT_DIR="/etc/letsencrypt"
NGINX_UID=${NGINX_UID}
# SECURITY (SEC-107): Private key is 600 (owner-only) to prevent unauthorized reads.
install -m 644 "\$LIVE_DIR/fullchain.pem" "\$OUT_DIR/fullchain.pem"
install -m 600 "\$LIVE_DIR/privkey.pem"   "\$OUT_DIR/privkey.pem"
install -m 644 "\$LIVE_DIR/chain.pem"     "\$OUT_DIR/ca-chain.pem"
chown \${NGINX_UID}:\${NGINX_UID} "\$OUT_DIR/fullchain.pem" "\$OUT_DIR/privkey.pem" "\$OUT_DIR/ca-chain.pem"
chmod 640 "\$OUT_DIR/privkey.pem"
# Reopen the certbot tree for the mta/imap containers, which run as uid 10001
# (apexmail) and load fullchain/privkey from live/<domain>/ at startup.
# certbot creates live/ and archive/ as 0700 root:root — reopen the dirs and
# make the pem files 0644 so the non-root mail containers can read them
# (the OUT_DIR copies above stay 0600/101 for nginx).
chmod 0755 "\$OUT_DIR/live" "\$OUT_DIR/archive"
for d in "\$OUT_DIR"/live/* "\$OUT_DIR"/archive/*; do
  [ -d "\$d" ] && chmod 0755 "\$d" && chmod 0644 "\$d"/*.pem 2>/dev/null || true
done
echo "[certbot] deploy-hook installed new cert at \$OUT_DIR (\$(date -u +%FT%TZ))"
HOOK
chmod +x /usr/local/bin/apexmail-deploy-hook.sh

cert_hash() {
  [ -f "$LIVE_DIR/fullchain.pem" ] && sha256sum "$LIVE_DIR/fullchain.pem" | awk '{print $1}' || echo ""
}

while :; do
  before="$(cert_hash || true)"
  if certbot renew --webroot -w /var/www/certbot \
      --deploy-hook /usr/local/bin/apexmail-deploy-hook.sh --quiet; then
    after="$(cert_hash || true)"
    if [ -n "$after" ] && [ "$after" != "$before" ]; then
      echo "[certbot] certificate renewed at $(date -u +%FT%TZ) — reloading services"
      reload_services
    fi
  else
    echo "[certbot] renew attempt failed at $(date -u +%FT%TZ); will retry"
  fi
  sleep 12h
done
