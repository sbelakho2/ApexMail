#!/bin/sh
# =============================================================================
# certbot renewal loop (runs inside the certbot service container as root).
# =============================================================================
# Every 12h: attempt renewal. On successful renewal (detected by comparing the
# fullchain.pem hash before/after — `certbot renew` exits 0 even when nothing
# was due), the deploy-hook copies fullchain / privkey / chain into the paths
# nginx and the mail containers read via their read-only bind mounts, and this
# loop then signals nginx to reload:
#
#   1. It drops a `reload-requested` sentinel into the shared certbot_webroot
#      volume. The nginx container runs a 60s watcher loop (see the nginx
#      service `command:` in docker-compose.prod.yml) that sees the sentinel
#      and runs `nginx -s reload` — graceful, picks up the new cert files.
#
#   2. mta / imap-server load their certs ONCE at startup and cannot reload
#      in place. This container deliberately no longer mounts
#      /var/run/docker.sock (audit: a root container with the engine socket
#      is host-root-equivalent), so it cannot restart them either. A
#      restart-flag file is written and a loud warning logged. The restart
#      itself is automated HOST-SIDE: deploy.sh installs a systemd path-unit
#      (deploy/hardening/apexmail-tls-renew-restart.path) that watches this
#      flag and runs deploy/hardening/tls-renew-restart.sh — which restarts
#      mta + imap-server exactly once per renewal (mtime guard) with
#      APEXMAIL_TLS_AUTO_RESTART=0 as the documented opt-out. When the
#      watcher is absent (non-root manual deploy), the flag + warning below
#      remain the manual runbook.
# =============================================================================
set -eu

LIVE_DIR="/etc/letsencrypt/live/apexmail.ee"
OUT_DIR="/etc/letsencrypt"
WEBROOT="/var/www/certbot"
# Sentinel watched by the nginx sidecar loop (shared certbot_webroot volume).
RELOAD_SENTINEL="${WEBROOT}/reload-requested"
# Marker consumed by the host-side systemd watcher
# (apexmail-tls-renew-restart.path -> tls-renew-restart.sh). When the
# watcher is not installed this flag + the warning below are the manual
# runbook.
TLS_RELOAD_FLAG="${TLS_RELOAD_FLAG:-/etc/letsencrypt/renewal-restart-flag}"
# UID/GID matrix for key permissions (see the deploy-hook below):
#   nginx container runs as 101:101 (docker-compose.prod.yml `user:`).
#   mta / imap-server images run as 10001:10001 (USER apexmail in
#   services/mail-server/Dockerfile). The live privkey.pem is read by BOTH
#   (nginx via its ssl mount, mta/imap via their certs mount of the same
#   tree), so it is owned 101:10001 with mode 0640: nginx reads it as the
#   owner (uid 101), the mail containers as the group (gid 10001), and no
#   other uid can read it.
NGINX_UID=101
MAIL_GID=10001

# --- Signal nginx + flag the mail-container restart ---------------------------
reload_services() {
  if touch "$RELOAD_SENTINEL" 2>/dev/null; then
    echo "[certbot] reload sentinel written — nginx reloads within 60s (${RELOAD_SENTINEL})"
  else
    echo "[certbot] WARN: could not write ${RELOAD_SENTINEL} — reload nginx manually (nginx -s reload)"
  fi
  echo "[certbot] ACTION: mta + imap-server load TLS certs at startup only."
  echo "[certbot] Host-side watcher (apexmail-tls-renew-restart.path) restarts them from this flag —"
  echo "[certbot] if it is NOT installed, run on the host: docker compose -f docker-compose.yml -f docker-compose.prod.yml restart mta imap-server"
  touch "$TLS_RELOAD_FLAG" 2>/dev/null || true
}

cat > /usr/local/bin/apexmail-deploy-hook.sh <<HOOK
#!/bin/sh
set -eu
LIVE_DIR="/etc/letsencrypt/live/apexmail.ee"
OUT_DIR="/etc/letsencrypt"
NGINX_UID=${NGINX_UID}
MAIL_GID=${MAIL_GID}
# SECURITY (SEC-107 + audit): key permissions are the minimum that works for
# the containers that read this tree:
#   directories            0755   (traversable by the mail containers)
#   fullchain/chain PEMs   0644   (public material)
#   privkey*.pem           0640, owned \${NGINX_UID}:\${MAIL_GID}
#                          (nginx = owner read; mta/imap = group read; no
#                          world-read — the previous blanket
#                          \`chmod 0644 \$d/*.pem\` made every TLS private key
#                          world-readable).
# ── Root-of-tree copies: read ONLY by nginx (its ssl mount maps TLS_CERT_DIR
# to /etc/nginx/ssl; nginx.conf points at the three files below). ──────────
install -m 644 "\$LIVE_DIR/fullchain.pem" "\$OUT_DIR/fullchain.pem"
install -m 600 "\$LIVE_DIR/privkey.pem"   "\$OUT_DIR/privkey.pem"
install -m 644 "\$LIVE_DIR/chain.pem"     "\$OUT_DIR/ca-chain.pem"
chown \${NGINX_UID}:\${NGINX_UID} "\$OUT_DIR/fullchain.pem" "\$OUT_DIR/privkey.pem" "\$OUT_DIR/ca-chain.pem"
chmod 0644 "\$OUT_DIR/fullchain.pem" "\$OUT_DIR/ca-chain.pem"
chmod 0640 "\$OUT_DIR/privkey.pem"
# ── live/ + archive/ tree: read by mta/imap (uid/gid 10001) and, for the
# privkey, effectively owned for nginx (uid 101). certbot creates live/ and
# archive/ as 0700 root:root — reopen the directories, then set per-file
# minimums. live/<domain>/*.pem are symlinks into ../../archive/, and
# chmod/chown follow symlinks, so the archive data files are covered through
# the live/ loop as well (and directly by the archive/ loop).
chmod 0755 "\$OUT_DIR/live" "\$OUT_DIR/archive"
for d in "\$OUT_DIR"/live/* "\$OUT_DIR"/archive/*; do
  [ -d "\$d" ] || continue
  chmod 0755 "\$d"
  if [ -f "\$d/fullchain.pem" ]; then chmod 0644 "\$d/fullchain.pem"; fi
  if [ -f "\$d/chain.pem" ];     then chmod 0644 "\$d/chain.pem"; fi
  for k in "\$d"/privkey*.pem; do
    [ -f "\$k" ] || continue
    chown "\${NGINX_UID}:\${MAIL_GID}" "\$k"
    chmod 0640 "\$k"
  done
done
echo "[certbot] deploy-hook installed new cert at \$OUT_DIR (\$(date -u +%FT%TZ))"
HOOK
chmod +x /usr/local/bin/apexmail-deploy-hook.sh

cert_hash() {
  [ -f "$LIVE_DIR/fullchain.pem" ] && sha256sum "$LIVE_DIR/fullchain.pem" | awk '{print $1}' || echo ""
}

while :; do
  before="$(cert_hash || true)"
  if certbot renew --webroot -w "$WEBROOT" \
      --deploy-hook /usr/local/bin/apexmail-deploy-hook.sh --quiet; then
    after="$(cert_hash || true)"
    if [ -n "$after" ] && [ "$after" != "$before" ]; then
      echo "[certbot] certificate renewed at $(date -u +%FT%TZ) — signaling nginx reload"
      reload_services
    fi
  else
    echo "[certbot] renew attempt failed at $(date -u +%FT%TZ); will retry"
  fi
  sleep 12h
done
