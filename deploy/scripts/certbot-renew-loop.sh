#!/bin/sh
# =============================================================================
# certbot renewal loop (runs inside the certbot service container as root).
# =============================================================================
# Every 12h: attempt renewal. On successful renewal (deploy-hook fires only when
# at least one cert was renewed), copy fullchain / privkey / chain into the path
# that the front nginx container reads via its read-only bind mount.
#
# A docker socket is NOT mounted here, so this container cannot SIGHUP nginx
# directly. Nginx will pick up the new cert on its next reload — which happens
# on every CI/CD deploy (`docker compose up -d nginx`). If you want to force an
# immediate pickup, run on the host:
#
#   docker compose -f docker-compose.yml -f docker-compose.prod.yml \
#     --env-file .env exec nginx nginx -s reload
# =============================================================================
set -eu

LIVE_DIR="/etc/letsencrypt/live/apexmail.ee"
OUT_DIR="/etc/letsencrypt"
# The nginx container runs as uid 101 (nginx); the certbot container runs as
# root, so install with mode 600 owned by uid 101 — owner-only read (SEC-107)
# while remaining readable by the nginx master process.
NGINX_UID=101
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

while :; do
  if certbot renew --webroot -w /var/www/certbot \
      --deploy-hook /usr/local/bin/apexmail-deploy-hook.sh --quiet; then
    :
  else
    echo "[certbot] renew attempt failed at $(date -u +%FT%TZ); will retry"
  fi
  sleep 12h
done
