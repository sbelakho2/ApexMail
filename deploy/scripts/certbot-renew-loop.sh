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

cat > /usr/local/bin/apexmail-deploy-hook.sh <<'HOOK'
#!/bin/sh
set -eu
LIVE_DIR="/etc/letsencrypt/live/apexmail.ee"
OUT_DIR="/etc/letsencrypt"
install -m 644 "$LIVE_DIR/fullchain.pem" "$OUT_DIR/fullchain.pem"
install -m 644 "$LIVE_DIR/privkey.pem"   "$OUT_DIR/privkey.pem"
install -m 644 "$LIVE_DIR/chain.pem"     "$OUT_DIR/ca-chain.pem"
echo "[certbot] deploy-hook installed new cert at $OUT_DIR ($(date -u +%FT%TZ))"
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
