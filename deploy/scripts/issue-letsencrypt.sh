#!/usr/bin/env bash
# =============================================================================
# Let's Encrypt — first-time certificate issuance for apexmail.ee
# =============================================================================
# Run ONCE on the Hetzner host AFTER:
#   1. DNS A records are live for every subdomain listed below
#   2. The docker compose stack is up (so nginx serves HTTP-01 challenges
#      from certbot_webroot via /var/www/certbot)
#
# Strategy: certbot webroot challenge through the running nginx.
#   - certbot writes /var/www/certbot/.well-known/acme-challenge/...
#   - nginx already serves location /.well-known/acme-challenge/ from /var/www/certbot
#   - LE validates each domain, places the cert under /etc/letsencrypt/live/apexmail.ee/
#   - we copy fullchain.pem / privkey.pem to /etc/nginx/ssl/ (= deploy/nginx/ssl on host)
#   - nginx is reloaded (no downtime)
# =============================================================================
set -euo pipefail

DEPLOY_DIR="${DEPLOY_DIR:-/opt/apexmail}"
EMAIL="${LETSENCRYPT_EMAIL:?LETSENCRYPT_EMAIL is required (admin contact for renewals)}"
STAGING="${LETSENCRYPT_STAGING:-false}"

DOMAINS=(
  apexmail.ee
  www.apexmail.ee
  api.apexmail.ee
  app.apexmail.ee
  admin.apexmail.ee
  control.apexmail.ee
  enterprise.apexmail.ee
  track.apexmail.ee
  mail.apexmail.ee
  smtp.apexmail.ee
  imap.apexmail.ee
  autoconfig.apexmail.ee
  status.apexmail.ee
)

cd "$DEPLOY_DIR"

domain_args=()
for d in "${DOMAINS[@]}"; do
  domain_args+=(-d "$d")
done

staging_flag=""
if [[ "$STAGING" == "true" ]]; then
  staging_flag="--staging"
  echo "[letsencrypt] STAGING mode (test cert, not trusted by browsers)"
fi

echo "[letsencrypt] issuing cert for: ${DOMAINS[*]}"
# --user root: certbot needs to write /var/log/letsencrypt and chown
# /etc/letsencrypt/{accounts,archive,live} which the compose service runs as 1000:1000.
docker compose -f docker-compose.yml -f docker-compose.prod.yml --env-file .env \
  run --rm --user root --entrypoint certbot certbot \
  certonly --webroot -w /var/www/certbot \
  --email "$EMAIL" --agree-tos --no-eff-email \
  --non-interactive --keep-until-expiring --expand \
  $staging_flag "${domain_args[@]}"

# Copy the issued material into the path nginx mounts read-only.
LIVE="${DEPLOY_DIR}/deploy/nginx/ssl"
SRC="${DEPLOY_DIR}/deploy/nginx/ssl/live/apexmail.ee"
if [[ ! -d "$SRC" ]]; then
  echo "[letsencrypt] ERROR: certbot did not create $SRC" >&2
  exit 1
fi

# SECURITY (SEC-107): Private key must be 600 (owner-only) to prevent
# unauthorized reads. The nginx container reads the key via Docker secret
# or tmpfs mount — NOT via direct filesystem bind mount.
# If using a bind mount, ensure the nginx container user (uid 101) can
# read the key by either:
#   a) Using Docker secrets (recommended)
#   b) Setting group ownership: chown :101 privkey.pem && chmod 640 privkey.pem
install -m 644 "$SRC/fullchain.pem" "$LIVE/fullchain.pem"
install -m 600 "$SRC/privkey.pem"   "$LIVE/privkey.pem"
install -m 644 "$SRC/chain.pem"     "$LIVE/ca-chain.pem"

echo "[letsencrypt] reloading nginx with new cert"
docker compose -f docker-compose.yml -f docker-compose.prod.yml --env-file .env \
  exec nginx nginx -s reload

echo "[letsencrypt] DONE"
openssl x509 -in "$LIVE/fullchain.pem" -noout -subject -issuer -enddate
