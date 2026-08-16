#!/bin/bash
# Certbot renewal deploy hook for ApexMail.
#
# Runs automatically after certbot renews the certificate. Copies the renewed
# cert to all paths the services read from, then reloads nginx and restarts
# the mail containers so they pick up the new cert immediately.
#
# Install at: /etc/letsencrypt/renewal-hooks/deploy/apexmail-deploy-cert.sh
# Or place in the Docker certbot volume's renewal-hooks/deploy/ directory.
#
# Container names: docker compose v2 names containers <project>-<service>-1.
# The stack is deployed from /opt/apexmail, so the project is "apexmail" and
# the names are apexmail-nginx-1, apexmail-mta-1, apexmail-imap-server-1
# (NOT the legacy apexmail-mta / apexmail-imap names — those never match).

set -e

DEPLOY_DIR="${DEPLOY_DIR:-/opt/apexmail}"
COMPOSE="docker compose -f ${DEPLOY_DIR}/docker-compose.yml -f ${DEPLOY_DIR}/docker-compose.prod.yml --env-file ${DEPLOY_DIR}/.env"

# Source lineage of the renewed cert. certbot sets $RENEWED_LINEAGE when the
# hook runs as a renewal deploy hook (points at /etc/letsencrypt/live/<name>).
# Fall back to the standard lineage path for manual invocations. The live
# server currently uses the apexmail.ee-0002 lineage; do NOT hardcode it here —
# whichever lineage certbot is renewing (or the operator passes) is correct.
SRC="${RENEWED_LINEAGE:-/etc/letsencrypt/live/${CERT_LINEAGE:-apexmail.ee}}"

echo "[cert-hook] Deploying renewed cert to all service paths"

# Docker nginx SSL path (bind-mounted read-only into the nginx container)
cp "$SRC/fullchain.pem" "$DEPLOY_DIR/deploy/nginx/ssl/fullchain.pem"
cp "$SRC/privkey.pem"   "$DEPLOY_DIR/deploy/nginx/ssl/privkey.pem"
# nginx runs as 101:101 — same ownership/mode as deploy.sh Step 4 so a
# root-owned 600 key can never break the next reload.
chown 101:101 "$DEPLOY_DIR/deploy/nginx/ssl/fullchain.pem" "$DEPLOY_DIR/deploy/nginx/ssl/privkey.pem"
chmod 640 "$DEPLOY_DIR/deploy/nginx/ssl/privkey.pem"

# Mail services cert path (bind-mounted into mta + imap containers)
mkdir -p "$DEPLOY_DIR/certs"
for name in apexmail.crt apexmail.key mta.crt mta.key fullchain.pem privkey.pem; do
    case "$name" in
        *.crt|fullchain.pem) cp "$SRC/fullchain.pem" "$DEPLOY_DIR/certs/$name" ;;
        *.key|privkey.pem)   cp "$SRC/privkey.pem"   "$DEPLOY_DIR/certs/$name" ;;
    esac
done

# Reload Docker nginx (graceful). Prefer compose from the project dir; fall
# back to the compose v2 container name. Never fail the renewal over this.
if ! $COMPOSE exec -T nginx nginx -s reload 2>/dev/null; then
    docker exec apexmail-nginx-1 nginx -s reload 2>/dev/null || \
        echo "[cert-hook] WARN: could not reload nginx — reload manually" >&2
fi

# Restart mail containers so they load the new cert (they read certs once at
# startup). Service names are mta and imap-server.
if ! $COMPOSE restart mta imap-server 2>/dev/null; then
    docker restart apexmail-mta-1 apexmail-imap-server-1 2>/dev/null || \
        echo "[cert-hook] WARN: could not restart mta/imap-server — restart manually to pick up the new cert" >&2
fi

echo "[cert-hook] Done"
