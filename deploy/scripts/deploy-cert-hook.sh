#!/bin/bash
# Certbot renewal deploy hook for ApexMail.
#
# Runs automatically after certbot renews the certificate. Copies the renewed
# cert to all paths the services read from, then reloads nginx and restarts
# the mail containers so they pick up the new cert immediately.
#
# Install at: /etc/letsencrypt/renewal-hooks/deploy/apexmail-deploy-cert.sh
# Or place in the Docker certbot volume's renewal-hooks/deploy/ directory.

set -e

# Source lineage of the renewed cert. certbot sets $RENEWED_LINEAGE when the
# hook runs as a renewal deploy hook (points at /etc/letsencrypt/live/<name>).
# Fall back to the standard lineage path for manual invocations. The live
# server currently uses the apexmail.ee-0002 lineage; do NOT hardcode it here —
# whichever lineage certbot is renewing (or the operator passes) is correct.
SRC="${RENEWED_LINEAGE:-/etc/letsencrypt/live/${CERT_LINEAGE:-apexmail.ee}}"

echo "[cert-hook] Deploying renewed cert to all service paths"

# Docker nginx SSL path (bind-mounted read-only into the nginx container)
cp "$SRC/fullchain.pem" /opt/apexmail/deploy/nginx/ssl/fullchain.pem
cp "$SRC/privkey.pem"   /opt/apexmail/deploy/nginx/ssl/privkey.pem

# Mail services cert path (bind-mounted into mta + imap containers)
mkdir -p /opt/apexmail/certs
for name in apexmail.crt apexmail.key mta.crt mta.key fullchain.pem privkey.pem; do
    case "$name" in
        *.crt|fullchain.pem) cp "$SRC/fullchain.pem" "/opt/apexmail/certs/$name" ;;
        *.key|privkey.pem)   cp "$SRC/privkey.pem"   "/opt/apexmail/certs/$name" ;;
    esac
done

# Reload Docker nginx
docker exec apexmail-nginx-1 nginx -s reload 2>/dev/null || true

# Restart mail containers so they load the new cert
docker restart apexmail-mta apexmail-imap 2>/dev/null || true

echo "[cert-hook] Done"
