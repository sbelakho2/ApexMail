# TLS Certificate Directory

Place your TLS certificates here for production deployment:

- `fullchain.pem` — Full certificate chain (server cert + intermediates)
- `privkey.pem` — Private key (**must be chmod 640, owned :101** — see below)
- `ca-chain.pem` — CA chain for OCSP stapling (refreshed by the certbot
  deploy-hook)

## dhparam.pem — REMOVED (audit)

The placeholder `dhparam.pem` and `generate-dhparams.sh` were deleted:
`deploy/nginx/nginx.conf` never referenced `ssl_dhparam`, and its cipher
list is pure ECDHE (no DHE suites are offered), so DH parameters could
never be used. Regenerating a file nothing reads was pure startup cost.
Do NOT reintroduce `ssl_dhparam` unless you also add DHE cipher suites.

## Security: Private Key Permissions

TLS private keys **must** have restricted permissions. The nginx container
runs as UID/GID 101; the mta/imap-server containers run as 10001:10001 and
read `live/<domain>/privkey.pem` through their own bind mount of this tree.
The certbot deploy-hook (deploy/scripts/certbot-renew-loop.sh) enforces:

- tree-root `privkey.pem`: owner `101:101`, mode `0640` (nginx-only copy)
- `live/`+`archive/` directories: `0755`
- `fullchain.pem` / `chain.pem`: `0644` (public material)
- `live`/`archive` `privkey*.pem`: owner `101:10001`, mode `0640` — nginx
  reads as owner, mta/imap as group, nobody else.

Manual copies should match:

```bash
chmod 640 ./deploy/nginx/ssl/privkey.pem
chown :101 ./deploy/nginx/ssl/privkey.pem
chmod 644 ./deploy/nginx/ssl/fullchain.pem ./deploy/nginx/ssl/ca-chain.pem
```

## Using Let's Encrypt (recommended)

The certbot service maintains this tree automatically (renewal loop +
deploy-hook, see deploy/scripts/certbot-renew-loop.sh). For a manual
bootstrap:

```bash
# Install certbot and generate certificates
sudo certbot certonly --webroot -w /var/www/certbot \
  -d api.apexmail.ee \
  -d track.apexmail.ee

# Copy certificates with correct permissions
cp /etc/letsencrypt/live/apexmail.ee/fullchain.pem ./deploy/nginx/ssl/
cp /etc/letsencrypt/live/apexmail.ee/privkey.pem  ./deploy/nginx/ssl/
chmod 644 ./deploy/nginx/ssl/fullchain.pem
chown :101 ./deploy/nginx/ssl/privkey.pem && chmod 640 ./deploy/nginx/ssl/privkey.pem
```

## Using self-signed certificates (development only)

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout deploy/nginx/ssl/privkey.pem \
  -out deploy/nginx/ssl/fullchain.pem \
  -subj '/CN=localhost'

chown :101 deploy/nginx/ssl/privkey.pem
chmod 640 deploy/nginx/ssl/privkey.pem
```

## Override certificate path

Set `TLS_CERT_DIR` environment variable to use a custom certificate directory:

```bash
TLS_CERT_DIR=/etc/letsencrypt/live/apexmail.ee docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```
