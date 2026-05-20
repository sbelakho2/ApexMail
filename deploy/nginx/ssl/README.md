# TLS Certificate Directory

Place your TLS certificates here for production deployment:

- `fullchain.pem` — Full certificate chain (server cert + intermediates)
- `privkey.pem` — Private key (**must be chmod 600**)
- `dhparam.pem` — Generated per-deployment (see below)

## Security: Private Key Permissions

TLS private keys **must** have restricted permissions. Run after copying:

```bash
chmod 600 deploy/nginx/ssl/privkey.pem
chmod 644 deploy/nginx/ssl/fullchain.pem
```

The Nginx container runs as a non-root user, so the key must be readable by
the container's user (typically UID 101 for the `nginx` image). If using
Docker Compose, ensure the volume mount preserves these permissions.

## Using Let's Encrypt (recommended)

```bash
# Install certbot and generate certificates
sudo certbot certonly --webroot -w /var/www/certbot \
  -d api.apexmail.ee \
  -d track.apexmail.ee

# Copy certificates with correct permissions
cp /etc/letsencrypt/live/apexmail.ee/fullchain.pem ./deploy/nginx/ssl/
cp /etc/letsencrypt/live/apexmail.ee/privkey.pem ./deploy/nginx/ssl/
chmod 600 ./deploy/nginx/ssl/privkey.pem
chmod 644 ./deploy/nginx/ssl/fullchain.pem

# Generate unique 4096-bit DH parameters (takes several minutes)
./deploy/nginx/ssl/generate-dhparams.sh
```

## Using self-signed certificates (development only)

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout deploy/nginx/ssl/privkey.pem \
  -out deploy/nginx/ssl/fullchain.pem \
  -subj '/CN=localhost'

chmod 600 deploy/nginx/ssl/privkey.pem

# Generate DH parameters (optional — only needed for DHE cipher suites)
./deploy/nginx/ssl/generate-dhparams.sh
```

## Override certificate path

Set `TLS_CERT_DIR` environment variable to use a custom certificate directory:

```bash
TLS_CERT_DIR=/etc/letsencrypt/live/apexmail.ee docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```
