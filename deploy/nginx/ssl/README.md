# TLS Certificate Directory

Place your TLS certificates here for production deployment:

- `fullchain.pem` — Full certificate chain (server cert + intermediates)
- `privkey.pem` — Private key
- `dhparam.pem` — 2048-bit DH parameters consumed by nginx `ssl_dhparam`

## Using Let's Encrypt (recommended)

```bash
# Install certbot and generate certificates
sudo certbot certonly --webroot -w /var/www/certbot \
  -d api.apexmail.ee \
  -d track.apexmail.ee

# Copy certificates
cp /etc/letsencrypt/live/apexmail.ee/fullchain.pem ./deploy/nginx/ssl/
cp /etc/letsencrypt/live/apexmail.ee/privkey.pem ./deploy/nginx/ssl/
openssl dhparam -out ./deploy/nginx/ssl/dhparam.pem 2048
```

## Using self-signed certificates (development only)

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout deploy/nginx/ssl/privkey.pem \
  -out deploy/nginx/ssl/fullchain.pem \
  -subj '/CN=localhost'

openssl dhparam -out deploy/nginx/ssl/dhparam.pem 2048
```

## Override certificate path

Set `TLS_CERT_DIR` environment variable to use a custom certificate directory:

```bash
TLS_CERT_DIR=/etc/letsencrypt/live/apexmail.ee docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```
