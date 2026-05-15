# ApexMail Marketing Site — Zola Static Site
#
# Multi-stage build: build CSS → build Zola → nginx serve

# =============================================================================
# Build Stage
# =============================================================================
FROM --platform=linux/amd64 debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Zola v0.19.2 only publishes a Linux x86_64 binary. Pin the builder stage to
# linux/amd64 so local Apple Silicon builds and CI builds use the same toolchain.
RUN set -eux; \
        curl -sL "https://github.com/getzola/zola/releases/download/v0.19.2/zola-v0.19.2-x86_64-unknown-linux-gnu.tar.gz" \
            | tar xz -C /usr/local/bin; \
        curl -sLo /usr/local/bin/tailwindcss \
            "https://github.com/tailwindlabs/tailwindcss/releases/download/v3.4.17/tailwindcss-linux-x64"; \
        chmod +x /usr/local/bin/tailwindcss

# Copy source
COPY . .

# Build CSS and Zola site
RUN tailwindcss -i static/css/input.css -o static/css/styles.css --minify
RUN zola build

# =============================================================================
# Production Stage
# =============================================================================
FROM nginx:1.27-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10 AS runtime

# Create non-root user
RUN apk add --no-cache curl \
    && adduser -D -H -u 10001 -s /sbin/nologin apexmail \
    && chown -R apexmail:apexmail /var/cache/nginx /var/log/nginx /etc/nginx/conf.d \
    && chmod -R 755 /var/cache/nginx

# Copy built site
COPY --from=builder /app/public /usr/share/nginx/html

# Nginx config for static Zola site.
# Heredoc is quoted ('EOF') so $uri / \. are written literally.
COPY <<'EOF' /etc/nginx/conf.d/default.conf
server {
    listen 8080;
    server_name _;

    root /usr/share/nginx/html;
    index index.html;

    # When try_files lands on a directory, nginx issues a 301 to <uri>/.
    # We sit behind a TLS-terminating reverse proxy, so emit relative
    # redirects (no scheme, no host:port leak).
    absolute_redirect off;
    port_in_redirect off;

    # Security headers
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Gzip (must be at server/http level, before location matching)
    gzip on;
    gzip_comp_level 6;
    gzip_min_length 256;
    gzip_proxied any;
    gzip_vary on;
    gzip_types
        text/plain
        text/css
        text/xml
        text/javascript
        application/javascript
        application/json
        application/xml
        application/rss+xml
        application/atom+xml
        application/wasm
        image/svg+xml
        font/ttf
        font/otf;

    # Long-cache static assets (fingerprinted by Zola where applicable).
    # Use add_header (not `expires`) so we emit exactly one Cache-Control
    # header that includes `immutable`.
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|webp|avif|woff|woff2|ttf|eot|otf)$ {
        add_header Cache-Control "public, max-age=31536000, immutable" always;
        try_files $uri =404;
        access_log off;
    }

    # Health check
    location = /health {
        access_log off;
        default_type text/plain;
        return 200 "OK";
    }

    # One-time browser cache reset used by apexmail-site.js for users who saw
    # the previous broken permanent redirects.
    location = /cache-reset-20260515 {
        access_log off;
        add_header Cache-Control "no-store" always;
        add_header Clear-Site-Data '"cache"' always;
        return 204;
    }

    # Serve the home page without storing the HTML shell. Assets remain
    # long-cached by the fingerprinted asset location above.
    location = / {
        add_header Cache-Control "no-store" always;
        try_files /index.html =404;
    }

    # Default: serve file, slashless directory index, directory index, or .html
    # fallback (Zola layout). Checking $uri/index.html before $uri/ keeps
    # /pricing and /pricing/ both as 200 responses, so browsers never receive
    # another cacheable /pricing -> /pricing/ directory redirect.
    location / {
        try_files $uri.html $uri/index.html $uri $uri/ =404;
    }
}
EOF

USER apexmail
EXPOSE 8080

LABEL org.opencontainers.image.title="apexmail-marketing" \
    org.opencontainers.image.description="ApexMail marketing website" \
    org.opencontainers.image.source="https://github.com/apexmail" \
    org.opencontainers.image.licenses="PROPRIETARY"

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
    CMD ["curl", "-fsS", "http://127.0.0.1:8080/health"]
