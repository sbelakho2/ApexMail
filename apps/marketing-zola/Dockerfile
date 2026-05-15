# ApexMail Marketing Site — Zola Static Site
#
# Multi-stage build: build CSS → build Zola → nginx serve

# =============================================================================
# Build Stage
# =============================================================================
FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Zola
RUN curl -sL https://github.com/getzola/zola/releases/download/v0.19.2/zola-v0.19.2-x86_64-unknown-linux-gnu.tar.gz \
    | tar xz -C /usr/local/bin

# Install Tailwind CSS standalone CLI
RUN curl -sLo /usr/local/bin/tailwindcss \
    https://github.com/tailwindlabs/tailwindcss/releases/download/v3.4.17/tailwindcss-linux-x64 \
    && chmod +x /usr/local/bin/tailwindcss

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
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|webp|avif|woff|woff2|ttf|eot|otf)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
        try_files $uri =404;
        access_log off;
    }

    # Health check
    location = /health {
        access_log off;
        default_type text/plain;
        return 200 "OK";
    }

    # Default: serve file, directory index, or .html fallback (Zola layout).
    # Also redirect /foo -> /foo/ when /foo is a directory so trailing slashes
    # are canonical without nuking asset URLs.
    location / {
        try_files $uri $uri/ $uri.html $uri/index.html =404;
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
