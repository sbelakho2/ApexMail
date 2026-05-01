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
FROM nginx:1.27-alpine AS runtime

# Create non-root user
RUN adduser -D -H -u 10001 -s /sbin/nologin apexmail \
    && chown -R apexmail:apexmail /var/cache/nginx /var/log/nginx /etc/nginx/conf.d \
    && chmod -R 755 /var/cache/nginx

# Copy built site
COPY --from=builder /app/public /usr/share/nginx/html

# Nginx config for SPA + static
COPY <<EOF /etc/nginx/conf.d/default.conf
server {
    listen 8080;
    server_name _;

    root /usr/share/nginx/html;
    index index.html;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Cache static assets
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    # Serve files or fallback to index.html
    location / {
        try_files \$uri \$uri/index.html \$uri.html =404;
    }

    # Health check
    location /health {
        access_log off;
        default_type text/plain;
        return 200 "OK";
    }

    # Gzip
    gzip on;
    gzip_types text/plain text/css application/json text/xml application/xml;
    gzip_vary on;
}
EOF

USER apexmail
EXPOSE 8080

LABEL org.opencontainers.image.title="apexmail-marketing" \
    org.opencontainers.image.description="ApexMail marketing website" \
    org.opencontainers.image.source="https://github.com/apexmail" \
    org.opencontainers.image.licenses="PROPRIETARY"

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
    CMD ["wget", "-qO-", "http://127.0.0.1:8080/health"]
