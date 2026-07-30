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

# Pin the builder stage to linux/amd64 so local Apple Silicon builds and CI
# builds use the same toolchain.
RUN set -eux; \
        curl -sL "https://github.com/getzola/zola/releases/download/v0.22.1/zola-v0.22.1-x86_64-unknown-linux-gnu.tar.gz" \
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
COPY nginx.conf /etc/nginx/conf.d/default.conf

USER apexmail
EXPOSE 8080

LABEL org.opencontainers.image.title="apexmail-marketing" \
    org.opencontainers.image.description="ApexMail marketing website" \
    org.opencontainers.image.source="https://github.com/apexmail" \
    org.opencontainers.image.licenses="PROPRIETARY"

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
    CMD ["curl", "-fsS", "http://127.0.0.1:8080/health"]
