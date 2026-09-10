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

# Download the toolchain matching the BUILD target architecture. TARGETARCH
# is provided automatically by the builder (amd64/arm64) — including under
# buildx cross-builds — so local Apple Silicon and CI amd64 builds both get
# a runnable binary instead of the previously hard-pinned x86_64 one.
ARG TARGETARCH
RUN set -eux; \
        case "${TARGETARCH:-amd64}" in \
            amd64) ZOLA_ARCH='x86_64';  TW_ARCH='x64'   ;; \
            arm64) ZOLA_ARCH='aarch64'; TW_ARCH='arm64' ;; \
            *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
        esac; \
        curl -sL "https://github.com/getzola/zola/releases/download/v0.22.1/zola-v0.22.1-${ZOLA_ARCH}-unknown-linux-gnu.tar.gz" \
            | tar xz -C /usr/local/bin; \
        curl -sLo /usr/local/bin/tailwindcss \
            "https://github.com/tailwindlabs/tailwindcss/releases/download/v3.4.17/tailwindcss-linux-${TW_ARCH}"; \
        chmod +x /usr/local/bin/tailwindcss

# Copy source
COPY . .

# Build CSS and Zola site
RUN tailwindcss -i static/css/input.css -o static/css/styles.css --minify
# Patch: ensure dark-mode media query has :not(.light) guard so the JS toggle
# can override OS-level dark mode. Tailwind's minifier normalizes :root:not(.light)
# back to :root inside @media, so we fix it AFTER the Tailwind build.
RUN sed -i 's/@media(prefers-color-scheme:dark){:root/@media(prefers-color-scheme:dark){:root:not(.light)/g; s/@media (prefers-color-scheme:dark){:root/@media (prefers-color-scheme:dark){:root:not(.light)/g' static/css/styles.css
# Cachebust @font-face src URLs in the built CSS so they match the cachebusted
# <link rel=preload> URLs that base.html emits via Zola's get_url(cachebust=true).
# Without this, browsers fetch each font twice on a cold cache (preload with
# hash, @font-face without). We hash the font bytes (sha256, 20 chars) and
# inject ?h=<hash> into every url('/fonts/...') reference in styles.css.
RUN set -eux; \
    for font in static/fonts/*; do \
        [ -f "$font" ] || continue; \
        base=$(basename "$font"); \
        h=$(sha256sum "$font" | cut -c1-20); \
        sed -i "s|url('/fonts/${base}')|url('/fonts/${base}?h=${h}')|g" static/css/styles.css; \
        sed -i "s|url(/fonts/${base})|url(/fonts/${base}?h=${h})|g" static/css/styles.css; \
    done
RUN zola build

# =============================================================================
# Production Stage
# =============================================================================
FROM nginx:1.29-alpine@sha256:5616878291a2eed594aee8db4dade5878cf7edcb475e59193904b198d9b830de AS runtime

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

# source label = the repo home the site itself publishes
# (config.extra.github_url); the old github.com/apexmail org does not
# exist.
LABEL org.opencontainers.image.title="apexmail-marketing" \
    org.opencontainers.image.description="ApexMail marketing website" \
    org.opencontainers.image.source="https://apexmail.ee" \
    org.opencontainers.image.licenses="PROPRIETARY"

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
    CMD ["curl", "-fsS", "http://127.0.0.1:8080/health"]
