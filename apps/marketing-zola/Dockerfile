# ApexMail Marketing Site — Zola Static Site
#
# Multi-stage build: build CSS → build Zola → nginx serve

# =============================================================================
# Build Stage
# =============================================================================
FROM debian:bookworm-slim AS builder

# bash + pipefail: the RUN steps below pipe curl|tar and sha256sum|cut —
# without pipefail a failed download would be masked by tar's success.
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Builder-stage tooling (curl/xz); reproducibility is governed by the pinned
# zola download below, not the apt set, and version-pinning curl against the
# moving bookworm-slim tag would break on every point release.
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Source revision stamped into the export and the image label (pass
# --build-arg SOURCE_REVISION=$(git rev-parse HEAD) in CI). Defaults to
# "unknown" so a local build still produces a coherent, self-describing export.
ARG SOURCE_REVISION=unknown

# Download the toolchain matching the BUILD target architecture. TARGETARCH
# is provided automatically by the builder (amd64/arm64) — including under
# buildx cross-builds — so local Apple Silicon and CI amd64 builds both get
# a runnable binary instead of the previously hard-pinned x86_64 one.
ARG TARGETARCH
RUN set -eux; \
        case "${TARGETARCH:-amd64}" in \
            amd64) ZOLA_ARCH='x86_64'  ;; \
            arm64) ZOLA_ARCH='aarch64' ;; \
            *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
        esac; \
        curl -sL "https://github.com/getzola/zola/releases/download/v0.22.1/zola-v0.22.1-${ZOLA_ARCH}-unknown-linux-gnu.tar.gz" \
            | tar xz -C /usr/local/bin

# Copy source
COPY . .

# The stylesheet is a COMMITTED artifact built by cssgen (the all-Rust CSS
# generator in ui-foundation; no Tailwind, no JavaScript anywhere in the
# repo). CI regenerates and gate-checks it (cssgen --check) before the
# Docker build runs, so the image just ships the verified file. The
# dark-mode media query's :root:not(.light) guard is authored in the
# authority (ark.css) and passes through cssgen verbatim.
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
# Provenance: stamp what actually produced this export (source revision +
# pinned toolchain versions). The api-server serves public/** as-is, so this
# file is the deployment's own record of which HTML/CSS/assets it shipped.
RUN set -eux; \
    printf '{"source_revision":"%s","zola":"0.22.1","cssgen":"rust-ui-foundation","styled_sheet":"css/styles.css"}\n' \
        "${SOURCE_REVISION}" > public/build-provenance.json

# =============================================================================
# Production Stage
# =============================================================================
FROM nginx:1.29-alpine@sha256:5616878291a2eed594aee8db4dade5878cf7edcb475e59193904b198d9b830de AS runtime

# Create non-root user. apk upgrade first: the pinned base digest's apk
# packages can lag published CVE fixes (curl 8.17 carried five HIGHs fixed
# in 8.22) — lifting them here keeps the trivy gate honest without
# chasing ever-newer base digests.
# The apk upgrade/add pair deliberately tracks the NEWEST CVE-fixed curl
# (see the comment above); pinning would freeze the exact HIGHs the Trivy
# images gate exists to catch.
# hadolint ignore=DL3018
RUN apk upgrade --no-cache && apk add --no-cache curl \
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
    org.opencontainers.image.licenses="PROPRIETARY" \
    org.opencontainers.image.revision="${SOURCE_REVISION}"

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
    CMD ["curl", "-fsS", "http://127.0.0.1:8080/health"]
