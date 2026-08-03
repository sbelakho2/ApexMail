# ApexMail Mail Server - Multi-stage Dockerfile
#
# Builds the Rust mail server services.

# =============================================================================
# Dependency Cache Stage
# =============================================================================
FROM rust:1.93.1-slim-bookworm AS deps

WORKDIR /app/services/mail-server
ENV CARGO_TARGET_DIR=/app/target

# Install protobuf compiler for gRPC and native deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    protobuf-compiler \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace manifests only (cacheable)
COPY services/mail-server/Cargo.toml services/mail-server/Cargo.lock ./
# This workspace relies on implicit src/lib.rs and src/main.rs targets, so
# cargo metadata/fetch must see the full crate trees rather than manifests only.
COPY services/mail-server/crates ./crates
COPY packages/kiwicaptcha/Cargo.toml /app/packages/kiwicaptcha/Cargo.toml

RUN cargo fetch --locked

# =============================================================================
# Build Stage (API-only first)
# =============================================================================
# Keep the API-focused builder before the full workspace builder so legacy
# Docker builds using --target api-server don't compile every binary first.
FROM deps AS api-server-builder

COPY docs /app/docs
COPY apps/marketing-zola/public /app/apps/marketing-zola/public
COPY packages/kiwicaptcha /app/packages/kiwicaptcha

RUN cargo build --release --bin api-server

# Shared builder for non-API runtime targets.
FROM deps AS builder

COPY docs /app/docs
COPY apps/marketing-zola/public /app/apps/marketing-zola/public

RUN cargo build --release

# =============================================================================
# Runtime Base
# =============================================================================
FROM debian:bookworm-slim AS runtime-base

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    tini \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 10001 -s /sbin/nologin apexmail

LABEL org.opencontainers.image.title="apexmail-mail-server" \
    org.opencontainers.image.description="ApexMail mail server services" \
    org.opencontainers.image.source="https://github.com/apexmail" \
    org.opencontainers.image.licenses="PROPRIETARY"

# =============================================================================
# Outbound Queue Service
# =============================================================================
FROM runtime-base AS outbound-queue

COPY --from=builder /app/target/release/outbound-queue /usr/local/bin/

USER apexmail
EXPOSE 50052

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD ["sh", "-c", "nc -z 127.0.0.1 50052"]

ENTRYPOINT ["/usr/bin/tini", "--", "outbound-queue"]
CMD ["--listen", "0.0.0.0:50052"]

# =============================================================================
# SMTP Edge Server
# =============================================================================
FROM runtime-base AS smtp-edge

COPY --from=builder /app/target/release/smtp-edge /usr/local/bin/

USER apexmail
EXPOSE 25
# Port 25 requires NET_BIND_SERVICE when running as non-root.

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD ["sh", "-c", "nc -z 127.0.0.1 25"]

ENTRYPOINT ["/usr/bin/tini", "--", "smtp-edge"]
CMD ["--listen", "0.0.0.0:25"]

# =============================================================================
# Submission Server
# =============================================================================
FROM runtime-base AS submission

COPY --from=builder /app/target/release/submission-server /usr/local/bin/

USER apexmail
EXPOSE 587 465

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD ["sh", "-c", "nc -z 127.0.0.1 587"]

ENTRYPOINT ["/usr/bin/tini", "--", "submission-server"]
CMD ["--listen", "0.0.0.0:587"]

# =============================================================================
# Mailstore Service
# =============================================================================
FROM runtime-base AS mailstore

COPY --from=builder /app/target/release/mailstore /usr/local/bin/

USER apexmail
EXPOSE 50051

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD ["sh", "-c", "nc -z 127.0.0.1 50051"]

ENTRYPOINT ["/usr/bin/tini", "--", "mailstore"]

# =============================================================================
# Send Email CLI Tool
# =============================================================================
FROM runtime-base AS send-email

COPY --from=builder /app/target/release/send-email /usr/local/bin/

USER apexmail

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["sh", "-c", "/usr/local/bin/send-email --help > /dev/null 2>&1"]

ENTRYPOINT ["/usr/bin/tini", "--", "send-email"]

# =============================================================================
# API Server
# =============================================================================
FROM runtime-base AS api-server

COPY --from=api-server-builder /app/target/release/api-server /usr/local/bin/
COPY --from=api-server-builder /app/apps/marketing-zola/public /app/apps/marketing-zola/public

ENV MARKETING_PUBLIC_DIR=/app/apps/marketing-zola/public
WORKDIR /app

USER apexmail
EXPOSE 3000

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD ["sh", "-c", "nc -z 127.0.0.1 3000"]

ENTRYPOINT ["/usr/bin/tini", "--", "api-server"]
CMD ["--listen", "0.0.0.0:3000"]

# =============================================================================
# Billing Service
# =============================================================================
FROM runtime-base AS billing-service

COPY --from=builder /app/target/release/billing-service /usr/local/bin/

USER apexmail
EXPOSE 3001

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD ["sh", "-c", "nc -z 127.0.0.1 3001"]

ENTRYPOINT ["/usr/bin/tini", "--", "billing-service"]
CMD ["--listen", "0.0.0.0:3001"]

# =============================================================================
# Analytics Worker
# =============================================================================
FROM runtime-base AS analytics

COPY --from=builder /app/target/release/analytics-worker /usr/local/bin/

USER apexmail
EXPOSE 3002

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD ["sh", "-c", "nc -z 127.0.0.1 3002"]

ENTRYPOINT ["/usr/bin/tini", "--", "analytics-worker"]

# =============================================================================
# MTA Server
# =============================================================================
FROM runtime-base AS mta

COPY --from=builder /app/target/release/mta-server /usr/local/bin/

USER apexmail
EXPOSE 3003

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD ["sh", "-c", "nc -z 127.0.0.1 3003"]

ENTRYPOINT ["/usr/bin/tini", "--", "mta-server"]
CMD ["--listen", "0.0.0.0:3003"]

# =============================================================================
# Template Renderer
# =============================================================================
FROM runtime-base AS template-renderer

COPY --from=builder /app/target/release/template-renderer /usr/local/bin/

USER apexmail
EXPOSE 3005

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD ["sh", "-c", "nc -z 127.0.0.1 3005"]

ENTRYPOINT ["/usr/bin/tini", "--", "template-renderer"]
CMD ["--listen", "0.0.0.0:3005"]

# =============================================================================
# Worker Processors
# =============================================================================
FROM runtime-base AS worker

COPY --from=builder /app/target/release/worker /usr/local/bin/

USER apexmail
EXPOSE 3006

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD ["sh", "-c", "nc -z 127.0.0.1 3006"]

ENTRYPOINT ["/usr/bin/tini", "--", "worker"]

# =============================================================================
# Compliance Server
# =============================================================================
FROM runtime-base AS compliance

COPY --from=builder /app/target/release/compliance-server /usr/local/bin/

USER apexmail
EXPOSE 3007

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD ["sh", "-c", "nc -z 127.0.0.1 3007"]

ENTRYPOINT ["/usr/bin/tini", "--", "compliance-server"]
CMD ["--listen", "0.0.0.0:3007"]

# =============================================================================
# Enterprise Server
# =============================================================================
FROM runtime-base AS enterprise

COPY --from=builder /app/target/release/enterprise-server /usr/local/bin/

USER apexmail
EXPOSE 3008

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD ["sh", "-c", "nc -z 127.0.0.1 3008"]

ENTRYPOINT ["/usr/bin/tini", "--", "enterprise-server"]
CMD ["--listen", "0.0.0.0:3008"]

# =============================================================================
# DevEx Service
# =============================================================================
FROM runtime-base AS devex

COPY --from=builder /app/target/release/devex-service /usr/local/bin/

USER apexmail
EXPOSE 3009

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD ["sh", "-c", "nc -z 127.0.0.1 3009"]

ENTRYPOINT ["/usr/bin/tini", "--", "devex-service"]
CMD ["--listen", "0.0.0.0:3009"]

# =============================================================================
# Observability Service
# =============================================================================
FROM runtime-base AS observability

COPY --from=builder /app/target/release/observability-service /usr/local/bin/

USER apexmail
EXPOSE 4400

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD ["sh", "-c", "nc -z 127.0.0.1 4400"]

ENTRYPOINT ["/usr/bin/tini", "--", "observability-service"]

# =============================================================================
# Ops Service
# =============================================================================
FROM runtime-base AS ops

COPY --from=builder /app/target/release/ops-service /usr/local/bin/

USER apexmail
EXPOSE 3011

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD ["sh", "-c", "nc -z 127.0.0.1 3011"]

ENTRYPOINT ["/usr/bin/tini", "--", "ops-service"]
CMD ["--listen", "0.0.0.0:3011"]

# =============================================================================
# HA Server
# =============================================================================
FROM runtime-base AS ha

COPY --from=builder /app/target/release/ha-server /usr/local/bin/

USER apexmail
EXPOSE 3012

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD ["sh", "-c", "nc -z 127.0.0.1 3012"]

ENTRYPOINT ["/usr/bin/tini", "--", "ha-server"]
CMD ["--listen", "0.0.0.0:3012"]

# =============================================================================
# Isolation Server
# =============================================================================
FROM runtime-base AS isolation

COPY --from=builder /app/target/release/isolation-server /usr/local/bin/

USER apexmail
EXPOSE 3013

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD ["sh", "-c", "nc -z 127.0.0.1 3013"]

ENTRYPOINT ["/usr/bin/tini", "--", "isolation-server"]
CMD ["--listen", "0.0.0.0:3013"]

# =============================================================================
# Edge Cases Server
# =============================================================================
FROM runtime-base AS edge-cases

COPY --from=builder /app/target/release/edge-cases-server /usr/local/bin/

USER apexmail
EXPOSE 3014

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD ["sh", "-c", "nc -z 127.0.0.1 3014"]

ENTRYPOINT ["/usr/bin/tini", "--", "edge-cases-server"]
CMD ["--listen", "0.0.0.0:3014"]

# =============================================================================
# AI Service
# =============================================================================
FROM runtime-base AS ai-service

COPY --from=builder /app/target/release/ai-service /usr/local/bin/

USER apexmail
EXPOSE 3015

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD ["sh", "-c", "nc -z 127.0.0.1 3015"]

ENTRYPOINT ["/usr/bin/tini", "--", "ai-service"]
CMD ["--listen", "0.0.0.0:3015"]

# =============================================================================
# AI Embeddings
# =============================================================================
FROM runtime-base AS ai-embeddings

COPY --from=builder /app/target/release/ai-embeddings /usr/local/bin/

USER apexmail
EXPOSE 3016

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD ["sh", "-c", "nc -z 127.0.0.1 3016"]

ENTRYPOINT ["/usr/bin/tini", "--", "ai-embeddings"]
CMD ["--listen", "0.0.0.0:3016"]

# =============================================================================
# Sales Autopilot
# =============================================================================
FROM runtime-base AS sales-autopilot

COPY --from=builder /app/target/release/sales-autopilot /usr/local/bin/

USER apexmail
EXPOSE 3017

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD ["sh", "-c", "nc -z 127.0.0.1 3017"]

ENTRYPOINT ["/usr/bin/tini", "--", "sales-autopilot"]
CMD ["--listen", "0.0.0.0:3017"]
