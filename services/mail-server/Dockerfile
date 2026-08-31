# ApexMail Mail Server - Multi-stage Dockerfile
#
# Builds the Rust mail server services.

# =============================================================================
# Dependency Cache Stages (cargo-chef)
# =============================================================================
# The dependency layer is keyed on the CARGO MANIFESTS ONLY (recipe.json), so
# source-only commits reuse the compiled-dependency cache instead of
# re-resolving and rebuilding the world: any `cargo build` after the cook
# starts from fully compiled third-party dependencies. Previously the deps
# stage COPYed the entire crates tree, invalidating the cache on every commit.
FROM rust:1.93.1-slim-bookworm AS chef

WORKDIR /app/services/mail-server
ENV CARGO_TARGET_DIR=/app/target

# Install protobuf compiler for gRPC and native deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    protobuf-compiler \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# cargo-chef itself is a layer of the base image: compiled once per toolchain.
RUN cargo install cargo-chef --locked

# --- planner: serialize the dependency graph from the real manifests -------------
FROM chef AS planner
COPY services/mail-server .
COPY packages/kiwicaptcha /app/packages/kiwicaptcha
RUN cargo chef prepare --recipe-path recipe.json

# --- deps: compile third-party dependencies from the recipe (the cache layer) ----
FROM chef AS deps
COPY --from=planner /app/services/mail-server/recipe.json recipe.json
# The recipe skeletonizes packages, but cargo must still be able to RESOLVE
# the workspace graph before cooking. Two path dependencies live outside the
# workspace member set and therefore need their manifests (plus stub sources
# so implicit lib targets resolve) on disk:
#   1. packages/kiwicaptcha        (api-server + integration-tests path dep)
#   2. crates/imap-proto-patched   ([patch.crates-io] imap-proto)
# CONTRACT: adding another external path dep or [patch] entry requires a
# matching block here, or cargo chef cook fails at resolution.
COPY services/mail-server/Cargo.lock ./Cargo.lock
# kiwicaptcha: no external crate depends on it, so the manifest + stub is
# enough for graph resolution (chef skeletonizes the dependents).
COPY packages/kiwicaptcha/Cargo.toml /app/packages/kiwicaptcha/Cargo.toml
RUN mkdir -p /app/packages/kiwicaptcha/src && \
    echo "#![allow(dead_code)] pub fn _placeholder() {}" > /app/packages/kiwicaptcha/src/lib.rs
# imap-proto-patched: the EXTERNAL imap crate compiles against the patched
# API during cook, so the real source must be present (and being a stable
# vendored crate, caching its compilation is desirable).
COPY services/mail-server/crates/imap-proto-patched ./crates/imap-proto-patched
RUN cargo chef cook --release --recipe-path recipe.json

# =============================================================================
# Build Stage (API-only first)
# =============================================================================
# Keep the API-focused builder before the full workspace builder so legacy
# Docker builds using --target api-server don't compile every binary first.
FROM deps AS api-server-builder

# Real sources over the skeleton: everything cargo needs to build the binary.
# static/css is required: ui-foundation embeds the marketing input.css at
# compile time (MARKETING_INPUT_CSS include_str!).
COPY services/mail-server .
COPY packages/kiwicaptcha /app/packages/kiwicaptcha
COPY packages/kiwicaptcha-wasm /app/packages/kiwicaptcha-wasm
COPY docs /app/docs
COPY apps/marketing-zola/public /app/apps/marketing-zola/public
COPY apps/marketing-zola/static/css /app/apps/marketing-zola/static/css

# BuildKit COPY keeps context mtimes; files older than the cook artifacts
# would be considered FRESH (skeleton rlibs reused). Touch everything so
# every workspace member rebuilds from its real sources; the dependency
# cache from the cook stays fully valid.
RUN find /app/services/mail-server /app/packages -type f -exec touch {} +

RUN cargo build --release --bin api-server

# Shared builder for non-API runtime targets.
FROM deps AS builder

COPY services/mail-server .
COPY packages/kiwicaptcha /app/packages/kiwicaptcha
COPY packages/kiwicaptcha-wasm /app/packages/kiwicaptcha-wasm
COPY docs /app/docs
COPY apps/marketing-zola/public /app/apps/marketing-zola/public
COPY apps/marketing-zola/static/css /app/apps/marketing-zola/static/css

# See api-server-builder: force-rebuild members over the cook skeletons.
RUN find /app/services/mail-server /app/packages -type f -exec touch {} +

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
    org.opencontainers.image.source="https://github.com/Bel-Consulting-OU/ApexMail" \
    org.opencontainers.image.licenses="PROPRIETARY"

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
# Binds 0.0.0.0:4100 (crates/billing-service/src/bin/server.rs default via
# BILLING_LISTEN_ADDR). GET /health is the unauthenticated liveness probe.
FROM runtime-base AS billing-service

COPY --from=builder /app/target/release/billing-service /usr/local/bin/

USER apexmail
EXPOSE 4100

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD ["sh", "-c", "nc -z 127.0.0.1 4100"]

ENTRYPOINT ["/usr/bin/tini", "--", "billing-service"]
CMD ["--listen", "0.0.0.0:4100"]

# =============================================================================
# MTA Server
# =============================================================================
FROM runtime-base AS mta

COPY --from=builder /app/target/release/mta-server /usr/local/bin/

USER apexmail
# 25 inbound, 587 submission (STARTTLS), 465 submission (implicit TLS),
# 2525 VERP/DSN bounce receiver, 2526 ISP FBL (abuse/complaint) receiver.
EXPOSE 25 587 465 2525 2526

# mta-server binds 25 (inbound, STARTTLS) and 587 (submission) unconditionally.
# The old probe targeted port 3003 which no service ever binds, marking the
# container unhealthy despite functioning SMTP.
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD ["sh", "-c", "nc -z 127.0.0.1 25 || nc -z 127.0.0.1 587"]

ENTRYPOINT ["/usr/bin/tini", "--", "mta-server"]

# =============================================================================
# IMAP Server
# =============================================================================
FROM runtime-base AS imap-server

COPY --from=builder /app/target/release/imap-server /usr/local/bin/

USER apexmail
# 143 (cleartext IMAP) is intentionally NOT exposed — IMAP is SSL-only on 993.
EXPOSE 993

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD ["sh", "-c", "nc -z 127.0.0.1 993"]

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["imap-server"]

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
# Auth Server / Status Server — serves the public status page (/status),
# status API (/status/api) and history (/status/history) for the status
# backend (status.apexmail.ee + apexmail.ee/api/status-data).
# =============================================================================
FROM runtime-base AS auth-server

COPY --from=builder /app/target/release/auth-server /usr/local/bin/

USER apexmail
EXPOSE 3000

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD ["sh", "-c", "nc -z 127.0.0.1 3000"]

ENTRYPOINT ["/usr/bin/tini", "--", "auth-server"]

# =============================================================================
# Sales Autopilot
# =============================================================================
FROM runtime-base AS sales-autopilot

COPY --from=builder /app/target/release/sales-autopilot /usr/local/bin/

USER apexmail
# The binary reads SALES_PORT (default 3010) — no CLI flags. Port 3010 is the
# nginx upstream (api.apexmail.ee/sales-api/) and the healthcheck target.
EXPOSE 3010

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD ["sh", "-c", "nc -z 127.0.0.1 3010"]

ENTRYPOINT ["/usr/bin/tini", "--", "sales-autopilot"]

# =============================================================================
# Compliance Service (GDPR/DSR pipeline, retention crons, hash-chain audit)
# =============================================================================
# Binds 0.0.0.0:3011 (crates/compliance/src/bin/server.rs, COMPLIANCE_PORT
# overrides). GET /health is liveness; GET /health/ready is readiness (pings
# Postgres). Internal-only: nginx never proxies it; the control plane calls
# compliance:3011 server-side with the COMPLIANCE_AUTH_TOKEN bearer.
FROM runtime-base AS compliance

COPY --from=builder /app/target/release/compliance-server /usr/local/bin/

USER apexmail
EXPOSE 3011

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD ["sh", "-c", "nc -z 127.0.0.1 3011"]

ENTRYPOINT ["/usr/bin/tini", "--", "compliance-server"]

# =============================================================================
# Analytics worker (events compaction + retention + reconciliation cron)
# =============================================================================
# The ONLY mechanism that ages events out of the Postgres `events` table
# (hot → cold compaction, then retention delete) and runs the
# reconciliation checks. It was compiled but never deployed, so Postgres
# event rows grew unboundedly and the published retention policy was
# enforced only on the ClickHouse copy. Internal-only; no ports.
FROM runtime-base AS analytics-worker

COPY --from=builder /app/target/release/analytics-worker /usr/local/bin/

USER apexmail

ENTRYPOINT ["/usr/bin/tini", "--", "analytics-worker"]

# =============================================================================
# PDF Renderer (invoice PDFs; billing-service renders every invoice through it)
# =============================================================================
# Built from the cargo-chef workspace like every other service — the crate's
# own Dockerfile (stub-then-copy) hit the cargo mtime trap and miscompiled.
# Fonts are include_bytes!-embedded at compile time — no runtime assets.
FROM runtime-base AS pdf-renderer

RUN apt-get update && apt-get install -y --no-install-recommends wget \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/pdf-renderer /usr/local/bin/pdf-renderer

USER apexmail
EXPOSE 3004

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD ["wget", "-qO-", "http://localhost:3004/health"]

ENTRYPOINT ["/usr/bin/tini", "--", "pdf-renderer"]
CMD ["--host", "0.0.0.0", "--port", "3004"]

# =============================================================================
# AI Service (grounded assistant: chat, docs index, deterministic tools)
# =============================================================================
# Internal-only (port 3012, single shared service token). Requires Postgres
# for the docs index + chat audit (DATABASE_URL). Model runtime is
# config-driven and FAILS CLOSED: AI_MODEL_ENABLED=false until an inference
# endpoint (vLLM/llama-server/Bedrock-compat) is configured.
FROM runtime-base AS ai-service

COPY --from=builder /app/target/release/ai-service /usr/local/bin/

USER apexmail
EXPOSE 3012

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD ["sh", "-c", "nc -z 127.0.0.1 3012"]

ENTRYPOINT ["/usr/bin/tini", "--", "ai-service"]

# =============================================================================
# AI Embeddings (inference sidecar; optional — chat works without it today)
# =============================================================================
# Internal-only (port 9090, same service token). Proxies an OpenAI-compatible
# /v1/embeddings endpoint; INFERENCE_URL must be https unless
# SIDECAR_TLS_ENABLED=false.
FROM runtime-base AS ai-embeddings

COPY --from=builder /app/target/release/ai-embeddings /usr/local/bin/

USER apexmail
EXPOSE 9090

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD ["sh", "-c", "nc -z 127.0.0.1 9090"]

ENTRYPOINT ["/usr/bin/tini", "--", "ai-embeddings"]

# =============================================================================
# Migrator (one-shot database migration job — runs BEFORE `compose up`)
# =============================================================================
# Applies services/mail-server/migrations via sqlx::migrate!. Run as
#   docker compose ... --profile migrate run --rm migrator
# (see deploy/DEPLOYMENT.md § "Database migrations"). DATABASE_URL is
# assembled from DB_* + the postgres_password secret by entrypoint-wrapper.sh.
FROM runtime-base AS migrator

COPY --from=builder /app/target/release/migrator /usr/local/bin/

USER apexmail

ENTRYPOINT ["/usr/bin/tini", "--", "migrator"]
