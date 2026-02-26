# ApexMail Mail Server - Multi-stage Dockerfile
#
# Builds the Rust mail server services.

# =============================================================================
# Dependency Cache Stage
# =============================================================================
FROM rust:1.82.0-slim-bookworm AS deps

WORKDIR /app

# Install protobuf compiler for gRPC and native deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    protobuf-compiler \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace manifests only (cacheable)
COPY Cargo.toml Cargo.lock ./
COPY crates/*/Cargo.toml crates/*/Cargo.toml

RUN cargo fetch --locked

# =============================================================================
# Build Stage
# =============================================================================
FROM deps AS builder

COPY crates ./crates

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
    org.opencontainers.image.source="https://github.com/apexmail/apexmail" \
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
