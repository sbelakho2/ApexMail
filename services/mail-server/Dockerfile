# ApexMail Mail Server - Multi-stage Dockerfile
#
# Builds the Rust mail server services.

# =============================================================================
# Build Stage
# =============================================================================
FROM rust:1.82-bookworm AS builder

WORKDIR /app

# Install protobuf compiler for gRPC
RUN apt-get update && apt-get install -y protobuf-compiler && rm -rf /var/lib/apt/lists/*

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# Build all binaries
RUN cargo build --release

# =============================================================================
# Runtime Base
# =============================================================================
FROM debian:bookworm-slim AS runtime-base

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 apexmail

# =============================================================================
# Outbound Queue Service
# =============================================================================
FROM runtime-base AS outbound-queue

COPY --from=builder /app/target/release/outbound-queue /usr/local/bin/

USER apexmail
EXPOSE 50052

ENTRYPOINT ["outbound-queue"]
CMD ["--listen", "0.0.0.0:50052"]

# =============================================================================
# SMTP Edge Server
# =============================================================================
FROM runtime-base AS smtp-edge

COPY --from=builder /app/target/release/smtp-edge /usr/local/bin/

USER apexmail
EXPOSE 25

ENTRYPOINT ["smtp-edge"]
CMD ["--listen", "0.0.0.0:25"]

# =============================================================================
# Submission Server
# =============================================================================
FROM runtime-base AS submission

COPY --from=builder /app/target/release/submission-server /usr/local/bin/

USER apexmail
EXPOSE 587 465

ENTRYPOINT ["submission-server"]
CMD ["--listen", "0.0.0.0:587"]

# =============================================================================
# Send Email CLI Tool
# =============================================================================
FROM runtime-base AS send-email

COPY --from=builder /app/target/release/send-email /usr/local/bin/

USER apexmail

ENTRYPOINT ["send-email"]
