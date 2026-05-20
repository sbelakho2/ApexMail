FROM rust:1.82-bookworm AS builder

WORKDIR /app

# Copy workspace Cargo files for dependency caching
COPY Cargo.toml Cargo.lock ./

# Copy Cargo.toml files for pdf-renderer and its workspace dependencies
COPY crates/pdf-renderer/Cargo.toml crates/pdf-renderer/Cargo.toml
COPY crates/apexmail-lib/Cargo.toml crates/apexmail-lib/Cargo.toml
COPY crates/apexmail-db/Cargo.toml crates/apexmail-db/Cargo.toml
COPY crates/observability-service/Cargo.toml crates/observability-service/Cargo.toml

# Create stub libs to pre-compile dependencies
RUN mkdir -p crates/pdf-renderer/src && \
    echo "fn main() {}" > crates/pdf-renderer/src/main.rs && \
    echo "" > crates/pdf-renderer/src/lib.rs && \
    mkdir -p crates/apexmail-lib/src && \
    echo "" > crates/apexmail-lib/src/lib.rs && \
    mkdir -p crates/apexmail-db/src && \
    echo "" > crates/apexmail-db/src/lib.rs && \
    mkdir -p crates/observability-service/src && \
    echo "" > crates/observability-service/src/lib.rs && \
    cargo build --release --package pdf-renderer 2>/dev/null || true

# Copy actual source for all dependency crates
COPY crates/apexmail-lib/ crates/apexmail-lib/
COPY crates/apexmail-db/ crates/apexmail-db/
COPY crates/observability-service/ crates/observability-service/

# Copy actual source for pdf-renderer
COPY crates/pdf-renderer/ crates/pdf-renderer/

# Build the real binary
RUN cargo build --release --bin pdf-renderer && \
    strip target/release/pdf-renderer

# ── Runtime ─────────────────────────────────────────────────────────────

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        wget \
        fonts-dejavu-core \
        fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --no-create-home --uid 1001 pdf

COPY --from=builder /app/target/release/pdf-renderer /usr/local/bin/pdf-renderer-server

USER pdf

EXPOSE 3004

HEALTHCHECK --interval=15s --timeout=5s --retries=3 \
    CMD wget -qO- http://localhost:3004/health || exit 1

ENTRYPOINT ["pdf-renderer-server"]
CMD ["--host", "0.0.0.0", "--port", "3004"]
