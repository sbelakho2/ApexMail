FROM rust:1.82-bookworm AS builder

WORKDIR /app

# Copy workspace Cargo files for dependency caching
COPY Cargo.toml Cargo.lock ./
COPY crates/pdf-renderer/Cargo.toml crates/pdf-renderer/Cargo.toml

# Create stub lib to pre-compile dependencies
RUN mkdir -p crates/pdf-renderer/src && \
    echo "fn main() {}" > crates/pdf-renderer/src/main.rs && \
    echo "" > crates/pdf-renderer/src/lib.rs && \
    cargo build --release --package pdf-renderer 2>/dev/null || true

# Copy actual source
COPY crates/pdf-renderer/ crates/pdf-renderer/

# Build the real binary
RUN cargo build --release --bin pdf-renderer-server && \
    strip target/release/pdf-renderer-server

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

COPY --from=builder /app/target/release/pdf-renderer-server /usr/local/bin/pdf-renderer-server

USER pdf

EXPOSE 3004

HEALTHCHECK --interval=15s --timeout=5s --retries=3 \
    CMD wget -qO- http://localhost:3004/health || exit 1

ENTRYPOINT ["pdf-renderer-server"]
CMD ["--host", "0.0.0.0", "--port", "3004"]
