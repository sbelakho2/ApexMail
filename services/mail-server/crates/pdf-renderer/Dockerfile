FROM rust:1.93-bookworm AS builder

# bash + pipefail: the manifest-stub RUN pipes grep|sed|while — without
# pipefail a failed grep would be masked by the loop's success.
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

WORKDIR /app

# Copy workspace Cargo files for dependency caching
COPY Cargo.toml Cargo.lock ./

# Copy ALL workspace member Cargo.toml files so cargo can resolve the workspace.
# The pdf-renderer only depends on a few crates, but the workspace Cargo.toml
# references all members, so we need stub manifests for all of them.
RUN grep -oP '"crates/[^"]+' Cargo.toml | sed 's/"crates\///' | while read -r crate; do \
        mkdir -p "crates/$crate/src" && \
        printf '[package]\nname = "%s"\nversion = "0.0.0"\nedition = "2021"\n\n[lib]\npath = "src/lib.rs"\n' "$crate" > "crates/$crate/Cargo.toml" && \
        echo "" > "crates/$crate/src/lib.rs"; \
    done && \
    # Handle the patched imap-proto crate (it's named imap-proto-patched in the path
    # but publishes as imap-proto)
    printf '[package]\nname = "imap-proto"\nversion = "0.1.0"\nedition = "2021"\n\n[lib]\npath = "src/lib.rs"\n' > crates/imap-proto-patched/Cargo.toml

# Overwrite with the REAL Cargo.toml for the crates we actually need
COPY crates/pdf-renderer/Cargo.toml crates/pdf-renderer/Cargo.toml
COPY crates/apexmail-lib/Cargo.toml crates/apexmail-lib/Cargo.toml
COPY crates/apexmail-db/Cargo.toml crates/apexmail-db/Cargo.toml
COPY crates/observability-service/Cargo.toml crates/observability-service/Cargo.toml

# Create real stub libs for the crates we need
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

# Runtime deps from the moving bookworm-slim pool; pinning fonts/wget
# versions would break on every base refresh while the Trivy images gate
# covers CVE exposure.
# hadolint ignore=DL3008
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
    CMD ["wget", "-qO-", "http://localhost:3004/health"]

ENTRYPOINT ["pdf-renderer-server"]
CMD ["--host", "0.0.0.0", "--port", "3004"]
