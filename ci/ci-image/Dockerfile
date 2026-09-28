# =============================================================================
# ci/ci-image/Dockerfile — the hermetic Woodpecker executor image.
# =============================================================================
# WHY THIS EXISTS: .woodpecker.yml used to run every stage in the stock
# `rust:1.98-bookworm` image. The stage scripts expect far more than Rust
# (nextest/llvm-cov/deny/machete/audit, gitleaks/semgrep/trivy, shellcheck/
# hadolint, python3, the PHP/Go/Maven/Ruby SDK lanes, node for the contrast
# gates) — and `ci_have_tool` only fails closed on the deploy host, so on
# Woodpecker missing tools WARNED-AND-SKIPPED. Some security gates could
# silently disappear instead of proving the configuration wrong.
#
# This image contains EVERY tool the stages require, at the versions the
# deploy host runs. `ci/woodpecker/toolchain.sh` asserts them at pipeline
# start, and the pipeline sets CI_MISSING_TOOLS=fail so nothing can degrade
# to warn-and-skip.
#
# BUILD + PUBLISH (one-time, and after any version bump):
#   docker build -t ghcr.io/sbelakho2/apexmail-ci:1 ci/ci-image/
#   docker push ghcr.io/sbelakho2/apexmail-ci:1
# Bump the tag (and the reference in .woodpecker.yml) whenever a pinned
# version changes — the tag IS the hermeticity contract.
# =============================================================================

FROM rust:1.98-bookworm

# --- pinned tool versions (mirror the deploy host; bump consciously) --------
ARG NEXTEST_VERSION=0.9.143
ARG LLVMCOV_VERSION=0.9.1
ARG DENY_VERSION=0.20.2
ARG MACHETE_VERSION=0.9.2
ARG AUDIT_VERSION=0.22.2
ARG SQLX_VERSION=0.9.0
ARG GITLEAKS_VERSION=8.30.1
ARG TRIVY_VERSION=0.74.0
ARG SEMGREP_VERSION=1.176.0
ARG HADOLINT_VERSION=2.12.0
ARG ZOLA_VERSION=0.22.1
ARG NODE_MAJOR=22
ARG GO_VERSION=1.23.4

ENV DEBIAN_FRONTEND=noninteractive

# --- apt layer: languages and shell tooling ---------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl git jq xz-utils unzip \
        python3 python3-pip python3-venv \
        php-cli php-xml php-mbstring unzip \
        golang-go \
        default-jdk-headless maven \
        ruby-full \
        shellcheck \
        nodejs npm \
    && rm -rf /var/lib/apt/lists/*

# --- composer (PHP dependency manager) --------------------------------------
RUN curl -fsS https://getcomposer.org/installer \
      | php -- --install-dir=/usr/local/bin --filename=composer --version=2.8.4

# --- node 22 (contrast/layout gates need modern playwright) -----------------
RUN curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

# --- python security tooling -------------------------------------------------
RUN pip3 install --break-system-packages --no-cache-dir \
        "semgrep==${SEMGREP_VERSION}"

# --- standalone binaries ------------------------------------------------------
ARG TARGETARCH
RUN curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${TARGETARCH/x86_64/x64}" \
        -o /usr/local/bin/gitleaks && chmod +x /usr/local/bin/gitleaks \
    && curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
        | tar xz -C /usr/local/bin trivy \
    && curl -fsSL "https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VERSION}/hadolint-Linux-x86_64" \
        -o /usr/local/bin/hadolint && chmod +x /usr/local/bin/hadolint \
    && curl -fsSL "https://github.com/getzola/zola/releases/download/v${ZOLA_VERSION}/zola-v${ZOLA_VERSION}-x86_64-unknown-linux-gnu.tar.gz" \
        | tar xz -C /usr/local/bin zola \
    && curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" \
        | tar xz -C /usr/local && ln -s /usr/local/go/bin/go /usr/local/bin/go

# --- cargo tooling (pinned) ---------------------------------------------------
RUN cargo install --locked \
        cargo-nextest@${NEXTEST_VERSION} \
        cargo-llvm-cov@${LLVMCOV_VERSION} \
        cargo-deny@${DENY_VERSION} \
        cargo-machete@${MACHETE_VERSION} \
        cargo-audit@${AUDIT_VERSION} \
        sqlx-cli@${SQLX_VERSION}

# Playwright chromium for the contrast/layout pixel gates: provisioned at
# image build so CI never downloads browsers mid-run.
RUN cd /tmp \
    && npm init -y >/dev/null 2>&1 \
    && npm install playwright@1.49.1 >/dev/null 2>&1 \
    && npx playwright install --with-deps chromium \
    && rm -rf /tmp/node_modules /tmp/package*.json

# The stages read tool versions from here (ci/woodpecker/toolchain.sh).
COPY toolchain-versions.env /etc/apexmail-ci/toolchain-versions.env
COPY toolchain.sh /usr/local/bin/apexmail-ci-toolchain
RUN chmod +x /usr/local/bin/apexmail-ci-toolchain \
    && apexmail-ci-toolchain --assert
