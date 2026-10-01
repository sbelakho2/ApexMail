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
# deploy host runs. `apexmail-ci-toolchain --assert` (baked in below) proves
# them at pipeline start, and the pipeline sets CI_MISSING_TOOLS=fail so
# nothing can degrade to warn-and-skip.
#
# BUILD + PUBLISH (one-time, and after any version bump):
#   docker build -t ghcr.io/sbelakho2/apexmail-ci ci/ci-image/
#   docker push ghcr.io/sbelakho2/apexmail-ci
#   docker buildx imagetools inspect ghcr.io/sbelakho2/apexmail-ci \
#     | grep -o 'sha256:[0-9a-f]*'   # (or: docker inspect <img> --format ...)
# Then update the `&ci_image` YAML anchor in .woodpecker.yml with that
# digest. Audit SM14 F9: .woodpecker.yml must reference the image BY DIGEST
# (`ghcr.io/sbelakho2/apexmail-ci@sha256:<digest>`) — the mutable `:1` tag
# used to be re-pushed on every bump, silently replacing every tool version
# CI runs (with GITHUB_TOKEN mounted). The validate stage fails any run whose
# .woodpecker.yml still carries a tag-pinned/inline apexmail-ci reference.
# =============================================================================

FROM rust:1.98-bookworm

# --- pinned tool versions (mirror the deploy host; bump consciously) --------
# The SAME pins live in toolchain-versions.env (COPYed to
# /etc/apexmail-ci/toolchain-versions.env and asserted by
# `apexmail-ci-toolchain --assert` at the END of this build) — bump both
# files in ONE change or the image build fails (that is the point).
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
ARG PRE_COMMIT_VERSION=4.3.0
ARG COMPOSER_VERSION=2.8.4
ARG ZOLA_VERSION=0.22.1
ARG NODE_MAJOR=22
ARG GO_VERSION=1.23.4
# MUST equal the playwright version resolved by the committed
# tools/contrast-audit/package-lock.json (the executor npm-ci's the WORKSPACE
# playwright and runs it against the browser binaries baked in below).
ARG PLAYWRIGHT_VERSION=1.63.0

ENV DEBIAN_FRONTEND=noninteractive

# --- apt layer: languages and shell tooling ---------------------------------
# distro packages deliberately track bookworm security updates (.hadolint.yaml)
# hadolint ignore=DL3008
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

# --- docker CLI + compose plugin (CLIENT-SIDE ONLY) --------------------------
# Audit SM14 F5: the compose-contract gate (ci/stages/validate.sh
# validate_compose) is a client-side `docker compose config` render — it
# needs the CLI + compose plugin but NO daemon (the executor has none).
# Without them the gate silently vanished on the executor while the pipeline
# still posted "release gates GREEN". Like the distro packages above, the CLI
# tracks its vendor repo's bookworm security updates (unpinned on purpose —
# see .hadolint.yaml). The repo line pins arch=amd64, consistent with the
# other release assets below (the executor host is x86_64).
# vendor repo packages track their bookworm repo security updates (see .hadolint.yaml)
# hadolint ignore=DL3008
RUN install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc \
    && chmod a+r /etc/apt/keyrings/docker.asc \
    && echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian bookworm stable" \
        > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends docker-ce-cli docker-compose-plugin \
    && rm -rf /var/lib/apt/lists/*

# --- composer (PHP dependency manager) --------------------------------------
# Download-then-execute (no pipe): a truncated installer can never half-run.
RUN curl -fsSL https://getcomposer.org/installer -o /tmp/composer-setup.php \
    && php /tmp/composer-setup.php --install-dir=/usr/local/bin --filename=composer \
        --version=${COMPOSER_VERSION} \
    && rm -f /tmp/composer-setup.php

# --- node 22 (contrast/layout gates need modern playwright) -----------------
# nodejs tracks the nodesource repo security updates (see .hadolint.yaml)
# hadolint ignore=DL3008
RUN curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" -o /tmp/nodesource-setup.sh \
    && bash /tmp/nodesource-setup.sh \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -f /tmp/nodesource-setup.sh \
    && rm -rf /var/lib/apt/lists/*

# --- python security tooling -------------------------------------------------
# pre-commit: the test stage runs `pre-commit run --all-files` as a REQUIRED
# lane (audit SM14 F12) — the developer-side .pre-commit-config.yaml can no
# longer drift from CI, so CI itself must carry the tool.
RUN pip3 install --break-system-packages --no-cache-dir \
        "semgrep==${SEMGREP_VERSION}" \
        "pre-commit==${PRE_COMMIT_VERSION}"

# --- standalone binaries ------------------------------------------------------
# Download-then-extract (no pipes), and POSIX-safe arch mapping: BuildKit's
# TARGETARCH is amd64/arm64 while gitleaks' release assets are named x64.
# (The previous `${TARGETARCH/x86_64/x64}` substitution was BOTH a bashism —
# /bin/sh is dash, "Bad substitution" at build time — and matched the wrong
# value.) The remaining assets are the x86_64 release builds, matching the
# executor host.
ARG TARGETARCH
RUN case "$TARGETARCH" in \
        amd64) GL_ARCH=x64 ;; \
        arm64) GL_ARCH=arm64 ;; \
        *)     GL_ARCH="$TARGETARCH" ;; \
    esac \
    && curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GL_ARCH}" \
        -o /usr/local/bin/gitleaks && chmod +x /usr/local/bin/gitleaks \
    && curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
        -o /tmp/trivy.tgz && tar xzf /tmp/trivy.tgz -C /usr/local/bin trivy && rm -f /tmp/trivy.tgz \
    && curl -fsSL "https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VERSION}/hadolint-Linux-x86_64" \
        -o /usr/local/bin/hadolint && chmod +x /usr/local/bin/hadolint \
    && curl -fsSL "https://github.com/getzola/zola/releases/download/v${ZOLA_VERSION}/zola-v${ZOLA_VERSION}-x86_64-unknown-linux-gnu.tar.gz" \
        -o /tmp/zola.tgz && tar xzf /tmp/zola.tgz -C /usr/local/bin zola && rm -f /tmp/zola.tgz \
    && curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" \
        -o /tmp/go.tgz && tar xzf /tmp/go.tgz -C /usr/local && rm -f /tmp/go.tgz \
    && ln -s /usr/local/go/bin/go /usr/local/bin/go

# --- cargo tooling (pinned) ---------------------------------------------------
RUN cargo install --locked \
        cargo-nextest@${NEXTEST_VERSION} \
        cargo-llvm-cov@${LLVMCOV_VERSION} \
        cargo-deny@${DENY_VERSION} \
        cargo-machete@${MACHETE_VERSION} \
        cargo-audit@${AUDIT_VERSION} \
        sqlx-cli@${SQLX_VERSION}

# Playwright chromium for the contrast/layout pixel gates: provisioned at
# image build so CI never downloads browsers mid-run. The playwright version
# MUST equal the committed tools/contrast-audit/package-lock.json pin: the
# test stage npm-ci's the WORKSPACE playwright (audit SM14 F2) and runs it
# against THESE browser binaries — a skew makes playwright demand a browser
# build the image does not carry.
WORKDIR /tmp
RUN npm init -y >/dev/null 2>&1 \
    && npm install "playwright@${PLAYWRIGHT_VERSION}" >/dev/null 2>&1 \
    && npx playwright install --with-deps chromium \
    && rm -rf /tmp/node_modules /tmp/package*.json
WORKDIR /

# --- the toolchain contract, baked in -----------------------------------------
# Copies the version pins + the assertion script, then proves THIS image at
# build time: an image whose installed tools disagree with
# /etc/apexmail-ci/toolchain-versions.env cannot even be built, let alone
# pushed. The first Woodpecker step (.woodpecker.yml) re-runs
# `apexmail-ci-toolchain --assert` against the pushed image.
COPY toolchain-versions.env /etc/apexmail-ci/toolchain-versions.env
COPY toolchain.sh /usr/local/bin/apexmail-ci-toolchain
RUN chmod +x /usr/local/bin/apexmail-ci-toolchain \
    && apexmail-ci-toolchain --assert
