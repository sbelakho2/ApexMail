#!/bin/sh
# =============================================================================
# ci/install.sh — ApexMail pipeline host installer (idempotent).
# =============================================================================
# Prepares a Debian/Ubuntu deploy host (the Hetzner box) to run ci/pipeline.sh
# as a systemd service. Safe to re-run; every step checks before changing.
#
# Usage:
#   sudo ci/install.sh                full install: deps + tools + units + env
#   sudo ci/install.sh units          (re)install + enable the systemd units only
#   sudo ci/install.sh deploy-key     generate the read-only deploy keypair and
#                                     print the PUBLIC key to add on GitHub
#   sudo ci/install.sh webhook-token  (re)generate the webhook shared secret
#   sudo ci/install.sh check          verify the install (dry, no changes)
#
# What the full install does:
#   1. apt deps: git curl jq python3 ca-certificates rsync openssl bc file
#   2. cargo toolchain + cargo-audit + sqlx-cli when missing (PATH-aware);
#      gitleaks + trivy as pinned release binaries in /usr/local/bin
#   3. /etc/apexmail/pipeline.conf   (host overrides: CI_DEPLOY_DIR, env file)
#   4. systemd units: apexmail-pipeline.service (oneshot)
#                     apexmail-pipeline.timer   (every 5 minutes)
#                     apexmail-pipeline-webhook.service+socket (optional)
#   5. `systemctl enable --now apexmail-pipeline.timer`
#
# macOS / non-systemd machines: only `check` and `deploy-key` apply; the
# pipeline is run manually (`ci/pipeline.sh run`) or from cron.
# =============================================================================
set -eu

CI_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
# shellcheck source=lib.sh
. "$CI_DIR/lib.sh"

DEPLOY_DIR=${CI_DEPLOY_DIR:-/opt/apexmail}
ETC_DIR=/etc/apexmail
UNIT_DST=/etc/systemd/system

log() { printf '[install] %s\n' "$*"; }

need_root() {
    [ "$(id -u)" = 0 ] || { printf 'run as root (sudo)\n' >&2; exit 1; }
}

have() { command -v "$1" >/dev/null 2>&1; }

# --- 1. distro packages -----------------------------------------------------------
install_apt_deps() {
    [ -f /etc/debian_version ] || { log "not Debian/Ubuntu — install deps manually"; return 0; }
    _missing=''
    for p in git curl jq python3 ca-certificates rsync openssl bc file; do
        have "$p" || _missing="$_missing $p"
    done
    [ -n "$_missing" ] || { log "apt deps already present"; return 0; }
    log "installing apt deps:$_missing"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    # shellcheck disable=SC2086  # word list
    apt-get install -y $_missing
}

# --- 2. rust + cargo tooling ----------------------------------------------------------
install_cargo_tools() {
    if ! have cargo; then
        log "installing rustup (stable) for root"
        curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal \
            --default-toolchain stable
        . /root/.cargo/env
    else
        log "cargo present: $(cargo --version)"
    fi
    if ! have cargo-audit; then
        log "installing cargo-audit (few minutes)"
        cargo install cargo-audit --locked
    else
        log "cargo-audit present"
    fi
    if ! have sqlx; then
        log "installing sqlx-cli (few minutes)"
        cargo install sqlx-cli --locked --no-default-features --features rustls,postgres
    else
        log "sqlx present"
    fi
    if ! have cargo-nextest; then
        log "installing cargo-nextest (rust-check.yml's test runner — process isolation)"
        cargo install cargo-nextest --locked
    else
        log "cargo-nextest present"
    fi
    # Optional but recommended gates (warn-only when absent):
    for t in cargo-deny cargo-machete cargo-vet cargo-outdated; do
        have "$t" || log "OPTIONAL: cargo install $t --locked  (gate currently skipped)"
    done
}

# Pinned single-file release binaries. gitleaks/trivy publish tarballs; these
# installs untar into /usr/local/bin. Versions are pinned on purpose — bump
# them consciously.
install_gitleaks() {
    have gitleaks && { log "gitleaks present: $(gitleaks version)"; return 0; }
    _v=8.18.2
    _tmp=$(mktemp -d)
    log "installing gitleaks v$_v"
    curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/v$_v/gitleaks_${_v}_linux_x64.tar.gz" \
        | tar xz -C "$_tmp"
    install -m 0755 "$_tmp/gitleaks" /usr/local/bin/gitleaks
    rm -rf "$_tmp"
}

install_trivy() {
    have trivy && { log "trivy present: $(trivy --version | head -1)"; return 0; }
    # v0.58.x never existed as a tag — the original pin 404'd. v0.74.0 is the
    # current release with the Linux-64bit tarball asset.
    _v=0.74.0
    _arch=64bit
    case "$(uname -m)" in
        aarch64|arm64) _arch=ARM64 ;;
    esac
    _tmp=$(mktemp -d)
    log "installing trivy v$_v (${_arch})"
    curl -sSLf "https://github.com/aquasecurity/trivy/releases/download/v$_v/trivy_${_v}_Linux-${_arch}.tar.gz" \
        | tar xz -C "$_tmp"
    install -m 0755 "$_tmp/trivy" /usr/local/bin/trivy
    rm -rf "$_tmp"
}

# zola — needed on the host by the validate stage (marketing/pricing/legal
# gates) and the test stage (ui-foundation include_str!s the built site when
# apps/marketing-zola/public has not been synced yet).
install_zola() {
    # Version-pinned: the marketing Docker build uses 0.22.1, and older
    # host zolas (0.20) do not clean orphan output files from public/ —
    # deleted pages then linger and fail the forbidden-pattern gate with
    # stale content. Replace a mismatched version instead of keeping it.
    _v=0.22.1
    if have zola; then
        if [ "$(zola --version 2>/dev/null | awk '{print $2}')" = "v$_v" ]; then
            log "zola present: $(zola --version)"
            return 0
        fi
        log "zola version mismatch ($(zola --version)) — replacing with v$_v"
    fi
    _tmp=$(mktemp -d)
    log "installing zola v$_v"
    curl -sSL "https://github.com/getzola/zola/releases/download/v${_v}/zola-v${_v}-x86_64-unknown-linux-gnu.tar.gz" \
        | tar xz -C "$_tmp"
    install -m 0755 "$_tmp/zola" /usr/local/bin/zola
    rm -rf "$_tmp"
}

# --- 3. host config -------------------------------------------------------------------
install_etc_conf() {
    install -d -m 0755 "$ETC_DIR"
    if [ -f "$ETC_DIR/pipeline.conf" ]; then
        log "$ETC_DIR/pipeline.conf exists — left untouched"
        return 0
    fi
    cat >"$ETC_DIR/pipeline.conf" <<EOF
# Host-wide pipeline overrides (sourced by ci/pipeline.sh; env vars win).
# See ci/pipeline.conf for the full variable list.
: "\${CI_DEPLOY_DIR:=$DEPLOY_DIR}"
: "\${CI_ENV_FILE:=$DEPLOY_DIR/.env}"
: "\${CI_REF:=main}"
: "\${CI_KEEP_RUNS:=30}"
EOF
    chmod 0644 "$ETC_DIR/pipeline.conf"
    log "wrote $ETC_DIR/pipeline.conf"
}

# --- 4. systemd units --------------------------------------------------------------------
install_units() {
    need_root
    command -v systemctl >/dev/null 2>&1 || { log "no systemd — units skipped"; return 0; }
    for u in apexmail-pipeline.service apexmail-pipeline.timer \
             apexmail-pipeline-webhook.socket apexmail-pipeline-webhook.service; do
        install -m 0644 "$CI_DIR/units/$u" "$UNIT_DST/$u"
    done
    install -m 0755 "$CI_DIR/units/webhook-handler.sh" "$CI_DIR/units/webhook-handler.sh" 2>/dev/null || true
    systemctl daemon-reload
    systemctl enable --now apexmail-pipeline.timer
    log "timer enabled: $(systemctl list-timers apexmail-pipeline.timer --no-pager | sed -n 2p)"
    log "webhook socket is OPTIONAL — enable with:"
    log "  systemctl enable --now apexmail-pipeline-webhook.socket"
}

# --- deploy key ------------------------------------------------------------------------------
install_deploy_key() {
    _key=/root/.ssh/apexmail_deploy_key
    if [ ! -f "$_key" ]; then
        log "generating ed25519 deploy key at $_key"
        install -d -m 0700 /root/.ssh
        ssh-keygen -t ed25519 -N '' -C 'apexmail-ci-deploy-key' -f "$_key" >/dev/null
    else
        log "deploy key already exists at $_key"
    fi
    chmod 0600 "$_key"
    # Wire git to the key (only for github.com).
    grep -q 'Host github.com' /root/.ssh/config 2>/dev/null || cat >>/root/.ssh/config <<EOF

Host github.com
    User git
    IdentityFile $_key
    IdentitiesOnly yes
EOF
    chmod 0600 /root/.ssh/config 2>/dev/null || true
    # The fetch stage picks this up automatically.
    printf 'GIT_SSH_COMMAND="ssh -i %s -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new"\n' \
        "$_key" >"$CI_DIR/deploy-key.env"
    chmod 0600 "$CI_DIR/deploy-key.env"
    log "PUBLIC key below — add it as a READ-ONLY deploy key at"
    log "https://github.com/sbelakho2/ApexMail/settings/keys/new :"
    printf '\n---\n'
    cat "${_key}.pub"
    printf -- '---\n\n'
}

# --- webhook token -------------------------------------------------------------------------------
install_webhook_token() {
    need_root
    install -d -m 0755 "$ETC_DIR"
    if [ -f "$ETC_DIR/webhook-token" ]; then
        log "$ETC_DIR/webhook-token exists — left untouched"
        return 0
    fi
    _tok=$(openssl rand -hex 24)
    printf '%s\n' "$_tok" >"$ETC_DIR/webhook-token"
    chmod 0600 "$ETC_DIR/webhook-token"
    log "webhook token written to $ETC_DIR/webhook-token (0600)"
    log "trigger: curl -H \"X-ApexMail-Token: \$(sudo cat $ETC_DIR/webhook-token)\" \\\n  -d '{\"ref\":\"main\"}' http://127.0.0.1:8088/hooks/pipeline"
}

# --- check ------------------------------------------------------------------------------------------
do_check() {
    _bad=0
    for c in git curl jq python3 docker openssl; do
        have "$c" && log "ok: $c" || { log "MISSING: $c"; _bad=1; }
    done
    for c in cargo cargo-audit sqlx gitleaks trivy zola; do
        if have "$c"; then log "ok: $c"; else log "optional-missing: $c (gate degrades, see ci/README.md)"; fi
    done
    [ -d "$DEPLOY_DIR" ] || log "note: $DEPLOY_DIR not present (dev machine?)"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl is-enabled apexmail-pipeline.timer >/dev/null 2>&1 \
            && log "ok: apexmail-pipeline.timer enabled" \
            || { log "missing: apexmail-pipeline.timer not enabled (run: sudo ci/install.sh units)"; _bad=1; }
    fi
    [ "$_bad" -eq 0 ] && log "check: host ready" || log "check: see items above"
    return "$_bad"
}

case "${1:-all}" in
    all)
        need_root
        install_apt_deps
        install_cargo_tools
        install_gitleaks
        install_trivy
        install_zola
        install_etc_conf
        install_units
        log "install complete — next: sudo ci/install.sh deploy-key"
        ;;
    units)        install_units ;;
    deploy-key)   need_root; install_deploy_key ;;
    webhook-token) install_webhook_token ;;
    check)        do_check ;;
    *)            sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
