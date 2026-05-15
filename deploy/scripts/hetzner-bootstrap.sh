#!/usr/bin/env bash
# =============================================================================
# ApexMail — Hetzner host bootstrap (one-time, idempotent)
# =============================================================================
# Run this ONCE on a fresh Hetzner host (37.27.119.181) as root after the
# hetzner-db-mac.pub SSH key has been installed in /root/.ssh/authorized_keys.
#
# Local usage:
#   scp deploy/scripts/hetzner-bootstrap.sh root@37.27.119.181:/root/
#   ssh root@37.27.119.181 'bash /root/hetzner-bootstrap.sh'
#
# Idempotent: safe to re-run.
# =============================================================================
set -euo pipefail

DEPLOY_DIR="${DEPLOY_DIR:-/opt/apexmail}"

log() { printf '[bootstrap] %s\n' "$*"; }

require_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "Must run as root" >&2
    exit 1
  fi
}

install_docker() {
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    log "Docker + compose plugin already installed"
    return
  fi
  log "Installing Docker Engine + compose plugin"
  apt-get update -y
  apt-get install -y ca-certificates curl gnupg lsb-release
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/debian/gpg \
    | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  codename="$(. /etc/os-release && echo "${VERSION_CODENAME}")"
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian ${codename} stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  systemctl enable --now docker
}

install_baseline_tools() {
  log "Installing baseline utilities (rsync, ufw, fail2ban)"
  apt-get install -y rsync ufw fail2ban ca-certificates curl
}

configure_firewall() {
  if ! command -v ufw >/dev/null 2>&1; then return; fi
  log "Configuring UFW (allow 22, 80, 443, 25, 587, 465)"
  ufw --force reset >/dev/null
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow 22/tcp
  ufw allow 80/tcp
  ufw allow 443/tcp
  ufw allow 25/tcp
  ufw allow 587/tcp
  ufw allow 465/tcp
  ufw --force enable
  ufw status verbose
}

prepare_deploy_dir() {
  log "Preparing deploy directory at ${DEPLOY_DIR}"
  install -d -m 750 "${DEPLOY_DIR}"
  install -d -m 750 "${DEPLOY_DIR}/secrets"
}

harden_sshd() {
  log "Hardening sshd (disable password auth, keep publickey only)"
  sed -i \
    -e 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' \
    -e 's/^#\?ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' \
    -e 's/^#\?PermitRootLogin.*/PermitRootLogin prohibit-password/' \
    /etc/ssh/sshd_config
  systemctl reload ssh || systemctl reload sshd || true
}

main() {
  require_root
  install_baseline_tools
  install_docker
  configure_firewall
  prepare_deploy_dir
  harden_sshd
  log "Bootstrap complete. Deploy directory: ${DEPLOY_DIR}"
  log "Next: trigger the GitHub Action 'Deploy — Hetzner' (workflow_dispatch)."
}

main "$@"
