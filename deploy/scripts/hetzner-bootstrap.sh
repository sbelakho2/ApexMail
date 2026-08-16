#!/usr/bin/env bash
# =============================================================================
# ApexMail — Hetzner host bootstrap (one-time, idempotent)
# =============================================================================
# Run this ONCE on the production Hetzner host (95.216.226.51 — matches the
# Makefile SERVER_HOST and the DNS A records in ARCHITECTURE.md; the CI
# workflow takes the host from the HETZNER_SSH_HOST secret) as root after
# the hetzner-db-mac.pub SSH key has been installed in /root/.ssh/authorized_keys.
#
# Local usage:
#   scp deploy/scripts/hetzner-bootstrap.sh root@95.216.226.51:/root/
#   ssh root@95.216.226.51 'bash /root/hetzner-bootstrap.sh'
#
# Idempotent: safe to re-run.
# =============================================================================
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
export APT_LISTCHANGES_FRONTEND=none
export NEEDRESTART_MODE=a
export NEEDRESTART_SUSPEND=1

DEPLOY_DIR="${DEPLOY_DIR:-/opt/apexmail}"

# Preseed grub-efi-amd64 install-devices so postinst never blocks on TTY
preseed_grub() {
  if command -v debconf-set-selections >/dev/null 2>&1; then
    debconf-set-selections <<'EOF'
grub-efi-amd64 grub-efi/install_devices multiselect /dev/nvme0n1, /dev/nvme1n1
grub-efi-amd64-signed grub-efi/install_devices multiselect /dev/nvme0n1, /dev/nvme1n1
grub2-common grub-efi/install_devices multiselect /dev/nvme0n1, /dev/nvme1n1
grub-efi-amd64 grub-efi/install_devices_disks_changed multiselect /dev/nvme0n1, /dev/nvme1n1
grub-efi-amd64-signed grub-efi/install_devices_disks_changed multiselect /dev/nvme0n1, /dev/nvme1n1
EOF
  fi
}

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
  os_id="$(. /etc/os-release && echo "${ID}")"
  case "${os_id}" in
    ubuntu) docker_repo="https://download.docker.com/linux/ubuntu" ;;
    debian) docker_repo="https://download.docker.com/linux/debian" ;;
    *)      docker_repo="https://download.docker.com/linux/debian" ;;
  esac
  curl -fsSL "${docker_repo}/gpg" \
    | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  codename="$(. /etc/os-release && echo "${VERSION_CODENAME}")"
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] ${docker_repo} ${codename} stable" \
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
  log "Configuring UFW (allow 22, 80, 443, 25, 587, 465, 993, 2525, 2526)"
  ufw --force reset >/dev/null
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow 22/tcp
  ufw allow 80/tcp
  ufw allow 443/tcp
  ufw allow 25/tcp
  ufw allow 587/tcp
  ufw allow 465/tcp
  # IMAPS (imap-server publishes 993; 143 is intentionally closed — SSL-only)
  ufw allow 993/tcp
  # Bounce (VERP/DSN) and FBL (abuse/complaint) SMTP endpoints published by
  # the production mta service (docker-compose.prod.yml).
  ufw allow 2525/tcp
  ufw allow 2526/tcp
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
  preseed_grub
  install_baseline_tools
  install_docker
  configure_firewall
  prepare_deploy_dir
  harden_sshd
  log "Bootstrap complete. Deploy directory: ${DEPLOY_DIR}"
  log "Next: trigger the GitHub Action 'Deploy — Hetzner' (workflow_dispatch)."
}

main "$@"
