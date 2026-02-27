#!/usr/bin/env bash
# ApexMail Toolchain Bootstrap Script
# Installs exact versions of all required tooling to ./.toolchain/
# Can run in network-isolated container with cached artifacts

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TOOLCHAIN_DIR="$PROJECT_ROOT/.toolchain"
CHECKSUMS_FILE="$SCRIPT_DIR/checksums.sha256"

# Version pins - update these for upgrades
NODE_VERSION="20.11.0"
PNPM_VERSION="8.14.0"
RUST_VERSION="1.82.0"
GO_VERSION="1.22.6"

CURL_RETRY_ARGS=(--retry 5 --retry-delay 2 --retry-all-errors)

# Platform detection
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64) ARCH="x64" ;;
  aarch64|arm64) ARCH="arm64" ;;
esac

log() {
  echo "[bootstrap] $(date '+%Y-%m-%d %H:%M:%S') $*"
}

error() {
  echo "[bootstrap] ERROR: $*" >&2
  exit 1
}

verify_checksum() {
  local file="$1"
  local expected="$2"
  local actual
  
  if [[ "$OS" == "darwin" ]]; then
    actual="$(shasum -a 256 "$file" | cut -d' ' -f1)"
  else
    actual="$(sha256sum "$file" | cut -d' ' -f1)"
  fi
  
  if [[ "$actual" != "$expected" ]]; then
    error "Checksum mismatch for $file\nExpected: $expected\nActual: $actual"
  fi
  log "Checksum verified: $file"
}

get_checksum() {
  local name="$1"
  grep "^$name " "$CHECKSUMS_FILE" | cut -d' ' -f2
}

require_checksum() {
  local name="$1"
  local checksum
  checksum="$(get_checksum "$name")"
  if [[ -z "$checksum" ]]; then
    error "Missing required checksum entry for $name in $CHECKSUMS_FILE"
  fi
  echo "$checksum"
}

download_with_retry() {
  local url="$1"
  local output="$2"
  curl -fL "${CURL_RETRY_ARGS[@]}" "$url" -o "$output"
}

verify_archive_integrity() {
  local archive_path="$1"
  if ! tar -tzf "$archive_path" >/dev/null 2>&1; then
    error "Archive integrity check failed for $archive_path"
  fi
}

setup_node() {
  local node_dir="$TOOLCHAIN_DIR/node"
  local node_bin="$node_dir/bin/node"
  
  if [[ -x "$node_bin" ]] && "$node_bin" --version | grep -q "v$NODE_VERSION"; then
    log "Node.js $NODE_VERSION already installed"
    return
  fi
  
  log "Installing Node.js $NODE_VERSION..."
  rm -rf "$node_dir"
  mkdir -p "$node_dir"
  
  local archive_name="node-v${NODE_VERSION}-${OS}-${ARCH}.tar.gz"
  local download_url="https://nodejs.org/dist/v${NODE_VERSION}/${archive_name}"
  local archive_path="$TOOLCHAIN_DIR/downloads/$archive_name"
  
  mkdir -p "$TOOLCHAIN_DIR/downloads"
  
  if [[ ! -f "$archive_path" ]]; then
    download_with_retry "$download_url" "$archive_path"
  fi

  local expected_checksum
  expected_checksum="$(require_checksum "node-${OS}-${ARCH}")"
  verify_checksum "$archive_path" "$expected_checksum"
  verify_archive_integrity "$archive_path"
  
  tar -xzf "$archive_path" -C "$node_dir" --strip-components=1
  log "Node.js $NODE_VERSION installed to $node_dir"
}

setup_pnpm() {
  local node_bin="$TOOLCHAIN_DIR/node/bin/node"
  local pnpm_bin="$TOOLCHAIN_DIR/node/bin/pnpm"
  
  if [[ -x "$pnpm_bin" ]] && "$pnpm_bin" --version | grep -q "$PNPM_VERSION"; then
    log "pnpm $PNPM_VERSION already installed"
    return
  fi
  
  log "Installing pnpm $PNPM_VERSION..."
  export PATH="$TOOLCHAIN_DIR/node/bin:$PATH"
  npm install -g "pnpm@$PNPM_VERSION"
  log "pnpm $PNPM_VERSION installed"
}

setup_rust() {
  local rustup_home="$TOOLCHAIN_DIR/rustup"
  local cargo_home="$TOOLCHAIN_DIR/cargo"
  local rustc_bin="$cargo_home/bin/rustc"
  
  export RUSTUP_HOME="$rustup_home"
  export CARGO_HOME="$cargo_home"
  
  if [[ -x "$rustc_bin" ]] && "$rustc_bin" --version | grep -q "$RUST_VERSION"; then
    log "Rust $RUST_VERSION already installed"
    return
  fi
  
  log "Installing Rust $RUST_VERSION..."
  mkdir -p "$rustup_home" "$cargo_home"

  local rustup_script="$TOOLCHAIN_DIR/downloads/rustup-init.sh"
  mkdir -p "$TOOLCHAIN_DIR/downloads"
  download_with_retry "https://sh.rustup.rs" "$rustup_script"
  sh "$rustup_script" -y --default-toolchain "$RUST_VERSION" --no-modify-path
  
  log "Rust $RUST_VERSION installed"
}

setup_go() {
  local go_dir="$TOOLCHAIN_DIR/go"
  local go_bin="$go_dir/bin/go"
  
  if [[ -x "$go_bin" ]] && "$go_bin" version | grep -q "go$GO_VERSION"; then
    log "Go $GO_VERSION already installed"
    return
  fi
  
  log "Installing Go $GO_VERSION..."
  rm -rf "$go_dir"
  mkdir -p "$go_dir"
  
  local go_os="$OS"
  local go_arch="$ARCH"
  [[ "$go_arch" == "x64" ]] && go_arch="amd64"
  
  local archive_name="go${GO_VERSION}.${go_os}-${go_arch}.tar.gz"
  local download_url="https://go.dev/dl/${archive_name}"
  local archive_path="$TOOLCHAIN_DIR/downloads/$archive_name"
  
  mkdir -p "$TOOLCHAIN_DIR/downloads"
  
  if [[ ! -f "$archive_path" ]]; then
    download_with_retry "$download_url" "$archive_path"
  fi

  local expected_checksum
  expected_checksum="$(require_checksum "go-${go_os}-${go_arch}")"
  verify_checksum "$archive_path" "$expected_checksum"
  verify_archive_integrity "$archive_path"
  
  tar -xzf "$archive_path" -C "$TOOLCHAIN_DIR"
  log "Go $GO_VERSION installed to $go_dir"
}

create_env_script() {
  local env_script="$TOOLCHAIN_DIR/env.sh"
  
  cat > "$env_script" << 'EOF'
#!/usr/bin/env bash
# Source this file to activate the ApexMail toolchain
# Usage: source .toolchain/env.sh

TOOLCHAIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export PATH="$TOOLCHAIN_DIR/node/bin:$TOOLCHAIN_DIR/go/bin:$TOOLCHAIN_DIR/cargo/bin:$PATH"
export RUSTUP_HOME="$TOOLCHAIN_DIR/rustup"
export CARGO_HOME="$TOOLCHAIN_DIR/cargo"
export GOROOT="$TOOLCHAIN_DIR/go"
export GOPATH="$TOOLCHAIN_DIR/gopath"

mkdir -p "$GOPATH"

echo "ApexMail toolchain activated"
echo "  Node: $(node --version 2>/dev/null || echo 'not found')"
echo "  pnpm: $(pnpm --version 2>/dev/null || echo 'not found')"
echo "  Rust: $(rustc --version 2>/dev/null || echo 'not found')"
echo "  Go:   $(go version 2>/dev/null || echo 'not found')"
EOF
  
  chmod +x "$env_script"
  log "Environment script created: $env_script"
}

main() {
  log "ApexMail Toolchain Bootstrap"
  log "Project root: $PROJECT_ROOT"
  log "Toolchain dir: $TOOLCHAIN_DIR"
  log "Platform: $OS-$ARCH"
  
  mkdir -p "$TOOLCHAIN_DIR"
  
  setup_node
  setup_pnpm
  setup_rust
  setup_go
  create_env_script
  
  log "Bootstrap complete!"
  log "Activate with: source .toolchain/env.sh"
}

main "$@"
