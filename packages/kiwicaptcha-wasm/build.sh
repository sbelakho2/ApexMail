#!/usr/bin/env bash
# Regenerates assets/kiwicaptcha-wasm.js (the widget's embedded WASM + glue).
# Requires: cargo, the wasm32-unknown-unknown target, and wasm-bindgen-cli
# (a Rust binary; installed via `cargo install` if missing).
# Pure Rust pipeline — no Node.js, no wasm-pack.
set -euo pipefail
cd "$(dirname "$0")"

WASM_BINDGEN_VERSION="0.2.127"
WASM_BINDGEN_BIN="${WASM_BINDGEN_BIN:-wasm-bindgen}"

if ! command -v "$WASM_BINDGEN_BIN" >/dev/null 2>&1; then
  echo "wasm-bindgen-cli not found; installing ${WASM_BINDGEN_VERSION} via cargo..." >&2
  cargo install wasm-bindgen-cli --version "$WASM_BINDGEN_VERSION"
fi

cargo build --release --target wasm32-unknown-unknown

# Optimize the wasm with binaryen (wasm-opt -O) if available. wasm-opt is a
# C++ binary — NOT Node.js — and is optional: the pipeline works without it,
# but -O typically shrinks the wasm ~20% and speeds up the hot solver loops.
# Download a pinned, checksum-verified wasm-opt on first use (no package
# managers, no runtime deps). The tarball is verified with SHA-256 before
# extraction; platforms with no known hash (or a hash mismatch) print a
# warning and SKIP optimization — the build never fails on it. Set
# WASM_OPT_SHA256 to override the expected hash for any platform.
# Known hashes (computed with `shasum -a 256` at pin time):
#   Darwin-arm64 version_119: c12dffafb3e3274026268e90577bd86d98186f7be32457618672f8ca437d8d53
# Known hashes per platform (computed with `shasum -a 256` at pin time).
# Note: macOS ships GNU bash 3.2, which has no associative arrays, so the
# {"platform": "sha256"} map is expressed as a function (same semantics).
#   Darwin-arm64 version_119: c12dffafb3e3274026268e90577bd86d98186f7be32457618672f8ca437d8d53
known_wasm_opt_sha256() {
  case "${OS}-${ARCH}" in
    Darwin-arm64) echo "c12dffafb3e3274026268e90577bd86d98186f7be32457618672f8ca437d8d53" ;;
    *) echo "" ;;
  esac
}
sha256_of() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    sha256sum "$1" | awk '{print $1}'
  fi
}
WASM_OPT_BIN="${WASM_OPT_BIN:-}"
if [[ -z "$WASM_OPT_BIN" ]]; then
  CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/kiwicaptcha-wasm"
  WASM_OPT_BIN="$CACHE_DIR/wasm-opt"
fi
if [[ ! -x "$WASM_OPT_BIN" ]]; then
  mkdir -p "$(dirname "$WASM_OPT_BIN")"
  OS="$(uname -s)"
  ARCH="$(uname -m)"
  case "${OS}-${ARCH}" in
    Linux-x86_64)  WASM_OPT_ARCH="x86_64-linux" ;;
    Linux-aarch64) WASM_OPT_ARCH="aarch64-linux" ;;
    Darwin-arm64)  WASM_OPT_ARCH="arm64-macos" ;;
    Darwin-x86_64) WASM_OPT_ARCH="x86_64-macos" ;;
    *)             WASM_OPT_ARCH="" ;;
  esac
  if [[ -n "$WASM_OPT_ARCH" ]]; then
    WASM_OPT_VERSION="version_119"
    WASM_OPT_URL="https://github.com/WebAssembly/binaryen/releases/download/${WASM_OPT_VERSION}/binaryen-${WASM_OPT_VERSION}-${WASM_OPT_ARCH}.tar.gz"
    EXPECTED_SHA256="${WASM_OPT_SHA256:-$(known_wasm_opt_sha256)}"
    if [[ -z "$EXPECTED_SHA256" ]]; then
      echo "no known SHA-256 for ${OS}-${ARCH} — skipping optimization" >&2
      WASM_OPT_BIN=""
    elif curl -fsSL "$WASM_OPT_URL" -o "$CACHE_DIR/binaryen.tar.gz" 2>/dev/null; then
      ACTUAL_SHA256="$(sha256_of "$CACHE_DIR/binaryen.tar.gz")"
      if [[ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]]; then
        echo "binaryen tarball SHA-256 mismatch (got $ACTUAL_SHA256, expected $EXPECTED_SHA256) — skipping optimization" >&2
        WASM_OPT_BIN=""
      else
        tar xzf "$CACHE_DIR/binaryen.tar.gz" -C "$CACHE_DIR"
        # wasm-opt links against libbinaryen (shared lib on macOS, static on
        # Linux); keep the extracted tree and reference the binary in place so
        # the rpath resolves regardless of platform.
        BIN_DIR="$(find "$CACHE_DIR" -path "*/bin/wasm-opt" -type f | head -1)"
        if [[ -n "$BIN_DIR" ]]; then
          WASM_OPT_BIN="$BIN_DIR"
          echo "wasm-opt ready at $WASM_OPT_BIN (SHA-256 verified)"
        else
          echo "wasm-opt not found in binaryen archive — continuing without optimization" >&2
          WASM_OPT_BIN=""
        fi
      fi
    else
      echo "wasm-opt download failed — continuing without optimization" >&2
      WASM_OPT_BIN=""
    fi
  fi
fi
if [[ -n "$WASM_OPT_BIN" && -x "$WASM_OPT_BIN" ]]; then
  "$WASM_OPT_BIN" -O target/wasm32-unknown-unknown/release/kiwicaptcha_wasm.wasm \
      -o target/wasm32-unknown-unknown/release/kiwicaptcha_wasm.opt.wasm
  mv target/wasm32-unknown-unknown/release/kiwicaptcha_wasm.opt.wasm \
     target/wasm32-unknown-unknown/release/kiwicaptcha_wasm.wasm
fi

"$WASM_BINDGEN_BIN" --target web --out-dir pkg target/wasm32-unknown-unknown/release/kiwicaptcha_wasm.wasm
cargo run --release --manifest-path tools/embed/Cargo.toml -- pkg assets/kiwicaptcha-wasm.js
echo "assets/kiwicaptcha-wasm.js regenerated"
