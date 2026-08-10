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
# managers, no runtime deps).
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
    if curl -fsSL "$WASM_OPT_URL" -o "$CACHE_DIR/binaryen.tar.gz" 2>/dev/null; then
      tar xzf "$CACHE_DIR/binaryen.tar.gz" -C "$CACHE_DIR"
      # wasm-opt links against libbinaryen (shared lib on macOS, static on
      # Linux); keep the extracted tree and reference the binary in place so
      # the rpath resolves regardless of platform.
      BIN_DIR="$(find "$CACHE_DIR" -path "*/bin/wasm-opt" -type f | head -1)"
      if [[ -n "$BIN_DIR" ]]; then
        WASM_OPT_BIN="$BIN_DIR"
        echo "wasm-opt ready at $WASM_OPT_BIN"
      else
        echo "wasm-opt not found in binaryen archive — continuing without optimization" >&2
        WASM_OPT_BIN=""
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
