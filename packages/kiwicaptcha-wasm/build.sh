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
"$WASM_BINDGEN_BIN" --target web --out-dir pkg target/wasm32-unknown-unknown/release/kiwicaptcha_wasm.wasm
cargo run --release --manifest-path tools/embed/Cargo.toml -- pkg assets/kiwicaptcha-wasm.js
echo "assets/kiwicaptcha-wasm.js regenerated"
