#!/usr/bin/env bash
# Regenerates assets/kiwicaptcha-wasm.js (the widget's embedded WASM + glue).
# Requires: wasm-pack, wasm32-unknown-unknown target, node.
set -euo pipefail
cd "$(dirname "$0")"
wasm-pack build --target web --release
node build-embed.mjs
echo "assets/kiwicaptcha-wasm.js regenerated"
