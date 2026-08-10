#!/usr/bin/env bash
# Syncs the shared widget assets from the Rust packages into this PHP package.
#
# The KiwiCaptcha widget is a single source of truth (Rust); the Twig template
# inlines the same CSS, WASM solver embed, and driver script so the PHP and
# Rust implementations can never drift apart. Run this after rebuilding the
# wasm solver (packages/kiwicaptcha-wasm/build.sh) or editing the driver/CSS.
set -euo pipefail
cd "$(dirname "$0")/.."

ROOT="$(cd ../.. && pwd)"
DEST="Resources/public"

mkdir -p "$DEST"

cp "$ROOT/packages/kiwicaptcha-wasm/assets/kiwicaptcha-wasm.js" "$DEST/kiwicaptcha-wasm.js"
cp "$ROOT/packages/kiwicaptcha-wasm/assets/widget-driver.js"   "$DEST/widget-driver.js"
cp "$ROOT/packages/kiwicaptcha-wasm/assets/widget.css"          "$DEST/widget.css"

echo "Widget assets synced to $DEST"
