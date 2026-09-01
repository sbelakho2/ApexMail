#!/usr/bin/env bash
# Syncs the shared widget assets from the Rust packages into this Symfony
# bundle's Resources/public.
#
# The KiwiCaptcha widget is a single source of truth (Rust). This bundle
# inlines the same CSS, WASM solver embed, and driver script at render time,
# so the PHP and Rust implementations can never drift apart and the widget
# makes zero external requests.
#
# Run this after rebuilding the wasm solver
# (packages/kiwicaptcha-wasm/build.sh) or editing the driver/CSS.
set -euo pipefail
# Every copied asset must stay byte-identical to the canonical
# packages/kiwicaptcha-wasm/assets: a stale mirror changes the behavior
# a given installation path receives. The same parity is enforced by
# packages/kiwicaptcha/tools/verify-asset-parity.sh and by build.sh.
HERE="$(cd "$(dirname "$0")" && pwd)"        # .../integrations/symfony/bin
BUNDLE_DIR="$(cd "$HERE/.." && pwd)"         # .../integrations/symfony
ROOT="$(cd "$BUNDLE_DIR/../../../.." && pwd)" # repo root
DEST="$BUNDLE_DIR/Resources/public"

mkdir -p "$DEST"

cp "$ROOT/packages/kiwicaptcha-wasm/assets/kiwicaptcha-wasm.js" "$DEST/kiwicaptcha-wasm.js"
cp "$ROOT/packages/kiwicaptcha-wasm/assets/kiwi-worker.js"       "$DEST/kiwi-worker.js"
cp "$ROOT/packages/kiwicaptcha-wasm/assets/widget-driver.js"   "$DEST/widget-driver.js"
cp "$ROOT/packages/kiwicaptcha-wasm/assets/widget.css"          "$DEST/widget.css"
cp "$ROOT/packages/kiwicaptcha-wasm/assets/execution-interpreter.js" "$DEST/execution-interpreter.js"

echo "Widget assets synced to $DEST"
