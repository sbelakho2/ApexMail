#!/usr/bin/env bash
# verify-asset-parity.sh — the tested-browser-bytes == packaged-bytes ==
# released-bytes invariant, enforced outside the build too.
#
# The canonical browser assets live in packages/kiwicaptcha-wasm/assets
# and are mirrored byte-identically into the core crate's embedded
# resources/ and the Symfony bundle's Resources/public/. A stale mirror
# means a different installation path receives different JavaScript
# behavior (the R76 hCaptcha readiness gate was once shipped to the
# canonical asset but not the mirrors — the CI parity job caught it).
# This gate byte-compares every mirror against the canonical assets and
# fails when any of them drift. build.sh runs the same comparison after
# every rebuild.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

CANON="packages/kiwicaptcha-wasm/assets"
FAILED=0
for mirror in packages/kiwicaptcha/resources packages/kiwicaptcha/integrations/symfony/Resources/public; do
  for f in widget-driver.js widget.css kiwicaptcha-wasm.js kiwi-worker.js; do
    if ! cmp -s "$CANON/$f" "$mirror/$f"; then
      echo "ASSET PARITY FAILED: $mirror/$f differs from $CANON/$f" >&2
      FAILED=1
    fi
  done
done
if [[ "$FAILED" == "1" ]]; then
  echo "run packages/kiwicaptcha-wasm/build.sh to regenerate and re-mirror the assets" >&2
  exit 1
fi
echo "verify-asset-parity: OK (all mirrors byte-identical to the canonical assets)"
