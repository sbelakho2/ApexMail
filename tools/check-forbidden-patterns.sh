#!/usr/bin/env bash
set -euo pipefail

FORBIDDEN_PATTERNS=("16192499" "16942833")

# KiwiCaptcha leak tokens (post-build backstop). The source-tree guard lives
# in tools/check-kiwi-marketing-isolation.sh and runs at commit time; this
# array catches any leak that slipped through and made it into the built
# public/ output. See marketing_audit.md v2 §6.
FORBIDDEN_PATTERNS+=("kiwicaptcha" "kiwi-widget" "kiwi-container" "KIWI_WASM_B64" "kcaptcha")

FOUND=0
HTML_FILES=$(find apps/marketing-zola/public -name "*.html" 2>/dev/null || true)

if [ -z "$HTML_FILES" ]; then
  echo "No HTML files found in public/ directory."
  exit 0
fi

for pattern in "${FORBIDDEN_PATTERNS[@]}"; do
  if grep -l "$pattern" $HTML_FILES 2>/dev/null; then
    echo "ERROR: Forbidden pattern '$pattern' found in built HTML files."
    FOUND=1
  fi
done

if [ "$FOUND" -eq 1 ]; then
  echo "Forbidden patterns detected. Failing CI check."
  exit 1
fi

echo "No forbidden patterns found. CI check passed."
exit 0
