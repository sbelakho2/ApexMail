#!/usr/bin/env bash
set -euo pipefail

FORBIDDEN_PATTERNS=("16192499" "16942833")

# KiwiCaptcha leak tokens (post-build backstop). The source-tree guard lives
# in tools/check-kiwi-marketing-isolation.sh and runs at commit time; this
# array catches any leak that slipped through and made it into the built
# public/ output. See marketing_audit.md v2 §6.
FORBIDDEN_PATTERNS+=("kiwicaptcha" "kiwi-widget" "kiwi-container" "KIWI_WASM_B64" "kcaptcha")

# Old-generation marketing vocabulary (external review 2026-09-08 §17):
# phrases from the retired site generation — and the undocumented "signed
# proof" contract (§1) and "static explorer" contradiction (§8) — that
# must never reappear in built output while current claims say otherwise.
FORBIDDEN_PATTERNS+=(
  "Apex Style"
  "System Integrity Verified"
  "Infrastructure Operational"
  "Initialize Deployment"
  "deterministic deliverability"
  "built-in regulatory compliance"
  "HIPAA BAA"
  "HIPAA Ready"
  "proof 0x"
  "Proof 0x"
  "signed proof"
  "Signed proof"
  "static API explorer"
  "live server requests"
  "Endpoint Lanes"
  "Operator Notes"
  "Comparative Mappings"
  "Execution Domain"
  "HMAC-Signed Telemetry"
  "high-fidelity telemetry"
  "Compliance-as-Code"
  "Economic Model"
  "High-Precision Infrastructure"
  "High-precision infrastructure"
  "Deterministic Outcomes"
  "Deterministic outcomes"
  "Pure engineering, no fluff"
)

FOUND=0
HTML_FILES=$(find apps/marketing-zola/public -name "*.html" 2>/dev/null || true)

# The gate scans the BUILT site, so it is meaningful only after a zola build
# (CI runs it in zola_gates, after the build). "No input" must not silently
# read as "no violations": --require-build (used by CI) turns the absent-site
# case into a hard failure; without it (the pre-commit hook, a fresh
# checkout) the skip is announced explicitly.
if [ -z "$HTML_FILES" ]; then
  if [ "${1:-}" = "--require-build" ]; then
    echo "ERROR: no built HTML under apps/marketing-zola/public — run the zola build first (CI runs this gate right after the zola_gates build)." >&2
    exit 1
  fi
  echo "No HTML files found in public/ directory — gate SKIPPED (needs a built site; run the zola build, or pass --require-build to fail instead)."
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
