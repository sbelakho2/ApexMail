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
