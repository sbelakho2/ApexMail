#!/usr/bin/env bash
# =============================================================================
# check-kiwi-marketing-isolation.sh
#
# Enforces the hard boundary between KiwiCaptcha (the standalone proof-of-work
# CAPTCHA package at packages/kiwicaptcha*) and the ApexMail marketing site
# (apps/marketing-zola). KiwiCaptcha must NEVER appear anywhere in the
# marketing build — not as a script, an asset, a CSS class, a config key, or
# rendered HTML. The marketing site sells ApexMail; KiwiCaptcha is a separate
# product with its own brand identity, and the two must not be conflated.
#
# This guard scans the marketing SOURCE trees (pre-build) so leaks are caught
# at commit time, before they ever reach a rendered page. The companion guard
# in tools/check-forbidden-patterns.sh scans the BUILT public/ output as a
# post-build backstop.
#
# Exit codes:
#   0 — no KiwiCaptcha references found (boundary intact)
#   1 — KiwiCaptcha reference detected in marketing source (boundary breached)
#
# See: marketing_audit.md v2 §6, APEXMAIL_KIWI_SEPARATION.md
# =============================================================================
set -euo pipefail

# Tokens that, if present in marketing, indicate a KiwiCaptcha leak. Each
# pattern is anchored to KiwiCaptcha-specific identifiers (not generic words),
# so ApexMail's own "kiwi" mascot branding (templates/partials/kiwi-logo.html,
# static/icon.svg, static/favicon.svg) is intentionally NOT matched: those
# assets use the bare word "kiwi" inside the ApexMail-owned kiwi-logo partial
# and are prefixed with `apex-` in their identifiers to stay distinct.
#
# To allow ApexMail's mascot branding while blocking KiwiCaptcha, the patterns
# below match KiwiCaptcha's product names but explicitly allow the ApexMail
# mascot partial via a negative path filter (see ALLOWED_PATHS below).
FORBIDDEN_PATTERNS=(
  'kiwicaptcha'         # product name (any case matched via -i)
  'kiwi-captcha'
  'kiwi_captcha'
  'kiwi-widget'         # KiwiCaptcha widget class
  'kiwi-container'      # KiwiCaptcha container class
  'KIWI_WASM_B64'       # KiwiCaptcha WASM embed token
  'kcaptcha'            # KiwiCaptcha short slug
)

# ApexMail-owned mascot assets that legitimately contain "kiwi" — these are
# the new brand-mark artwork, NOT KiwiCaptcha. Skip them when matching the
# bare-word patterns above. (None of the FORBIDDEN_PATTERNS above are the bare
# word "kiwi", so this allowlist is belt-and-suspenders.)
ALLOWED_PATHS=(
  'apps/marketing-zola/templates/partials/kiwi-logo.html'
  'apps/marketing-zola/static/icon.svg'
  'apps/marketing-zola/static/favicon.svg'
)

# Marketing source trees to scan (NOT public/ — that is build output and is
# covered by tools/check-forbidden-patterns.sh).
SOURCE_PATHS=(
  "apps/marketing-zola/content"
  "apps/marketing-zola/templates"
  "apps/marketing-zola/static"
  "apps/marketing-zola/config.toml"
  "apps/marketing-zola/data"
)

FOUND=0
HITS=""

for src_path in "${SOURCE_PATHS[@]}"; do
  [ -e "$src_path" ] || continue

  # Build a grep exclude list from ALLOWED_PATHS (relative to repo root).
  excludes=()
  for ap in "${ALLOWED_PATHS[@]}"; do
    excludes+=( --exclude="$ap" )
  done

  for pattern in "${FORBIDDEN_PATTERNS[@]}"; do
    # -r recursive, -i case-insensitive, -I skip binary files, -l list files.
    # --exclude ensures the ApexMail mascot assets are never flagged.
    matches=$(grep -rIl ${excludes[@]} -e "$pattern" "$src_path" 2>/dev/null || true)
    if [ -n "$matches" ]; then
      while IFS= read -r file; do
        # Belt-and-suspenders: skip allowed mascot assets by absolute path.
        case "$file" in
          */templates/partials/kiwi-logo.html|*/static/icon.svg|*/static/favicon.svg)
            continue
            ;;
        esac
        # Pull the matching line for a useful error message.
        line=$(grep -In -e "$pattern" "$file" 2>/dev/null | head -1 || true)
        HITS+="  - $file: $line"$'\n'
        FOUND=1
      done <<< "$matches"
    fi
  done
done

if [ "$FOUND" -eq 1 ]; then
  echo "ERROR: KiwiCaptcha reference detected in ApexMail marketing source." >&2
  echo "       KiwiCaptcha must remain completely separate from the ApexMail" >&2
  echo "       marketing site. See marketing_audit.md v2 §6." >&2
  echo "" >&2
  echo "Offending files:" >&2
  printf "%s" "$HITS" >&2
  echo "" >&2
  echo "If you intended to add ApexMail mascot branding (not KiwiCaptcha)," >&2
  echo "use the apex-prefixed assets in templates/partials/kiwi-logo.html," >&2
  echo "static/icon.svg, or static/favicon.svg — those are allowlisted." >&2
  exit 1
fi

echo "OK: ApexMail marketing source is free of KiwiCaptcha references."
exit 0
