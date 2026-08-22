#!/bin/sh
# =============================================================================
# tools/contrast-audit/layout-gate.sh — CI gate for layout spills.
# =============================================================================
# Runs layout-audit.mjs over every console (web) + control-plane fixture and
# every built marketing page at desktop AND mobile widths in all themes,
# failing on: document horizontal overflow, content past the viewport, text
# escaping or cut off in its box, invisible text, broken images, and
# overlapping content cards — the defect class browsers silently repair by
# re-nesting the page (the CP unclosed-header bug, the compare-page span that
# swallowed the footer).
#
# Prerequisites (same self-provisioning contract as gate.sh; loud failure
# when the toolchain is missing so a bare runner cannot silently pass):
#   * node + tools/contrast-audit/node_modules (npm install in that dir)
#   * playwright chromium
#   * tools/contrast-audit/fixtures/ — exported when absent via
#     APEX_EXPORT_ALL_UI_ROUTES=1 cargo run --bin export_visual_fixtures
#   * apps/marketing-zola/public/ — built when absent via `zola build`
#
# Report: tools/contrast-audit/reports/layout/violations.json
# Triage screenshots for flagged runs: reports/layout/screenshots/
# =============================================================================
set -eu

HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
REPO=$(CDPATH='' cd -- "$HERE/../.." && pwd -P)

# --- marketing build output (audited surface) -------------------------------------
if [ ! -f "$REPO/apps/marketing-zola/public/index.html" ]; then
    if command -v zola >/dev/null 2>&1; then
        echo "[layout-gate] building marketing output (zola build)"
        (cd "$REPO/apps/marketing-zola" && zola build >/dev/null 2>&1)
    else
        echo "[layout-gate] FAIL: apps/marketing-zola/public is missing and zola is not installed" >&2
        exit 1
    fi
fi

# --- console/control-plane fixtures ------------------------------------------------
if [ ! -f "$HERE/fixtures/manifest.json" ]; then
    echo "[layout-gate] exporting UI fixtures (APEX_EXPORT_ALL_UI_ROUTES=1 cargo run --bin export_visual_fixtures)"
    (cd "$REPO/services/mail-server" && \
        APEX_EXPORT_ALL_UI_ROUTES=1 cargo run --bin export_visual_fixtures -- "$HERE/fixtures" >/dev/null)
fi

# --- toolchain ------------------------------------------------------------------------
if ! command -v node >/dev/null 2>&1; then
    echo "[layout-gate] FAIL: node is required" >&2
    exit 1
fi
if [ ! -d "$HERE/node_modules/playwright" ]; then
    echo "[layout-gate] FAIL: playwright not installed — run: (cd tools/contrast-audit && npm install)" >&2
    exit 1
fi

cd "$HERE"
exec node layout-audit.mjs
