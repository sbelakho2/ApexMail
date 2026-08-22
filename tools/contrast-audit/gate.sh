#!/bin/sh
# =============================================================================
# tools/contrast-audit/gate.sh — CI gate for WCAG 2.1 AA text contrast.
# =============================================================================
# Audits a representative subset with tools/contrast-audit/audit.mjs --gate:
#   * every console (web) + control-plane fixture route, all three themes
#     (light / prefers-dark / .dark-class)
#   * a curated top-20 of the built marketing pages, both themes
# and requires ZERO AA text failures (any page load error also fails).
#
# Prerequisites (the gate degrades to a loud skip when they are missing, so
# a bare runner without browsers cannot silently pass):
#   * node + tools/contrast-audit/node_modules (npm install in that dir)
#   * playwright's chromium (channel "chromium"; `npx playwright install chromium`)
#   * tools/contrast-audit/fixtures/ — exported when absent via
#     APEX_EXPORT_ALL_UI_ROUTES=1 cargo run --bin export_visual_fixtures
#   * apps/marketing-zola/public/ — built when absent via `zola build`
#
# Report: tools/contrast-audit/reports/gate-report.json
# Full-surface audit (all 116 marketing pages, writes violations.json):
#   node tools/contrast-audit/audit.mjs
# =============================================================================
set -eu

HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
REPO=$(CDPATH='' cd -- "$HERE/../.." && pwd -P)

# --- marketing build output (audited surface + compile input) --------------------
if [ ! -f "$REPO/apps/marketing-zola/public/index.html" ]; then
    if command -v zola >/dev/null 2>&1; then
        echo "[gate] building marketing output (zola build)"
        (cd "$REPO/apps/marketing-zola" && zola build >/dev/null 2>&1)
    else
        echo "[gate] FAIL: apps/marketing-zola/public is missing and zola is not installed" >&2
        exit 1
    fi
fi

# --- console/control-plane fixtures ------------------------------------------------
if [ ! -f "$HERE/fixtures/manifest.json" ]; then
    echo "[gate] exporting UI fixtures (APEX_EXPORT_ALL_UI_ROUTES=1 cargo run --bin export_visual_fixtures)"
    (cd "$REPO/services/mail-server" && \
        APEX_EXPORT_ALL_UI_ROUTES=1 cargo run --bin export_visual_fixtures -- "$HERE/fixtures" >/dev/null)
fi

# --- toolchain ------------------------------------------------------------------------
if ! command -v node >/dev/null 2>&1; then
    echo "[gate] FAIL: node is required" >&2
    exit 1
fi
if [ ! -d "$HERE/node_modules/playwright" ]; then
    echo "[gate] FAIL: playwright not installed — run: (cd tools/contrast-audit && npm install)" >&2
    exit 1
fi

cd "$HERE"
exec node audit.mjs --gate
