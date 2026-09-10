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
# F52: before certifying real pages, the audit runs its CLASSIFIER SELF-TEST
# (white text on an opaque white gradient with a black fallback MUST fail;
# a passing gradient must pass; sticky headers must be measured via element
# screenshots) — a gate that cannot classify known inputs cannot certify
# anything, so a self-test failure fails the gate outright.
#
# Prerequisites (missing tooling FAILS the gate — a required gate can never
# pass without execution):
#   * node + tools/contrast-audit/node_modules (npm install in that dir)
#   * playwright's chromium (channel "chromium"; `npx playwright install chromium`)
#   * tools/contrast-audit/fixtures/ — exported when absent via
#     APEX_EXPORT_ALL_UI_ROUTES=1 cargo run --bin export_visual_fixtures
#   * apps/marketing-zola/public/ — built when absent via `zola build`
#
# Report: tools/contrast-audit/reports/gate-report.json
# Execution record (F52): tools/contrast-audit/reports/gate-execution.json —
#   an executed/skipped/failed result bound to the reviewed git revision,
#   written next to the report.
# Full-surface audit (all 116 marketing pages, writes violations.json):
#   node tools/contrast-audit/audit.mjs
# Self-test only: node tools/contrast-audit/audit.mjs --self-test
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

# --- run + persist the execution record (F52) -----------------------------------------
# The record is bound to the reviewed revision (HEAD, plus a dirty flag so
# uncommitted working-tree runs are not mistaken for clean-revision runs)
# and written next to the gate report, whatever the outcome.
REV=$(git -C "$REPO" rev-parse HEAD 2>/dev/null || echo unknown)
DIRTY_COUNT=$(git -C "$REPO" status --porcelain=v1 2>/dev/null | wc -l | tr -d '[:space:]')
STATUS_DIRTY=false
[ "${DIRTY_COUNT:-0}" -gt 0 ] 2>/dev/null && STATUS_DIRTY=true
mkdir -p "$HERE/reports"

write_execution_record() {
    # $1 = status (executed | failed), $2 = detail
    node -e '
const fs = require("fs");
const [file, revision, status, dirty, detail] = process.argv.slice(1);
fs.writeFileSync(file, JSON.stringify({
  tool: "tools/contrast-audit/gate.sh",
  gate: "wcag-aa-contrast",
  revision,
  dirtyWorkingTree: dirty === "true",
  status,
  detail: detail || "",
  recordedAt: new Date().toISOString(),
}, null, 1) + "\n");
' "$HERE/reports/gate-execution.json" "$REV" "$1" "$STATUS_DIRTY" "${2:-}"
}

cd "$HERE"
GATE_RC=0
node audit.mjs --gate || GATE_RC=$?
if [ "$GATE_RC" -eq 0 ]; then
    write_execution_record executed ""
else
    write_execution_record failed "audit exit code $GATE_RC (see reports/gate-report.json and reports/self-test.json)"
fi
exit "$GATE_RC"
