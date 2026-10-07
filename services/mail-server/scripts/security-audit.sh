#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# ApexMail — Local Security Audit Script
# Runs cargo-audit and generates a human-readable report.
#
# FAIL-CLOSED contract (coverage audit U-1): a cargo-audit run that
# does not produce parseable JSON, or that exits non-zero without
# reporting a vulnerability count, is an AUDIT FAILURE — never a
# clean audit. Typed exit codes:
#   0  clean (no vulnerabilities; warnings gate passed)
#   1  vulnerabilities found (or FAIL_ON_WARNINGS=1 and warnings found)
#   2  audit tool / advisory-DB failure (non-zero exit, no vuln count)
#   3  cargo-audit output was not parseable JSON (jq -e failure)
#
# Environment:
#   REPORT_DIR        report output dir (default: <workspace>/target/security-audit)
#   FAIL_ON_WARNINGS  1 = unmaintained/unsound/yanked warning-class notices
#                     fail the run (exit 1); default 0, matching the CI
#                     security lane's warning policy (logged, not gating).
# ─────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPORT_DIR="${REPORT_DIR:-${PROJECT_ROOT}/target/security-audit}"
TIMESTAMP="$(date -u +%Y%m%d-%H%M%S)"
REPORT_FILE="${REPORT_DIR}/security-audit-${TIMESTAMP}.txt"
REPORT_JSON="${REPORT_FILE}.json"
SUMMARY_FILE="${REPORT_DIR}/security-audit-summary-${TIMESTAMP}.md"
FAIL_ON_WARNINGS="${FAIL_ON_WARNINGS:-0}"

EXIT_CLEAN=0
EXIT_VULNS=1
EXIT_TOOL=2
EXIT_PARSE=3

if [ "${1:-}" = "--self-test" ]; then
    exec bash "${SCRIPT_DIR}/security-audit-selftest.sh"
fi

mkdir -p "${REPORT_DIR}"

echo "═══════════════════════════════════════════════════════"
echo "  ApexMail — Security Audit"
echo "  Timestamp: ${TIMESTAMP}"
echo "  Working directory: ${PROJECT_ROOT}"
echo "═══════════════════════════════════════════════════════"
echo ""

# ── Check if cargo-audit is installed ───────────────────
if ! command -v cargo-audit &>/dev/null; then
    echo "❌ cargo-audit is not installed."
    echo "   Install it with: cargo install cargo-audit --locked"
    exit "${EXIT_TOOL}"
fi

# ── Check if Cargo.lock exists ──────────────────────────
if [ ! -f "${PROJECT_ROOT}/Cargo.lock" ]; then
    echo "❌ Cargo.lock not found at ${PROJECT_ROOT}/Cargo.lock"
    echo "   Run 'cargo generate-lockfile' first."
    exit "${EXIT_TOOL}"
fi

# ── Run cargo audit (JSON, machine contract) ────────────
echo "🔍 Running cargo audit..."
echo ""

cd "${PROJECT_ROOT}"

# Capture the exit code explicitly. cargo-audit exits 1 when it reports
# vulnerabilities; any other non-zero exit is a tool/network/DB failure.
set +e
cargo audit --json > "${REPORT_JSON}" 2>&1
AUDIT_JSON_RC=$?
set -e

# ── Validate the machine contract BEFORE believing any number ──
if ! jq -e 'type == "object"' "${REPORT_JSON}" >/dev/null 2>&1; then
    echo "❌ cargo audit --json did not produce parseable JSON (exit ${AUDIT_JSON_RC})."
    echo "   A failed/unreachable advisory DB is NOT a clean audit."
    echo "   Raw output kept at: ${REPORT_JSON}"
    exit "${EXIT_PARSE}"
fi

if ! VULN_COUNT="$(jq -er '.vulnerabilities.count | numbers' "${REPORT_JSON}" 2>/dev/null)"; then
    echo "❌ cargo audit JSON has no numeric .vulnerabilities.count — schema not understood."
    echo "   Refusing to report success from a payload this script cannot read."
    echo "   Raw output kept at: ${REPORT_JSON}"
    exit "${EXIT_PARSE}"
fi

# cargo-audit has no `.warnings.count`; the warning-class arrays are the
# only honest source. Sum their lengths (absent keys count as 0).
WARN_COUNT="$(jq -r '[.warnings // {} | to_entries[] | (.value | length)] | add // 0' "${REPORT_JSON}")"
[[ "${WARN_COUNT}" =~ ^[0-9]+$ ]] || {
    echo "❌ could not parse warning counts from ${REPORT_JSON}"
    exit "${EXIT_PARSE}"
}

# Non-zero exit without a vulnerability count = the audit itself failed
# (advisory DB unreachable, network error, lockfile parse error, …).
if [ "${AUDIT_JSON_RC}" -ne 0 ] && [ "${VULN_COUNT}" -eq 0 ]; then
    echo "❌ cargo audit exited ${AUDIT_JSON_RC} without reporting a vulnerability count —"
    echo "   the audit could not be completed (advisory DB unreachable / tool error)."
    echo "   This is a FAILED audit, not a clean one. Raw output: ${REPORT_JSON}"
    exit "${EXIT_TOOL}"
fi

# ── Human-readable output (informational; the JSON above is the contract) ──
set +e
cargo audit --deny warnings > "${REPORT_FILE}" 2>&1
AUDIT_HUMAN_RC=$?
set -e

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  RESULTS"
echo "═══════════════════════════════════════════════════════"
echo "  Vulnerabilities found: ${VULN_COUNT}"
echo "  Warnings:              ${WARN_COUNT}"
echo "  cargo audit exit:      ${AUDIT_JSON_RC} (json) / ${AUDIT_HUMAN_RC} (human)"
echo "  Report:                ${REPORT_FILE}"
echo "═══════════════════════════════════════════════════════"

# ── Generate summary markdown ───────────────────────────
{
    echo "# Security Audit Report"
    echo ""
    echo "**Date:** ${TIMESTAMP}"
    echo "**Project:** ApexMail Mail Server"
    echo "**Path:** ${PROJECT_ROOT}"
    echo "**Advisory DB reachable / audit completed:** yes"
    echo ""
    echo "## Summary"
    echo ""
    echo "| Metric | Value |"
    echo "|--------|-------|"
    echo "| Vulnerabilities | ${VULN_COUNT} |"
    echo "| Warnings | ${WARN_COUNT} |"
    echo "| cargo audit exit (json) | ${AUDIT_JSON_RC} |"
    echo "| Status | $([ "${VULN_COUNT}" -eq 0 ] && echo "✅ Clean" || echo "❌ Vulnerabilities found") |"
    echo ""

    if [ "${VULN_COUNT}" -gt 0 ]; then
        echo "## Vulnerabilities"
        echo ""
        echo "\`\`\`"
        jq -r '.vulnerabilities.list[] | "- [\(.advisory.severity)] \(.advisory.id): \(.advisory.title) (package: \(.package.name)@\(.package.version))"' "${REPORT_JSON}" 2>/dev/null || true
        echo "\`\`\`"
        echo ""
    fi

    echo "## Advisories"
    echo ""
    echo "\`\`\`"
    cat "${REPORT_FILE}" 2>/dev/null || echo "(no human-readable output captured)"
    echo "\`\`\`"
} > "${SUMMARY_FILE}"

echo ""
echo "📄 Summary: ${SUMMARY_FILE}"
echo ""

# ── Exit with the real result ───────────────────────────
if [ "${VULN_COUNT}" -gt 0 ]; then
    echo "❌ Security audit failed: ${VULN_COUNT} vulnerabilities found."
    echo "   Review the report at: ${REPORT_FILE}"
    exit "${EXIT_VULNS}"
fi

if [ "${FAIL_ON_WARNINGS}" = "1" ] && [ "${WARN_COUNT}" -gt 0 ]; then
    echo "❌ Security audit failed: ${WARN_COUNT} warning-class advisories (FAIL_ON_WARNINGS=1)."
    echo "   Review the report at: ${REPORT_FILE}"
    exit "${EXIT_VULNS}"
fi

echo "✅ Security audit passed — no vulnerabilities found (advisory DB checked, JSON contract valid)."
exit "${EXIT_CLEAN}"
