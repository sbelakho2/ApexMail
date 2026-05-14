#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# ApexMail — Local Security Audit Script
# Runs cargo-audit and generates a human-readable report.
# ─────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPORT_DIR="${PROJECT_ROOT}/target/security-audit"
TIMESTAMP="$(date -u +%Y%m%d-%H%M%S)"
REPORT_FILE="${REPORT_DIR}/security-audit-${TIMESTAMP}.txt"
SUMMARY_FILE="${REPORT_DIR}/security-audit-summary-${TIMESTAMP}.md"

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
    exit 1
fi

# ── Check if Cargo.lock exists ──────────────────────────
if [ ! -f "${PROJECT_ROOT}/Cargo.lock" ]; then
    echo "❌ Cargo.lock not found at ${PROJECT_ROOT}/Cargo.lock"
    echo "   Run 'cargo generate-lockfile' first."
    exit 1
fi

# ── Run cargo audit ─────────────────────────────────────
echo "🔍 Running cargo audit..."
echo ""

cd "${PROJECT_ROOT}"

# Full audit with JSON output for machine parsing
cargo audit --json \
    > "${REPORT_FILE}.json" \
    2>&1 || true

# Human-readable output
cargo audit \
    --deny warnings \
    > "${REPORT_FILE}" \
    2>&1 || true

# ── Parse results ───────────────────────────────────────
VULN_COUNT=$(jq '.vulnerabilities.count | values // 0' "${REPORT_FILE}.json" 2>/dev/null || echo "0")
WARN_COUNT=$(jq '.warnings.count | values // 0' "${REPORT_FILE}.json" 2>/dev/null || echo "0")

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  RESULTS"
echo "═══════════════════════════════════════════════════════"
echo "  Vulnerabilities found: ${VULN_COUNT}"
echo "  Warnings:              ${WARN_COUNT}"
echo "  Report:                ${REPORT_FILE}"
echo "═══════════════════════════════════════════════════════"

# ── Generate summary markdown ───────────────────────────
{
    echo "# Security Audit Report"
    echo ""
    echo "**Date:** ${TIMESTAMP}"
    echo "**Project:** ApexMail Mail Server"
    echo "**Path:** ${PROJECT_ROOT}"
    echo ""
    echo "## Summary"
    echo ""
    echo "| Metric | Value |"
    echo "|--------|-------|"
    echo "| Vulnerabilities | ${VULN_COUNT} |"
    echo "| Warnings | ${WARN_COUNT} |"
    echo "| Status | $([ "${VULN_COUNT}" -eq 0 ] && echo "✅ Clean" || echo "❌ Vulnerabilities found") |"
    echo ""

    if [ "${VULN_COUNT}" -gt 0 ]; then
        echo "## Vulnerabilities"
        echo ""
        echo "\`\`\`"
        jq -r '.vulnerabilities.list[] | "- [\(.advisory.severity)] \(.advisory.id): \(.advisory.title) (package: \(.package.name)@\(.package.version))"' "${REPORT_FILE}.json" 2>/dev/null || true
        echo "\`\`\`"
        echo ""
    fi

    echo "## Advisories"
    echo ""
    echo "\`\`\`"
    cat "${REPORT_FILE}"
    echo "\`\`\`"
} > "${SUMMARY_FILE}"

echo ""
echo "📄 Summary: ${SUMMARY_FILE}"
echo ""

# ── Exit with error if vulnerabilities found ────────────
if [ "${VULN_COUNT}" -gt 0 ]; then
    echo "❌ Security audit failed: ${VULN_COUNT} vulnerabilities found."
    echo "   Review the report at: ${REPORT_FILE}"
    exit 1
fi

echo "✅ Security audit passed — no vulnerabilities found."
