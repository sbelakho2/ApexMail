#!/usr/bin/env bash
# =============================================================================
# ApexMail — Security Audit Script
# =============================================================================
# Runs cargo-audit and cargo-deny checks for the mail-server workspace.
# This script is used both in CI (security-audit.yml) and as a pre-commit hook
# (see .pre-commit-config.yaml).
#
# Usage:
#   ./scripts/security-audit.sh            # Run all security audits
#   ./scripts/security-audit.sh --ci       # CI mode (strict exit codes)
#   ./scripts/security-audit.sh --quick    # Skip cargo-deny (faster)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MAIL_SERVER_DIR="$PROJECT_ROOT/services/mail-server"

echo "============================================"
echo "  ApexMail Security Audit"
echo "============================================"
echo ""

# ── Parse arguments ──────────────────────────────────────────────────────────
CI_MODE=false
QUICK_MODE=false
for arg in "$@"; do
    case "$arg" in
        --ci) CI_MODE=true ;;
        --quick) QUICK_MODE=true ;;
    esac
done

# ── Check for cargo-audit ────────────────────────────────────────────────────
if ! command -v cargo-audit &> /dev/null; then
    echo "[!] cargo-audit not found. Installing..."
    cargo install cargo-audit --locked
fi

echo "[1/3] Running cargo audit (dependency vulnerability scan)..."
echo "      Working directory: $MAIL_SERVER_DIR"
cd "$MAIL_SERVER_DIR"

# SEC-17: cargo audit with advisory ignore list
# This list must match .cargo/audit.toml and deny.toml
cargo audit --deny warnings \
    --ignore RUSTSEC-2026-0119 \
    --ignore RUSTSEC-2024-0437 \
    --ignore RUSTSEC-2023-0071 \
    --ignore RUSTSEC-2026-0098 \
    --ignore RUSTSEC-2026-0099 \
    --ignore RUSTSEC-2026-0104 \
    --ignore RUSTSEC-2025-0141 \
    --ignore RUSTSEC-2025-0057 \
    --ignore RUSTSEC-2024-0384 \
    --ignore RUSTSEC-2024-0436 \
    --ignore RUSTSEC-2024-0370 \
    --ignore RUSTSEC-2025-0134 \
    --ignore RUSTSEC-2024-0320 \
    --ignore RUSTSEC-2023-0086 \
    --ignore RUSTSEC-2026-0002 \
    2>&1 | tee "$MAIL_SERVER_DIR/cargo-audit-report.txt"

echo ""
echo "[2/3] Checking for outdated dependencies..."
if command -v cargo-outdated &> /dev/null; then
    cargo outdated --exit-code 1 2>&1 | tee "$MAIL_SERVER_DIR/cargo-outdated-report.txt" || true
else
    echo "      cargo-outdated not installed; skipping."
fi

if [ "$QUICK_MODE" = false ]; then
    echo ""
    echo "[3/3] Running cargo deny check..."
    if command -v cargo-deny &> /dev/null; then
        cargo deny check advisories bans sources 2>&1 | tee "$MAIL_SERVER_DIR/cargo-deny-report.txt"
    else
        echo "      cargo-deny not found. Installing..."
        cargo install cargo-deny --locked
        cargo deny check advisories bans sources 2>&1 | tee "$MAIL_SERVER_DIR/cargo-deny-report.txt"
    fi
else
    echo "[3/3] Skipping cargo-deny (--quick mode)"
fi

echo ""
echo "============================================"
echo "  Security Audit Complete"
echo "============================================"

if [ "$CI_MODE" = true ]; then
    # In CI mode, surface any failures from cargo-audit
    # cargo-audit already exits non-zero on findings due to --deny warnings
    echo "CI mode: audit completed."
fi
