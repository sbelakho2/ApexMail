#!/usr/bin/env bash
# Build-time check: verify no raw Tera/Zola template syntax leaked into output.
# Run after `zola build` in apps/marketing-zola/
# Exit 0 = clean, Exit 1 = leaks found.

set -euo pipefail

BUILD_DIR="${1:-public}"
STATUS=0

check_leak() {
    local label="$1"
    local pattern="$2"
    local files
    files=$(grep -r "$pattern" "$BUILD_DIR" --include="*.html" -l 2>/dev/null || true)
    if [ -n "$files" ]; then
        echo "FAIL: $label — found in:"
        echo "$files" | sed 's/^/  /'
        STATUS=1
    else
        echo "PASS: $label"
    fi
}

echo "=== Template leak check: $BUILD_DIR ==="

check_leak "Raw {% tags"           '{% '
check_leak "Raw {% if i18n blocks"           '{% if i18n'
check_leak "Raw {{ i18n/trans/config"    '\{\{ (i18n_|trans|lang|config\.)'
check_leak "Single-brace template vars { config."    '{ config\.'
check_leak "i18n_data references"  'i18n_data'
check_leak "translation_missing"   'translation_missing'

echo ""
if [ "$STATUS" -eq 0 ]; then
    echo "=== All checks PASSED ==="
else
    echo "=== LEAKS FOUND — build must be fixed before deploy ==="
fi
exit $STATUS
