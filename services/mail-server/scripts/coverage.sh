#!/bin/bash
# ==============================================================================
# Rust Coverage Enforcement Script
# ==============================================================================
# Uses cargo-llvm-cov to generate coverage reports and enforce thresholds
# for LINE, BRANCH and FUNCTION coverage.
#
# Usage:
#   ./coverage.sh             # Run coverage for all crates
#   ./coverage.sh -p waf-engine  # Run for specific crate
#   ./coverage.sh --html      # Generate HTML report
#
# Prerequisites:
#   cargo install cargo-llvm-cov
#
# Exit codes:
#   0 - All coverage thresholds met
#   1 - Coverage below threshold
#   2 - Tool error / bad usage / no coverage data
#
# Security note (coverage audit U-7): the coverage command is built as an
# argv array and executed directly — never through `eval`. Package names are
# validated against ^[A-Za-z0-9_-]+$ so `-p 'x; rm -rf …'` cannot inject
# shell metacharacters.
# ==============================================================================

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Thresholds (adjust these based on project requirements)
MIN_LINE_COVERAGE=75
MIN_BRANCH_COVERAGE=70
MIN_FUNCTION_COVERAGE=75

# Parse arguments
PACKAGE=""
HTML_REPORT=false
JSON_OUTPUT=false
FAIL_UNDER_THRESHOLD=true

while [[ $# -gt 0 ]]; do
    case $1 in
        -p|--package)
            [ $# -ge 2 ] || { echo "ERROR: $1 requires a value" >&2; exit 2; }
            PACKAGE="$2"
            shift 2
            ;;
        --html)
            HTML_REPORT=true
            shift
            ;;
        --json)
            JSON_OUTPUT=true
            shift
            ;;
        --no-fail)
            FAIL_UNDER_THRESHOLD=false
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 2
            ;;
    esac
done

# Reject shell metacharacters before they can reach any command line.
if [ -n "$PACKAGE" ] && [[ ! "$PACKAGE" =~ ^[A-Za-z0-9_-]+$ ]]; then
    echo "ERROR: invalid package name '$PACKAGE' (allowed: letters, digits, '_', '-')" >&2
    exit 2
fi

# Check for cargo-llvm-cov
if ! command -v cargo-llvm-cov &> /dev/null; then
    echo -e "${YELLOW}Installing cargo-llvm-cov...${NC}"
    cargo install cargo-llvm-cov
fi

# Build coverage command as an argv array (no eval — see header).
COVERAGE_ARGS=(llvm-cov --manifest-path Cargo.toml)

if [ -n "$PACKAGE" ]; then
    COVERAGE_ARGS+=(-p "$PACKAGE")
fi

# Add output format
OUTPUT_FILE="coverage-report"
if $HTML_REPORT; then
    COVERAGE_ARGS+=(--html --output-dir coverage-html)
    echo -e "${GREEN}Generating HTML coverage report...${NC}"
fi

if $JSON_OUTPUT; then
    COVERAGE_ARGS+=(--json --output-path "${OUTPUT_FILE}.json")
fi

# Always generate lcov for CI integration
COVERAGE_ARGS+=(--lcov --output-path "${OUTPUT_FILE}.lcov")

# Run coverage
echo -e "${GREEN}Running coverage analysis...${NC}"
echo "Command: cargo ${COVERAGE_ARGS[*]}"
cargo "${COVERAGE_ARGS[@]}"

# ── Parse coverage from lcov file ────────────────────────────────────────────
if [ ! -f "${OUTPUT_FILE}.lcov" ]; then
    echo -e "${RED}✗ cargo-llvm-cov produced no ${OUTPUT_FILE}.lcov — coverage was not measured.${NC}" >&2
    exit 2
fi
if [ ! -s "${OUTPUT_FILE}.lcov" ]; then
    echo -e "${RED}✗ ${OUTPUT_FILE}.lcov is empty — coverage was not measured.${NC}" >&2
    exit 2
fi

echo ""
echo -e "${GREEN}=== Coverage Summary ===${NC}"

# Portable lcov totals (awk — no GNU paste/bc dependency).
read -r TOTAL_LINES COVERED_LINES TOTAL_BRANCHES COVERED_BRANCHES TOTAL_FUNCTIONS COVERED_FUNCTIONS <<< "$(
    awk -F: '
        /^LF:/  { lf += $2 }
        /^LH:/  { lh += $2 }
        /^BRF:/ { brf += $2 }
        /^BRH:/ { brh += $2 }
        /^FNF:/ { fnf += $2 }
        /^FNH:/ { fnh += $2 }
        END { printf "%d %d %d %d %d %d\n", lf, lh, brf, brh, fnf, fnh }
    ' "${OUTPUT_FILE}.lcov"
)"

pct() {
    awk -v covered="$1" -v total="$2" 'BEGIN { if (total > 0) printf "%.2f", covered * 100 / total; else printf "0" }'
}
ge() {
    # true when $1 >= $2 (numeric, tolerant of decimals)
    awk -v value="$1" -v threshold="$2" 'BEGIN { exit !(value + 0 >= threshold + 0) }'
}
lcov_int() {
    local value="$1"
    echo "${value%.*}"
}

LINE_COVERAGE="$(pct "$COVERED_LINES" "$TOTAL_LINES")"
BRANCH_COVERAGE="$(pct "$COVERED_BRANCHES" "$TOTAL_BRANCHES")"
FUNCTION_COVERAGE="$(pct "$COVERED_FUNCTIONS" "$TOTAL_FUNCTIONS")"

echo "Lines:     $COVERED_LINES / $TOTAL_LINES ($LINE_COVERAGE%)"
echo "Branches:  $COVERED_BRANCHES / $TOTAL_BRANCHES ($BRANCH_COVERAGE%)"
echo "Functions: $COVERED_FUNCTIONS / $TOTAL_FUNCTIONS ($FUNCTION_COVERAGE%)"

FAILED=false

enforce() {
    local label="$1" value="$2" threshold="$3"
    if ge "$value" "$threshold"; then
        echo -e "${GREEN}✓ ${label} coverage ${value}% meets threshold ${threshold}%${NC}"
    else
        echo -e "${RED}✗ ${label} coverage ${value}% is below threshold ${threshold}%${NC}"
        if $FAIL_UNDER_THRESHOLD; then
            FAILED=true
        fi
    fi
}

# All three dimensions are enforced; lcov without branch/function records
# reports 0% and fails rather than passing vacuously.
enforce "Line" "$LINE_COVERAGE" "$MIN_LINE_COVERAGE"
enforce "Branch" "$BRANCH_COVERAGE" "$MIN_BRANCH_COVERAGE"
enforce "Function" "$FUNCTION_COVERAGE" "$MIN_FUNCTION_COVERAGE"

# Generate summary JSON
cat > "${OUTPUT_FILE}-summary.json" << EOF
{
  "generated_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "thresholds": {
    "lines": $MIN_LINE_COVERAGE,
    "branches": $MIN_BRANCH_COVERAGE,
    "functions": $MIN_FUNCTION_COVERAGE
  },
  "coverage": {
    "lines": {
      "total": $TOTAL_LINES,
      "covered": $COVERED_LINES,
      "percentage": $LINE_COVERAGE
    },
    "branches": {
      "total": $TOTAL_BRANCHES,
      "covered": $COVERED_BRANCHES,
      "percentage": $BRANCH_COVERAGE
    },
    "functions": {
      "total": $TOTAL_FUNCTIONS,
      "covered": $COVERED_FUNCTIONS,
      "percentage": $FUNCTION_COVERAGE
    }
  },
  "passed": $([ "$FAILED" = true ] && echo "false" || echo "true")
}
EOF
echo ""
echo "Summary written to ${OUTPUT_FILE}-summary.json"

# Report HTML location
if $HTML_REPORT && [ -d "coverage-html" ]; then
    echo ""
    echo -e "${GREEN}HTML report generated: coverage-html/index.html${NC}"
    echo "Open in browser: open coverage-html/index.html"
fi

# Final status
if ${FAILED:-false}; then
    echo ""
    echo -e "${RED}Coverage check FAILED - thresholds not met${NC}"
    exit 1
else
    echo ""
    echo -e "${GREEN}Coverage check PASSED${NC}"
    exit 0
fi
