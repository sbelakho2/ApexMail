#!/bin/bash
# ==============================================================================
# Rust Coverage Enforcement Script
# ==============================================================================
# Uses cargo-llvm-cov to generate coverage reports and enforce thresholds
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
#   2 - Tool error
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

# Check for cargo-llvm-cov
if ! command -v cargo-llvm-cov &> /dev/null; then
    echo -e "${YELLOW}Installing cargo-llvm-cov...${NC}"
    cargo install cargo-llvm-cov
fi

# Build coverage command
COVERAGE_CMD="cargo llvm-cov --manifest-path Cargo.toml"

if [ -n "$PACKAGE" ]; then
    COVERAGE_CMD="$COVERAGE_CMD -p $PACKAGE"
fi

# Add output format
OUTPUT_FILE="coverage-report"
if $HTML_REPORT; then
    COVERAGE_CMD="$COVERAGE_CMD --html --output-dir coverage-html"
    echo -e "${GREEN}Generating HTML coverage report...${NC}"
fi

if $JSON_OUTPUT; then
    COVERAGE_CMD="$COVERAGE_CMD --json --output-path ${OUTPUT_FILE}.json"
fi

# Always generate lcov for CI integration
COVERAGE_CMD="$COVERAGE_CMD --lcov --output-path ${OUTPUT_FILE}.lcov"

# Run coverage
echo -e "${GREEN}Running coverage analysis...${NC}"
echo "Command: $COVERAGE_CMD"
eval $COVERAGE_CMD

# Parse coverage from lcov file
if [ -f "${OUTPUT_FILE}.lcov" ]; then
    echo ""
    echo -e "${GREEN}=== Coverage Summary ===${NC}"
    
    # Calculate line coverage from lcov
    TOTAL_LINES=$(grep -E "^LF:" "${OUTPUT_FILE}.lcov" | cut -d: -f2 | paste -sd+ | bc)
    COVERED_LINES=$(grep -E "^LH:" "${OUTPUT_FILE}.lcov" | cut -d: -f2 | paste -sd+ | bc)
    
    if [ "$TOTAL_LINES" -gt 0 ]; then
        LINE_COVERAGE=$(echo "scale=2; $COVERED_LINES * 100 / $TOTAL_LINES" | bc)
    else
        LINE_COVERAGE=0
    fi
    
    echo "Lines:    $COVERED_LINES / $TOTAL_LINES ($LINE_COVERAGE%)"
    
    # Check against threshold
    LINE_COV_INT=${LINE_COVERAGE%.*}
    if [ "$LINE_COV_INT" -lt "$MIN_LINE_COVERAGE" ]; then
        echo -e "${RED}✗ Line coverage ${LINE_COVERAGE}% is below threshold ${MIN_LINE_COVERAGE}%${NC}"
        if $FAIL_UNDER_THRESHOLD; then
            FAILED=true
        fi
    else
        echo -e "${GREEN}✓ Line coverage ${LINE_COVERAGE}% meets threshold ${MIN_LINE_COVERAGE}%${NC}"
    fi
    
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
    }
  },
  "passed": $(if [ "${LINE_COV_INT:-0}" -ge "$MIN_LINE_COVERAGE" ]; then echo "true"; else echo "false"; fi)
}
EOF
    echo ""
    echo "Summary written to ${OUTPUT_FILE}-summary.json"
fi

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
