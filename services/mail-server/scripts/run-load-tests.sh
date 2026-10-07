#!/usr/bin/env bash
# =============================================================================
# ApexMail Load Test Runner
# =============================================================================
# Runs k6 load tests against a target environment.
# Supports staging, production, and local deployments.
#
# Usage:
#   ./scripts/run-load-tests.sh                # Run all tests against localhost
#   ./scripts/run-load-tests.sh staging        # Run all tests against staging
#   ./scripts/run-load-tests.sh api            # Run only API load tests (env stays local)
#   ./scripts/run-load-tests.sh smtp           # Run only SMTP load tests (env stays local)
#   ENV=staging ./scripts/run-load-tests.sh api   # API tests against staging
#
# The first positional is EITHER an environment (local|staging|prod) OR a
# test selector (all|api|smtp); anything else exits 2. A run that executes
# zero tests is an error, never a pass.
#
# Environment:
#   ENV             - Target environment (local|staging|prod). Default: local
#   K6_API_BASE     - API base URL. Auto-derived from ENV if not set
#   K6_API_KEY      - API key for authentication
#   K6_DURATION     - Test duration override (e.g., "10m")
#   K6_VUS          - Max VUs override (e.g., "100")
#   K6_OUT          - k6 output options (e.g., "influxdb=http://localhost:8086/k6")
#   REPORT_DIR      - Directory for test reports. Default: ./reports/load-tests
# =============================================================================

set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
K6_DIR="$PROJECT_ROOT/crates/load-tests/tests/k6"
REPORT_DIR="${REPORT_DIR:-$PROJECT_ROOT/reports/load-tests}"

TARGET_ENV="${ENV:-local}"

# ── Parse the first positional (coverage audit U-6) ──────────────────────────
# The README documents `run-load-tests.sh staging` as "run all tests against
# staging". It previously fell through every branch, ran zero k6 tests and
# still printed "ALL TESTS PASSED" with exit 0. The positional is now either
# an environment or a test selector; everything else is rejected.
TARGET="all"
POSITIONAL="${1:-}"
if [ -n "$POSITIONAL" ]; then
  case "$POSITIONAL" in
    local|staging|prod|production) TARGET_ENV="$POSITIONAL" ;;
    all|api|smtp)                  TARGET="$POSITIONAL" ;;
    *)
      echo "ERROR: unknown argument '$POSITIONAL'." >&2
      echo "       Use an environment (local|staging|prod) or a test selector (all|api|smtp)." >&2
      exit 2
      ;;
  esac
fi

case "$TARGET_ENV" in
  local)
    K6_API_BASE="${K6_API_BASE:-http://localhost:3000}"
    K6_API_KEY="${K6_API_KEY:-test-api-key-00000000000000000000000000000}"
    ;;
  staging)
    K6_API_BASE="${K6_API_BASE:-https://api.staging.apexmail.ee}"
    if [ -z "${K6_API_KEY:-}" ]; then
      echo "ERROR: K6_API_KEY must be set for staging environment"
      exit 1
    fi
    ;;
  prod|production)
    K6_API_BASE="${K6_API_BASE:-https://api.apexmail.ee}"
    if [ -z "${K6_API_KEY:-}" ]; then
      echo "ERROR: K6_API_KEY must be set for production environment"
      exit 1
    fi
    echo "WARNING: Running load tests against PRODUCTION! Use with extreme caution."
    echo "         This will generate real traffic and consume API quota."
    read -rp "Continue? [y/N] " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
      echo "Aborted."
      exit 1
    fi
    ;;
  *)
    echo "Unknown environment: $TARGET_ENV (use: local, staging, prod)"
    exit 1
    ;;
esac

# ── Prerequisites check ──────────────────────────────────────────────────────
if ! command -v k6 &>/dev/null; then
  echo "ERROR: k6 is not installed."
  echo "       Install it: https://k6.io/docs/getting-started/installation/"
  echo "       macOS: brew install k6"
  exit 1
fi

mkdir -p "$REPORT_DIR"

# ── Timestamp ─────────────────────────────────────────────────────────────────
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SUMMARY_FILE="$REPORT_DIR/summary-$TIMESTAMP.md"

# ── Functions ────────────────────────────────────────────────────────────────
run_test() {
  local name="$1"
  local script="$2"
  local extra_args="${3:-}"
  local report_file="$REPORT_DIR/${name}-${TIMESTAMP}.json"

  echo ""
  echo "═══════════════════════════════════════════════════════════════"
  echo "  Running: $name"
  echo "  Script:  $script"
  echo "  Target:  $K6_API_BASE"
  echo "═══════════════════════════════════════════════════════════════"

  K6_API_BASE="$K6_API_BASE" \
  K6_API_KEY="$K6_API_KEY" \
  k6 run "$script" \
    --out json="$report_file" \
    --summary-export="$REPORT_DIR/${name}-${TIMESTAMP}-summary.json" \
    $extra_args \
    2>&1 | tee "$REPORT_DIR/${name}-${TIMESTAMP}-output.log"

  local exit_code="${PIPESTATUS[0]}"
  if [ "$exit_code" -eq 0 ]; then
    echo "✅ $name: PASSED"
  else
    echo "❌ $name: FAILED (exit code $exit_code)"
  fi
  return "$exit_code"
}

# ── Derived k6 flags ─────────────────────────────────────────────────────────
K6_EXTRA="${K6_DURATION:+--duration $K6_DURATION} ${K6_VUS:+--vus $K6_VUS}"

# ── Run tests ─────────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║       ApexMail Load Test Runner                             ║"
echo "║       Environment: $TARGET_ENV"
echo "║       Target URL:  $K6_API_BASE"
echo "║       Report Dir:  $REPORT_DIR"
echo "║       Started:     $(date)"
echo "╚══════════════════════════════════════════════════════════════╝"

EXIT_CODE=0
RUN_COUNT=0

if [ "$TARGET" = "all" ] || [ "$TARGET" = "api" ]; then
  RUN_COUNT=$((RUN_COUNT + 1))
  run_test "api-load-test" "$K6_DIR/api-load-test.js" "$K6_EXTRA" || EXIT_CODE=$?
fi

if [ "$TARGET" = "all" ] || [ "$TARGET" = "smtp" ]; then
  RUN_COUNT=$((RUN_COUNT + 1))
  run_test "smtp-load-test" "$K6_DIR/smtp-load-test.js" "$K6_EXTRA" || EXIT_CODE=$?
fi

# ── Refuse to report success when nothing ran (coverage audit U-6) ───────────
if [ "$RUN_COUNT" -eq 0 ]; then
  echo ""
  echo "❌ No load tests were executed (target '$TARGET', environment '$TARGET_ENV')."
  echo "   A run with zero executed tests is an error, not a pass."
  exit 2
fi

# ── Generate summary ──────────────────────────────────────────────────────────
{
  echo "# ApexMail Load Test Summary"
  echo ""
  echo "**Date:** $(date)"
  echo "**Environment:** $TARGET_ENV"
  echo "**Target:** $K6_API_BASE"
  echo ""
  echo "## Results"
  echo ""
  echo "| Test | Status |"
  echo "|------|--------|"
  # Only THIS run's summaries: stale files from earlier invocations must not
  # be reported as this run's results.
  for f in "$REPORT_DIR"/*-"${TIMESTAMP}"-summary.json; do
    if [ -f "$f" ]; then
      name=$(basename "$f" | sed "s/-${TIMESTAMP}-summary.json//")
      status="❌ FAILED"
      if jq -e '.metrics.http_req_failed.rate < 0.01' "$f" > /dev/null 2>&1; then
        status="✅ PASSED"
      fi
      echo "| $name | $status |"
    fi
  done
  echo ""
  echo "## Thresholds"
  echo ""
  echo "- p95 response time < 500ms"
  echo "- p99 response time < 1000ms"
  echo "- Error rate < 1%"
  echo ""
  echo "## Artifacts"
  echo ""
  echo "- Raw data: \`$REPORT_DIR/*.json\`"
  echo "- Output logs: \`$REPORT_DIR/*.log\`"
  echo "- Summary: \`$SUMMARY_FILE\`"
} > "$SUMMARY_FILE"

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  Summary written to: $SUMMARY_FILE"
if [ "$EXIT_CODE" -eq 0 ]; then
  echo "  ✅ ALL TESTS PASSED"
else
  echo "  ❌ SOME TESTS FAILED (exit code $EXIT_CODE)"
fi
echo "═══════════════════════════════════════════════════════════════"

exit "$EXIT_CODE"
