#!/usr/bin/env bash
# =============================================================================
# ApexMail Baseline Comparison Script
# =============================================================================
# Compares test results JSON against a baseline and exits with non-zero if any
# metric degrades by more than the regression threshold (default: 10%).
#
# Usage:
#   ./scripts/compare-baseline.sh results.json
#   ./scripts/compare-baseline.sh results.json --baseline docs/evaluation/baselines/v0.1.json
#   ./scripts/compare-baseline.sh results.json --threshold 15
#   ./scripts/compare-baseline.sh results.json --verbose
#
# Exit codes:
#   0 — all metrics pass (within threshold of baseline)
#   1 — one or more metrics exceed the degradation threshold
#   2 — usage error or missing dependencies
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── Defaults ────────────────────────────────────────────────────────────────
DEFAULT_BASELINE="$PROJECT_ROOT/docs/evaluation/baselines/v1.0.json"
REGRESSION_THRESHOLD=10  # percent degradation allowed
VERBOSE=false
RESULTS_FILE=""
BASELINE_FILE=""

# ── Parse arguments ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --baseline)
      BASELINE_FILE="$2"
      shift 2
      ;;
    --threshold)
      REGRESSION_THRESHOLD="$2"
      shift 2
      ;;
    --verbose)
      VERBOSE=true
      shift
      ;;
    --help)
      echo "Usage: $0 <results.json> [--baseline <baseline.json>] [--threshold <pct>] [--verbose]"
      exit 0
      ;;
    *)
      if [[ -z "$RESULTS_FILE" ]]; then
        RESULTS_FILE="$1"
      else
        echo "ERROR: Unexpected argument: $1"
        exit 2
      fi
      shift
      ;;
  esac
done

if [[ -z "$RESULTS_FILE" ]]; then
  echo "ERROR: No results file specified."
  echo "Usage: $0 <results.json> [--baseline <baseline.json>] [--threshold <pct>] [--verbose]"
  exit 2
fi

if [[ ! -f "$RESULTS_FILE" ]]; then
  echo "ERROR: Results file not found: $RESULTS_FILE"
  exit 2
fi

BASELINE_FILE="${BASELINE_FILE:-$DEFAULT_BASELINE}"
if [[ ! -f "$BASELINE_FILE" ]]; then
  echo "ERROR: Baseline file not found: $BASELINE_FILE"
  echo "Create one at docs/evaluation/baselines/ or specify --baseline."
  exit 2
fi

# ── Check dependencies ─────────────────────────────────────────────────────
if ! command -v jq &>/dev/null; then
  echo "ERROR: 'jq' is required but not installed."
  echo "Install: brew install jq  (macOS)  |  apt install jq  (Linux)"
  exit 2
fi

# ── Load data ──────────────────────────────────────────────────────────────
echo "─── Baseline Comparison ─────────────────────────────────────────────"
echo "  Results:  $RESULTS_FILE"
echo "  Baseline: $BASELINE_FILE"
echo "  Threshold: ${REGRESSION_THRESHOLD}% degradation allowed"
echo ""

# ── Metric comparison mapping ─────────────────────────────────────────────
# Each entry: <section>.<field>  <unit>  <higher_is_better>
# higher_is_better=true means: increase is improvement (throughput)
# higher_is_better=false means: increase is degradation (latency, error rate)
METRICS=(
  "api_throughput.sustained_rps:req/s:true"
  "api_throughput.p95_latency_ms:ms:false"
  "api_throughput.p99_latency_ms:ms:false"
  "api_throughput.error_rate:ratio:false"
  "tracking_pixel.sustained_rps:req/s:true"
  "tracking_pixel.p95_latency_ms:ms:false"
  "tracking_pixel.data_loss_pct:%:false"
  "ssr_browsers.concurrent_sessions:sessions:true"
  "ssr_browsers.page_load_p95_ms:ms:false"
  "ssr_browsers.ssr_render_p95_ms:ms:false"
  "id_generation.throughput_ops_per_sec:ops/s:true"
  "email_validation.throughput_ops_per_sec:ops/s:true"
  "prediction_scoring.throughput_ops_per_sec:ops/s:true"
  "pattern_matching.throughput_ops_per_sec:ops/s:true"
  "billing_calculations.throughput_ops_per_sec:ops/s:true"
  "trust_scoring.throughput_ops_per_sec:ops/s:true"
  "template_rendering.p95_latency_ms:ms:false"
  "analytics_rollup.p95_latency_ms:ms:false"
  "compliance_evaluation.p95_latency_ms:ms:false"
  "smtp_submission.p95_latency_ms:ms:false"
  "smtp_submission.p99_latency_ms:ms:false"
  "smtp_submission.error_rate:ratio:false"
)

# Helper: extract value using jq path
get_val() {
  local file="$1"
  local section="$2"
  local field="$3"
  jq -r ".[\"$section\"].[\"$field\"] // empty" "$file"
}

# ── Compare ────────────────────────────────────────────────────────────────
HAS_ERROR=false
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

for entry in "${METRICS[@]}"; do
  IFS=':' read -r path unit higher_better <<< "$entry"
  section="${path%.*}"
  field="${path#*.}"

  baseline_val=$(get_val "$BASELINE_FILE" "$section" "$field")
  results_val=$(get_val "$RESULTS_FILE" "$section" "$field")

  if [[ -z "$baseline_val" ]] || [[ -z "$results_val" ]]; then
    $VERBOSE && echo "  ⚠ SKIP  ${section}.${field}  (missing in results or baseline)"
    SKIP_COUNT=$((SKIP_COUNT + 1))
    continue
  fi

  # Calculate percent change
  if [[ "$higher_better" == "true" ]]; then
    # Higher is better: change = (results - baseline) / baseline
    pct_change=$(echo "scale=4; ($results_val - $baseline_val) / $baseline_val * 100" | bc -l 2>/dev/null || echo "0")
    degraded=$(echo "$pct_change < -$REGRESSION_THRESHOLD" | bc -l 2>/dev/null || echo "0")
  else
    # Lower is better: change = (results - baseline) / baseline
    pct_change=$(echo "scale=4; ($results_val - $baseline_val) / $baseline_val * 100" | bc -l 2>/dev/null || echo "0")
    degraded=$(echo "$pct_change > $REGRESSION_THRESHOLD" | bc -l 2>/dev/null || echo "0")
  fi

  PASS=true
  if [[ "$degraded" == "1" ]]; then
    PASS=false
  fi

  if $PASS; then
    echo "  ✅ PASS  ${section}.${field}  (${unit})  baseline=${baseline_val}  results=${results_val}  change=${pct_change}%"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    echo "  ❌ FAIL  ${section}.${field}  (${unit})  baseline=${baseline_val}  results=${results_val}  change=${pct_change}%  (exceeds ${REGRESSION_THRESHOLD}% threshold)"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    HAS_ERROR=true
  fi
done

# ── Summary ────────────────────────────────────────────────────────────────
echo ""
echo "─── Summary ─────────────────────────────────────────────────────────"
echo "  Pass:  $PASS_COUNT"
echo "  Fail:  $FAIL_COUNT"
echo "  Skip:  $SKIP_COUNT"
echo ""

if $HAS_ERROR; then
  echo "❌ REGRESSION DETECTED — $FAIL_COUNT metric(s) exceed the ${REGRESSION_THRESHOLD}% threshold."
  echo "   Review the failing metrics above and either fix the regression or"
  echo "   request a baseline exception from the engineering lead."
  exit 1
else
  echo "✅ All metrics pass — no regressions detected."
  exit 0
fi
