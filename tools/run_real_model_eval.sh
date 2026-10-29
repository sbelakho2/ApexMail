#!/usr/bin/env bash
# =============================================================================
# tools/run_real_model_eval.sh — the real-model evaluation lane (audit 6 #8)
# =============================================================================
# The audit's ask: "Run the 500–1,000 real-model Mailbot corpus and ~500-task
# Console corpus. Autonomy promotion should then be per-purpose and
# evidence-based." This lane is the EXECUTION INFRASTRUCTURE for exactly
# that; the run itself requires the owner's real-model credentials.
#
# Two phases, both always recorded:
#
#   1. CORPUS CONTRACT (always): the goldens in docs/eval/ are complete and
#      structurally grader-ready — `python3 tools/check_eval_corpora.py`
#      runs its own seeded-defect self-test first, then the tree check.
#      A broken corpus fails the lane even when no model key exists: the
#      evaluator must be sound before any result can mean anything.
#
#   2. REAL-MODEL RUN (credential-gated): when AI_MODEL_API_KEY is set and
#      the endpoint is NOT a local mock, the lane drives the corpora through
#      a real product stack (tools/run-eval-live.py, the same live replay
#      harness the dogfood uses) with --strict grading and writes
#      real-model-eval.json with status EXECUTED + the runner's verdict.
#      Without credentials the artifact is status NOT_EXECUTED with the
#      exact env to set — NEVER a healthy result (the report's standard for
#      missing credentials applies verbatim).
#
# The verdict contract: EXECUTED+PASS promotes autonomy per purpose class;
# anything else keeps autonomous sending gated. The runner's evidence dir
# (per-case expected vs actual) is retained beside the artifact.
#
# Usage: run_real_model_eval.sh --out DIR
# Env:   AI_MODEL_API_KEY, AI_MODEL_ENDPOINT (real provider), plus the usual
#        live-stack anchors the runner documents in tools/run-eval-live.py.
# Exit:  0 = corpus contract green AND (real run PASSED or honestly
#            NOT_EXECUTED); 1 = corpus broken or real run FAILED.
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT=""
log() { printf '[real-model-eval] %s\n' "$*" >&2; }
die() { printf '[real-model-eval] ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
  cat >&2 <<'USAGE'
usage: run_real_model_eval.sh --out DIR
       run_real_model_eval.sh --self-test
USAGE
  exit 2
}

# write_artifact <status> <reason-or-verdict> [evidence-dir]
write_artifact() {
  python3 - "$OUT" "$1" "$2" "${3:-}" <<'PY'
import json, sys
out, status, detail, evidence = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
artifact = {"status": status, "detail": detail, "evidence_dir": evidence or None}
if status == "NOT_EXECUTED":
    artifact["reason"] = (
        "real-model credentials absent or mock endpoint — a corpus replay "
        "against a mock is NOT real-model evidence (sixth external audit, "
        "remediation #8: missing credentials must yield NOT EXECUTED, "
        "never a healthy result)"
    )
    artifact["requires"] = {
        "AI_MODEL_API_KEY": "the production model provider key",
        "AI_MODEL_ENDPOINT": "the provider endpoint (not the local mock)",
        "live stack": "the documented run-eval-live.py anchors",
    }
from pathlib import Path
Path(out, "real-model-eval.json").write_text(
    json.dumps(artifact, indent=2, sort_keys=True) + "\n")
print(json.dumps({"phase": "real-model-eval", **artifact}, sort_keys=True))
PY
}

self_test() {
  local tmp rc=0
  tmp=$(mktemp -d "${TMPDIR:-/tmp}/apexmail-eval-lane-test.XXXXXX")
  OUT="$tmp" write_artifact NOT_EXECUTED "missing credentials" >/dev/null 2>&1 \
    || { echo "self-test FAIL: artifact writer errored" >&2; rc=1; }
  python3 - "$tmp" <<'PY' || rc=1
import json, sys
from pathlib import Path
data = json.loads(Path(sys.argv[1], "real-model-eval.json").read_text())
assert data["status"] == "NOT_EXECUTED", data
assert data["reason"], "NOT_EXECUTED must carry a reason"
assert data["requires"], "NOT_EXECUTED must name what it needs"
print("self-test: NOT_EXECUTED carries reason + requirements")
PY
  # The corpus contract must be sound even without credentials: run the
  # graded-golden gate's own self-test here (hermetic, seconds).
  python3 "$ROOT/tools/check_eval_corpora.py" --self-test >/dev/null 2>&1 \
    || { echo "self-test FAIL: check_eval_corpora --self-test failed" >&2; rc=1; }
  # Usage contract.
  local inner=0; bash "$0" >/dev/null 2>&1 || inner=$?
  [ "$inner" -eq 2 ] || { echo "self-test FAIL: missing --out must exit 2" >&2; rc=1; }
  rm -rf "$tmp"
  [ "$rc" -eq 0 ] || { echo "run_real_model_eval self-test FAIL" >&2; exit 1; }
  echo "run_real_model_eval self-test: ok (NOT_EXECUTED artifact honest, corpus self-test green, usage contract holds)"
  exit 0
}

[ "${1:-}" = "--self-test" ] && self_test

while [ $# -gt 0 ]; do
  case $1 in
    --out) [ $# -ge 2 ] || usage; OUT=$2; shift 2 ;;
    *) usage ;;
  esac
done
[ -n "$OUT" ] || usage
mkdir -p "$OUT"

# Phase 1: corpus contract (always, regardless of credentials).
log "phase 1/2: corpus contract"
python3 "$ROOT/tools/check_eval_corpora.py" >/dev/null \
  || die "the eval corpus contract is broken — grading goldens would lie"

# Phase 2: the real-model run, credential-gated.
key="${AI_MODEL_API_KEY:-}"
endpoint="${AI_MODEL_ENDPOINT:-}"
if [ -z "$key" ]; then
  log "phase 2/2: NOT EXECUTED (AI_MODEL_API_KEY unset)"
  write_artifact NOT_EXECUTED "AI_MODEL_API_KEY is not set"
  exit 0
fi
case "$endpoint" in
  ""|*mock*|*127.0.0.1*|*localhost*)
    log "phase 2/2: NOT EXECUTED (AI_MODEL_ENDPOINT is unset or a mock: '$endpoint')"
    write_artifact NOT_EXECUTED "AI_MODEL_ENDPOINT is a mock or unset; set the provider endpoint"
    exit 0
    ;;
esac

log "phase 2/2: real-model replay via tools/run-eval-live.py (strict)"
set +e
python3 "$ROOT/tools/run-eval-live.py" \
  --out "$OUT/evidence" --strict --suffix "realmodel" >>"$OUT/eval-run.log" 2>&1
eval_rc=$?
set -e
if [ "$eval_rc" -eq 0 ]; then
  write_artifact EXECUTED "corpora replayed against the configured real model; strict grading PASSED" "$OUT/evidence"
  exit 0
fi
write_artifact EXECUTED_FAILED "corpora replay against the real model FAILED (see evidence_dir + eval-run.log)" "$OUT/evidence"
log "real-model replay FAILED — autonomy promotion stays per-purpose gated"
exit 1
