#!/usr/bin/env bash
# =============================================================================
# tools/run_journey_lane.sh — the T6 live-stack journey lane (CI wiring).
#
# The ApexMail journey drivers (tests/journeys/*.mjs, own playwright lock)
# are full-fidelity black-box sweeps of the REAL stack: console + control
# plane + recipient surfaces, light/dark, multiple viewports, axe-core,
# contrast computed from rendered pixels. Until now they had NO CI lane —
# the T6 work package stayed "planned". This tool is that lane:
#
#   1. boots the dev compose stack under an ISOLATED project name
#      (apexmail-journey-lane) so it can never collide with a developer
#      stack or the deploy host;
#   2. health-fences the api (bounded wait on /health — a stack that never
#      becomes healthy fails the lane, it never runs blind);
#   3. provisions tests/journeys/node_modules from the committed lockfile;
#   4. runs journey-deep --quick (the fast lane of the deepest sweep);
#   5. enforces the ADVERSARIAL contract: ZERO findings. Any finding in
#      findings.json — including a single AA contrast miss or a missing
#      accessible name — fails the lane. The artifact set (findings.json +
#      screenshots) is preserved under --out for diagnosis.
#   6. ALWAYS tears the stack down (trap), volumes included.
#
# Never points at production: it composes docker-compose.yml + the local
# override only, and the journeys take explicit --base/--cp URLs.
#
# --self-test (no docker, no stack, no network): proves the findings
# evaluator fails on seeded findings and passes on zero, that the usage
# contract is enforced, and (when docker exists) that the compose project
# renders.
#
# Usage: run_journey_lane.sh --out DIR
# Env:   CI_JOURNEY_API_BASE (default http://127.0.0.1:8080)
#        CI_JOURNEY_CP_BASE  (default http://admin.localhost:8080)
#        CI_JOURNEY_HEALTH_TIMEOUT_SECS (default 300)
# Exit:  0 = stack up, sweep ran, zero findings; 1 = failure; 2 = usage.
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROJECT=apexmail-journey-lane
OUT=""
API_BASE="${CI_JOURNEY_API_BASE:-http://127.0.0.1:8080}"
CP_BASE="${CI_JOURNEY_CP_BASE:-http://admin.localhost:8080}"
HEALTH_TIMEOUT="${CI_JOURNEY_HEALTH_TIMEOUT_SECS:-300}"

log() { printf '[journey-lane] %s\n' "$*" >&2; }
die() { printf '[journey-lane] ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
  cat >&2 <<'USAGE'
usage: run_journey_lane.sh --out DIR
       run_journey_lane.sh --self-test
USAGE
  exit 2
}

# evaluate_findings <findings.json> — the adversarial zero-findings gate.
# Fails when the file is missing, unreadable, malformed, or carries ANY
# finding. This is the lane's teeth: a sweep that produced no verdict fails
# exactly like a sweep that found a defect.
evaluate_findings() {
  local file=$1
  [ -s "$file" ] || { printf 'findings artifact missing or empty: %s\n' "$file" >&2; return 1; }
  python3 - "$file" <<'PY'
import json, sys
try:
    data = json.load(open(sys.argv[1]))
except (OSError, ValueError) as exc:
    print(f"findings artifact unreadable: {exc}", file=sys.stderr)
    sys.exit(1)
findings = data.get("findings") if isinstance(data, dict) else None
if not isinstance(findings, list):
    print("findings artifact malformed: no findings[] array", file=sys.stderr)
    sys.exit(1)
if findings:
    by = {}
    for f in findings:
        by[f.get("severity", "?")] = by.get(f.get("severity", "?"), 0) + 1
    print(f"journey findings: {len(findings)} {by} — the lane demands ZERO", file=sys.stderr)
    sys.exit(1)
print("journey findings: 0 (clean sweep)")
PY
}

stack_up() {
  log "booting the dev compose stack (isolated project $PROJECT)"
  (cd "$ROOT" && docker compose -p "$PROJECT" up -d --build --wait) \
    || die "compose up failed — the lane never runs against a half-built stack"
}

wait_healthy() {
  local deadline=$(( $(date +%s) + HEALTH_TIMEOUT ))
  log "waiting for api health at $API_BASE/health (bounded ${HEALTH_TIMEOUT}s)"
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if curl -fsS --max-time 5 "$API_BASE/health" >/dev/null 2>&1; then
      log "api healthy"
      return 0
    fi
    sleep 5
  done
  die "api did not become healthy within ${HEALTH_TIMEOUT}s"
}

stack_down() {
  docker compose -p "$PROJECT" down -v --remove-orphans >/dev/null 2>&1 || true
}

self_test() {
  local tmp rc=0
  tmp=$(mktemp -d "${TMPDIR:-/tmp}/apexmail-journey-lane-test.XXXXXX")
  # 1. zero findings passes
  printf '{"summary": {}, "findings": []}' > "$tmp/zero.json"
  evaluate_findings "$tmp/zero.json" || { echo "self-test FAIL: zero-findings artifact rejected" >&2; rc=1; }
  # 2. one finding fails
  printf '{"summary": {}, "findings": [{"severity": "error", "what": "x"}]}' > "$tmp/one.json"
  if evaluate_findings "$tmp/one.json" >/dev/null 2>&1; then
    echo "self-test FAIL: a seeded finding was accepted" >&2
    rc=1
  fi
  # 3. malformed artifact fails (a sweep that crashed mid-run must not pass)
  printf 'not json' > "$tmp/bad.json"
  if evaluate_findings "$tmp/bad.json" >/dev/null 2>&1; then
    echo "self-test FAIL: a malformed findings artifact was accepted" >&2
    rc=1
  fi
  # 4. missing artifact fails
  if evaluate_findings "$tmp/absent.json" >/dev/null 2>&1; then
    echo "self-test FAIL: a missing findings artifact was accepted" >&2
    rc=1
  fi
  # 5. usage contract: run mode without --out exits 2
  if bash "$0" >/dev/null 2>&1; then rc_inner=0; else rc_inner=$?; fi
  if [ "${rc_inner:-0}" -ne 2 ]; then
    echo "self-test FAIL: missing --out must exit 2, got ${rc_inner:-0}" >&2
    rc=1
  fi
  # 6. the compose project renders (only when docker exists; the wiring is
  #    additionally pinned by the validate stage's compose -q gate).
  if command -v docker >/dev/null 2>&1 \
     && docker info >/dev/null 2>&1 \
     && (cd "$ROOT" && docker compose -p "$PROJECT" config -q >/dev/null 2>&1); then
    :
  elif command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    echo "self-test FAIL: the dev compose project does not render" >&2
    rc=1
  fi
  rm -rf "$tmp"
  if [ "$rc" -ne 0 ]; then
    echo "run_journey_lane self-test FAIL" >&2
    exit 1
  fi
  echo "run_journey_lane self-test: ok (zero-findings enforced; seeded finding, malformed and missing artifacts all rejected; usage contract holds)"
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

trap stack_down EXIT INT TERM
stack_up
wait_healthy

if [ ! -x "$ROOT/tests/journeys/node_modules/.bin/playwright" ]; then
  log "provisioning tests/journeys/node_modules from the committed lockfile"
  (cd "$ROOT/tests/journeys" && npm ci --no-audit --no-fund >&2) || die "npm ci failed in tests/journeys"
fi

log "running journey-deep --quick against $API_BASE (cp $CP_BASE)"
cd "$ROOT/tests/journeys"
node journey-deep.mjs --quick --out "$OUT" --base "$API_BASE" --cp "$CP_BASE" >&2 \
  || die "journey-deep exited non-zero — the sweep itself failed"

evaluate_findings "$OUT/findings.json"
