#!/usr/bin/env bash
# =============================================================================
# scripts/tests/compare-baseline-selftest.sh — fixture for
# scripts/compare-baseline.sh's regression arithmetic (audit P3).
# =============================================================================
# A 50% latency regression must FAIL even with a broken/absent `bc` (the old
# pipeline swallowed bc errors into `0` and reported "All metrics pass"), and
# non-numeric metrics must fail loudly instead of being computed as 0.
#
# A stub `bc` on PATH exits 1 — deterministic reproduction of "no usable bc"
# on any host.
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
_work="$(mktemp -d "${TMPDIR:-/tmp}/apexmail-baseline-selftest.XXXXXX")"
trap 'rm -rf "$_work"' EXIT

_fail=0
_ok()  { printf 'ok   %s\n' "$*"; }
_bad() { printf 'FAIL %s\n' "$*" >&2; _fail=$((_fail + 1)); }

mkdir -p "$_work/bin"
cat > "$_work/bin/bc" <<'STUB'
#!/bin/sh
# simulate a host where bc is absent/broken
echo "bc: broken" >&2
exit 1
STUB
chmod +x "$_work/bin/bc"

cat > "$_work/baseline.json" <<'EOF'
{"api_throughput": {"p95_latency_ms": 100}}
EOF
cat > "$_work/regressed.json" <<'EOF'
{"api_throughput": {"p95_latency_ms": 150}}
EOF
cat > "$_work/improved.json" <<'EOF'
{"api_throughput": {"p95_latency_ms": 80}}
EOF
cat > "$_work/nonnumeric.json" <<'EOF'
{"api_throughput": {"p95_latency_ms": "fast"}}
EOF

_run() { # <results> ; PATH forces the broken bc
    PATH="$_work/bin:$PATH" bash "$REPO_ROOT/scripts/compare-baseline.sh" "$1" \
        --baseline "$_work/baseline.json" --threshold 10
}

_rc=0
_run "$_work/regressed.json" >"$_work/regressed.log" 2>&1 || _rc=$?
if [[ "$_rc" -eq 1 ]] && grep -q 'REGRESSION DETECTED' "$_work/regressed.log"; then
    _ok "regression: 50% latency degradation FAILS without a usable bc"
else
    _bad "regression: exit $_rc — $(tail -2 "$_work/regressed.log")"
fi

_rc=0
_run "$_work/improved.json" >"$_work/improved.log" 2>&1 || _rc=$?
if [[ "$_rc" -eq 0 ]] && grep -q 'All metrics pass' "$_work/improved.log"; then
    _ok "improvement: faster than baseline still passes"
else
    _bad "improvement: exit $_rc — $(tail -2 "$_work/improved.log")"
fi

_rc=0
_run "$_work/nonnumeric.json" >"$_work/nonnumeric.log" 2>&1 || _rc=$?
if [[ "$_rc" -eq 2 ]] && grep -q 'non-numeric metric' "$_work/nonnumeric.log"; then
    _ok "non-numeric metric: fails loudly (exit 2) instead of computing 0%"
else
    _bad "non-numeric metric: exit $_rc — $(tail -2 "$_work/nonnumeric.log")"
fi

# --- teeth: HEAD's bc-based comparison passes the regression -----------------
if command -v git >/dev/null 2>&1 && git -C "$REPO_ROOT" cat-file -e HEAD:scripts/compare-baseline.sh 2>/dev/null; then
    git -C "$REPO_ROOT" show HEAD:scripts/compare-baseline.sh > "$_work/old-compare.sh"
    _rc=0
    PATH="$_work/bin:$PATH" bash "$_work/old-compare.sh" "$_work/regressed.json" \
        --baseline "$_work/baseline.json" --threshold 10 >"$_work/old.log" 2>&1 || _rc=$?
    if [[ "$_rc" -eq 0 ]] && grep -q 'All metrics pass' "$_work/old.log"; then
        _ok "teeth: HEAD reports 'All metrics pass' on a 50% regression without bc (bug reproduced)"
    else
        _bad "teeth: HEAD did not reproduce the fail-open (exit $_rc)"
    fi
else
    echo "skip teeth probe: git/HEAD:scripts/compare-baseline.sh unavailable" >&2
fi

if [[ "$_fail" -eq 0 ]]; then
    echo "compare-baseline-selftest: ALL OK"
    exit 0
fi
echo "compare-baseline-selftest: $_fail assertion(s) FAILED" >&2
exit 1
