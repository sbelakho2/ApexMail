#!/usr/bin/env bash
# =============================================================================
# tools/check-risk-lua-parity.sh — mechanical gate for the risk-Lua invariants
#
# The assess_v2.lua trust-credit drift (round 83/84) slipped through because
# the "packaged copies are byte-identical / SolveSuccess is trust-neutral"
# invariants were asserted ONLY in prose comments. This gate enforces them:
#
#   1. Every canonical script in protocol/risk-v1/ has byte-identical copies
#      in the Rust package's resources/ directory (the sync invariant). The
#      PHP packages are NOT carried since 2026-10-28 (owner directive: the
#      KiwiCaptcha mirror is Rust-only), so their copies are no longer
#      compared here.
#   2. SolveSuccess (event 3) is TRUST-NEUTRAL in every script that has an
#      event-3 arm: the block between 'event == 3' and the next 'elseif'/
#      'end' must not write s.trust. A valid PoW proves expenditure, never
#      legitimacy — trust credit may come only from server-confirmed
#      outcomes.
#
# Exit 0 = all invariants hold; non-zero with a listed violation otherwise.
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CANONICAL="$ROOT/protocol/risk-v1"
COPIES=(
  "$ROOT/packages/kiwicaptcha-risk/resources"
)

failures=0

# ── 1. byte-identical packaged copies ────────────────────────────────────────
for script in "$CANONICAL"/*.lua; do
  name="$(basename "$script")"
  for dir in "${COPIES[@]}"; do
    target="$dir/$name"
    if [[ ! -f "$target" ]]; then
      # assess_v2.lua is the consolidated superset that lives only in packages
      if [[ "$name" == "assess_v2.lua" ]]; then
        continue
      fi
      echo "PARITY FAIL: $name missing from $dir" >&2
      failures=$((failures + 1))
      continue
    fi
    if ! cmp -s "$script" "$target"; then
      echo "PARITY FAIL: $dir/$name differs from protocol/risk-v1/$name" >&2
      failures=$((failures + 1))
    fi
  done
done

# ── 2. SolveSuccess trust-neutrality ─────────────────────────────────────────
check_script() {
  local file="$1"
  # Extract the event-3 arm and reject any trust write inside it. Lua blocks
  # in these scripts end at the next 'elseif' at the same nesting level.
  if awk '
    /event == 3/ { inarm = 1 }
    inarm && /elseif event ==/ { inarm = 0 }
    inarm && /s\.trust/ {
      print FILENAME ": SolveSuccess arm writes s.trust (must be trust-neutral)" > "/dev/stderr"
      bad = 1
    }
    END { exit bad ? 1 : 0 }
  ' "$file"; then
    :
  else
    failures=$((failures + 1))
  fi
}

for script in "$CANONICAL"/*.lua \
  "$ROOT/packages/kiwicaptcha-risk/resources"/*.lua; do
  check_script "$script"
done

if [[ $failures -gt 0 ]]; then
  echo "check-risk-lua-parity: $failures violation(s)" >&2
  exit 1
fi

echo "check-risk-lua-parity: all copies identical; SolveSuccess trust-neutral everywhere"
