#!/usr/bin/env bash
# =============================================================================
# ApexMail — Forbidden Pattern Quality Gate
#
# Prevents regressions by failing CI if prohibited patterns creep back into
# production code.  Run via:  pnpm verify:forbidden-patterns
# =============================================================================
set -euo pipefail

ERRORS=0
MAIL_SERVER="services/mail-server"

red()   { printf '\033[1;31m%s\033[0m\n' "$*"; }
green() { printf '\033[1;32m%s\033[0m\n' "$*"; }
check() {
  local label="$1" pattern="$2" path="$3" opts="${4:-}"
  # shellcheck disable=SC2086
  if matches=$(grep -rn $opts "$pattern" --include='*.rs' "$path" 2>/dev/null | grep -v '#\[cfg(test' | grep -v 'tests/' | grep -v '/// '); then
    count=$(echo "$matches" | wc -l)
    red "FAIL: $label ($count matches)"
    echo "$matches" | head -5
    ERRORS=$((ERRORS + 1))
  else
    green "PASS: $label"
  fi
}

echo "═══════════════════════════════════════════════════════════════"
echo " ApexMail Forbidden Pattern Gate"
echo "═══════════════════════════════════════════════════════════════"

# 1. No todo!/unimplemented! in production Rust
check "No todo!() macros" 'todo!()' "$MAIL_SERVER/crates"
check "No unimplemented!() macros" 'unimplemented!()' "$MAIL_SERVER/crates"

# 2. No localhost fallbacks in service binaries
check "No localhost connection fallbacks in binaries" \
  'unwrap_or.*localhost\|unwrap_or_else.*localhost' \
  "$MAIL_SERVER/crates/*/src/bin"

# 3. No floating container image tags in docker-compose
if grep -Pn 'image:.*:(latest|[a-z]+-[a-z]+)$' docker-compose.yml docker-compose.prod.yml 2>/dev/null | grep -v '#'; then
  red "FAIL: Floating container tags in docker-compose"
  ERRORS=$((ERRORS + 1))
else
  green "PASS: No floating container tags"
fi

# 4. No unpinned GitHub Actions (must use SHA)
if grep -rn 'uses:.*@v[0-9]' .github/workflows/*.yml 2>/dev/null; then
  red "FAIL: Unpinned GitHub Actions (must use SHA)"
  ERRORS=$((ERRORS + 1))
else
  green "PASS: All GitHub Actions SHA-pinned"
fi

# 5. All CI jobs have timeout-minutes
if python3 -c "
import yaml, sys
for f in sys.argv[1:]:
    with open(f) as fh:
        doc = yaml.safe_load(fh)
    for name, job in (doc.get('jobs') or {}).items():
        if 'timeout-minutes' not in job:
            print(f'{f}: job {name} missing timeout-minutes')
            sys.exit(1)
" .github/workflows/*.yml 2>/dev/null; then
  green "PASS: All CI jobs have timeout-minutes"
else
  red "FAIL: CI jobs missing timeout-minutes"
  ERRORS=$((ERRORS + 1))
fi

# 6. No console.* in billing TS app
if grep -rn 'console\.' --include='*.ts' apps/billing/src/ 2>/dev/null; then
  red "FAIL: console.* in billing app (use structured logger)"
  ERRORS=$((ERRORS + 1))
else
  green "PASS: No console.* in billing"
fi

# 7. No 'any' type in billing TS app
if grep -rn ': any\b' --include='*.ts' apps/billing/src/ 2>/dev/null; then
  red "FAIL: 'any' type in billing app"
  ERRORS=$((ERRORS + 1))
else
  green "PASS: No 'any' type in billing"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════"
if [ "$ERRORS" -gt 0 ]; then
  red "FAILED: $ERRORS forbidden pattern(s) detected"
  exit 1
else
  green "ALL CHECKS PASSED"
fi
