#!/bin/sh
# verify-error-code-parity.sh — cross-language error-code drift gate.
#
# The Rust core's VerifyError::code() claims to carry the PHP SDK's
# VerifyError case values as the shared machine-readable wire
# vocabulary. A handwritten Rust-side list "proving" that parity passes
# vacuously the moment the PHP enum grows a case the list forgot, so
# this gate does the real check mechanically:
#
#   1. parse packages/kiwicaptcha-php/src/VerifyError.php for every
#      `case X = 'code';` value;
#   2. grep the code() mapping in packages/kiwicaptcha/src/verify.rs for
#      every wire code it returns;
#   3. fail on any PHP code absent from the Rust mapping, unless it is
#      listed in the documented-divergence table below with a comment
#      per divergence explaining why the twin does not exist.
#
# The reverse direction (Rust-only codes) is deliberately NOT an error:
# the Rust core has codes the PHP core does not return (e.g.
# counter_too_large, rejected outright by the Rust decoder where PHP
# maps oversized counters to malformed_token). Only the PHP→Rust
# direction is the compatibility contract: a PHP-emitted code that no
# Rust consumer can branch on is silent drift.
#
# posix sh; awk conventions follow docs-lint.sh (gawk preferred, awk
# fallback, pinned C locale). Exits 0 when the parity holds, 1 with a
# per-code diff otherwise.
set -u
LC_ALL=C
export LC_ALL

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PHP_ENUM="$HERE/../../kiwicaptcha-php/src/VerifyError.php"
RUST_VERIFY="$HERE/../src/verify.rs"

# The documented divergences: PHP codes with no Rust twin, each with the
# reason it is absent. Keep this table empty — a divergence entry is
# a last resort and must carry a comment. (After the Argon2
# harmonization the table is empty; the BotDetected variant is not a
# divergence — the Rust variant exists and carries PHP's
# telemetry_rejected code; only the variant name differs.)
DIVERGENCES="
"

fail=0
ok() { echo "PASS: $1"; }
bad() { echo "FAIL: $1" >&2; fail=1; }

for f in "$PHP_ENUM" "$RUST_VERIFY"; do
  if [ ! -f "$f" ]; then
    bad "missing input $f"
    exit 1
  fi
done

AWK_BIN="$(command -v gawk 2>/dev/null || command -v awk)"

# PHP side: the case values of the string-backed enum, one per line.
php_codes=$($AWK_BIN '
  # Strip /* */ comments so a doc reference to a case value is never
  # collected as an enum case.
  {
    line = $0
    out = ""
    i = 1
    n = length(line)
    while (i <= n) {
      two = substr(line, i, 2)
      if (two == "/*") {
        j = index(substr(line, i), "*/")
        if (j > 0) { i += j + 1; continue }
        break
      }
      out = out substr(line, i, 1)
      i++
    }
    if (match(out, /case[ \t]+[A-Za-z0-9_]+[ \t]*=[ \t]*'\''[a-z0-9_]+'\''[ \t]*;/)) {
      s = substr(out, RSTART, RLENGTH)
      sub(/^case[ \t]+[A-Za-z0-9_]+[ \t]*=[ \t]*'\''/, "", s)
      sub(/'\''[ \t]*;$/, "", s)
      print s
    }
  }
' "$PHP_ENUM")

# Rust side: every string literal the code() match arm returns.
rust_codes=$(grep -oE '=> "[a-z0-9_]+"' "$RUST_VERIFY" | sed 's/^=> "//; s/"$//')

php_count=$(printf '%s\n' "$php_codes" | grep -c .)
rust_count=$(printf '%s\n' "$rust_codes" | grep -c .)

# Uniqueness of the Rust mapping: a duplicated wire code would make the
# parity check ambiguous.
dup=$(printf '%s\n' "$rust_codes" | sort | uniq -d)
if [ -n "$dup" ]; then
  bad "duplicated Rust wire codes: $(printf '%s ' $dup)"
fi

missing=0
for code in $php_codes; do
  if printf '%s\n' "$rust_codes" | grep -qx "$code"; then
    continue
  fi
  if printf '%s\n' "$DIVERGENCES" | grep -qx "$code"; then
    continue
  fi
  bad "PHP wire code '$code' has no Rust twin in VerifyError::code() ($RUST_VERIFY) and no documented divergence"
  missing=1
done

if [ "$missing" -eq 0 ] && [ -z "$dup" ]; then
  ok "all $php_count PHP error codes have Rust twins ($rust_count Rust wire codes mapped)"
fi

# Stale-divergence hygiene: an entry whose code now HAS a Rust twin is a
# stale row and fails the gate, so the table cannot rot.
for code in $DIVERGENCES; do
  if printf '%s\n' "$rust_codes" | grep -qx "$code"; then
    bad "stale divergence entry: '$code' now has a Rust twin — remove it from the table"
  fi
done

exit $fail
