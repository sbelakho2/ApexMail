#!/bin/sh
# docs-lint-one-shot-test.sh — shell-level tests for the one-shot
# adoption manifest semantics of docs-lint.sh --integrity.
#
# Scenarios (each against throwaway baselines/manifests via
# --current-baseline / --adopted-manifest, so the committed files are
# never touched):
#
#  1. adoption applies once:      a new baseline path listed in the
#                                 manifest passes the integrity check.
#  2. no adoption, no pass:       the same new path WITHOUT an entry
#                                 fails ("not adopted").
#  3. consumed entry removed:     once the path has a row in the
#                                 current baseline, the integrity run
#                                 removes the entry from the manifest
#                                 (comments/blank lines preserved).
#  4. reintroduction not re-adopted: after the entry was consumed and
#                                 the path was dropped from the
#                                 baseline, a reintroduced row fails
#                                 without a fresh entry.
#  5. fresh adoption works again: a new entry for the reintroduced path
#                                 passes (adoption is repeatable, one
#                                 shot at a time).
#  6. --no-write-adopted:         the manifest is left untouched (the
#                                 consumed entry survives for a later
#                                 writable run).
#
# Exits 0 when every scenario holds, 1 otherwise. POSIX sh; the lint
# itself runs under the tool's own pinned C locale and awk selection.
set -u

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
LINT="$HERE/docs-lint.sh"

fail=0
ok() { echo "PASS: $1"; }
bad() { echo "FAIL: $1" >&2; fail=1; }

work=$(mktemp -d "${TMPDIR:-/tmp}/docs-lint-oneshot.XXXXXX") || exit 1
trap 'rm -rf "$work"' EXIT HUP INT TERM

# A minimal scan root: the tool requires ROOT/packages, and the scan
# covers packages/kiwicaptcha — one clean markdown file yields one
# zero-violation row and cannot perturb the baseline comparisons.
root="$work/root"
mkdir -p "$root/packages/kiwicaptcha"
printf '# KiwiCaptcha\n\nA clean file with no lint violations.\n' > "$root/packages/kiwicaptcha/README.md"

P='packages/kiwicaptcha/README.md'
N='packages/kiwicaptcha/NEW.md'

run_integrity() {
  # run_integrity <base-baseline> <cur-baseline> <manifest> [--no-write-adopted]
  extra=""
  if [ "${1:-}" = "--no-write-adopted" ]; then extra="--no-write-adopted"; shift; fi
  sh "$LINT" --integrity "$1" --current-baseline "$2" --adopted-manifest "$3" $extra "$root" >/dev/null 2>&1
}

# ── 1. adoption applies once ────────────────────────────────────────────
printf '0 %s\nTOTAL 0\n' "$P" > "$work/base1"
printf '0 %s\n0 %s\nTOTAL 0\n' "$P" "$N" > "$work/cur1"
printf '# adoption manifest (test)\n\n%s\n' "$N" > "$work/man1"
if run_integrity "$work/base1" "$work/cur1" "$work/man1"; then
  ok 'adoption applies once (a listed new path passes)'
else
  bad 'a listed new path must pass the integrity check'
fi

# ── 2. no adoption, no pass ─────────────────────────────────────────────
printf '# adoption manifest (test)\n' > "$work/man2"
if run_integrity "$work/base1" "$work/cur1" "$work/man2"; then
  bad 'an unlisted new path must fail (not adopted)'
else
  ok 'an unlisted new path fails (not adopted)'
fi

# ── 3. consumed entry removed from the manifest ─────────────────────────
printf '# adoption manifest (test)\n\n%s # adopted in cur1\n' "$N" > "$work/man3"
run_integrity "$work/base1" "$work/cur1" "$work/man3"
if grep -qxF "$N" "$work/man3"; then
  bad 'the consumed entry must be removed from the manifest'
else
  ok 'the consumed entry is removed from the manifest'
fi
if ! grep -qxF '# adoption manifest (test)' "$work/man3"; then
  bad 'manifest comments must be preserved by the rewrite'
else
  ok 'manifest comments are preserved by the rewrite'
fi

# ── 4. reintroduction is not re-adopted by a stale entry ────────────────
# base2 drops NEW.md (the path left the baseline); cur2 reintroduces it.
# The pre-one-shot behavior (a stale entry re-adopting forever) must be
# gone: with the manifest already consumed in step 3, the reintroduced
# row fails.
printf '0 %s\nTOTAL 0\n' "$P" > "$work/base2"
printf '0 %s\n0 %s\nTOTAL 0\n' "$P" "$N" > "$work/cur2"
if run_integrity "$work/base2" "$work/cur2" "$work/man3"; then
  bad 'a reintroduced path must not be re-adopted by a stale entry'
else
  ok 'a reintroduced path is not re-adopted by a stale entry'
fi

# ── 5. a fresh adoption entry works again ───────────────────────────────
printf '%s\n' "$N" > "$work/man5"
if run_integrity "$work/base2" "$work/cur2" "$work/man5"; then
  ok 'a fresh adoption entry passes (one shot at a time)'
else
  bad 'a fresh adoption entry must pass'
fi
# ...and is itself consumed by that very run.
if grep -qxF "$N" "$work/man5"; then
  bad 'the fresh entry must be consumed by its landing run'
else
  ok 'the fresh entry is consumed by its landing run'
fi

# ── 6. --no-write-adopted keeps the manifest read-only ──────────────────
printf '# adoption manifest (test)\n\n%s\n' "$N" > "$work/man6"
if run_integrity --no-write-adopted "$work/base2" "$work/cur2" "$work/man6"; then
  ok '--no-write-adopted still adopts for the run'
else
  bad '--no-write-adopted must still count the entry as adopted'
fi
if grep -qxF "$N" "$work/man6"; then
  ok '--no-write-adopted leaves the manifest untouched'
else
  bad '--no-write-adopted must not rewrite the manifest'
fi
# A later writable run then consumes it.
run_integrity "$work/base2" "$work/cur2" "$work/man6"
if grep -qxF "$N" "$work/man6"; then
  bad 'a later writable run must consume the pending entry'
else
  ok 'a later writable run consumes the pending entry'
fi

if [ "$fail" -eq 0 ]; then
  echo 'docs-lint-one-shot-test.sh: ALL PASS'
  exit 0
fi
echo 'docs-lint-one-shot-test.sh: FAILURES (see above)' >&2
exit 1
