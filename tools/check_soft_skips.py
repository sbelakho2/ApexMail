#!/usr/bin/env python3
"""Release-mode soft-skip log gate (audit CI-2).

`APEXMAIL_RELEASE_TEST_MODE=1` turns every soft skip of a
REQUIRES-INFRASTRUCTURE test into a hard panic inside the helper that owns
the skip decision (migrator::test_support::assert_soft_skip_allowed and the
per-crate mirrors). A helper that was MISSED in that sweep does not panic —
it quietly prints its old "skipping: …" line and the harness records PASSED.

This tool closes that hole: it scans a test-run log for the KNOWN soft-skip
marker families (the exact strings the workspace helpers eprintln when an
infrastructure variable is unset, or a configured failure is misreported as
a skip) and exits non-zero if any of them appear in a release-mode run.

Deliberately NOT markers (never flagged):
  * "marketing site not built"  — build-artifact convenience, not infra.
  * "redis-server not available/did not become ready", "cannot allocate
    port"       — locally spawned fixture binaries, no variable to name.
  * "DNS unavailable in test environment", "FAILBACK_ENABLED explicitly
    set", "FALLBACK_PODS_ENV set in environment", "DKIM fixture
    unavailable" — environment-conditioned unit tests, not infra gates.
  * "ENTERPRISE_TEST … unreachable" style lines are still flagged: in a
    release run the service is provided, so "unreachable" IS a broken
    fixture.

Usage: check_soft_skips.py <run.log> [--self-test]
Exit codes: 0 = clean, 1 = soft-skip markers found, 2 = usage/IO error.
"""

from __future__ import annotations

import re
import sys

# One alternation per marker FAMILY. These are literal substrings of the
# eprintln lines the workspace helpers print on the unset/unconfigured path;
# they are grepped as plain (regex-escaped) fragments so new tests that
# reword around them still match.
MARKER_FRAGMENTS = [
    # — the "set VAR" family —
    "set TEST_DATABASE_URL",
    "set TEST_REDIS_URL",
    "set REDIS_TEST_URL",
    "set HA_TEST_DATABASE_URL",
    "set CLICKHOUSE_TEST_URL",
    "set TEST_DATABASE_ADMIN_URL",
    "set TEST_FRESH_DATABASE_URL",
    "set SALES_TEST_DATABASE_URL",
    "set ENTERPRISE_TEST_DATABASE_URL",
    "set TEST_DATABASE_URL + TEST_REDIS_URL",
    "set TEST_REDIS_URL + TEST_DATABASE_URL",
    "set TEST_DATABASE_URL (+ TEST_REDIS_URL)",
    # — the "VAR not set / unset / not configured" family —
    "TEST_DATABASE_URL not set",
    "TEST_REDIS_URL not set",
    "REDIS_TEST_URL not set",
    "HA_TEST_DATABASE_URL not set",
    "TEST_DATABASE_ADMIN_URL not set",
    "TEST_FRESH_DATABASE_URL not set",
    "TEST_DATABASE_URL unset",
    "TEST_REDIS_URL unset",
    "REDIS_TEST_URL unset",
    "TEST_DATABASE_URL is not configured",
    "TEST_REDIS_URL is not configured",
    "no TEST_DATABASE_URL",
    "no TEST_REDIS_URL",
    "TEST_DATABASE_URL has no database segment",
    "unconfigured",  # functional_sales / integration_routes "skipping {name}: unconfigured"
    # — configured-failure-as-skip (must fail, never read as a skip) —
    "migrator could not run",
    "could not create isolated test database",
    "CLICKHOUSE_TEST_URL is not configured",
    "no ClickHouse at",
    # — env set but the fixture is dead: in release CI the service IS
    #   provided, so "unreachable"/"Redis unavailable" means real breakage —
    "TEST_REDIS_URL unreachable",
    "Redis unreachable",
    "Redis unavailable",
    "cannot reach Postgres admin database",
    "skipping session env",
    "skipping: no live Redis at",
]

# Substrings that mark a line as an INTENTIONAL, non-infrastructure skip.
ALLOWLIST_FRAGMENTS = [
    "marketing site not built",
    "redis-server not available",
    "redis-server did not become ready",
    "cannot allocate port",
    "DNS unavailable in test environment",
    "FAILBACK_ENABLED explicitly set",
    "FALLBACK_PODS_ENV",
    "DKIM fixture unavailable",
]

_MARKER_RE = re.compile("|".join(re.escape(f) for f in MARKER_FRAGMENTS))
_ALLOW_RE = re.compile("|".join(re.escape(f) for f in ALLOWLIST_FRAGMENTS))


def scan(text: str) -> list[str]:
    """Return the offending log lines (verbatim) that carry a soft-skip marker."""
    hits: list[str] = []
    for line in text.splitlines():
        if "skipping" not in line:
            continue
        if _ALLOW_RE.search(line):
            continue
        if _MARKER_RE.search(line):
            hits.append(line.rstrip())
    return hits


_SELF_TEST_CASES = [
    # (line, expected_flagged)
    ('skipping: set TEST_DATABASE_URL to run DB-backed test', True),
    ('skipping my_test: set TEST_DATABASE_URL', True),
    ('skipping: set TEST_REDIS_URL to run the outage matrix', True),
    ('skipping: set TEST_REDIS_URL + TEST_DATABASE_URL to run', True),
    ('skipping suspended_tenant_session_is_refused: no TEST_DATABASE_URL', True),
    ('skipping: HA_TEST_DATABASE_URL not set', True),
    ('skipping: REDIS_TEST_URL not set', True),
    ('skipping: TEST_DATABASE_ADMIN_URL not set', True),
    ('skipping f01_unset: TEST_DATABASE_URL unset', True),
    ('skipping integration_full_saml_login_flow: set TEST_DATABASE_URL', True),
    ('skipping api_test: TEST_DATABASE_URL is not configured', True),
    ('skipping: TEST_DATABASE_URL has no database segment', True),
    ('skipping: migrator could not run (no such table)', True),
    ('skipping clickhouse_roundtrip: no ClickHouse at http://127.0.0.1:8124', True),
    ('skipping: TEST_REDIS_URL unreachable', True),
    ('skipping: Redis unavailable: conn refused', True),
    ('skipping: cannot reach Postgres admin database', True),
    ('skipping session env: TEST_REDIS_URL unreachable', True),
    ('skipping: no live Redis at redis://127.0.0.1:6379/9', True),
    ('skipping: could not create isolated test database xyz_foo', True),
    ('skipping: CLICKHOUSE_TEST_URL is not configured', True),
    # Coverage for the remaining marker families (every MARKER_FRAGMENTS
    # family must have at least one proving case, or a reworded helper could
    # silently drop out of the gate's protection).
    ('skipping redis_roundtrip: set REDIS_TEST_URL to run', True),
    ('skipping fresh_db_case: set TEST_FRESH_DATABASE_URL to run', True),
    ('skipping sales_flow: set SALES_TEST_DATABASE_URL to run', True),
    ('skipping enterprise_flow: set ENTERPRISE_TEST_DATABASE_URL to run', True),
    ('skipping both_fixtures: set TEST_DATABASE_URL (+ TEST_REDIS_URL) to run', True),
    ('skipping tenant_query: TEST_DATABASE_URL not set', True),
    ('skipping outage_case: TEST_REDIS_URL not set', True),
    ('skipping cache_case: TEST_REDIS_URL unset', True),
    ('skipping: REDIS_TEST_URL unset', True),
    ('skipping api_case: TEST_REDIS_URL is not configured', True),
    ('skipping: Redis unreachable: connection refused', True),
    ('skipping: marketing site not built (placeholder pages embedded)', False),
    ('skipping: redis-server not available', False),
    ('skipping: redis-server did not become ready', False),
    ('skipping: cannot allocate port', False),
    ('skipping: DNS unavailable in test environment', False),
    ('skipping: FAILBACK_ENABLED explicitly set in environment', False),
    ('skipping: RATE_LIMIT_FALLBACK_PODS set in environment', False),
    ('skipping register_duplicate_email: DKIM fixture unavailable', False),
    ('test result: ok. 5 passed; 0 failed', False),
    ('skipping: no test called this', False),
]


def self_test() -> int:
    failures = 0
    for line, expected in _SELF_TEST_CASES:
        got = bool(scan(line))
        if got != expected:
            print(f"SELF-TEST FAIL: {line!r} → flagged={got}, expected={expected}")
            failures += 1
    if failures:
        print(f"self-test: {failures} case(s) failed")
        return 2
    print(f"self-test: all {len(_SELF_TEST_CASES)} cases pass")
    return 0


def main(argv: list[str]) -> int:
    args = [a for a in argv[1:] if a != "--self-test"]
    if "--self-test" in argv[1:]:
        return self_test()
    if len(args) != 1:
        print(__doc__.strip().splitlines()[-6], file=sys.stderr)
        return 2
    try:
        with open(args[0], encoding="utf-8", errors="replace") as fh:
            hits = scan(fh.read())
    except OSError as exc:
        print(f"check_soft_skips: cannot read {args[0]}: {exc}", file=sys.stderr)
        return 2
    if not hits:
        print("check_soft_skips: clean — no soft-skip markers in the release run log")
        return 0
    print(
        f"check_soft_skips: {len(hits)} SOFT SKIP(S) in a "
        "APEXMAIL_RELEASE_TEST_MODE=1 run — a REQUIRES-INFRASTRUCTURE test "
        "degraded into a green no-op (audit CI-2):",
        file=sys.stderr,
    )
    for line in hits[:50]:
        print(f"  {line}", file=sys.stderr)
    if len(hits) > 50:
        print(f"  … and {len(hits) - 50} more", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
