#!/usr/bin/env python3
"""Advisory-lane waiver gate (plan Tests & enforcement rule 3, WP T1).

`ci/waivers.toml` records why a lane that would otherwise be required is
being run advisory instead. Three rules make a waiver mean something:

  1. Every waiver names the lane, a reason, an owner and an expiry date.
  2. The expiry is at most 14 days out from the waiver's written date.
  3. An expired waiver fails the run (it is removed, not renewed silently).

This gate reads `ci/waivers.toml` and FAILS when any waiver is expired, when
its expiry exceeds the 14-day maximum, when a required field is missing, or
when a waived lane is not a lane at all (not listed in
`ci/required-lanes.txt`). A lane may only be waived; a lane that does not
exist cannot be.

Usage: check_waivers.py [--waivers PATH] [--lanes PATH] [--self-test]
Exit codes: 0 = clean, 1 = violation, 2 = usage/IO error.
"""

from __future__ import annotations

import datetime as dt
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
WAIVERS = REPO / "ci" / "waivers.toml"
LANES = REPO / "ci" / "required-lanes.txt"
MAX_WAIVER_DAYS = 14


def load_lanes(path: Path) -> set[str]:
    lanes: set[str] = set()
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            lanes.add(line.split()[0])
    return lanes


def check(waivers_path: Path, lanes_path: Path, *, today: dt.date | None = None) -> list[str]:
    today = today or dt.date.today()
    lanes = load_lanes(lanes_path)
    data = tomllib.loads(waivers_path.read_text())
    problems: list[str] = []
    seen: set[str] = set()
    for w in data.get("waiver", []):
        lane = str(w.get("lane", "")).strip()
        if not lane:
            problems.append("waiver without a lane")
            continue
        if lane in seen:
            problems.append(f"{lane}: duplicate waiver")
        seen.add(lane)
        if lane not in lanes:
            problems.append(f"{lane}: waived lane is not in {lanes_path.name}")
        for field in ("reason", "owner", "written", "expires"):
            if not str(w.get(field, "")).strip():
                problems.append(f"{lane}: waiver field {field!r} is missing")
        try:
            written = dt.date.fromisoformat(str(w["written"]))
            expires = dt.date.fromisoformat(str(w["expires"]))
        except (KeyError, ValueError) as exc:
            problems.append(f"{lane}: unreadable written/expires date ({exc})")
            continue
        if expires > written + dt.timedelta(days=MAX_WAIVER_DAYS):
            problems.append(
                f"{lane}: waiver expires {expires} but may run at most "
                f"{MAX_WAIVER_DAYS} days past {written}"
            )
        if expires < today:
            problems.append(f"{lane}: waiver EXPIRED on {expires} — remove it and run the lane")
    # An unknown stray key is a typo in the schema; catch it.
    for key in data:
        if key != "waiver":
            problems.append(f"unknown top-level table {key!r} (expected [waiver])")
    return problems


def self_test(tmp: Path) -> int:
    """Prove the gate fails on known-bad fixtures and passes a clean one."""
    lanes = tmp / "lanes.txt"
    lanes.write_text("# required lanes\nvalidate\ntest\n")
    clean = tmp / "clean.toml"
    clean.write_text(
        "[[waiver]]\nlane = 'test'\nreason = 'infra down, ticket 42'\n"
        "owner = 'owner'\nwritten = '2026-10-22'\nexpires = '2026-11-01'\n"
    )
    if check(clean, lanes, today=dt.date(2026, 10, 22)):
        print("self-test FAIL: a valid waiver was rejected", file=sys.stderr)
        return 1
    bad = tmp / "bad.toml"
    bad.write_text(
        "[[waiver]]\nlane = 'test'\nreason = 'r'\nowner = 'o'\n"
        "written = '2026-01-01'\nexpires = '2026-11-01'\n"
        "[[waiver]]\nlane = 'no-such-lane'\nreason = 'r'\nowner = 'o'\n"
        "written = '2026-10-01'\nexpires = '2026-10-02'\n"
        "[[waiver]]\nlane = 'validate'\nreason = 'r'\nowner = 'o'\n"
        "written = '2026-09-01'\nexpires = '2026-09-02'\n"
    )
    problems = check(bad, lanes, today=dt.date(2026, 10, 22))
    kinds = "\n".join(problems)
    for needle in ("14 days", "not in", "EXPIRED"):
        if needle not in kinds:
            print(f"self-test FAIL: expected a {needle!r} problem, got:\n{kinds}", file=sys.stderr)
            return 1
    print("self-test: ok (valid waiver accepted; over-long, unknown-lane and "
          "expired waivers rejected)")
    return 0


def main(argv: list[str]) -> int:
    waivers = WAIVERS
    lanes_path = LANES
    do_self_test = "--self-test" in argv
    args = list(argv)
    if "--waivers" in args:
        waivers = Path(args[args.index("--waivers") + 1])
    if "--lanes" in args:
        lanes_path = Path(args[args.index("--lanes") + 1])
    if do_self_test:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            return self_test(Path(tmp))
    if not waivers.exists():
        # An empty (or absent) waiver file is the clean state: every lane is
        # required. Nothing to check, nothing waived.
        print("waivers: none (ci/waivers.toml absent — every lane required)")
        return 0
    problems = check(waivers, lanes_path)
    if problems:
        print("waiver gate FAILED:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        print(f"see {waivers} — an expired waiver is removed, not renewed", file=sys.stderr)
        return 1
    count = len(tomllib.loads(waivers.read_text()).get("waiver", []))
    print(f"waivers: {count} active, none expired, all within the "
          f"{MAX_WAIVER_DAYS}-day maximum")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
