#!/usr/bin/env python3
"""Dated cargo-audit waiver gate.

`services/mail-server/.cargo/audit.toml` is both the cargo-audit config
(cargo-audit 0.22+ applies [advisories].ignore natively) and the DATED waiver
ledger. Each ignored id carries a waiver block immediately above it:

    # waiver: package="rsa" version="0.9.10" written="2026-10-29" expires="2027-01-27"
    # reason: ...
    # reachable: yes|no: <call path or why no shipped path reaches it>

Rules (plan Tests & enforcement rule 3 applied to dependency advisories):

  1. Every ignored id has exactly one waiver block with package, version,
     reason, reachable, written and expires.
  2. The expiry is at most 90 days past `written`.
  3. An expired waiver fails the lane: it is removed or re-reviewed, never
     renewed silently.
  4. The waived package (and pinned version) must still exist in
     services/mail-server/Cargo.lock. An obsolete waiver is deleted, not kept
     as a permanent blanket ignore.
  5. An ignore entry without a waiver block (an undated ignore) FAILS — every
     ignore in this file must be dated.

The WARNING-class ledger (unmaintained/unsound) is deliberately NOT here: it
lives in ci/pipeline.conf CI_CARGO_AUDIT_IGNORES, in exact lockstep with
deny.toml and scripts/security-audit.sh.

Usage:
  check_audit_waivers.py [--file PATH] [--lockfile PATH] [--today YYYY-MM-DD]
  check_audit_waivers.py --print-ignores   # ids from [advisories].ignore
  check_audit_waivers.py --self-test
Exit codes: 0 = clean, 1 = violation, 2 = usage/IO error.
"""

from __future__ import annotations

import datetime as dt
import re
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
WAIVERS = REPO / "services" / "mail-server" / ".cargo" / "audit.toml"
LOCKFILE = REPO / "services" / "mail-server" / "Cargo.lock"
MAX_WAIVER_DAYS = 90
REQUIRED_FIELDS = ("package", "version", "reason", "reachable", "written", "expires")

WAIVER_LINE_RE = re.compile(r"^\s*#\s*waiver:\s*(.+)$")
KV_RE = re.compile(r'(\w+)\s*=\s*"([^"]*)"')
REASON_RE = re.compile(r"^\s*#\s*reason:\s*(.+)$")
REACHABLE_RE = re.compile(r"^\s*#\s*reachable:\s*((?i:yes|no)[^:]*):\s*(.+)$")
ID_LINE_RE = re.compile(r'^\s*"((?:RUSTSEC|CVE|GHSA)-[^"]+)"\s*,?\s*$')


def load_locked_packages(path: Path) -> dict[str, set[str]]:
    """name -> versions from a Cargo.lock ([[package]] entries)."""
    packages: dict[str, set[str]] = {}
    name = None
    for line in path.read_text().splitlines():
        m = re.match(r'^name = "(.+)"$', line)
        if m:
            name = m.group(1)
            continue
        m = re.match(r'^version = "(.+)"$', line)
        if m and name is not None:
            packages.setdefault(name, set()).add(m.group(1))
            name = None
    return packages


def parse_waivers(waivers_path: Path) -> tuple[list[dict[str, str]], list[str], list[str]]:
    """Return (waiver blocks, ignore ids, parse problems)."""
    text = waivers_path.read_text()
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        return [], [], [f"invalid TOML: {exc}"]
    ignore_ids = data.get("advisories", {}).get("ignore", [])
    problems: list[str] = []
    if not isinstance(ignore_ids, list):
        return [], [], ["[advisories].ignore must be an array of advisory ids"]
    ignore_ids = [str(i) for i in ignore_ids]
    waivers: list[dict[str, str]] = []
    pending: dict[str, str] | None = None
    for line in text.splitlines():
        m = WAIVER_LINE_RE.match(line)
        if m:
            if pending is not None:
                problems.append(
                    f"{pending.get('id', '<pending>')}: waiver block without an "
                    "advisory id line (the id must come immediately after the block)"
                )
            pending = dict(KV_RE.findall(m.group(1)))
            pending.setdefault("reason", "")
            pending.setdefault("reachable", "")
            continue
        if pending is not None:
            m = REASON_RE.match(line)
            if m:
                pending["reason"] = m.group(1).strip()
                continue
            m = REACHABLE_RE.match(line)
            if m:
                pending["reachable"] = f"{m.group(1).strip()}: {m.group(2).strip()}"
                continue
            m = ID_LINE_RE.match(line)
            if m:
                pending["id"] = m.group(1)
                pending["_id_in_array"] = "yes"
                waivers.append(pending)
                pending = None
    if pending is not None:
        problems.append("waiver block at end of file without an advisory id")
    listed = set(ignore_ids)
    block_ids = {w.get("id", "") for w in waivers}
    for advisory_id in sorted(listed - block_ids):
        problems.append(
            f"{advisory_id}: ignored in [advisories].ignore but has no DATED "
            "waiver block (an undated ignore is not allowed)"
        )
    for advisory_id in sorted(block_ids - listed):
        problems.append(
            f"{advisory_id}: waiver block has no matching id in [advisories].ignore"
        )
    return waivers, ignore_ids, problems


def check(
    waivers_path: Path,
    lock_path: Path,
    *,
    today: dt.date | None = None,
) -> list[str]:
    today = today or dt.date.today()
    waivers, _ignore_ids, problems = parse_waivers(waivers_path)
    locked = load_locked_packages(lock_path)
    seen: set[str] = set()
    for w in waivers:
        advisory_id = str(w.get("id", "")).strip()
        where = advisory_id or "<missing id>"
        if advisory_id in seen:
            problems.append(f"{where}: duplicate waiver")
        seen.add(advisory_id)
        for field in REQUIRED_FIELDS:
            if not str(w.get(field, "")).strip():
                problems.append(f"{where}: waiver field {field!r} is missing")
        if len(str(w.get("reason", "")).strip()) < 20:
            problems.append(f"{where}: reason must explain the acceptance (>=20 chars)")
        if not re.match(r"(?i)^(yes|no)\b", str(w.get("reachable", "")).strip()):
            problems.append(
                f"{where}: reachable must start with yes or no and name the call path"
            )
        try:
            written = dt.date.fromisoformat(str(w["written"]))
            expires = dt.date.fromisoformat(str(w["expires"]))
        except (KeyError, ValueError) as exc:
            problems.append(f"{where}: unreadable written/expires date ({exc})")
            continue
        if expires < written:
            problems.append(f"{where}: expires {expires} is before written {written}")
        if expires > written + dt.timedelta(days=MAX_WAIVER_DAYS):
            problems.append(
                f"{where}: waiver expires {expires} but may run at most "
                f"{MAX_WAIVER_DAYS} days past {written}"
            )
        if expires < today:
            problems.append(
                f"{where}: waiver EXPIRED on {expires} — remove it or re-review the advisory"
            )
        package = str(w.get("package", "")).strip()
        version = str(w.get("version", "")).strip()
        if package:
            if package not in locked:
                problems.append(
                    f"{where}: waived package {package!r} is not in {lock_path.name} — "
                    "an obsolete waiver must be deleted"
                )
            elif version and version not in locked[package]:
                problems.append(
                    f"{where}: waived version {package} {version} is not in "
                    f"{lock_path.name} (locked: {', '.join(sorted(locked[package]))}) — "
                    "an obsolete waiver must be deleted"
                )
    return problems


def self_test(tmp: Path) -> int:
    lock = tmp / "Cargo.lock"
    lock.write_text(
        '[[package]]\nname = "demo-crate"\nversion = "1.2.3"\n'
        '[[package]]\nname = "other"\nversion = "0.1.0"\n'
    )
    today = dt.date(2026, 10, 29)

    def fixture(
        expires: str,
        package: str = "demo-crate",
        version: str = "1.2.3",
        written: str = "2026-10-01",
    ) -> Path:
        path = tmp / f"audit-{written}-{expires}-{package}-{version}.toml"
        path.write_text(
            "[advisories]\nignore = [\n"
            f'    # waiver: package="{package}" version="{version}" '
            f'written="{written}" expires="{expires}"\n'
            "    # reason: test fixture explaining the acceptance\n"
            '    # reachable: no: never linked by a shipped target\n'
            '    "RUSTSEC-2026-9999",\n'
            "]\n"
        )
        return path

    if check(fixture("2026-12-30"), lock, today=today):
        print("self-test FAIL: a valid waiver was rejected", file=sys.stderr)
        return 1
    text = "\n".join(
        check(fixture("2026-11-01", written="2026-01-01"), lock, today=today)
    )
    if "at most 90 days past" not in text:
        print(f"self-test FAIL: expected an over-long waiver error in:\n{text}", file=sys.stderr)
        return 1
    text = "\n".join(
        check(fixture("2026-09-02", written="2026-09-01"), lock, today=today)
    )
    if "EXPIRED" not in text:
        print(f"self-test FAIL: expected an expired waiver error in:\n{text}", file=sys.stderr)
        return 1
    text = "\n".join(check(fixture("2026-12-30", package="gone-crate"), lock, today=today))
    if "not in Cargo.lock" not in text:
        print("self-test FAIL: an obsolete package waiver was accepted", file=sys.stderr)
        return 1
    text = "\n".join(check(fixture("2026-12-30", version="9.9.9"), lock, today=today))
    if "is not in Cargo.lock" not in text:
        print("self-test FAIL: a stale version pin was accepted", file=sys.stderr)
        return 1
    undated = tmp / "undated.toml"
    undated.write_text('[advisories]\nignore = ["RUSTSEC-2026-8888"]\n')
    text = "\n".join(check(undated, lock, today=today))
    if "no DATED waiver block" not in text:
        print("self-test FAIL: an undated ignore was accepted", file=sys.stderr)
        return 1
    print("self-test: ok (valid waiver accepted; expired, over-long, obsolete-package, "
          "stale-version and undated ignores rejected)")
    return 0


def main(argv: list[str]) -> int:
    waivers = WAIVERS
    lock = LOCKFILE
    today = None
    args = list(argv)
    for flag in ("--file", "--lockfile", "--today"):
        if flag in args:
            value = args[args.index(flag) + 1]
            if flag == "--file":
                waivers = Path(value)
            elif flag == "--lockfile":
                lock = Path(value)
            else:
                try:
                    today = dt.date.fromisoformat(value)
                except ValueError:
                    print(f"invalid --today value: {value}", file=sys.stderr)
                    return 2
    if "--self-test" in args:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            return self_test(Path(tmp))
    if not waivers.exists() or not lock.exists():
        missing = waivers if not waivers.exists() else lock
        print(f"missing file: {missing}", file=sys.stderr)
        return 2
    problems = check(waivers, lock, today=today)
    if problems:
        print("cargo-audit waiver gate FAILED:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        print(
            f"see {waivers} — an expired waiver is removed, not renewed silently",
            file=sys.stderr,
        )
        return 1
    waivers_list, ignore_ids, _ = parse_waivers(waivers)
    if "--print-ignores" in args:
        for advisory_id in ignore_ids:
            print(advisory_id)
        return 0
    print(
        f"cargo-audit waivers: {len(waivers_list)} dated, none expired, all within the "
        f"{MAX_WAIVER_DAYS}-day maximum"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
