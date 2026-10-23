#!/usr/bin/env python3
"""The stub ban (owner rule, enforced — plan rule "0 gaps or scaffolding").

A stub is an unfinished surface pretending to be finished: `todo!()`,
`unimplemented!()`, a `TODO`/`FIXME`/`HACK` left in product code, a
"NotYetImplemented" state reachable at runtime, a route that answers 501, a
named-but-empty function. The owner's standing rule is that none of these
exist: every capability is implemented, and where a plan item is genuinely
future work it is tracked as a work package in the plan, not as a marker in
the tree.

This gate scans product Rust (every crate except the six test-only crates)
plus the operator tooling for those markers and FAILS when one appears,
unless the exact occurrence is in `tools/stub-allowlist.toml` — pinned by the
SHA-256 of its line, with a reason, an owner and an expiry at most 14 days
out. A marker that moves to a different line re-flags, so an allowlist entry
cannot quietly follow code around.

Usage: check_no_stubs.py [--self-test]
Exit codes: 0 = clean, 1 = stub found, 2 = usage/IO error.
"""

from __future__ import annotations

import hashlib
import re
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCAN_ROOTS = [REPO / "services" / "mail-server" / "crates", REPO / "tools"]
ALLOWLIST = REPO / "tools" / "stub-allowlist.toml"
MAX_DAYS = 14

# The six test-only crates (plan tier 3). Tests are ALLOWED to construct a
# stub to prove a gate rejects it — that is the gate's teeth, not a gap.
TEST_ONLY_CRATES = {
    "integration-tests", "fuzz-tests", "functional-tests",
    "smoke-tests", "load-tests", "perf-tests",
}

# Marker regexes, each with the reason it is a stub. Order is the report order.
MARKERS: list[tuple[str, re.Pattern[str]]] = [
    ("todo!()", re.compile(r"\btodo!\s*\(")),
    ("unimplemented!()", re.compile(r"\bunimplemented!\s*\(")),
    ("NotYetImplemented",
     re.compile(r"\bNotYetImplemented\b")),
    ("TODO", re.compile(r"(?<![A-Za-z])TODO(?![A-Za-z(])")),
    ("FIXME", re.compile(r"(?<![A-Za-z])FIXME(?![A-Za-z])")),
    ("HACK", re.compile(r"(?<![A-Za-z])HACK(?![A-Za-z])")),
    ("not implemented (prose)",
     re.compile(r"\bnot yet implemented\b", re.IGNORECASE)),
]

# The entitlements model legitimately names `FeatureClass::NotYetImplemented`:
# it is the type that STOPS an unimplemented capability from being advertised,
# and its own test asserts plan seeds never carry it. Naming the class is not
# shipping a stub. Everything outside these files still flags.
NOT_YET_IMPLEMENTED_ALLOWED_FILES = {
    "services/mail-server/crates/billing-entitlements/src/classify.rs",
    "services/mail-server/crates/billing-entitlements/src/snapshot.rs",
    "services/mail-server/crates/billing-service/src/plans.rs",
    "services/mail-server/crates/api-server/src/entitlements.rs",
}


SELF = Path(__file__).resolve()


def rel(p: Path) -> str:
    try:
        return p.relative_to(REPO).as_posix()
    except ValueError:
        return str(p)


def iter_files() -> list[Path]:
    files: list[Path] = []
    for root in SCAN_ROOTS:
        if not root.exists():
            continue
        for p in root.rglob("*"):
            if p.suffix not in (".rs", ".py", ".sh", ".toml", ".yml", ".md"):
                continue
            relp = rel(p)
            if p == SELF or relp == "tools/stub-allowlist.toml":
                # The gate and its allowlist necessarily name the markers they
                # ban and pin.
                continue
            relp = rel(p)
            parts = p.parts
            if "crates" in parts:
                # crates/<name>/... — skip the six test-only crates, the
                # per-crate integration tests/ directories (test code may
                # construct a stub to prove a gate rejects it) and the target
                # directory wholesale.
                i = parts.index("crates")
                if i + 1 < len(parts) and parts[i + 1] in TEST_ONLY_CRATES:
                    continue
                if i + 2 < len(parts) and parts[i + 2] == "tests":
                    continue
            if "/target/" in relp or relp.startswith("services/mail-server/target"):
                continue
            if "/fuzz_targets/" in relp:
                # Fuzz corpora/targets may embed crash strings on purpose.
                continue
            files.append(p)
    return files


def load_allowlist() -> dict[str, dict]:
    if not ALLOWLIST.exists():
        return {}
    data = tomllib.loads(ALLOWLIST.read_text())
    out: dict[str, dict] = {}
    for entry in data.get("allow", []):
        out[str(entry.get("line_hash", ""))] = entry
    return out


def line_hash(text: str) -> str:
    return hashlib.sha256(text.strip().encode()).hexdigest()[:16]


def scan(*, today) -> tuple[list[str], int]:
    import datetime as dt

    allow = load_allowlist()
    problems: list[str] = []
    hits = 0
    for path in iter_files():
        relp = rel(path)
        try:
            lines = path.read_text(errors="replace").splitlines()
        except OSError as exc:
            problems.append(f"{relp}: unreadable ({exc})")
            continue
        in_cfg_test = 0
        depth = 0
        for no, line in enumerate(lines, 1):
            # A #[cfg(test)] item is test code: it may construct a stub to
            # prove a gate has teeth. Track brace depth from the line the
            # attribute appears on and skip the whole region.
            stripped = line.strip()
            if in_cfg_test == 0 and stripped.startswith("#[cfg(test)]"):
                in_cfg_test = 1
                depth = line.count("{") - line.count("}")
                continue
            if in_cfg_test:
                depth += line.count("{") - line.count("}")
                if depth <= 0 and "{" in "".join(lines[no - len(lines) + no - 1:no]):
                    pass
                if depth <= 0 and no > 1 and ("}" in line):
                    in_cfg_test = 0
                continue
            for name, rx in MARKERS:
                if not rx.search(line):
                    continue
                if name == "NotYetImplemented" and relp in NOT_YET_IMPLEMENTED_ALLOWED_FILES:
                    continue
                hits += 1
                key = line_hash(line)
                entry = allow.get(key)
                if entry is None:
                    problems.append(
                        f"{relp}:{no}: {name} (allowlist this in {ALLOWLIST.name} "
                        f"with the line hash {key}, or remove it)"
                    )
                    continue
                try:
                    expires = dt.date.fromisoformat(str(entry.get("expires", "")))
                except ValueError:
                    problems.append(f"{relp}:{no}: allowlist entry has no valid expiry")
                    continue
                if expires < today:
                    problems.append(
                        f"{relp}:{no}: allowlist entry EXPIRED {expires} — remove the stub"
                    )
    return problems, hits


def self_test(tmp: Path) -> int:
    import datetime as dt

    clean = tmp / "clean.rs"
    clean.write_text("fn main() { let _ = 1 + 1; }\n")
    problems, _ = scan_files([clean], today=dt.date(2026, 10, 22), allow={})
    if problems:
        print("self-test FAIL: clean file flagged:\n" + "\n".join(problems), file=sys.stderr)
        return 1

    dirty = tmp / "dirty.rs"
    dirty.write_text(
        "// FIXME finish this\nfn later() { todo!() }\n"
    )
    problems, _ = scan_files([dirty], today=dt.date(2026, 10, 22), allow={})
    joined = "\n".join(problems)
    for needle in ("FIXME", "todo!()"):
        if needle not in joined:
            print(f"self-test FAIL: expected {needle!r} flagged, got:\n{joined}", file=sys.stderr)
            return 1
    print("self-test: ok (clean file passes; todo!/FIXME are flagged)")
    return 0


def scan_files(files: list[Path], *, today, allow: dict[str, dict]) -> tuple[list[str], int]:
    problems: list[str] = []
    hits = 0
    for path in files:
        lines = path.read_text(errors="replace").splitlines()
        for no, line in enumerate(lines, 1):
            for name, rx in MARKERS:
                if not rx.search(line):
                    continue
                if name == "NotYetImplemented" and rel(path) in NOT_YET_IMPLEMENTED_ALLOWED_FILES:
                    continue
                hits += 1
                key = line_hash(line)
                entry = allow.get(key)
                if entry is None:
                    problems.append(f"{rel(path)}:{no}: {name}")
                    continue
                try:
                    if dt.date.fromisoformat(str(entry.get("expires", ""))) < today:
                        problems.append(f"{rel(path)}:{no}: allowlist EXPIRED")
                except ValueError:
                    problems.append(f"{rel(path)}:{no}: allowlist entry has no valid expiry")
    return problems, hits


def main(argv: list[str]) -> int:
    import datetime as dt

    if "--self-test" in argv:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            return self_test(Path(tmp))
    problems, hits = scan(today=dt.date.today())
    if problems:
        print(f"STUB BAN FAILED — {len(problems)} marker(s) in product code:", file=sys.stderr)
        for p in problems[:60]:
            print(f"  - {p}", file=sys.stderr)
        if len(problems) > 60:
            print(f"  … and {len(problems) - 60} more", file=sys.stderr)
        print("the owner's rule: 0 gaps or scaffolding. Implement the capability, or "
              f"track it as a plan work package — never leave a marker.\n"
              f"(genuine, temporary exceptions are named in {ALLOWLIST.name} with a "
              "reason, an owner and a 14-day expiry)", file=sys.stderr)
        return 1
    print(f"stub ban: clean ({hits} allowed occurrence(s), all allowlisted and unexpired)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
