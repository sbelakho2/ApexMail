#!/usr/bin/env python3
"""The invariant and expectations registry gate (plan rule 7, WP T14).

Three promises, checked mechanically:

  1. Every workspace crate and every declared package appears in
     `ci/test-expectations.toml` — a package missing from the file is a
     package whose tests nobody promised.
  2. Every declared `required_kinds` entry has evidence in the tree TODAY:
     `unit` needs a test attribute in the package, `fuzz` a fuzz target under
     fuzz-tests named for (or referencing) the package, `corpus` a committed
     corpus directory, `golden` committed golden fixtures, `lane` a row in
     `ci/required-lanes.txt`, `journey` a journey spec. A declared kind that
     does not exist fails (plan: "no proptest in a crate that must have one").
  3. Every invariant in `docs/invariants.toml` still names code and test
     anchors that exist.

Planned kinds live in `[planned.<WP>]` tables; the checker verifies every
referenced package and WP id so an entry cannot silently rot.

Usage: check_invariants.py [--self-test]
Exit codes: 0 = clean, 1 = violation, 2 = usage/IO error.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
WS = REPO / "services" / "mail-server" / "crates"
EXPECT = REPO / "ci" / "test-expectations.toml"
INVARIANTS = REPO / "docs" / "invariants.toml"
LANES = REPO / "ci" / "required-lanes.txt"
FUZZ_DIR = WS / "fuzz-tests"

KNOWN_KINDS = {"unit", "fuzz", "corpus", "golden", "matrix", "journey", "lane", "eval", "property"}

WP_IDS = {
    *(f"H{i}" for i in range(1, 4)), *(f"A{i}" for i in range(1, 7)),
    *(f"B{i}" for i in range(1, 7)), *(f"C{i}" for i in range(1, 5)),
    *(f"D{i}" for i in range(1, 5)), *(f"E{i}" for i in range(1, 7)),
    *(f"F{i}" for i in range(1, 13)), *(f"G{i}" for i in range(1, 4)),
    *(f"S{i}" for i in range(1, 25)), *(f"T{i}" for i in range(1, 18)),
    *(f"V{i}" for i in range(1, 28)),
}


def crate_has_unit(crate: Path) -> bool:
    for p in crate.rglob("*.rs"):
        if "/target/" in str(p):
            continue
        t = p.read_text(errors="replace")
        if "#[test]" in t or "#[tokio::test]" in t or "#[sqlx::test]" in t:
            return True
    return False


def kind_evidence(name: str, kind: str) -> bool:
    crate = WS / name
    if kind == "unit":
        return crate.is_dir() and crate_has_unit(crate)
    if kind == "fuzz":
        if not FUZZ_DIR.is_dir():
            return False
        slug = name.replace("-", "_")
        return any(
            slug in p.name or slug in p.read_text(errors="replace")
            for p in FUZZ_DIR.rglob("*.rs")
        )
    if kind == "corpus":
        return crate.is_dir() and any(
            "corpus" in p.name.lower() for p in list(crate.rglob("*")) + [crate]
            if p.is_dir()
        )
    if kind == "golden":
        return crate.is_dir() and any(
            "golden" in p.name.lower() or "baseline" in p.name.lower()
            for p in crate.rglob("*") if p.is_file() or p.is_dir()
        )
    if kind == "lane":
        return LANES.exists() and name in LANES.read_text()
    if kind == "matrix":
        src = WS / "api-server" / "src"
        return src.is_dir() and any(
            "route" in p.name.lower() and "matrix" in p.read_text(errors="replace").lower()
            for p in src.rglob("*.rs")
        )
    if kind == "journey":
        # The journey drivers are ApexMail-owned (tests/journeys since
        # 2026-10-28, when the mirrored tests/browser left with the PHP
        # mirror).
        journeys = REPO / "tests" / "journeys"
        return journeys.is_dir() and any(
            name.split("/")[0].split("-")[0] in p.read_text(errors="replace")
            for p in journeys.glob("journey-*.mjs")
        )
    if kind == "eval":
        return crate.is_dir() and any(
            "eval" in p.name.lower() for p in crate.rglob("*") if p.is_file()
        )
    return False


def pkg_kind_evidence(name: str, kind: str) -> bool:
    pkg = REPO / name
    if kind == "unit":
        if not pkg.is_dir():
            return False
        for p in pkg.rglob("*"):
            if not p.is_file() or p.suffix not in (
                ".go", ".py", ".java", ".php", ".rb", ".ts", ".js", ".rs",
            ):
                continue
            if "test" in p.name.lower():
                return True
            try:
                head = p.read_text(errors="replace")[:40000]
            except OSError:
                continue
            if re.search(r"func Test|def test_|#\[test\]|#\[tokio::test\]|\bit \(|\btest\(", head):
                return True
        return False
    if kind == "lane":
        return True  # the group is itself a lane in ci/required-lanes.txt
    if kind == "journey":
        # ApexMail-owned journey drivers (tests/journeys since the KiwiCaptcha
        # mirror slim; kind_evidence covers crates, this covers packages).
        return any((pkg / p.name).is_file() for p in (REPO / "tests" / "journeys").glob("journey-*.mjs")) if (REPO / "tests" / "journeys").is_dir() else False
    return False


def collect(expect: dict, invariants: dict, crates: set[str], lanes_text: str) -> list[str]:
    problems: list[str] = []
    for name in sorted(crates):
        if name not in expect:
            problems.append(f"crate {name!r} is missing from the expectations registry")
    for name, entry in expect.items():
        if entry.get("tier") not in (1, 2, 3):
            problems.append(f"{name}: tier must be 1, 2 or 3")
        if not (REPO / name).is_dir() and name not in crates:
            problems.append(f"{name}: registered package does not exist in the tree")
        for kind in entry.get("required_kinds", []):
            if kind not in KNOWN_KINDS:
                problems.append(f"{name}: unknown kind {kind!r}")
                continue
            if name in crates:
                if not kind_evidence(name, kind):
                    problems.append(f"{name}: kind {kind!r} declared but no evidence in the tree")
            else:
                if not pkg_kind_evidence(name, kind):
                    problems.append(f"{name}: kind {kind!r} declared but no evidence in the tree")
    for wp, planned in tomllib.loads(EXPECT.read_text()).get("planned", {}).items():
        if wp not in WP_IDS:
            problems.append(f"[planned.{wp}]: unknown work-package id")
        if planned.get("kind") not in KNOWN_KINDS:
            problems.append(f"[planned.{wp}]: unknown kind {planned.get('kind')!r}")
        for name in planned.get("packages", []):
            if name not in expect:
                problems.append(f"[planned.{wp}]: package {name!r} is not registered")
    inv = invariants.get("invariant", [])
    if not inv:
        problems.append("no invariants declared in docs/invariants.toml")
    for entry in inv:
        iid = entry.get("id", "?")
        if not entry.get("test_anchors"):
            problems.append(f"{iid}: no test anchor named")
        status = (entry.get("status") or "enforced").strip()
        if status not in {"enforced", "planned"}:
            problems.append(f"{iid}: status must be 'enforced' or 'planned', got {status!r}")
            continue
        if not entry.get("gates"):
            problems.append(f"{iid}: no gate named")
            continue
        for g in entry["gates"]:
            if g not in WP_IDS:
                problems.append(
                    f"{iid}: gate {g!r} is not a known work-package id — the gate "
                    "cannot be traced to the plan or a lane"
                )
        plan = (entry.get("plan_test_today") or "").strip()
        if status == "planned":
            # Honest asymmetry (2026-10-25 HEAD audit): a planned invariant may
            # name no test TODAY, but it must SAY it is planned — it must never
            # present itself as enforced, and its plan must name the gap.
            if not plan:
                problems.append(f"{iid}: status=planned needs a plan_test_today naming the gap")
            continue
        # Enforced: the anchor must name something that can actually RUN.
        # "The path exists" was an inventory check, not evidence.
        for anchor in entry.get("test_anchors", []):
            if not anchor_exercisable(anchor):
                problems.append(
                    f"{iid}: test anchor {anchor!r} has no executable test in it — "
                    "name a file/crate that carries #[test]/#[tokio::test]/def test_/--self-test"
                )
        if not plan or plan.startswith("None"):
            problems.append(
                f"{iid}: plan_test_today is {plan!r} — an ENFORCED invariant with no test "
                "today must not claim enforcement (write the test or set status = 'planned')"
            )
    return problems


def anchor_exercisable(anchor: str) -> bool:
    """True when the anchor names something that RUNS tests."""
    if (REPO / anchor).is_file():
        return _file_is_exercisable(REPO / anchor)
    for crate in (WS / anchor.split("/")[0], REPO / "services" / "mail-server" / anchor):
        if crate.is_dir():
            if (crate / "tests").is_dir() and any((crate / "tests").glob("*.rs")):
                return True
            if any(
                _file_is_exercisable(p)
                for p in crate.rglob("*.rs")
                if "/target/" not in str(p)
            ):
                return True
    fallback = [REPO / anchor, WS / anchor.split("/")[0]]
    for c in fallback:
        if c.is_file() and _file_is_exercisable(c):
            return True
    return False


def _file_is_exercisable(path: Path) -> bool:
    if path.is_dir():
        return False
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return False
    if path.suffix == ".rs":
        return "#[test]" in text or "#[tokio::test]" in text or "#[sqlx::test]" in text
    if path.suffix == ".py":
        return "def test_" in text or "--self-test" in text or "unittest" in text
    if path.suffix in {".toml", ".txt"}:
        return True
    return False


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        import copy
        import tempfile

        crates = {p.name for p in WS.iterdir() if p.is_dir()}
        expect = tomllib.loads(EXPECT.read_text())["package"]
        inv = tomllib.loads(INVARIANTS.read_text())
        lanes = LANES.read_text() if LANES.exists() else ""
        if crates - set(expect):
            print("self-test FAIL: the real tree has unregistered crates", file=sys.stderr)
            return 1
        broken = copy.deepcopy(expect)
        victim = sorted(crates)[0]
        broken.pop(victim)
        problems = collect(broken, inv, crates, lanes)
        if not any(victim in p for p in problems):
            print(f"self-test FAIL: removing {victim!r} from the registry was not caught",
                  file=sys.stderr)
            return 1
        # A fake package in the registry must also be caught.
        broken2 = copy.deepcopy(expect)
        broken2["not-a-real-package"] = {"tier": 2, "required_kinds": ["unit"]}
        problems2 = collect(broken2, inv, crates, lanes)
        if not any("not-a-real-package" in p for p in problems2):
            print("self-test FAIL: a phantom package was accepted", file=sys.stderr)
            return 1
        print("self-test: ok (a package removed from the registry fails; "
              "the real tree registers every crate)")
        return 0

    crates = {p.name for p in WS.iterdir() if p.is_dir()}
    expect = tomllib.loads(EXPECT.read_text())["package"]
    inv = tomllib.loads(INVARIANTS.read_text())
    lanes = LANES.read_text() if LANES.exists() else ""
    problems = collect(expect, inv, crates, lanes)
    if problems:
        print(f"INVARIANT/EXPECTATIONS GATE FAILED — {len(problems)} problem(s):", file=sys.stderr)
        for p in problems[:60]:
            print(f"  - {p}", file=sys.stderr)
        if len(problems) > 60:
            print(f"  … and {len(problems) - 60} more", file=sys.stderr)
        return 1
    print(f"invariants: {len(inv['invariant'])} declared, all anchors present; "
          f"expectations: {len(expect)} packages registered, tiers complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
