#!/usr/bin/env python3
"""Asset budget gate — what the ARK surfaces ship per page load.

Two laws, both checkable from the repository alone:

  1. **Budgets.** The served CSS and font payload is bounded. A design system
     that needs a new file to grow is a design system losing its economy:
     the budgets are ceilings with ~15 % headroom over today's measured
     bytes, so an accidental re-inline of an authority or a duplicated
     `@font-face` block fails here instead of on a user's connection.
  2. **No client JavaScript.** The marketing site and the console assets
     carry no `.js`/`.mjs` file at all — every interaction is native HTML or
     CSS, and the CSS is a `cssgen` product. A script creeping back into the
     served tree is the regression this arm exists for.

Measured against the committed artifacts (the exact bytes the servers read),
both raw and gzip (the tier nginx and the api-server actually transfer).

Usage: python3 tools/check_asset_budget.py [--self-test]
"""

from __future__ import annotations

import argparse
import gzip
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

ASSETS = ROOT / "services/mail-server/crates/ui-foundation/assets"
MARKETING_STATIC = ROOT / "apps/marketing-zola/static"

# (path, max raw bytes, max gzip bytes)
# Ceilings carry ~15% headroom over the measured bytes of the ARK
# marketing-system revision (2026-10-25: law 11/12, the global section
# roles/decision-table/comparison vocabulary). The previous ceilings
# predate that system and were met almost exactly; growth beyond these
# needs a design decision, not an accretion.
BUDGETS: list[tuple[Path, int, int]] = [
    (ASSETS / "ark.css", 98_000, 21_500),
    (ASSETS / "globals.css", 120_000, 26_000),
    (ASSETS / "globals.input.css", 6_000, 2_500),
    (MARKETING_STATIC / "css/ark.css", 98_000, 21_500),
    (MARKETING_STATIC / "css/styles.css", 116_000, 25_000),
    (MARKETING_STATIC / "css/no-js.css", 9_000, 3_000),
    (MARKETING_STATIC / "50x.html", 6_000, 3_000),
]

FONT_DIRS = [MARKETING_STATIC / "fonts"]
MAX_FONT_BYTES = 32_000
MAX_FONT_TOTAL = 550_000
FONT_EXTRAS = {"NOTICES.md"}

SCRIPT_DIRS: list[tuple[Path, str]] = [
    (MARKETING_STATIC, "*.js"),
    (ASSETS, "*.js"),
    (MARKETING_STATIC, "*.mjs"),
    (ASSETS, "*.mjs"),
]


def gzip_size(data: bytes) -> int:
    return len(gzip.compress(data, 9))


def check_size(path: Path, max_raw: int, max_gzip: int) -> list[str]:
    if not path.is_file():
        return [f"{path}: missing (the artifact must be committed)"]
    data = path.read_bytes()
    problems: list[str] = []
    if len(data) > max_raw:
        problems.append(f"{path}: {len(data)} raw bytes > {max_raw} budget")
    packed = gzip_size(data)
    if packed > max_gzip:
        problems.append(f"{path}: {packed} gzip bytes > {max_gzip} budget")
    return problems


def check_fonts() -> list[str]:
    problems: list[str] = []
    total = 0
    for directory in FONT_DIRS:
        if not directory.is_dir():
            problems.append(f"{directory}: missing")
            continue
        for font in sorted(directory.iterdir()):
            if font.name in FONT_EXTRAS:
                continue
            if font.suffix != ".woff2":
                problems.append(f"{font}: only woff2 belongs in the served font set")
                continue
            size = font.stat().st_size
            total += size
            if size > MAX_FONT_BYTES:
                problems.append(f"{font}: {size} bytes > {MAX_FONT_BYTES} per-font budget")
    if total > MAX_FONT_TOTAL:
        problems.append(f"served fonts total {total} bytes > {MAX_FONT_TOTAL} budget")
    return problems


def check_no_scripts(dirs: list[tuple[Path, str]] | None = None) -> list[str]:
    problems: list[str] = []
    for directory, pattern in (SCRIPT_DIRS if dirs is None else dirs):
        if not directory.is_dir():
            continue
        for script in sorted(directory.rglob(pattern)):
            problems.append(f"{script}: client JavaScript is banned on the served tree")
    return problems


def run() -> list[str]:
    problems: list[str] = []
    for path, max_raw, max_gzip in BUDGETS:
        problems.extend(check_size(path, max_raw, max_gzip))
    problems.extend(check_fonts())
    problems.extend(check_no_scripts())
    return problems


def self_test() -> int:
    failures: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        oversized = directory / "big.css"
        oversized.write_bytes(b"a" * 10)
        if not check_size(oversized, 5, 100):
            failures.append("self-test: a file over the raw budget must fail")
        if not check_size(directory / "absent.css", 5, 5):
            failures.append("self-test: a missing artifact must fail")
        (directory / "app.js").write_text("1")
        if not check_no_scripts([(directory, "*.js")]):
            failures.append("self-test: a planted .js must fail the no-script arm")
        (directory / "assets").mkdir()
        (directory / "assets" / "nested.mjs").write_text("1")
        if not check_no_scripts([(directory, "*.mjs")]):
            failures.append("self-test: a nested .mjs must fail the no-script arm")
    if failures:
        print("SELF-TEST FAILED")
        for failure in failures:
            print(" -", failure)
        return 1
    print("asset budget self-test: ok")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    problems = run()
    if problems:
        print(f"FAIL: {len(problems)} asset budget violation(s)")
        for problem in problems:
            print(" -", problem)
        return 1
    print("asset budget: 0 violations")
    for path, max_raw, max_gzip in BUDGETS:
        data = path.read_bytes()
        print(f"  {path.relative_to(ROOT)}: {len(data)} raw / {gzip_size(data)} gzip"
              f" (budget {max_raw} / {max_gzip})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
