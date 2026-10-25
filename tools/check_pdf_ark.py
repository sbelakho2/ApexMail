#!/usr/bin/env python3
"""ARK PDF design gate.

Every PDF template must draw from the ONE design authority
(`services/mail-server/crates/pdf-renderer/src/templates/ark.typ`): the
paper/ink/blue palette, Spectral+Overpass+Overpass Mono, 0 radius, the 3/2/1
rule hierarchy, the two-tone wordmark and the shared page/chip/notice
components. A template that hardcodes a colour, a luma grey, a font family or
its own page geometry is a design fork — it drifts from the web authority the
moment either side changes.

Ban list (template files only; `ark.typ` is the authority):
  * `rgb("#…")` / `luma(…)`  — colours come from the tokens
  * `#set page(` / `#set text(font:` / `#show heading` — page + type come
    from `page-setup`
  * `color.lighten(…)` / `color.darken(…)` — tones come from `tone-color`
  * `.lighten(` / `.darken(` anywhere — same reason

Also enforces that every template imports the authority and that the invoicing
success colour is not green (ARK: success is BLUE; there is no green).

Exit 0 clean, 1 on any violation. `--self-test` proves the gate catches each
class in a scratch fixture.
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = (
    ROOT / "services/mail-server/crates/pdf-renderer/src/templates"
)
AUTHORITY = "ark.typ"
TEMPLATE_FILES = sorted(
    path for path in TEMPLATES.glob("*.typ") if path.name != AUTHORITY
)

BANNED = [
    (re.compile(r'rgb\(\s*"#'), "raw rgb() colour literal", "use an ark.typ token"),
    (re.compile(r"\bluma\("), "luma() grey", "use an ark.typ token"),
    (re.compile(r"#set\s+page\s*\("), "local page geometry", "use page-setup"),
    (re.compile(r"#set\s+text\s*\(\s*font\s*:"), "local font choice", "page-setup owns the type"),
    (re.compile(r"#show\s+heading"), "local heading style", "page-setup owns headings"),
    (re.compile(r"\.lighten\("), "derived tint", "use tone-fill"),
    (re.compile(r"\.darken\("), "derived shade", "use tone-color"),
    (re.compile(r"#[0-9A-Fa-f]{6}\b"), "hex colour literal", "use an ark.typ token"),
]
GREEN = re.compile(r'rgb\(\s*"#(?:16a34a|22c55e|15803d|4ade80)"', re.IGNORECASE)


def scan(text: str) -> list[str]:
    violations: list[str] = []
    for pattern, reason, fix in BANNED:
        for match in pattern.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            violations.append(f"line {line}: {reason} — {fix}")
    if GREEN.search(text):
        violations.append("green success colour — ARK success is BLUE")
    return violations


def check(authority: Path, templates: list[Path]) -> list[str]:
    problems: list[str] = []
    if not authority.is_file():
        return [f"missing design authority: {authority}"]
    authority_text = authority.read_text(encoding="utf-8")
    for token in ("#B91C1C", "#09090B", "#1D4F7C", "#0E141B"):
        if token not in authority_text:
            problems.append(f"{authority.name}: ARK token {token} is missing")
    for path in templates:
        text = path.read_text(encoding="utf-8")
        if f'#import "{AUTHORITY}"' not in text:
            problems.append(f"{path.name}: does not import {AUTHORITY}")
        for violation in scan(text):
            problems.append(f"{path.name}: {violation}")
        if "page-setup" not in text:
            problems.append(f"{path.name}: does not use the shared page-setup")
    return problems


def self_test() -> int:
    with tempfile.TemporaryDirectory() as directory:
        base = Path(directory)
        (base / AUTHORITY).write_text(
            '#let ink = rgb("#0E141B")\n#let wordmark-apex = rgb("#B91C1C")\n'
            '#let wordmark-mail = rgb("#09090B")\n#let blue = rgb("#1D4F7C")\n',
            encoding="utf-8",
        )
        good = base / "good.typ"
        good.write_text(
            '#import "ark.typ": *\n#show: page-setup.with(title: "x")\n'
            "#text(fill: ink)[x]\n",
            encoding="utf-8",
        )
        if check(base / AUTHORITY, [good]):
            print("self-test FAILED: a clean template was flagged", file=sys.stderr)
            return 1
        cases = {
            "colour.typ": '#import "ark.typ": *\npage-setup\n#rect(fill: rgb("#fff"))\n',
            "font.typ": '#import "ark.typ": *\npage-setup\n#set text(font: ("x",))\n',
            "green.typ": '#import "ark.typ": *\npage-setup\n#text(fill: rgb("#16a34a"))[ok]\n',
            "nofont.typ": "#rect[]\n",
        }
        for name, source in cases.items():
            path = base / name
            path.write_text(source, encoding="utf-8")
            if not check(base / AUTHORITY, [path]):
                print(f"self-test FAILED: {name} was not flagged", file=sys.stderr)
                return 1
    print("pdf-ark self-test: ok")
    return 0


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()
    problems = check(TEMPLATES / AUTHORITY, TEMPLATE_FILES)
    if problems:
        for problem in problems:
            print(f"pdf-ark: {problem}", file=sys.stderr)
        print(
            f"pdf-ark: {len(problems)} violation(s) — every PDF template must "
            f"draw from {AUTHORITY}",
            file=sys.stderr,
        )
        return 1
    print(
        f"pdf-ark: clean ({len(TEMPLATE_FILES)} templates on the shared "
        "ARK authority)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
