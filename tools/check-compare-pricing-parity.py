#!/usr/bin/env python3
"""Compare-page locale pricing-parity gate.

Every `content/compare/<competitor>/` page has a canonical English variant
(`index.md`) and up to three translated variants (`index.{de,fr,es}.md`).
The audit (SM11 F3) caught the Resend locales carrying a 4-month-stale
`pricing_as_of` and the retired "Scale" plan name where canonical said
"Business" — silently, because nothing compared the locales. This gate
fails when any of that drifts again:

  1. `pricing_as_of` must be declared by the canonical AND every locale
     variant, and all copies must be identical. (A missing variant key is
     not harmless: partials/compare/table.html falls back to
     `config.extra.pricing_as_of`, so the locale then renders a third,
     unrelated date under the table.)
  2. Plan vocabulary in the ApexMail column (`apex = …` cells) must be
     parity-consistent: the set of current plan display names (from
     `data/pricing.json`) used by canonical must exactly equal the set
     used by each locale variant.
  3. Retired plan display names must not appear in any ApexMail cell of
     any compare page. They are derived from `data/pricing.json`: whenever
     a plan id's capitalized form differs from its current display name
     (scale→Business, starter→Developer), the capitalized id is a retired
     name. Competitor plan names (Mailgun's own "Scale" tier, AWS support
     plans, …) live in `comp = …` cells and are NOT scanned.

Violations print file:line; any violation exits 1.

Usage: python3 tools/check-compare-pricing-parity.py [compare-content-dir]
       (default: apps/marketing-zola/content/compare)
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_COMPARE_DIR = ROOT / "apps/marketing-zola/content/compare"
PRICING_JSON = ROOT / "apps/marketing-zola/data/pricing.json"

LOCALES = ("de", "fr", "es")

# Only pages rendered through the comparison table carry the per-page
# `pricing_as_of` (partials/compare/table.html) and the apex/comp cells.
# The methodology explainer (template = "prose.html") lives in the same
# directory tree but publishes no pricing claims.
COMPARE_PAGES = re.compile(r'^template\s*=\s*"compare\.html"\s*$', re.MULTILINE)

# `apex = '…'` / `apex = "…"` cell values (TOML literal/basic one-line
# strings, as emitted by every compare page today).
APEX_CELL = (re.compile(r"apex\s*=\s*'([^']*)'"), re.compile(r'apex\s*=\s*"([^"]*)"'))
PRICING_AS_OF = re.compile(r'pricing_as_of\s*=\s*"([^"]+)"')


def plan_vocabulary() -> tuple[dict[str, str], list[str]]:
    """Return (display-name token -> plan id) and the retired-name list."""
    data = json.loads(PRICING_JSON.read_text(encoding="utf-8"))
    names: dict[str, str] = {}
    retired: list[str] = []
    for plan in data.get("plans", []):
        plan_id, name = plan.get("id", ""), plan.get("name", "")
        if not plan_id or not name:
            continue
        names[name] = plan_id
        # A capitalized id that no longer matches the display name is the
        # retired public name of that plan ("Scale" → Business,
        # "Starter" → Developer).
        candidate = plan_id.capitalize()
        if candidate != name and candidate not in name:
            retired.append(candidate)
    return names, retired


def token_pattern(token: str) -> re.Pattern[str]:
    return re.compile(r"(?<![\w-])" + re.escape(token) + r"(?![\w-])")


def apex_plan_tokens(text: str, vocabulary: dict[str, str]) -> set[str]:
    """Plan display names used inside ApexMail-column cells of `text`."""
    cells: list[str] = []
    for pattern in APEX_CELL:
        cells.extend(pattern.findall(text))
    found: set[str] = set()
    for name in vocabulary:
        if any(pattern.search(cell) for cell in cells):
            found.add(name)
    return found


def retired_hits(text: str, retired: list[str]) -> list[tuple[int, str]]:
    """(line number, retired name) for every ApexMail cell carrying a
    retired plan name."""
    hits: list[tuple[int, str]] = []
    for line_no, line in enumerate(text.splitlines(), 1):
        cell = next(
            (m.group(1) for m in (p.search(line) for p in APEX_CELL) if m), None
        )
        if cell is None:
            continue
        for name in retired:
            if token_pattern(name).search(cell):
                hits.append((line_no, name))
    return hits


def display(path: Path) -> str:
    """Repo-relative path for messages (absolute when outside the repo)."""
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def main(argv: list[str]) -> int:
    compare_dir = Path(argv[1]) if len(argv) > 1 else DEFAULT_COMPARE_DIR
    if not compare_dir.is_dir():
        print(f"FAIL compare content directory missing: {compare_dir}")
        return 1

    try:
        vocabulary, retired = plan_vocabulary()
    except (OSError, json.JSONDecodeError) as error:
        print(f"FAIL cannot read plan vocabulary from {PRICING_JSON}: {error}")
        return 1

    failures: list[str] = []
    pages_seen = 0
    variants_seen = 0

    for competitor in sorted(compare_dir.iterdir()):
        if not competitor.is_dir():
            continue
        canonical_path = competitor / "index.md"
        if not canonical_path.is_file():
            continue
        canonical_text = canonical_path.read_text(encoding="utf-8")
        if not COMPARE_PAGES.search(canonical_text):
            continue  # not a comparison-table page (e.g. the methodology prose)
        pages_seen += 1

        canonical_asof = PRICING_AS_OF.search(canonical_text)
        if canonical_asof is None:
            failures.append(
                f"{display(canonical_path)}: canonical compare page "
                "declares no pricing_as_of"
            )
            canonical_asof_value = None
        else:
            canonical_asof_value = canonical_asof.group(1)

        canonical_tokens = apex_plan_tokens(canonical_text, vocabulary)
        for line_no, name in retired_hits(canonical_text, retired):
            failures.append(
                f"{display(canonical_path)}:{line_no}: retired plan "
                f"name {name!r} in ApexMail cell (current vocabulary: "
                f"{sorted(vocabulary)})"
            )

        for locale in LOCALES:
            variant_path = competitor / f"index.{locale}.md"
            if not variant_path.is_file():
                continue
            variants_seen += 1
            variant_text = variant_path.read_text(encoding="utf-8")

            variant_asof = PRICING_AS_OF.search(variant_text)
            if variant_asof is None:
                failures.append(
                    f"{display(variant_path)}: locale variant declares "
                    f"no pricing_as_of (canonical: {canonical_asof_value!r}; the "
                    "template would fall back to config.extra.pricing_as_of)"
                )
            elif canonical_asof_value is not None and (
                variant_asof.group(1) != canonical_asof_value
            ):
                failures.append(
                    f"{display(variant_path)}: pricing_as_of "
                    f"{variant_asof.group(1)!r} diverges from canonical "
                    f"{canonical_asof_value!r}"
                )

            variant_tokens = apex_plan_tokens(variant_text, vocabulary)
            missing = canonical_tokens - variant_tokens
            if missing:
                failures.append(
                    f"{display(variant_path)}: locale omits canonical "
                    f"plan vocabulary {sorted(missing)}"
                )
            extra = variant_tokens - canonical_tokens
            if extra:
                failures.append(
                    f"{display(variant_path)}: locale introduces plan "
                    f"vocabulary absent from canonical {sorted(extra)}"
                )

            for line_no, name in retired_hits(variant_text, retired):
                failures.append(
                    f"{display(variant_path)}:{line_no}: retired plan "
                    f"name {name!r} in ApexMail cell (current vocabulary: "
                    f"{sorted(vocabulary)})"
                )

    print(f"compare pages checked: {pages_seen} ({variants_seen} locale variants)")
    print(f"plan vocabulary: {sorted(vocabulary)}; retired names: {sorted(retired)}")

    if failures:
        print(f"FAIL {len(failures)} pricing-parity violation(s):")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("compare pricing parity OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
