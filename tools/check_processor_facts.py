#!/usr/bin/env python3
"""Gate: a processor's legal facts cannot drift (audit 15 Oct, WP H2).

The 2026-10-15 audit found the Adyen switch carried Stripe's facts into the
public legal pages: "US (primary), India (support)", US storage and SCCs on the
subprocessor register, the DPA, the privacy policy and the data-locations page,
in all four languages, plus the compliance mirrors. The register generator
(``tools/generate_subprocessors.py``) fixed the English public page and the
compliance mirror, but translations and the other legal pages are edited by
hand — exactly the surfaces that drifted. A processor-fact gate was missing,
which is how the error shipped.

This gate holds the committed surfaces to the canonical facts:

  * Adyen N.V. is the Dutch contracting entity (Amsterdam, Netherlands).
  * No legal page may claim Adyen processes or stores data in the United
    States or India, or carry Stripe's former location/SCC facts.
  * Every file that names Adyen must carry the EU fact (Netherlands / localized
    equivalent) on an Adyen line.

Usage:
    python3 tools/check_processor_facts.py            # exit 1 on drift
    python3 tools/check_processor_facts.py --self-test # prove both directions
"""
from __future__ import annotations

import argparse
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# ── Canonical facts (mirror PROCESSOR_CATALOG in generate_subprocessors.py) ──
ADYEN_ENTITY = "Adyen N.V."
ADYEN_CORPORATE_COUNTRY = "Netherlands"

# Localized spellings of the EU fact that may appear on an Adyen line.
EU_FACT_TOKENS = (
    "Netherlands",
    "Niederlande",
    "Países Bajos",
    "Pays-Bas",
    "Amsterdam",
    "EU-established",
    "EU established",
)

# Stripe-era facts that must never describe Adyen again. Matched
# case-insensitively against any line naming Adyen.
FORBIDDEN_ON_ADYEN_LINES = (
    "US (primary)",
    "USA (primär)",
    "US (primair)",
    "États-Unis (principal)",
    "EE. UU. (principal)",
    "Estados Unidos (principal)",
    "India (support)",
    "Indien (Support)",
    "Inde (support)",
    "India (soporte)",
    "Inde (assistance)",
    "US/India",
    "US/Indien",
    "EE. UU./India",
    "États-Unis/Inde",
    "Estados Unidos/India",
    "US, SCCs",
    "US (SCCs)",
    "Adyen (EU + US",
    "Adyen N.V. (US",
)

# Bare country names are forbidden on an Adyen line UNLESS the line also
# carries the EU fact (the correct English row says "card scheme networks
# process globally" without naming a country, and data-locations rows may name
# Germany for the EU database). The strict bare-country check catches rows that
# put Adyen in the US/India columns without one of the phrasings above.
FORBIDDEN_COUNTRY_WORDS = (
    "united states",
    "états-unis",
    "ee. uu.",
    "estados unidos",
    "india",
    "indien",
    "inde",
)

# ── Surfaces the audit named (plus the compliance mirrors) ──────────────────
CONTENT = ROOT / "apps/marketing-zola/content"
SURFACES = [
    CONTENT / "subprocessors/index.md",
    CONTENT / "subprocessors/index.de.md",
    CONTENT / "subprocessors/index.es.md",
    CONTENT / "subprocessors/index.fr.md",
    CONTENT / "dpa/index.md",
    CONTENT / "dpa/index.de.md",
    CONTENT / "dpa/index.es.md",
    CONTENT / "dpa/index.fr.md",
    CONTENT / "privacy/_index.md",
    CONTENT / "privacy/_index.de.md",
    CONTENT / "privacy/_index.es.md",
    CONTENT / "privacy/_index.fr.md",
    CONTENT / "data-locations.md",
    CONTENT / "data-locations.de.md",
    CONTENT / "data-locations.es.md",
    CONTENT / "data-locations.fr.md",
    ROOT / "templates/compliance/subprocessors.md",
    ROOT / "templates/compliance/data-locations.md",
]


def adyen_lines(text: str) -> list[tuple[int, str]]:
    return [
        (number, line)
        for number, line in enumerate(text.splitlines(), start=1)
        if "adyen" in line.lower()
    ]


def check_text(text: str) -> list[str]:
    """Return violations for one document."""
    violations: list[str] = []
    lines = adyen_lines(text)
    if not lines:
        return [f"no Adyen row found (the register must name {ADYEN_ENTITY})"]
    lowered_fact = False
    for number, line in lines:
        lowered = line.lower()
        for forbidden in FORBIDDEN_ON_ADYEN_LINES:
            if forbidden.lower() in lowered:
                violations.append(
                    f"line {number}: Stripe-era fact {forbidden!r} describes Adyen: {line.strip()[:160]}"
                )
        has_eu_fact = any(token.lower() in lowered for token in EU_FACT_TOKENS)
        # A provenance sentence ("card details are processed by Adyen") is not
        # a location row; only demand the EU fact on rows that place the
        # processor (a table row or a line that names a country).
        looks_like_row = "|" in line or any(
            token.lower() in lowered for token in FORBIDDEN_COUNTRY_WORDS
        )
        if has_eu_fact:
            lowered_fact = True
        elif looks_like_row and any(
            token.lower() in lowered for token in FORBIDDEN_COUNTRY_WORDS
        ):
            violations.append(
                f"line {number}: Adyen row names a non-EU country without the EU fact: {line.strip()[:160]}"
            )
    if not lowered_fact:
        violations.append(
            f"no Adyen line carries the canonical EU fact ({ADYEN_CORPORATE_COUNTRY}/Amsterdam)"
        )
    return violations


def run(check_root: Path) -> int:
    failures = 0
    for surface in SURFACES:
        path = check_root / surface.relative_to(ROOT)
        if not path.exists():
            print(f"processor-facts: MISSING {path.relative_to(check_root)}", file=sys.stderr)
            failures += 1
            continue
        violations = check_text(path.read_text(encoding="utf-8"))
        if violations:
            failures += len(violations)
            for violation in violations:
                print(
                    f"processor-facts: {path.relative_to(check_root)}: {violation}",
                    file=sys.stderr,
                )
    if failures:
        print(
            f"processor-facts: {failures} violation(s) — Adyen must be described as "
            f"{ADYEN_ENTITY}, {ADYEN_CORPORATE_COUNTRY} (EU) on every legal surface",
            file=sys.stderr,
        )
        return 1
    print(
        f"processor-facts: clean ({len(SURFACES)} legal surfaces; Adyen = "
        f"{ADYEN_ENTITY}, {ADYEN_CORPORATE_COUNTRY})"
    )
    return 0


def self_test() -> int:
    """Prove the checker fails on the exact shipped regression and passes on
    the corrected text. A checker that accepts everything is not a gate."""
    failures = 0
    with tempfile.TemporaryDirectory(prefix="processor-facts-") as tmp:
        copy = Path(tmp) / "repo"
        shutil.copytree(
            ROOT,
            copy,
            ignore=shutil.ignore_patterns(".git", "target", "public", "__pycache__", "node_modules"),
        )
        # 1. The corrected tree passes.
        if run(copy) != 0:
            print("self-test 1/3: FAIL — corrected tree rejected", file=sys.stderr)
            failures += 1
        else:
            print("self-test 1/3: corrected tree accepted")

        # 2. Reintroduce the audit's exact regression in one translated page.
        regressed = copy / "apps/marketing-zola/content/dpa/index.de.md"
        text = regressed.read_text(encoding="utf-8")
        regressed.write_text(
            text.replace(
                "Niederlande (EU); Kartennetzwerke verarbeiten global gemäß dem "
                "Adyen-DPA | Verarbeitung innerhalb der EU (Adyen N.V., Amsterdam)",
                "USA (primär), Indien (Support) | Standardvertragsklauseln",
            ),
            encoding="utf-8",
        )
        if run(copy) == 0:
            print("self-test 2/3: FAIL — the Stripe-era regression was accepted", file=sys.stderr)
            failures += 1
        else:
            print("self-test 2/3: Stripe-era regression rejected")

        # 3. A missing EU fact is rejected too.
        stripped = copy / "apps/marketing-zola/content/subprocessors/index.es.md"
        stripped.write_text(
            stripped.read_text(encoding="utf-8").replace("Países Bajos", "otro lugar"),
            encoding="utf-8",
        )
        if run(copy) == 0:
            print("self-test 3/3: FAIL — a missing EU fact was accepted", file=sys.stderr)
            failures += 1
        else:
            print("self-test 3/3: missing EU fact rejected")

    return 1 if failures else 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    return self_test() if args.self_test else run(ROOT)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
