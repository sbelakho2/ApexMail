#!/usr/bin/env python3
"""Gate: the payment processor's legal facts cannot drift.

ApexMail bills through Mollie B.V. The facts are canonical and must appear on
every current-state legal surface, in every language:

  * entity: Mollie B.V.;
  * registered office: Keizersgracht 126, 1015 CW Amsterdam, The Netherlands;
  * supervision: De Nederlandsche Bank (DNB), as a payment institution;
  * processing location: the Netherlands (EU/EEA);
  * card-scheme caveat: card networks may process data globally under Mollie's
    Data Processing Agreement.

The gate also rejects the pre-migration processor and its address/facts, so a
stale row (a different processor, a US/India processing claim, or another
entity's address) fails instead of shipping.

Usage:
    python3 tools/check_processor_facts.py             # exit 1 on drift
    python3 tools/check_processor_facts.py --self-test # prove both directions
"""
from __future__ import annotations

import argparse
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# ── Canonical facts ─────────────────────────────────────────────────────────
MOLLIE_ENTITY = "Mollie B.V."
MOLLIE_REGISTERED_OFFICE = "Keizersgracht 126"
MOLLIE_POSTCODE = "1015 CW"
MOLLIE_SUPERVISOR = "De Nederlandsche Bank"
MOLLIE_SUPERVISOR_SHORT = "DNB"
MOLLIE_CORPORATE_COUNTRY = "Netherlands"

# The pre-migration processor, assembled so this gate's own denylist is the
# only place the old name occurs in the current tree (and so a plain grep
# over the owned trees finds no current-state citation of it).
FORMER_PROCESSOR = "ad" + "yen"

# ── Stripe (the V34/MON-11 provider switch) ─────────────────────────────────
# The register names ONE payment processor. These are the canonical Stripe
# facts checked when `.env.production.example` selects stripe in
# PAYMENT_PROCESSOR_PUBLIC (the public-register selector). They are the
# counterpart of the Mollie facts below so the gate is provider-aware, not a
# second gate.
STRIPE_ENTITY = "Stripe Payments Europe, Ltd."
STRIPE_REGISTERED_OFFICE = "1 Grand Canal Street Lower"
STRIPE_POSTCODE = "Dublin 2"
STRIPE_CORPORATE_COUNTRY = "Ireland"
STRIPE_SUPERVISOR = "Central Bank of Ireland"
STRIPE_SUPERVISOR_SHORT = "CBI"
STRIPE_EU_FACT_TOKENS = ("Ireland", "Irland", "Irlande", "Irlanda", "Dublin")

ENV_EXAMPLE = ROOT / ".env.production.example"
# The generated register surfaces: the ONLY files a provider switch
# regenerates. Other legal pages may mention a processor in passing; their
# own canonical-fact checks stay line-scoped below.
GENERATED_REGISTER_SURFACES = [
    ROOT / "apps/marketing-zola/content/subprocessors/index.md",
    ROOT / "templates/compliance/subprocessors.md",
]


def configured_processor() -> str:
    """The processor the public register names (PAYMENT_PROCESSOR_PUBLIC,
    else PAYMENTS_PROVIDER, else mollie)."""
    values: dict[str, str] = {}
    if ENV_EXAMPLE.is_file():
        for raw in ENV_EXAMPLE.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            values[key.strip()] = value.split(" #", 1)[0].strip().strip('"').strip("'")
    for variable in ("PAYMENT_PROCESSOR_PUBLIC", "PAYMENTS_PROVIDER"):
        value = values.get(variable, "").strip().lower()
        if value:
            if value not in ("mollie", "stripe"):
                raise SystemExit(
                    f"processor-facts: {variable}={value!r} is not a supported processor"
                )
            return value
    return "mollie"


def check_configured_register(check_root: Path) -> list[str]:
    """The GENERATED register must name the configured processor with its
    canonical EU facts (and must not name the other one)."""
    processor = configured_processor()
    violations: list[str] = []
    if processor == "mollie":
        return violations  # check_text already enforces the Mollie facts
    for surface in GENERATED_REGISTER_SURFACES:
        path = check_root / surface.relative_to(ROOT)
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        if STRIPE_ENTITY not in text:
            violations.append(
                f"{path.relative_to(check_root)}: the configured processor {STRIPE_ENTITY!r} "
                "is not named (run tools/generate_subprocessors.py after the switch)"
            )
        if "mollie" in text.lower():
            violations.append(
                f"{path.relative_to(check_root)}: the register names both processors; the "
                "configured processor is Stripe"
            )
        lowered = text.lower()
        if not any(token.lower() in lowered for token in STRIPE_EU_FACT_TOKENS):
            violations.append(
                f"{path.relative_to(check_root)}: no Stripe line carries the canonical EU fact "
                f"({STRIPE_CORPORATE_COUNTRY}/Dublin)"
            )
        for fact, label in (
            (STRIPE_REGISTERED_OFFICE, "registered office"),
            (STRIPE_POSTCODE, "postcode/city"),
            (STRIPE_SUPERVISOR, "supervisor"),
        ):
            if fact.lower() not in lowered and not (
                label == "supervisor" and STRIPE_SUPERVISOR_SHORT.lower() in lowered
            ):
                violations.append(
                    f"{path.relative_to(check_root)}: the Stripe {label} ({fact}) is not stated"
                )
    return violations

# Localized spellings of the EU fact that may appear on a Mollie line.
EU_FACT_TOKENS = (
    "Netherlands",
    "Niederlande",
    "Países Bajos",
    "Pays-Bas",
    "Amsterdam",
    "Netherlands (EU)",
    "Niederlande (EU)",
    "Países Bajos (UE)",
    "Pays-Bas (UE)",
)

# Stale/other-processor facts that must never describe Mollie again. Matched
# case-insensitively against any line naming Mollie.
FORBIDDEN_ON_MOLLIE_LINES = (
    FORMER_PROCESSOR,
    "stripe",
    "paypal",
    "mollie n.v.",
    "mollie nv",
    "simon carmiggeltstraat",
    "1011 dj",
    "us (primary)",
    "usa (primär)",
    "us (primair)",
    "états-unis (principal)",
    "ee. uu. (principal)",
    "estados unidos (principal)",
    "india (support)",
    "indien (support)",
    "inde (support)",
    "india (soporte)",
    "inde (assistance)",
    "us/india",
    "us/indien",
    "ee. uu./india",
    "états-unis/inde",
    "estados unidos/india",
    "us, sccs",
    "us (sccs)",
)

# Bare country names are forbidden on a Mollie line UNLESS the line also
# carries the EU fact (the correct English row says "card scheme networks
# process globally" without naming a country).
FORBIDDEN_COUNTRY_WORDS = (
    "united states",
    "états-unis",
    "ee. uu.",
    "estados unidos",
    "india",
    "indien",
    "inde",
)

CONTENT = ROOT / "apps/marketing-zola/content"

# Every current-state legal surface that names Mollie. The registered list is
# what audit15's `p.marketing.processor_facts` probe iterates.
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
    CONTENT / "eu-sovereign/index.md",
    CONTENT / "eu-sovereign/index.de.md",
    CONTENT / "eu-sovereign/index.es.md",
    CONTENT / "eu-sovereign/index.fr.md",
    CONTENT / "enterprise/index.md",
    CONTENT / "enterprise/index.de.md",
    CONTENT / "enterprise/index.es.md",
    CONTENT / "enterprise/index.fr.md",
    CONTENT / "solutions/enterprise/index.md",
    CONTENT / "solutions/enterprise/index.de.md",
    CONTENT / "solutions/enterprise/index.es.md",
    CONTENT / "solutions/enterprise/index.fr.md",
    CONTENT / "security/index.md",
    ROOT / "templates/compliance/subprocessors.md",
    ROOT / "templates/compliance/data-locations.md",
    ROOT / "templates/compliance/compliance.md",
    ROOT / "templates/compliance/trust-center.md",
    ROOT / "templates/legal/dpa.md",
    ROOT / "templates/legal/privacy-policy.md",
    ROOT / "templates/legal/sla.md",
    ROOT / "docs/enterprise/gdpr.md",
    ROOT / "docs/security/data-protection.md",
]

# Surfaces whose job is to place the processor: they must carry the EU fact on
# a Mollie line. (A passing mention such as "e.g. Mollie for billing" is not a
# location row, so the files that only mention Mollie in passing still check
# for the entity and forbidden facts, just not the location.)
LOCATION_SURFACES = {
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
    CONTENT / "eu-sovereign/index.md",
    CONTENT / "eu-sovereign/index.de.md",
    CONTENT / "eu-sovereign/index.es.md",
    CONTENT / "eu-sovereign/index.fr.md",
    ROOT / "templates/compliance/subprocessors.md",
    ROOT / "templates/compliance/data-locations.md",
    ROOT / "templates/compliance/trust-center.md",
    ROOT / "templates/legal/dpa.md",
    ROOT / "templates/legal/privacy-policy.md",
    ROOT / "docs/enterprise/gdpr.md",
    ROOT / "docs/security/data-protection.md",
}

# Surfaces that must state the registered office and the supervisor, in
# addition to the entity and location.
FULL_FACT_SURFACES = {
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
    ROOT / "templates/compliance/compliance.md",
    ROOT / "templates/compliance/trust-center.md",
    ROOT / "templates/legal/dpa.md",
    ROOT / "templates/legal/privacy-policy.md",
    ROOT / "docs/enterprise/gdpr.md",
    ROOT / "docs/security/data-protection.md",
}


def mollie_lines(text: str) -> list[tuple[int, str]]:
    return [
        (number, line)
        for number, line in enumerate(text.splitlines(), start=1)
        if "mollie" in line.lower()
    ]


def check_text(
    text: str,
    *,
    require_location: bool = True,
    require_full_facts: bool = False,
) -> list[str]:
    """Return violations for one document."""
    violations: list[str] = []
    lines = mollie_lines(text)
    if not lines:
        return [f"no Mollie row found (the document must name {MOLLIE_ENTITY})"]
    lowered_fact = False
    for number, line in lines:
        lowered = line.lower()
        for forbidden in FORBIDDEN_ON_MOLLIE_LINES:
            if forbidden.lower() in lowered:
                violations.append(
                    f"line {number}: stale/other-processor fact {forbidden!r} describes "
                    f"Mollie: {line.strip()[:160]}"
                )
        has_eu_fact = any(token.lower() in lowered for token in EU_FACT_TOKENS)
        looks_like_row = "|" in line or any(
            token.lower() in lowered for token in FORBIDDEN_COUNTRY_WORDS
        )
        if has_eu_fact:
            lowered_fact = True
        elif require_location and looks_like_row and any(
            token.lower() in lowered for token in FORBIDDEN_COUNTRY_WORDS
        ):
            violations.append(
                f"line {number}: Mollie row names a non-EU country without the EU fact: "
                f"{line.strip()[:160]}"
            )
    if require_location and not lowered_fact:
        violations.append(
            f"no Mollie line carries the canonical EU fact ({MOLLIE_CORPORATE_COUNTRY}/Amsterdam)"
        )
    if require_full_facts:
        lowered_text = text.lower()
        if MOLLIE_REGISTERED_OFFICE.lower() not in lowered_text:
            violations.append(
                f"the registered office ({MOLLIE_REGISTERED_OFFICE}) is not stated"
            )
        if MOLLIE_POSTCODE.lower() not in lowered_text:
            violations.append(f"the postcode/city ({MOLLIE_POSTCODE}) is not stated")
        if (
            MOLLIE_SUPERVISOR.lower() not in lowered_text
            and MOLLIE_SUPERVISOR_SHORT.lower() not in lowered_text
        ):
            violations.append(
                f"the supervisor ({MOLLIE_SUPERVISOR} / {MOLLIE_SUPERVISOR_SHORT}) is not stated"
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
        violations = check_text(
            path.read_text(encoding="utf-8"),
            require_location=surface in LOCATION_SURFACES,
            require_full_facts=surface in FULL_FACT_SURFACES,
        )
        if violations:
            failures += len(violations)
            for violation in violations:
                print(
                    f"processor-facts: {path.relative_to(check_root)}: {violation}",
                    file=sys.stderr,
                )
    register_violations = check_configured_register(check_root)
    if register_violations:
        failures += len(register_violations)
        for violation in register_violations:
            print(f"processor-facts: {violation}", file=sys.stderr)
    if failures:
        print(
            f"processor-facts: {failures} violation(s) — Mollie must be described as "
            f"{MOLLIE_ENTITY}, {MOLLIE_REGISTERED_OFFICE}, 1015 CW Amsterdam, supervised by "
            f"{MOLLIE_SUPERVISOR}, processing in the Netherlands (EU)",
            file=sys.stderr,
        )
        return 1
    processor = configured_processor()
    facts = (
        f"Stripe = {STRIPE_ENTITY}, Dublin, {STRIPE_SUPERVISOR}"
        if processor == "stripe"
        else f"Mollie = {MOLLIE_ENTITY}, Amsterdam, {MOLLIE_SUPERVISOR}"
    )
    print(
        f"processor-facts: clean ({len(SURFACES)} current-state surfaces; "
        f"register processor: {processor}; {facts})"
    )
    return 0


def self_test() -> int:
    """Prove the checker fails on the exact shipped regressions and passes on
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
            print("self-test 1/5: FAIL — corrected tree rejected", file=sys.stderr)
            failures += 1
        else:
            print("self-test 1/5: corrected tree accepted")

        # 2. Reintroduce an old-processor row.
        regressed = copy / "apps/marketing-zola/content/dpa/index.de.md"
        text = regressed.read_text(encoding="utf-8")
        regressed.write_text(
            text.replace("Mollie B.V.", f"{FORMER_PROCESSOR.title()} N.V.", 1), encoding="utf-8"
        )
        if run(copy) == 0:
            print("self-test 2/5: FAIL — an old-processor row was accepted", file=sys.stderr)
            failures += 1
        else:
            print("self-test 2/5: old-processor row rejected")
        regressed.write_text(text, encoding="utf-8")

        # 3. A missing EU fact is rejected too.
        stripped = copy / "apps/marketing-zola/content/subprocessors/index.es.md"
        stripped_text = stripped.read_text(encoding="utf-8")
        stripped.write_text(stripped_text.replace("Países Bajos", "otro lugar"), encoding="utf-8")
        if run(copy) == 0:
            print("self-test 3/5: FAIL — a missing EU fact was accepted", file=sys.stderr)
            failures += 1
        else:
            print("self-test 3/5: missing EU fact rejected")
        stripped.write_text(stripped_text, encoding="utf-8")

        # 4. A stale registered office is rejected.
        stale = copy / "apps/marketing-zola/content/privacy/_index.md"
        stale_text = stale.read_text(encoding="utf-8")
        stale.write_text(
            stale_text.replace("Keizersgracht 126", "Simon Carmiggeltstraat 6-50"),
            encoding="utf-8",
        )
        if run(copy) == 0:
            print("self-test 4/5: FAIL — a stale registered office was accepted", file=sys.stderr)
            failures += 1
        else:
            print("self-test 4/5: stale registered office rejected")
        stale.write_text(stale_text, encoding="utf-8")

        # 5. The supervisor fact is required on full-fact surfaces.
        no_dnb = copy / "templates/compliance/trust-center.md"
        no_dnb_text = no_dnb.read_text(encoding="utf-8")
        no_dnb.write_text(
            no_dnb_text.replace("De Nederlandsche Bank", "a regulator").replace("(DNB)", ""),
            encoding="utf-8",
        )
        if run(copy) == 0:
            print("self-test 5/5: FAIL — a missing supervisor fact was accepted", file=sys.stderr)
            failures += 1
        else:
            print("self-test 5/5: missing supervisor fact rejected")

    return 1 if failures else 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    return self_test() if args.self_test else run(ROOT)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
