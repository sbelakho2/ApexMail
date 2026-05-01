#!/usr/bin/env python3
"""Validate marketing pricing copy against docs/pricing.md."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS_PRICING = ROOT / "docs" / "pricing.md"
MARKETING_PLANS = ROOT / "apps" / "marketing-zola" / "templates" / "partials" / "pricing" / "plans.html"
MARKETING_CALCULATOR = ROOT / "apps" / "marketing-zola" / "templates" / "partials" / "generated" / "pricing-calculator-island.html"
MARKETING_FAQ = ROOT / "apps" / "marketing-zola" / "templates" / "partials" / "generated" / "pricing-faq-island.html"

PLAN_ROW = re.compile(r"^\|\s*(Free|Starter|Pro|Growth|Scale|Enterprise)\s*\|\s*([^|]+?)\s*\|")
DEDICATED_IP_ROW = re.compile(r"^\|\s*Dedicated IP add-on\s*\|\s*(\$\d+/mo)\s*\|")


def extract_plan_prices(markdown: str) -> dict[str, str]:
    in_new_pricing = False
    prices: dict[str, str] = {}
    for line in markdown.splitlines():
        if line.startswith("## New ApexMail Pricing"):
            in_new_pricing = True
            continue
        if in_new_pricing and line.startswith("## "):
            break
        if not in_new_pricing:
            continue
        match = PLAN_ROW.match(line)
        if match:
            plan, price = match.groups()
            prices[plan] = price.strip()
    return prices


def extract_dedicated_ip_price(markdown: str) -> str | None:
    for line in markdown.splitlines():
        match = DEDICATED_IP_ROW.match(line)
        if match:
            return match.group(1)
    return None


def require_contains(errors: list[str], path: Path, needle: str) -> None:
    text = path.read_text()
    if needle not in text:
        errors.append(f"{path.relative_to(ROOT)} is missing {needle!r}")


def main() -> int:
    docs = DOCS_PRICING.read_text()
    prices = extract_plan_prices(docs)
    dedicated_ip_price = extract_dedicated_ip_price(docs)
    errors: list[str] = []

    expected_plans = ["Free", "Starter", "Pro", "Growth", "Scale", "Enterprise"]
    missing = [plan for plan in expected_plans if plan not in prices]
    if missing:
        errors.append(f"docs/pricing.md missing pricing rows for: {', '.join(missing)}")

    for plan in expected_plans:
        if plan not in prices:
            continue
        require_contains(errors, MARKETING_PLANS, plan)
        require_contains(errors, MARKETING_PLANS, prices[plan].split()[0])

    if dedicated_ip_price is None:
        errors.append("docs/pricing.md missing Dedicated IP add-on row")
    else:
        require_contains(errors, MARKETING_PLANS, dedicated_ip_price)
        require_contains(errors, MARKETING_CALCULATOR, dedicated_ip_price)

    require_contains(errors, MARKETING_FAQ, "roughly a 17% discount")
    require_contains(errors, MARKETING_FAQ, "HIPAA compliance is included with Enterprise")

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    print("pricing drift validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
