#!/usr/bin/env python3
"""Validate pricing, limits, billing gates, and training facts against docs/pricing.md."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS_PRICING = ROOT / "docs" / "pricing.md"
MARKETING_PLANS = ROOT / "apps" / "marketing-zola" / "templates" / "partials" / "pricing" / "plans.html"
MARKETING_CALCULATOR = ROOT / "apps" / "marketing-zola" / "templates" / "partials" / "generated" / "pricing-calculator-island.html"
MARKETING_FAQ = ROOT / "apps" / "marketing-zola" / "templates" / "partials" / "generated" / "pricing-faq-island.html"
BILLING_PLANS = ROOT / "services" / "mail-server" / "crates" / "billing-service" / "src" / "plans.rs"
BILLING_LIFECYCLE = ROOT / "docs" / "architecture" / "billing-lifecycle.md"
STRIPE_CONTRACT = ROOT / "docs" / "tool-contracts" / "stripe.md"
AI_TRAINING_FILES = [
    ROOT / "apps" / "ai" / "training" / "prompts_v2.py",
    ROOT / "apps" / "ai" / "training" / "generate_gap_training.py",
    ROOT / "apps" / "ai" / "training" / "generate_recovered_training.py",
    ROOT / "apps" / "ai" / "training" / "test_agent.py",
    ROOT / "data" / "system_prompts.json",
    ROOT / "data" / "train_agent.jsonl",
    ROOT / "data" / "train.jsonl",
    ROOT / "data" / "val.jsonl",
    ROOT / "data" / "test.jsonl",
    ROOT / "data" / "golden_qa.jsonl",
    ROOT / "data" / "recovered_training.jsonl",
]

EXPECTED_PLANS = ["Free", "Starter", "Pro", "Growth", "Scale", "Enterprise"]
EXPECTED_DEDICATED_IP_COUNTS = {"pro": 0, "growth": 1, "scale": 3, "enterprise": 10}
CANONICAL_LIFECYCLE_ROW_PREFIXES = {
    "Free": "| Free | `0` | `0` | `30,000` | `300,000` |",
    "Starter": "| Starter | `2,500` cents | `25,000` cents | `50,000` | `500,000` |",
    "Pro": "| Pro | `6,500` cents | `65,000` cents | `150,000` | `2,000,000` |",
    "Growth": "| Growth | `15,000` cents | `150,000` cents | `500,000` | `5,000,000` |",
    "Scale": "| Scale | `35,000` cents | `350,000` cents | `2,000,000` | `20,000,000` |",
    "Enterprise": "| Enterprise | `300,000` cents | `3,000,000` cents | `5,000,000` | unlimited (`-1`) |",
}

PLAN_ROW = re.compile(r"^\|\s*(Free|Starter|Pro|Growth|Scale|Enterprise)\s*\|\s*([^|]+?)\s*\|")
PLAN_FULL_ROW = re.compile(
    r"^\|\s*(Free|Starter|Pro|Growth|Scale|Enterprise)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|"
)
DEDICATED_IP_ROW = re.compile(r"^\|\s*Dedicated IP add-on\s*\|\s*(\$\d+/mo)\s*\|")
BILLING_PLAN_BLOCK = re.compile(r"PlanSeed\s*\{(?P<body>.*?)\n\s*\}", re.DOTALL)
BILLING_FIELD = re.compile(
    r"(?m)^\s*(?P<field>name|price_monthly|price_yearly):\s*(?P<value>\"[^\"]+\"|[\d_]+)"
)
DEDICATED_COUNT_FIELD = re.compile(r"dedicated_ip_count:\s*(?P<count>\d+)")

AI_FORBIDDEN_PATTERNS = [
    (re.compile(r"Enterprise[^\n]{0,160}\$8,000", re.IGNORECASE), "stale Enterprise annual price $8,000"),
    (re.compile(r"Enterprise[^\n]{0,160}\$12,990", re.IGNORECASE), "stale Enterprise annual price $12,990"),
    (re.compile(r"Enterprise[^\n]{0,160}\$15,588", re.IGNORECASE), "stale Enterprise annual monthly-math price $15,588"),
    (re.compile(r"Scale[^\n]{0,180}phone support", re.IGNORECASE), "Scale phone support gate"),
    (re.compile(r"plus phone support", re.IGNORECASE), "phone support as Scale feature"),
    (re.compile(r"phone support \+ priority email", re.IGNORECASE), "phone support support-policy drift"),
    (re.compile(r"We don't offer a self-service annual billing option", re.IGNORECASE), "stale annual-billing denial"),
    (re.compile(r"Free\s*[:|]\s*50,000"), "stale Free API limit"),
    (re.compile(r"Scale:\s*5,000,000"), "stale Scale API limit"),
    (re.compile(r"Enterprise\s*[:|]\s*20,000,000", re.IGNORECASE), "stale Enterprise API limit"),
    (re.compile(r"Enterprise\s*[:|]\s*2,000,000", re.IGNORECASE), "stale Enterprise email limit"),
    (re.compile(r"(?:have|with) 20,000 emails remaining"), "stale Scale remaining-email math"),
    (re.compile(r"Pro also includes:\\n- A/B testing"), "stale Pro A/B feature gate"),
    (re.compile(r"Pro[^\n]{0,180}includes A/B testing", re.IGNORECASE), "stale Pro A/B feature gate"),
    (re.compile(r"Pro[^\n]{0,180}A/B testing, send-time optimization", re.IGNORECASE), "stale Pro A/B feature gate"),
]


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


def extract_plan_billing(markdown: str) -> dict[str, tuple[int, int]]:
    in_new_pricing = False
    prices: dict[str, tuple[int, int]] = {}
    for line in markdown.splitlines():
        if line.startswith("## New ApexMail Pricing"):
            in_new_pricing = True
            continue
        if in_new_pricing and line.startswith("## "):
            break
        if not in_new_pricing:
            continue
        match = PLAN_FULL_ROW.match(line)
        if not match:
            continue
        plan, monthly, annual = match.groups()
        monthly_cents = int(monthly.split()[0].replace("$", "").replace(",", "")) * 100
        annual_cents = int(annual.split()[0].replace("$", "").replace(",", "").replace("/yr", "")) * 100
        prices[plan.lower()] = (monthly_cents, annual_cents)
    return prices


def extract_rust_plan_billing(text: str) -> dict[str, tuple[int, int]]:
    plans: dict[str, tuple[int, int]] = {}
    for block in BILLING_PLAN_BLOCK.finditer(text):
        values = {
            field_match.group("field"): field_match.group("value")
            for field_match in BILLING_FIELD.finditer(block.group("body"))
        }
        if {"name", "price_monthly", "price_yearly"}.issubset(values):
            name = values["name"].strip('"')
            plans[name] = (
                int(values["price_monthly"].replace("_", "")),
                int(values["price_yearly"].replace("_", "")),
            )
    return plans


def extract_rust_dedicated_ip_counts(text: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for block in BILLING_PLAN_BLOCK.finditer(text):
        name_match = re.search(r'name:\s*"(pro|growth|scale|enterprise)"', block.group("body"))
        count_match = DEDICATED_COUNT_FIELD.search(block.group("body"))
        if name_match and count_match:
            counts[name_match.group(1)] = int(count_match.group("count"))
    return counts


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


def _currency_variants(needle: str) -> list[str]:
    """Return currency-symbol variants of a price token.

    The canonical pricing source (`docs/pricing.md`) lists prices in USD
    (e.g. `$25`), while the marketing-zola surface localizes to EUR
    (`€25`). The numeric magnitudes are intentionally identical, so for
    drift checks against marketing files we accept either currency
    prefix.
    """
    variants = {needle}
    if needle.startswith("$"):
        variants.add("€" + needle[1:])
    elif needle.startswith("€"):
        variants.add("$" + needle[1:])
    return list(variants)


def require_contains_currency_agnostic(
    errors: list[str], path: Path, needle: str
) -> None:
    text = path.read_text()
    if not any(v in text for v in _currency_variants(needle)):
        errors.append(f"{path.relative_to(ROOT)} is missing {needle!r}")


def require_not_contains(errors: list[str], path: Path, needle: str) -> None:
    text = path.read_text()
    if needle in text:
        errors.append(f"{path.relative_to(ROOT)} still contains stale value {needle!r}")


def validate_billing_lifecycle(errors: list[str]) -> None:
    lifecycle = BILLING_LIFECYCLE.read_text()
    for plan, expected_row_prefix in CANONICAL_LIFECYCLE_ROW_PREFIXES.items():
        if expected_row_prefix not in lifecycle:
            errors.append(f"docs/architecture/billing-lifecycle.md has stale catalog row for {plan}")
    require_contains(errors, BILLING_LIFECYCLE, "live `plans` table does not persist Stripe price columns")


def validate_ai_training(errors: list[str]) -> None:
    for path in AI_TRAINING_FILES:
        if not path.exists():
            errors.append(f"{path.relative_to(ROOT)} is missing")
            continue
        text = path.read_text()
        for pattern, description in AI_FORBIDDEN_PATTERNS:
            if pattern.search(text):
                errors.append(f"{path.relative_to(ROOT)} contains {description}")


def main() -> int:
    docs = DOCS_PRICING.read_text()
    prices = extract_plan_prices(docs)
    billing_prices = extract_plan_billing(docs)
    rust_text = BILLING_PLANS.read_text()
    rust_prices = extract_rust_plan_billing(rust_text)
    rust_dedicated_counts = extract_rust_dedicated_ip_counts(rust_text)
    dedicated_ip_price = extract_dedicated_ip_price(docs)
    errors: list[str] = []

    missing = [plan for plan in EXPECTED_PLANS if plan not in prices]
    if missing:
        errors.append(f"docs/pricing.md missing pricing rows for: {', '.join(missing)}")

    for plan in EXPECTED_PLANS:
        if plan not in prices:
            continue
        require_contains(errors, MARKETING_PLANS, plan)
        require_contains_currency_agnostic(
            errors, MARKETING_PLANS, prices[plan].split()[0]
        )
        plan_key = plan.lower()
        if rust_prices.get(plan_key) != billing_prices.get(plan_key):
            errors.append(
                "billing-service plan constants drift for "
                f"{plan}: docs={billing_prices.get(plan_key)} rust={rust_prices.get(plan_key)}"
            )

    if dedicated_ip_price is None:
        errors.append("docs/pricing.md missing Dedicated IP add-on row")
    else:
        require_contains_currency_agnostic(errors, MARKETING_PLANS, dedicated_ip_price)
        require_contains_currency_agnostic(errors, MARKETING_CALCULATOR, dedicated_ip_price)

    if rust_dedicated_counts != EXPECTED_DEDICATED_IP_COUNTS:
        errors.append(
            "billing-service dedicated IP included counts drift: "
            f"expected={EXPECTED_DEDICATED_IP_COUNTS} rust={rust_dedicated_counts}"
        )

    validate_billing_lifecycle(errors)

    require_not_contains(errors, MARKETING_CALCULATOR, "$149")
    require_not_contains(errors, MARKETING_CALCULATOR, "$249")
    require_not_contains(errors, MARKETING_CALCULATOR, "$99/mo")
    require_not_contains(errors, MARKETING_CALCULATOR, "Custom pricing")
    require_contains(errors, MARKETING_CALCULATOR, "Starter + overage")
    require_contains(errors, MARKETING_CALCULATOR, "Scale+ included")
    require_contains(errors, MARKETING_CALCULATOR, "Enterprise annual contract")

    require_contains(errors, MARKETING_FAQ, "$0.40 per 1,000 extra emails")
    require_contains(errors, MARKETING_FAQ, "roughly a 17% discount")
    require_contains(errors, MARKETING_FAQ, "Enterprise includes a HIPAA BAA workflow")
    require_contains(errors, MARKETING_FAQ, "Enterprise annual contracts follow the signed order form")

    require_contains(errors, STRIPE_CONTRACT, "Enterprise annual contracts at $30,000/year")
    validate_ai_training(errors)

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    print("pricing drift validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
