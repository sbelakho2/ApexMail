#!/usr/bin/env python3
"""Validate public pricing artifacts against the executable billing catalog.

The runtime plan seeds are the primary catalog. This checker parses the Rust
seed records structurally and compares their values with the public JSON,
pricing reference, marketing source, lifecycle gates, and built Zola output.
It intentionally does not treat a marketing document or a currency-substitution
rule as authoritative.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BILLING_PLANS = ROOT / "services/mail-server/crates/billing-service/src/plans.rs"
AUTH_ROUTE = ROOT / "services/mail-server/crates/api-server/src/routes/auth.rs"
API_BILLING_ROUTE = ROOT / "services/mail-server/crates/api-server/src/routes/billing.rs"
UI_ROUTER = ROOT / "services/mail-server/crates/ui-foundation/src/axum_router.rs"
UI_VIEWS = ROOT / "services/mail-server/crates/ui-foundation/src/leptos_views.rs"
STRIPE_WEBHOOKS = ROOT / "services/mail-server/crates/billing-service/src/stripe_webhooks.rs"
ROOT_CANONICAL_RUST = ROOT / "compliance/src/legal_entity.rs"
ROOT_CANONICAL_JSON = ROOT / "apps/marketing-zola/data/canonical.json"
MARKETING_PRICING_JSON = ROOT / "apps/marketing-zola/data/pricing.json"
MARKETING_PLANS = ROOT / "apps/marketing-zola/templates/partials/pricing/plans.html"
MARKETING_CALCULATOR = ROOT / "apps/marketing-zola/templates/partials/pricing/calculator.html"
MARKETING_CALCULATOR_ISLAND = (
    ROOT / "apps/marketing-zola/templates/partials/generated/pricing-calculator-island.html"
)
MARKETING_FAQ = ROOT / "apps/marketing-zola/templates/partials/generated/pricing-faq-island.html"
DOCS_PRICING = ROOT / "docs/pricing.md"
BILLING_LIFECYCLE = ROOT / "docs/architecture/billing-lifecycle.md"
STRIPE_CONTRACT = ROOT / "docs/tool-contracts/stripe.md"
PRICING_AUTHORITY = ROOT / "docs/pricing-authority.md"
GENERATED_MARKETING = ROOT / "apps/marketing-zola/public"

RUNTIME_PLAN_IDS = [
    "free",
    "starter",
    "pro",
    "growth",
    "scale",
    "enterprise",
    "payg",
]
MARKETING_PLAN_IDS = RUNTIME_PLAN_IDS[:-1]
PUBLIC_SIGNUP_PLAN_IDS = ["free", "starter", "pro", "growth", "scale"]
SELF_SERVE_CHECKOUT_PLAN_IDS = ["starter", "pro", "growth", "scale"]


@dataclass(frozen=True)
class PlanExpectation:
    display_name: str
    monthly_cents: int
    yearly_cents: int
    email_limit: int
    api_call_limit: int
    domains: int
    team_members: int
    retention_days: int
    dedicated_ips: int
    support: str
    feature_flags: dict[str, bool]


EXPECTED_CATALOG: dict[str, PlanExpectation] = {
    "free": PlanExpectation(
        "Free", 0, 0, 3_000, 30_000, 1, 1, 7, 0, "Community",
        {"api_access": True, "webhooks_enabled": False, "dedicated_ip": False},
    ),
    "starter": PlanExpectation(
        "Developer", 2_900, 29_000, 50_000, 500_000, 5, 5, 30, 0, "Email",
        {
            "api_access": True,
            "webhooks_enabled": True,
            "advanced_analytics": True,
            "data_export": True,
            "custom_templates": True,
        },
    ),
    "pro": PlanExpectation(
        "Pro", 8_900, 89_000, 150_000, 2_000_000, 25, 10, 60, 0, "Email",
        {
            "dedicated_ip": True,
            "custom_tracking_domain": True,
            "send_time_optimization": True,
            "priority_onboarding": True,
        },
    ),
    "growth": PlanExpectation(
        "Growth", 22_900, 229_000, 500_000, 5_000_000, 100, 25, 90, 1, "Email",
        {
            "dedicated_ip": True,
            "audit_logs": True,
            "ab_testing": True,
            "time_travel_debugging": True,
            "custom_retention": True,
        },
    ),
    "scale": PlanExpectation(
        "Business", 69_900, 699_000, 2_000_000, 20_000_000, -1, 50, 365, 1, "Priority",
        {
            "dedicated_ip": True,
            "sso_enabled": True,
            "inbound_email": True,
            "subaccounts": True,
            "sla_guarantee": True,
        },
    ),
    "enterprise": PlanExpectation(
        "Enterprise Cloud", 175_000, 1_750_000, 5_000_000, -1, -1, -1, 730, 3, "Dedicated",
        {
            "dedicated_ip": True,
            "sso_enabled": True,
            "white_label": True,
            "private_cloud": True,
            "byoip": True,
            "hipaa_compliance": False,
            "soc2_compliance": False,
        },
    ),
    "payg": PlanExpectation(
        "Pay As You Go", 0, 0, -1, -1, 5, 5, 30, 0, "Email",
        {
            "api_access": True,
            "webhooks_enabled": True,
            "advanced_analytics": True,
            "data_export": True,
            "custom_templates": True,
        },
    ),
}


@dataclass(frozen=True)
class ParsedPlan:
    name: str
    display_name: str
    monthly_cents: int
    yearly_cents: int
    email_limit: int
    api_call_limit: int
    domains: int
    team_members: int
    retention_days: int
    dedicated_ips: int
    support: str
    feature_flags: dict[str, bool]


def read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as error:
        raise RuntimeError(f"cannot read {path.relative_to(ROOT)}: {error}") from error


def extract_balanced_block(text: str, opening_brace: int) -> str:
    """Return a balanced Rust brace block, including the opening/closing braces."""
    if opening_brace < 0 or text[opening_brace] != "{":
        raise ValueError("opening brace not found")
    depth = 0
    in_string = False
    escaped = False
    for index in range(opening_brace, len(text)):
        char = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[opening_brace : index + 1]
    raise ValueError("unclosed brace block")


def parse_string_field(block: str, field: str) -> str | None:
    match = re.search(rf"(?m)^\s*{re.escape(field)}:\s*\"([^\"]+)\"\s*,", block)
    return match.group(1) if match else None


def parse_int_field(block: str, field: str, default: int | None = None) -> int | None:
    match = re.search(rf"(?m)^\s*{re.escape(field)}:\s*(-?\d[\d_]*)\s*,", block)
    if not match:
        return default
    return int(match.group(1).replace("_", ""))


def parse_bool_field(block: str, field: str) -> bool:
    match = re.search(rf"(?m)^\s*{re.escape(field)}:\s*(true|false)\s*,", block)
    return match.group(1) == "true" if match else False


def parse_support_level(feature_block: str) -> str:
    match = re.search(r"support_level:\s*SupportLevel::(\w+)", feature_block)
    if not match:
        raise ValueError("missing support_level in PlanFeatures")
    return match.group(1)


def extract_runtime_catalog(source: str) -> dict[str, ParsedPlan]:
    plans: dict[str, ParsedPlan] = {}
    # Match initializer literals only. A substring search also matches function
    # signatures such as `fn free_plan_seed() -> PlanSeed {`, causing the
    # function body and its nested initializer to be parsed twice.
    for match in re.finditer(r"(?m)^\s*PlanSeed\s*\{", source):
        marker = match.start()
        brace = source.find("{", marker)
        block = extract_balanced_block(source, brace)
        name = parse_string_field(block, "name")
        if name is None:
            continue  # The PlanSeed struct declaration, not an instance.
        display_name = parse_string_field(block, "display_name")
        if display_name is None:
            raise ValueError(f"missing display_name for {name}")
        feature_marker = block.find("features: PlanFeatures {")
        if feature_marker < 0:
            raise ValueError(f"missing PlanFeatures for {name}")
        feature_block = extract_balanced_block(block, block.find("{", feature_marker))
        numeric_values = {
            key: parse_int_field(block, key)
            for key in ("price_monthly", "price_yearly", "email_limit", "api_call_limit")
        }
        if any(value is None for value in numeric_values.values()):
            raise ValueError(f"missing numeric plan value for {name}")
        plan = ParsedPlan(
            name=name,
            display_name=display_name,
            monthly_cents=numeric_values["price_monthly"],  # type: ignore[arg-type]
            yearly_cents=numeric_values["price_yearly"],  # type: ignore[arg-type]
            email_limit=numeric_values["email_limit"],  # type: ignore[arg-type]
            api_call_limit=numeric_values["api_call_limit"],  # type: ignore[arg-type]
            domains=parse_int_field(feature_block, "max_sending_domains", 0) or 0,
            team_members=parse_int_field(feature_block, "max_team_members", 0) or 0,
            retention_days=parse_int_field(feature_block, "max_retention_days", 0) or 0,
            dedicated_ips=parse_int_field(feature_block, "dedicated_ip_count", 0) or 0,
            support=parse_support_level(feature_block),
            feature_flags={
                field: parse_bool_field(feature_block, field)
                for field in (
                    "api_access",
                    "webhooks_enabled",
                    "advanced_analytics",
                    "data_export",
                    "custom_templates",
                    "dedicated_ip",
                    "custom_tracking_domain",
                    "send_time_optimization",
                    "priority_onboarding",
                    "audit_logs",
                    "ab_testing",
                    "time_travel_debugging",
                    "custom_retention",
                    "sso_enabled",
                    "inbound_email",
                    "subaccounts",
                    "sla_guarantee",
                    "white_label",
                    "private_cloud",
                    "byoip",
                    "hipaa_compliance",
                    "soc2_compliance",
                )
            },
        )
        if name in plans:
            raise ValueError(f"duplicate runtime PlanSeed {name}")
        plans[name] = plan
    return plans


def extract_string_array(source: str, constant: str) -> list[str] | None:
    match = re.search(
        rf"{re.escape(constant)}[^=]*=\s*&?\[([^\]]*)\]", source, re.DOTALL
    )
    if not match:
        return None
    return re.findall(r'"([^\"]+)"', match.group(1))


def check(condition: bool, message: str, errors: list[str]) -> None:
    if not condition:
        errors.append(message)


def check_contains(path: Path, needle: str, errors: list[str]) -> None:
    check(needle in read(path), f"{path.relative_to(ROOT)} is missing {needle!r}", errors)


def check_absent(path: Path, needle: str, errors: list[str]) -> None:
    check(needle not in read(path), f"{path.relative_to(ROOT)} still contains {needle!r}", errors)


def validate_runtime_catalog(errors: list[str]) -> dict[str, ParsedPlan]:
    try:
        catalog = extract_runtime_catalog(read(BILLING_PLANS))
    except (ValueError, RuntimeError) as error:
        errors.append(f"cannot parse runtime billing catalog: {error}")
        return {}

    check(
        list(catalog) == RUNTIME_PLAN_IDS,
        f"runtime plan IDs drift: expected {RUNTIME_PLAN_IDS}, got {list(catalog)}",
        errors,
    )
    for plan_id, expected in EXPECTED_CATALOG.items():
        actual = catalog.get(plan_id)
        if actual is None:
            continue
        fields = (
            ("display_name", actual.display_name, expected.display_name),
            ("price_monthly", actual.monthly_cents, expected.monthly_cents),
            ("price_yearly", actual.yearly_cents, expected.yearly_cents),
            ("email_limit", actual.email_limit, expected.email_limit),
            ("api_call_limit", actual.api_call_limit, expected.api_call_limit),
            ("max_sending_domains", actual.domains, expected.domains),
            ("max_team_members", actual.team_members, expected.team_members),
            ("max_retention_days", actual.retention_days, expected.retention_days),
            ("dedicated_ip_count", actual.dedicated_ips, expected.dedicated_ips),
            ("support_level", actual.support, expected.support),
        )
        for field, value, expected_value in fields:
            check(
                value == expected_value,
                f"runtime {plan_id}.{field} drift: expected {expected_value!r}, got {value!r}",
                errors,
            )
        for feature, expected_value in expected.feature_flags.items():
            check(
                actual.feature_flags[feature] == expected_value,
                f"runtime {plan_id}.{feature} drift: expected {expected_value}, got {actual.feature_flags[feature]}",
                errors,
            )
    return catalog


def display_money(cents: int, annual: bool = False) -> str:
    value = cents / 100
    formatted = f"{value:,.0f}" if value == int(value) else f"{value:,.2f}"
    return f"€{formatted}{'/year' if annual else ''}"


def display_limit(value: int) -> str:
    return "Unlimited" if value < 0 else f"{value:,}"


def validate_pricing_reference(catalog: dict[str, ParsedPlan], errors: list[str]) -> None:
    text = read(DOCS_PRICING)
    check_contains(DOCS_PRICING, "the active `plans` records, and verified Stripe webhooks", errors)
    check_contains(DOCS_PRICING, "HIPAA availability is **not currently offered**", errors)
    check_contains(DOCS_PRICING, "Only `active` or `trialing`", errors)
    for plan_id in MARKETING_PLAN_IDS:
        plan = catalog.get(plan_id)
        if plan is None:
            continue
        expected_row = "| `{id}` | {name} | {monthly} | {yearly} | {emails} | {api} |".format(
            id=plan_id,
            name=plan.display_name,
            monthly=display_money(plan.monthly_cents),
            yearly=("€0" if plan.yearly_cents == 0 else display_money(plan.yearly_cents, annual=True)),
            emails=display_limit(plan.email_limit),
            api=display_limit(plan.api_call_limit),
        )
        check(
            expected_row in text,
            f"docs/pricing.md catalog row drift for {plan_id}: missing {expected_row!r}",
            errors,
        )
    # 2026-09-08: Developer/Business are canonical ladder names now.
    for stale in ("10% on every self-serve",):
        check(stale not in text, f"docs/pricing.md contains stale pricing token {stale!r}", errors)


def validate_marketing_data(catalog: dict[str, ParsedPlan], errors: list[str]) -> None:
    try:
        data: dict[str, Any] = json.loads(read(MARKETING_PRICING_JSON))
    except json.JSONDecodeError as error:
        errors.append(f"apps/marketing-zola/data/pricing.json is invalid JSON: {error}")
        return

    check(data.get("currency_symbol") == "€", "marketing pricing data must use EUR '€'", errors)
    check(data.get("currency_code") == "EUR", "marketing pricing data must declare EUR", errors)
    check(data.get("ip_cost") == 30, "marketing dedicated-IP add-on must be €30/month", errors)
    plans = data.get("plans")
    if not isinstance(plans, list):
        errors.append("marketing pricing data has no plans array")
        return
    by_id = {plan.get("id"): plan for plan in plans if isinstance(plan, dict)}
    check(
        [plan.get("id") for plan in plans if isinstance(plan, dict)] == MARKETING_PLAN_IDS,
        f"marketing pricing plan IDs drift: expected {MARKETING_PLAN_IDS}",
        errors,
    )
    for plan_id in MARKETING_PLAN_IDS:
        runtime = catalog.get(plan_id)
        data_plan = by_id.get(plan_id)
        if runtime is None or not isinstance(data_plan, dict):
            continue
        expected = EXPECTED_CATALOG[plan_id]
        fields = (
            ("name", data_plan.get("name"), runtime.display_name),
            ("monthly_price", data_plan.get("monthly_price"), runtime.monthly_cents / 100),
            ("included_volume", data_plan.get("included_volume"), runtime.email_limit),
            ("included_domains", data_plan.get("included_domains"), runtime.domains),
            ("included_users", data_plan.get("included_users"), runtime.team_members),
            ("included_ips", data_plan.get("included_ips"), runtime.dedicated_ips),
            ("support", data_plan.get("support"), runtime.support.lower()),
        )
        for field, value, expected_value in fields:
            check(
                value == expected_value,
                f"marketing pricing data {plan_id}.{field} drift: expected {expected_value!r}, got {value!r}",
                errors,
            )
        annual_expected = runtime.yearly_cents / 100 / 12
        value = data_plan.get("annual_price_per_month")
        check(
            isinstance(value, (int, float)) and abs(value - annual_expected) < 0.0001,
            f"marketing pricing data {plan_id}.annual_price_per_month drift: expected {annual_expected}",
            errors,
        )
        check(
            data_plan.get("overage_per_1k") == (None if plan_id == "free" else 0.40),
            f"marketing pricing data {plan_id}.overage_per_1k is not the runtime public rate",
            errors,
        )
        check(
            data_plan.get("dedicated_ip_addon_available") == expected.feature_flags.get("dedicated_ip", False),
            f"marketing pricing data {plan_id}.dedicated_ip_addon_available drift",
            errors,
        )


def validate_marketing_source(catalog: dict[str, ParsedPlan], errors: list[str]) -> None:
    cards = read(MARKETING_PLANS)
    calculator = read(MARKETING_CALCULATOR)
    island = read(MARKETING_CALCULATOR_ISLAND)
    faq = read(MARKETING_FAQ)

    for plan_id in MARKETING_PLAN_IDS:
        runtime = catalog.get(plan_id)
        if runtime is None:
            continue
        price = display_money(runtime.monthly_cents)
        if plan_id == "enterprise":
            # 2026-09-08 review SS6: Enterprise renders as its own
            # full-width section (from-price + display name), not a card.
            check(
                f"from {price}" in cards and runtime.display_name in cards,
                f"pricing page does not contain the runtime {runtime.display_name} section price",
                errors,
            )
            continue
        check(
            f'plan_name = "{runtime.display_name}"' in cards and f'plan_price = "{price}"' in cards,
            f"pricing card does not contain the runtime {runtime.display_name} price",
            errors,
        )
        if plan_id in PUBLIC_SIGNUP_PLAN_IDS:
            query = "/signup" if plan_id == "free" else f"/signup?plan={plan_id}"
            check(query in cards, f"pricing card for {plan_id} has no vetted signup URL", errors)

    # 2026-09-08: Developer/Business are the canonical display names now;
    # the plan identity KEYS remain starter/scale, so key-form links are stale.
    for stale in ("plan=developer", "plan=business"):
        check(stale not in cards, f"pricing cards contain stale token {stale!r}", errors)
    check("Pay-as-you-go usage pricing is available" in cards, "pricing cards omit PAYG managed-flow disclosure", errors)
    check("HIPAA availability is not currently offered" in cards, "pricing cards omit current HIPAA availability status", errors)

    for needle in (
        "Developer (50K/mo)",
        "Business (2M/mo)",
        "Annual subscriptions are billed at 10&times; the monthly price",
        "Dedicated IPs are an add-on from \u20ac49/month (first) and \u20ac69/month (each additional) on Pro and above",
    ):
        check(needle in calculator, f"calculator source is missing {needle!r}", errors)
    for stale in ("Private Cloud (dedicated tenant)", "BYOC from", "&minus;10%"):
        check(stale not in calculator, f"calculator source contains stale token {stale!r}", errors)

    for needle in ("€29", "€89", "€229", "€699", "€1,750", "€17,500/yr", "€0.80, Pro €0.60, Growth/Business €0.35 per 1,000"):
        check(needle in island, f"generated pricing island source is missing {needle!r}", errors)
    for stale in ("SendGrid", "Mailchimp", "You Save"):
        check(stale not in island, f"generated pricing island contains stale token {stale!r}", errors)

    for needle in (
        "€0.80, Pro €0.60, Growth/Business €0.35",
        "roughly a 17% discount",
        "HIPAA availability is not currently offered",
        "Stripe billing portal",
        "verified Stripe webhook",
    ):
        check(needle in faq, f"pricing FAQ is missing {needle!r}", errors)
    # 2026-09-08 §9: 0.80/0.60/0.35 are the CANONICAL per-plan rates now.
    for stale in ("saves 10%", "upgraded or downgraded from the dashboard"):
        check(stale not in faq, f"pricing FAQ contains stale token {stale!r}", errors)


def validate_canonical_artifacts(errors: list[str]) -> None:
    try:
        canonical = json.loads(read(ROOT_CANONICAL_JSON))
    except json.JSONDecodeError as error:
        errors.append(f"apps/marketing-zola/data/canonical.json is invalid JSON: {error}")
        return
    check("pricing_plans" not in canonical, "canonical.json must not contain a duplicate pricing catalog", errors)
    check(
        canonical.get("_pricing_authority") == "services/mail-server/crates/billing-service/src/plans.rs (plus active plans table and verified Stripe webhooks)",
        "canonical.json must point to the runtime pricing authority",
        errors,
    )
    company = canonical.get("company", {})
    check(company.get("legal_name") == "Bel Consulting OÜ", "canonical company legal name drift", errors)
    check(company.get("registry_code") == "16588745", "canonical registry code drift", errors)
    check(
        canonical.get("claims", {}).get("compliance_status_wording", "").find("HIPAA not currently available") >= 0,
        "canonical claims must retain the current HIPAA availability status",
        errors,
    )

    rust = read(ROOT_CANONICAL_RUST)
    check("RUNTIME_PRICING_AUTHORITY" in rust, "legal-entity module must name the runtime pricing authority", errors)
    check("pub plans:" not in rust and "PlanConfig" not in rust, "legal-entity module must not define a duplicate pricing catalog", errors)
    check("SINGLE SOURCE OF TRUTH" not in rust, "legal-entity module still makes a false global-authority claim", errors)


def validate_entitlement_boundaries(errors: list[str]) -> None:
    auth = read(AUTH_ROUTE)
    router = read(UI_ROUTER)
    views = read(UI_VIEWS)
    # Test fixtures intentionally pass invalid values (for example, enterprise)
    # to prove that the production helper falls back to Free. Validate only the
    # implementation section so those safety tests do not look like accepted
    # public signup options.
    signup_view_implementation = views.split("\n#[cfg(test)]", 1)[0]
    billing = read(API_BILLING_ROUTE)
    webhooks = read(STRIPE_WEBHOOKS)

    for source_name, source in (("auth", auth), ("UI router", router)):
        allowed = extract_string_array(source, "PUBLIC_SIGNUP_PLAN_IDS")
        check(
            allowed == PUBLIC_SIGNUP_PLAN_IDS,
            f"{source_name} public signup allow-list drift: expected {PUBLIC_SIGNUP_PLAN_IDS}, got {allowed}",
            errors,
        )
    for plan_id in PUBLIC_SIGNUP_PLAN_IDS[1:]:
        check(
            f'Some("{plan_id}")' in signup_view_implementation,
            f"signup view does not independently vet {plan_id}",
            errors,
        )
    for forbidden in ("enterprise", "payg", "developer", "business"):
        check(
            f'Some("{forbidden}")' not in signup_view_implementation,
            f"signup view accepts forbidden public plan {forbidden}",
            errors,
        )
    check('"free"' in auth and "INSERT INTO tenants" in auth, "signup route must retain the Free initial entitlement", errors)

    checkout_allowed = extract_string_array(billing, "SELF_SERVE_CHECKOUT_PLAN_IDS")
    check(
        checkout_allowed == SELF_SERVE_CHECKOUT_PLAN_IDS,
        f"Checkout allow-list drift: expected {SELF_SERVE_CHECKOUT_PLAN_IDS}, got {checkout_allowed}",
        errors,
    )
    for needle in (
        "active_plan_name_for_stripe_price",
        "is_active = true",
        "SELF_SERVE_CHECKOUT_PLAN_IDS.contains",
        '"metadata[tenant_id]"',
        '"metadata[plan_name]"',
        '"subscription_data[metadata][tenant_id]"',
        '"subscription_data[metadata][plan_name]"',
        '"code": "CHECKOUT_REQUIRED"',
        '"code": "BILLING_PORTAL_REQUIRED"',
    ):
        check(needle in billing, f"billing route is missing safety boundary {needle!r}", errors)
    for unsafe in ("UPDATE tenants SET plan = $1, updated_at = $2 WHERE id = $3", "Subscription cancelled immediately"):
        check(unsafe not in billing, f"billing route contains direct local mutation {unsafe!r}", errors)

    for needle in (
        "fn entitlement_plan_name",
        "Self::Active | Self::Trialing => paid_plan_name",
        "Self::PastDue",
        "WHERE is_active = true",
        "$2 = 'monthly'",
        "$2 = 'yearly'",
        "Stripe subscription {} is already bound to a different tenant",
        "checkout completed; awaiting subscription state webhook",
    ):
        check(needle in webhooks, f"Stripe webhook reconciliation is missing {needle!r}", errors)


def validate_lifecycle_docs(errors: list[str]) -> None:
    lifecycle = read(BILLING_LIFECYCLE)
    stripe = read(STRIPE_CONTRACT)
    authority = read(PRICING_AUTHORITY)
    for needle in (
        "does not change tenant status or grant an entitlement",
        "Only verified `active` and `trialing` Stripe subscriptions grant",
        "`409 BILLING_PORTAL_REQUIRED`",
        "persists monthly and yearly Stripe price IDs",
    ):
        check(needle in lifecycle, f"billing lifecycle doc is missing {needle!r}", errors)
    check("does not persist Stripe price columns" not in lifecycle, "billing lifecycle retains false plans-table claim", errors)
    for needle in (
        "The public Checkout endpoint accepts",
        "A `checkout.session.completed` event is informational only",
        "Only `active` and `trialing` statuses grant",
    ):
        check(needle in stripe, f"Stripe contract is missing {needle!r}", errors)
    check(
        re.search(
            r"direct\s+`/switch-plan`\s+and\s+`/cancel`\s+endpoints\s+return\s+a\s+conflict",
            stripe,
        ) is not None,
        "Stripe contract is missing the direct switch/cancel conflict boundary",
        errors,
    )
    for stale in ("14-day free trial", "stripe.subscriptions.update", "Full access for 7 d grace period"):
        check(stale not in stripe, f"Stripe contract contains unsupported claim {stale!r}", errors)
    check("Operational authority" in authority, "pricing authority map is missing operational authority section", errors)


def validate_built_output(errors: list[str]) -> None:
    if not GENERATED_MARKETING.is_dir():
        errors.append("apps/marketing-zola/public is missing; run zola build before pricing validation")
        return
    pages = [
        path
        for path in (GENERATED_MARKETING / "index.html", GENERATED_MARKETING / "pricing" / "index.html")
        if path.is_file()
    ]
    if not pages:
        errors.append("no generated home/pricing HTML found; run zola build before pricing validation")
        return
    output = "\n".join(read(path) for path in pages)
    for needle in ("Developer", "Business", "€29", "€89", "€229", "€699", "€1,750", "€0.80, Pro €0.60, Growth/Business €0.35"):
        check(needle in output, f"generated marketing output is missing {needle!r}", errors)
    # 2026-09-08: the retired generation's names and prices (the ladder was
    # Free 30k / Starter EUR25 / Pro 65 / Growth 150 / Scale 350 / Ent 3000).
    for stale in ("Starter", "Scale", "€25", "€65", "€150", "€350", "plan=developer", "plan=business"):
        check(stale not in output, f"generated marketing output contains stale token {stale!r}", errors)



def validate_extended_artifacts(catalog: dict[str, ParsedPlan], errors: list[str]) -> None:
    """Cover the artifacts that historically drifted while this validator
    passed: the tools/ pricing mirror, the training corpus fixtures, and the
    marketing feature bullets (retention, limits) that the card checks never
    read."""
    mirror = ROOT / "tools/lib/pricing.py"
    if not mirror.exists():
        check(False, "tools/lib/pricing.py (declared single source of truth) is missing", errors)
    else:
        source = read(mirror)
        free = catalog.get("free")
        enterprise = catalog.get("enterprise")
        if free is not None:
            plain = str(free.email_limit)
            grouped = f"{free.email_limit:,}"
            underscore = f"{free.email_limit:_}"
            check(
                f'"Free":' in source and (plain in source or grouped in source or underscore in source),
                f"tools/lib/pricing.py Free email limit must be {free.email_limit} (was drifted to 3,000)",
                errors,
            )
        if enterprise is not None:
            check(
                '"api_calls": -1' in source or '"api_calls": -1,' in source,
                "tools/lib/pricing.py Enterprise API calls must be unlimited (-1), not a finite number",
                errors,
            )
        check("$" not in source.replace("$0.001", "").replace("$", ""),
              "tools/lib/pricing.py must not carry USD prices", errors)
        check("€" in source or "EUR" in source,
              "tools/lib/pricing.py must state EUR as the currency", errors)

    payg_fix = ROOT / "tools/fix_payg_calculations.py"
    if payg_fix.exists():
        source = read(payg_fix)
        check("€" in source, "tools/fix_payg_calculations.py must quote EUR amounts", errors)
        check("$" not in source, "tools/fix_payg_calculations.py must not write USD amounts", errors)

    profiles = ROOT / "apps/ai/training/new_customer_profiles.py"
    if profiles.exists():
        source = read(profiles)
        check('"email_limit": "30,000"' in source,
              "training profiles must carry the canonical Free limit 30,000", errors)
        check('"api_call_limit": "300,000"' in source,
              "training profiles must carry the canonical Free API limit 300,000", errors)
        check("$" not in source,
              "training profiles must not quote USD prices (platform is EUR-only)", errors)

    # Marketing feature bullets: retention is a runtime plan feature
    # (max_retention_days) and was published as 365 against 730.
    enterprise_runtime = catalog.get("enterprise")
    if enterprise_runtime is not None:
        retention = getattr(enterprise_runtime, "retention_days", None)
        if retention:
            for path, label in (
                (MARKETING_PLANS, "pricing cards"),
                (ROOT / "apps/marketing-zola/content/enterprise/index.md", "enterprise page"),
                (ROOT / "apps/marketing-zola/content/privacy/index.md", "privacy page"),
            ):
                if not path.exists():
                    continue
                source = read(path)
                check(
                    f"{retention}-day event retention" in source or f"{retention} days" in source,
                    f"{label}: Enterprise event retention must be {retention} days",
                    errors,
                )
                stale = {365: "365", 730: "365"}.get(retention)
                if stale and stale != str(retention):
                    check(
                        f"{stale}-day event retention" not in source and f"| {stale} days |" not in source,
                        f"{label}: stale Enterprise retention {stale} days contradicts runtime {retention}",
                        errors,
                    )

def main() -> int:
    errors: list[str] = []
    catalog = validate_runtime_catalog(errors)
    if catalog:
        validate_pricing_reference(catalog, errors)
        validate_marketing_data(catalog, errors)
        validate_marketing_source(catalog, errors)
    validate_canonical_artifacts(errors)
    if catalog:
        validate_extended_artifacts(catalog, errors)
    validate_entitlement_boundaries(errors)
    validate_lifecycle_docs(errors)
    validate_built_output(errors)

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print("pricing drift validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
