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
import math
import re
import sys
import types
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BILLING_PLANS = ROOT / "services/mail-server/crates/billing-service/src/plans.rs"
# The canonical plan facts (including overage rates) live here since the
# 2026-10-06 refactor; `plans.rs` delegates to it.
PLATFORM_CATALOG = ROOT / "services/mail-server/crates/platform-catalog/src/lib.rs"
AUTH_ROUTE = ROOT / "services/mail-server/crates/api-server/src/routes/auth.rs"
API_BILLING_ROUTE = ROOT / "services/mail-server/crates/api-server/src/routes/billing.rs"
UI_ROUTER = ROOT / "services/mail-server/crates/ui-foundation/src/axum_router.rs"
UI_VIEWS = ROOT / "services/mail-server/crates/ui-foundation/src/leptos_views.rs"
STRIPE_WEBHOOKS = ROOT / "services/mail-server/crates/billing-service/src/stripe_webhooks.rs"
# The root compliance/ package was removed in the 2026-09-30 audit campaign
# (SM8 F9: dead drifted duplicate); the live legal-entity module is the crate copy.
ROOT_CANONICAL_RUST = ROOT / "services/mail-server/crates/compliance/src/legal_entity.rs"
ROOT_CANONICAL_JSON = ROOT / "apps/marketing-zola/data/canonical.json"
MARKETING_PRICING_JSON = ROOT / "apps/marketing-zola/data/pricing.json"
MARKETING_PLANS = ROOT / "apps/marketing-zola/templates/partials/pricing/plans.html"
MARKETING_CALCULATOR = ROOT / "apps/marketing-zola/templates/partials/pricing/calculator.html"
MARKETING_CALCULATOR_ISLAND = (
    ROOT / "apps/marketing-zola/templates/partials/generated/pricing-calculator-island.html"
)
MARKETING_FAQ = ROOT / "apps/marketing-zola/templates/partials/generated/pricing-faq-island.html"
# The runtime dedicated-IP add-on ladder (first / each additional) is quoted by
# the sandbox estimator; the public calculator and docs/pricing.md must state
# the same rates.
EXPLORER_ROUTE = ROOT / "services/mail-server/crates/api-server/src/routes/explorer.rs"
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
        {
            "api_access": True,
            "webhooks_enabled": False,
            "dedicated_ip": False,
            "audit_logs": False,
            "ab_testing": False,
            "time_travel_debugging": False,
            "template_approval_workflow": False,
            "custom_tracking_domain": False,
            "custom_retention": False,
            "subaccounts": False,
        },
    ),
    "starter": PlanExpectation(
        "Developer", 2_900, 29_000, 50_000, 500_000, 5, 5, 30, 0, "Email",
        {
            "api_access": True,
            "webhooks_enabled": True,
            "advanced_analytics": True,
            "data_export": True,
            "custom_templates": True,
            "audit_logs": False,
            "ab_testing": False,
            "time_travel_debugging": False,
            "template_approval_workflow": False,
            "custom_tracking_domain": False,
            "custom_retention": False,
            "subaccounts": False,
        },
    ),
    "pro": PlanExpectation(
        "Pro", 8_900, 89_000, 150_000, 2_000_000, 25, 10, 60, 0, "Email",
        {
            "dedicated_ip": True,
            "send_time_optimization": True,
            "priority_onboarding": True,
            # Capability wave 2: `custom_tracking_domain` is RuntimeEnforced
            # (the /v1/tracking-domains lifecycle + verified-host serving) and
            # sold on Pro and above per docs/pricing.md; `custom_retention`
            # starts one tier higher.
            "custom_tracking_domain": True,
            "custom_retention": False,
            "audit_logs": False,
            "ab_testing": False,
            "time_travel_debugging": False,
            "template_approval_workflow": False,
            "subaccounts": False,
        },
    ),
    "growth": PlanExpectation(
        "Growth", 22_900, 229_000, 500_000, 5_000_000, 100, 25, 90, 1, "Email",
        {
            "dedicated_ip": True,
            # Capability waves 1+2+3: `audit_logs` (customer /v1/audit),
            # `ab_testing` (campaign experiment execution + results API),
            # `time_travel_debugging` (message timeline replay),
            # `custom_tracking_domain` (Pro and above) and `custom_retention`
            # (Growth and above) are RuntimeEnforced; the seeds carry them.
            "audit_logs": True,
            "ab_testing": True,
            "time_travel_debugging": True,
            "custom_tracking_domain": True,
            "custom_retention": True,
            "template_approval_workflow": False,
            "subaccounts": False,
        },
    ),
    "scale": PlanExpectation(
        "Business", 69_900, 699_000, 2_000_000, 20_000_000, -1, 50, 365, 1, "Priority",
        {
            "dedicated_ip": True,
            "sso_enabled": True,
            "inbound_email": True,
            "sla_guarantee": True,
            # Capability waves 1–3: audit logs, A/B testing, time-travel
            # debugging, the maker/checker template approval workflow,
            # subaccounts, a custom tracking domain and custom retention are
            # implemented and sold on Business; the runtime seeds carry the
            # same flags.
            "audit_logs": True,
            "ab_testing": True,
            "time_travel_debugging": True,
            "template_approval_workflow": True,
            "custom_tracking_domain": True,
            "custom_retention": True,
            "subaccounts": True,
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
            "audit_logs": True,
            "ab_testing": True,
            "time_travel_debugging": True,
            "template_approval_workflow": True,
            "custom_tracking_domain": True,
            "custom_retention": True,
            "subaccounts": True,
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
            "audit_logs": False,
            "ab_testing": False,
            "time_travel_debugging": False,
            "template_approval_workflow": False,
            "custom_tracking_domain": False,
            "custom_retention": False,
            "subaccounts": False,
        },
    ),
}

# Per-plan `max_subaccounts` ceiling (-1 = unlimited): Business 10 and
# Enterprise unlimited are the numbers the AI pricing prompts/tables use and
# the numbers `SubAccountService::create_with_plan_limit` refuses on.
EXPECTED_MAX_SUBACCOUNTS: dict[str, int] = {
    "free": 0,
    "starter": 0,
    "pro": 0,
    "growth": 0,
    "scale": 10,
    "enterprise": -1,
    "payg": 0,
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
    max_subaccounts: int
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
            max_subaccounts=parse_int_field(feature_block, "max_subaccounts", 0) or 0,
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
                    "template_approval_workflow",
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
        expected_subaccounts = EXPECTED_MAX_SUBACCOUNTS[plan_id]
        check(
            actual.max_subaccounts == expected_subaccounts,
            f"runtime {plan_id}.max_subaccounts drift: expected {expected_subaccounts}, "
            f"got {actual.max_subaccounts}",
            errors,
        )
    return catalog


def extract_catalog_overage_rates(source: str) -> dict[str, float]:
    """EUR per 1,000 emails per plan, from the canonical `platform_catalog::PLANS`."""
    rates: dict[str, float] = {}
    for block in re.findall(r"PlanRow \{(.*?)\n    \}", source, re.S):
        name = re.search(r'name: "([^"]+)"', block)
        overage = re.search(
            r"overage_millicents_per_email: Some\((-?[\d_]+)\)", block
        )
        if name and overage:
            rates[name.group(1)] = int(overage.group(1).replace("_", "")) / 100
    if not rates:
        raise ValueError("no overage rates parsed from platform-catalog PLANS rows")
    return rates


def extract_overage_rates(source: str) -> dict[str, float]:
    """EUR per 1,000 emails per plan.

    `plan_overage_rate_millicents` stores MILLICENTS per email
    (cents/1000), so the public per-1,000 rate is millicents/100:
    80 millicents/email = €0.80 per 1,000.

    Two shapes are legal: the historical literal-arm table (kept supported so
    a reintroduced drifting table still fails the check) and the
    platform-catalog delegation installed by the 2026-10-06 refactor
    (`platform_catalog::plan_by_name(...).overage_millicents_per_email`),
    where the canonical catalog rows are the authority.
    """
    body = re.search(
        r"pub fn plan_overage_rate_millicents\(plan_name: &str\) -> Option<i64> \{(.*?)\n\}",
        source,
        re.S,
    )
    if body is None:
        raise ValueError("plan_overage_rate_millicents not found in the runtime catalog")
    text = body.group(1)
    rates: dict[str, float] = {}
    for arm in re.finditer(r'((?:\s*\|?\s*"[^"]+"\s*)+)=>\s*Some\((\d+)\)', text):
        for name in re.findall(r'"([^"]+)"', arm.group(1)):
            rates[name] = int(arm.group(2)) / 100
    if rates:
        return rates
    if (
        "platform_catalog::plan_by_name" in text
        and "overage_millicents_per_email" in text
    ):
        return extract_catalog_overage_rates(read(PLATFORM_CATALOG))
    raise ValueError(
        "plan_overage_rate_millicents neither has literal arms nor delegates to the "
        "canonical platform-catalog (platform_catalog::plan_by_name(...)"
        ".overage_millicents_per_email)"
    )


def extract_dedicated_ip_addon(errors: list[str]) -> tuple[float, float] | None:
    """(first, each additional) EUR/month from the runtime estimator.

    `routes/explorer.rs` computes the add-on as
    `4_900 + (f.dedicated_ips.saturating_sub(1)) * 6_900`; the public
    calculator and docs/pricing.md quote the same ladder.
    """
    source = read(EXPLORER_ROUTE)
    match = re.search(
        r"(\d[\d_]*)\s*\+\s*\(f\.dedicated_ips\.saturating_sub\(1\)\)\s*\*\s*(\d[\d_]*)",
        source,
    )
    if match is None:
        errors.append(
            "cannot parse the dedicated-IP add-on ladder from "
            "api-server/src/routes/explorer.rs (first/additional rates)"
        )
        return None
    return (
        int(match.group(1).replace("_", "")) / 100,
        int(match.group(2).replace("_", "")) / 100,
    )


def pricing_row_cells(text: str, plan_id: str) -> list[str] | None:
    """The full catalog table row for `plan_id` in docs/pricing.md."""
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) == 10 and cells[0] == f"`{plan_id}`":
            return cells
    return None


def dedicated_ip_cell(plan: ParsedPlan) -> str:
    if plan.dedicated_ips > 0:
        return f"{plan.dedicated_ips} included"
    if plan.feature_flags.get("dedicated_ip"):
        return "Add-on eligible"
    return "—"


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
        cells = pricing_row_cells(text, plan_id)
        if cells is None:
            errors.append(f"docs/pricing.md has no full catalog row for {plan_id}")
        else:
            expected_ips = dedicated_ip_cell(plan)
            check(
                cells[9] == expected_ips,
                f"docs/pricing.md dedicated-IP cell drift for {plan_id}: "
                f"expected {expected_ips!r}, got {cells[9]!r}",
                errors,
            )
    # 2026-09-08: Developer/Business are canonical ladder names now.
    for stale in ("10% on every self-serve",):
        check(stale not in text, f"docs/pricing.md contains stale pricing token {stale!r}", errors)
    addon = extract_dedicated_ip_addon(errors)
    if addon is not None:
        first, additional = addon
        needle = (
            f"Dedicated IPs are an add-on from €{first:.0f}/month (first) and "
            f"€{additional:.0f}/month (each additional)"
        )
        check(
            needle in " ".join(text.split()),
            f"docs/pricing.md dedicated-IP add-on price drift vs the runtime "
            f"estimator: missing {needle!r}",
            errors,
        )
        check(
            "€30/month per additional IP" not in text,
            "docs/pricing.md contains the stale dedicated-IP price token '€30/month per additional IP'",
            errors,
        )


def validate_marketing_data(catalog: dict[str, ParsedPlan], errors: list[str]) -> None:
    try:
        overage_rates = extract_overage_rates(read(BILLING_PLANS))
    except (ValueError, RuntimeError) as error:
        errors.append(f"cannot parse runtime overage rates: {error}")
        return
    try:
        data: dict[str, Any] = json.loads(read(MARKETING_PRICING_JSON))
    except json.JSONDecodeError as error:
        errors.append(f"apps/marketing-zola/data/pricing.json is invalid JSON: {error}")
        return

    check(data.get("currency_symbol") == "€", "marketing pricing data must use EUR '€'", errors)
    check(data.get("currency_code") == "EUR", "marketing pricing data must declare EUR", errors)
    # `ip_cost` here is a dead legacy field (written by the retired €30/mo
    # generation; no template reads it). The ONE pinned add-on ladder is the
    # runtime first/additional pair checked against the calculator and
    # docs/pricing.md in validate_pricing_reference/validate_marketing_source,
    # so this table cannot pin a second contradictory price.
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
        expected_overage = overage_rates.get(plan_id)
        check(
            data_plan.get("overage_per_1k") == expected_overage,
            f"marketing pricing data {plan_id}.overage_per_1k is not the runtime public rate "
            f"(expected {expected_overage!r}, got {data_plan.get('overage_per_1k')!r})",
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
    ):
        check(needle in calculator, f"calculator source is missing {needle!r}", errors)
    addon = extract_dedicated_ip_addon(errors)
    if addon is not None:
        first, additional = addon
        needle = (
            f"Dedicated IPs are an add-on from €{first:.0f}/month (first) and "
            f"€{additional:.0f}/month (each additional)"
        )
        check(
            needle in calculator,
            f"calculator dedicated-IP add-on price drift vs the runtime estimator: "
            f"missing {needle!r}",
            errors,
        )
    for stale in ("Private Cloud (dedicated tenant)", "BYOC from", "&minus;10%"):
        check(stale not in calculator, f"calculator source contains stale token {stale!r}", errors)

    for needle in ("€29", "€89", "€229", "€699", "€1,750", "€17,500/yr", "€0.80, Pro €0.60, Growth/Business €0.35 per 1,000"):
        check(needle in island, f"generated pricing island source is missing {needle!r}", errors)
    for stale in ("SendGrid", "Mailchimp", "You Save"):
        check(stale not in island, f"generated pricing island contains stale token {stale!r}", errors)

    # Annual-savings needle DERIVED from the marketing catalog: the FAQ must
    # state the catalog's saving (annual_billing_months=10 ⇒ 16.7%), never the
    # retired "roughly a 17% discount" rounding the EN fallback used to carry
    # (R4 filed that fallback drift; the translated answers already matched).
    savings_needle: str | None = None
    try:
        pricing_data = json.loads(read(MARKETING_PRICING_JSON))
        months = int(pricing_data["annual_billing_months"])
        savings = 100.0 * (12 - months) / 12
        catalog_savings = float(pricing_data["annual_savings_percent"])
        if abs(catalog_savings - savings) > 0.05:
            errors.append(
                f"pricing.json annual_savings_percent {catalog_savings} disagrees with "
                f"annual_billing_months={months} ({savings:.1f}%)"
            )
        savings_needle = f"{savings:.1f}% saving"
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
        errors.append(
            f"apps/marketing-zola/data/pricing.json cannot yield the annual savings: {error}"
        )

    for needle in (
        "€0.80, Pro €0.60, Growth/Business €0.35",
        "HIPAA availability is not currently offered",
        "Stripe billing portal",
        "verified Stripe webhook",
    ):
        check(needle in faq, f"pricing FAQ is missing {needle!r}", errors)
    if savings_needle is not None:
        check(
            savings_needle in faq,
            f"pricing FAQ is missing the catalog annual saving {savings_needle!r}",
            errors,
        )
    # 2026-09-08 §9: 0.80/0.60/0.35 are the CANONICAL per-plan rates now.
    # Annual billing: the retired "roughly a 17%" rounding and the retired
    # Enterprise €0.22–€0.35 range must never come back (R4's fallback drift).
    for stale in (
        "saves 10%",
        "upgraded or downgraded from the dashboard",
        "roughly a 17% discount",
        "€0.22–€0.35 contractual",
    ):
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


def extract_sla_credit_caps(errors: list[str]) -> dict[str, int]:
    """Plan -> SLA credit cap (%) from the billing seeds (the runtime cap the
    maintenance SLA sweep enforces)."""
    source = read(BILLING_PLANS)
    caps: dict[str, int] = {}
    for match in re.finditer(r"(?m)^\s*PlanSeed\s*\{", source):
        block = extract_balanced_block(source, source.find("{", match.start()))
        name = parse_string_field(block, "name")
        if name is None:
            continue
        cap = re.search(r"sla_credit_percentage:\s*(\d+)", block)
        if cap:
            caps[name] = int(cap.group(1))
    if not caps:
        errors.append("no sla_credit_percentage values parsed from the billing plan seeds")
    return caps


def validate_sla_credit_docs(errors: list[str]) -> None:
    """The SLA promise must be the cap the maintenance sweep enforces."""
    caps = extract_sla_credit_caps(errors)
    sla_doc = " ".join(read(ROOT / "docs/sla.md").split())
    legal = " ".join(read(ROOT / "templates/legal/sla.md").split())
    for plan, cap in caps.items():
        if cap <= 0:
            continue
        if plan == "scale":
            check(
                f"capped at {cap}% of the monthly fee" in sla_doc,
                f"docs/sla.md must state the shipped Business SLA cap {cap}%",
                errors,
            )
            check(
                f"**{cap}%** of the monthly fee on the Business" in sla_doc,
                f"docs/sla.md Maximum Credit section must state {cap}% for Business",
                errors,
            )
            check(
                f"credits never exceed {cap}% of the monthly fee" in legal,
                f"templates/legal/sla.md must state the shipped Business SLA cap {cap}%",
                errors,
            )
        if plan == "enterprise":
            check(
                f"**{cap}%** on the Enterprise Cloud" in sla_doc,
                f"docs/sla.md Maximum Credit section must state {cap}% for Enterprise Cloud",
                errors,
            )
            check(
                f"credits never exceed {cap}% of the monthly fee" in legal,
                f"templates/legal/sla.md must state the shipped Enterprise Cloud SLA cap {cap}%",
                errors,
            )
    for stale, label in (
        ("capped at 10% of the monthly fee", "docs/sla.md"),
        ("credits never exceed 10% of the monthly fee", "templates/legal/sla.md"),
    ):
        check(stale not in sla_doc and stale not in legal, f"{label} contains the stale 10% SLA cap", errors)


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


# Locales the marketing build renders. The RENDERED locale pages are checked
# explicitly: validating only the English page let a translated pricing page
# keep stale prices with every gate green.
BUILT_LOCALES = ("de", "fr", "es")


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

    # ── Rendered LOCALE pricing pages ─────────────────────────────────────
    # Every localized pricing page is its own visible copy of the ladder:
    # the same current prices must appear and no retired price may survive in
    # a translation. Plan NAMES are translated, so the locale check pins the
    # currency amounts (locale-independent) rather than English labels.
    for locale in BUILT_LOCALES:
        locale_page = GENERATED_MARKETING / locale / "pricing" / "index.html"
        if not locale_page.is_file():
            errors.append(
                f"localized pricing page {locale}/pricing/index.html is missing from the build"
            )
            continue
        locale_output = read(locale_page)
        for needle in ("€29", "€89", "€229", "€699", "€1,750"):
            check(
                needle in locale_output,
                f"rendered [{locale}] pricing page is missing the current price {needle!r}",
                errors,
            )
        for stale in ("€25", "€65", "€150", "€350"):
            check(
                stale not in locale_output,
                f"rendered [{locale}] pricing page still carries the retired price {stale!r}",
                errors,
            )



# ── tools/lib/pricing.py mirror: STRUCTURAL per-field comparison ──────────
# The old check was a token scan over the whole file ("3000"/"3,000"/"3_000"
# anywhere), so DEDICATED_IP_PRICE_CENTS = 3_000 satisfied it while the Free
# row said 30_000, and no other plan field was pinned at all. This compares
# the REAL parsed numbers, per plan, per field.

MIRROR_PRICING = ROOT / "tools/lib/pricing.py"

MIRROR_FIELD_MAP: tuple[tuple[str, str], ...] = (
    ("price_cents", "monthly_cents"),
    ("price_yearly_cents", "yearly_cents"),
    ("emails", "email_limit"),
    ("api_calls", "api_call_limit"),
    ("domains", "domains"),
    ("team", "team_members"),
    ("retention_days", "retention_days"),
)


def exec_mirror(source: str, label: str) -> Any | None:
    """Execute tools/lib/pricing.py source in a throwaway module namespace."""
    module = types.ModuleType(label)
    module.__dict__["__file__"] = label
    try:
        exec(compile(source, label, "exec"), module.__dict__) # nosemgrep: python.lang.security.audit.exec-detected.exec-detected — executes tools/lib/pricing.py — our OWN single-source catalog mirror, read from the repo, never external input
    except Exception as error:  # noqa: BLE001 - any failure is a gate failure
        return None
    return module


def extract_catalog_payg_tiers(source: str) -> list[tuple[int, int]]:
    """[(upper_inclusive, millicents per email)] from the canonical catalog."""
    match = re.search(
        r"PAYG_TIERS_EUR_PER_EMAIL[^=]*=\s*&\[(.*?)\];", source, re.S
    )
    if match is None:
        raise ValueError("PAYG_TIERS_EUR_PER_EMAIL not found in platform-catalog")
    tiers: list[tuple[int, int]] = []
    for upper, rate in re.findall(r"\((i64::MAX|\d[\d_]*),\s*([\d.]+)\)", match.group(1)):
        bound = math.inf if upper == "i64::MAX" else int(upper.replace("_", ""))
        tiers.append((bound, int(round(float(rate) * 100_000))))
    if not tiers:
        raise ValueError("no PAYG tiers parsed from platform-catalog")
    return tiers


def validate_mirror_rows(
    catalog: dict[str, ParsedPlan],
    rows: Any,
    overage_millicents: dict[str, int | None],
    errors: list[str],
    label: str = "tools/lib/pricing.py",
) -> None:
    """Per-plan, per-field comparison of a mirror PLANS mapping."""
    if not isinstance(rows, dict):
        errors.append(f"{label} PLANS must be a dict, got {type(rows).__name__}")
        return
    if set(rows) != set(catalog):
        errors.append(
            f"{label} plan ids drift: expected {sorted(catalog)}, got {sorted(rows)}"
        )
    for plan_id, runtime in catalog.items():
        row = rows.get(plan_id)
        if not isinstance(row, dict):
            errors.append(f"{label} has no row for plan {plan_id!r}")
            continue
        for mirror_field, runtime_field in MIRROR_FIELD_MAP:
            expected = getattr(runtime, runtime_field)
            value = row.get(mirror_field)
            check(
                value == expected,
                f"{label} {plan_id}.{mirror_field} drift: expected {expected!r}, got {value!r}",
                errors,
            )
        expected_overage = overage_millicents.get(plan_id)
        value = row.get("overage_millicents_per_email")
        check(
            value == expected_overage,
            f"{label} {plan_id}.overage_millicents_per_email drift: "
            f"expected {expected_overage!r}, got {value!r}",
            errors,
        )


def validate_pricing_mirror(catalog: dict[str, ParsedPlan], errors: list[str]) -> None:
    """The Python mirror must equal the canonical catalog, field by field."""
    if not MIRROR_PRICING.exists():
        errors.append("tools/lib/pricing.py (declared tools mirror) is missing")
        return
    source = read(MIRROR_PRICING)
    module = exec_mirror(source, "tools/lib/pricing.py")
    if module is None:
        errors.append("tools/lib/pricing.py cannot be executed (syntax/import error)")
        return

    try:
        overage_rates = extract_catalog_overage_rates(read(PLATFORM_CATALOG))
    except (ValueError, RuntimeError) as error:
        errors.append(f"cannot parse canonical overage rates: {error}")
        overage_rates = {}
    overage_millicents = {
        plan_id: (None if rate is None else int(round(rate * 100)))
        for plan_id, rate in overage_rates.items()
    }

    validate_mirror_rows(catalog, getattr(module, "PLANS", None), overage_millicents, errors)

    # PAYG tiers: mirror must carry the canonical ladder (millicents/email).
    try:
        expected_tiers = extract_catalog_payg_tiers(read(PLATFORM_CATALOG))
    except (ValueError, RuntimeError) as error:
        errors.append(f"cannot parse canonical PAYG tiers: {error}")
    else:
        mirror_tiers = getattr(module, "PAYG_TIERS_MILLICENTS", None)
        normalized = None
        if isinstance(mirror_tiers, (tuple, list)):
            normalized = [
                (math.inf if bound == float("inf") else int(bound), int(rate))
                for bound, rate in mirror_tiers
            ]
        check(
            normalized == expected_tiers,
            f"tools/lib/pricing.py PAYG_TIERS_MILLICENTS drift: "
            f"expected {expected_tiers}, got {normalized}",
            errors,
        )

    # Dedicated-IP ladder (EUR 49 first / 69 additional from explorer.rs).
    addon = extract_dedicated_ip_addon(errors)
    if addon is not None:
        first_cents = int(round(addon[0] * 100))
        additional_cents = int(round(addon[1] * 100))
        check(
            getattr(module, "DEDICATED_IP_FIRST_CENTS", None) == first_cents,
            f"tools/lib/pricing.py DEDICATED_IP_FIRST_CENTS drift: expected {first_cents}",
            errors,
        )
        check(
            getattr(module, "DEDICATED_IP_ADDITIONAL_CENTS", None) == additional_cents,
            f"tools/lib/pricing.py DEDICATED_IP_ADDITIONAL_CENTS drift: expected {additional_cents}",
            errors,
        )

    # Currency discipline: EUR only, never USD.
    check("$" not in source, "tools/lib/pricing.py must not carry USD prices", errors)
    check("€" in source or "EUR" in source,
          "tools/lib/pricing.py must state EUR as the currency", errors)


# Historical (pre-2026-09-08) mirror values — the mutation fixture for the
# self-test. The comparison MUST reject this table (it is what the gate
# silently accepted before U-3).
STALE_MIRROR_ROWS: dict[str, dict] = {
    "free": {"price_cents": 0, "price_yearly_cents": 0, "emails": 30_000, "api_calls": 300_000,
             "domains": 1, "team": 1, "retention_days": 7, "overage_millicents_per_email": 40},
    "starter": {"price_cents": 2_500, "price_yearly_cents": 25_000, "emails": 50_000, "api_calls": 500_000,
                "domains": 5, "team": 5, "retention_days": 30, "overage_millicents_per_email": 40},
    "pro": {"price_cents": 6_500, "price_yearly_cents": 65_000, "emails": 150_000, "api_calls": 2_000_000,
            "domains": 25, "team": 10, "retention_days": 60, "overage_millicents_per_email": 40},
    "growth": {"price_cents": 15_000, "price_yearly_cents": 150_000, "emails": 500_000, "api_calls": 5_000_000,
               "domains": 100, "team": 25, "retention_days": 90, "overage_millicents_per_email": 40},
    "scale": {"price_cents": 35_000, "price_yearly_cents": 350_000, "emails": 2_000_000, "api_calls": 20_000_000,
              "domains": -1, "team": 50, "retention_days": 365, "overage_millicents_per_email": 40},
    "enterprise": {"price_cents": 300_000, "price_yearly_cents": 3_000_000, "emails": 5_000_000,
                   "api_calls": -1, "domains": -1, "team": -1, "retention_days": 730,
                   "overage_millicents_per_email": 40},
    "payg": {"price_cents": 0, "price_yearly_cents": 0, "emails": -1, "api_calls": -1,
             "domains": 5, "team": 5, "retention_days": 30, "overage_millicents_per_email": None},
}


def mirror_self_test(catalog: dict[str, ParsedPlan], verbose: bool = False) -> list[str]:
    """Mutation proof: the structural comparison rejects stale/mutated rows.

    Returns the list of checks that failed to detect drift (empty = healthy).
    """
    failures: list[str] = []

    def rate_map() -> dict[str, int | None]:
        try:
            rates = extract_catalog_overage_rates(read(PLATFORM_CATALOG))
        except (ValueError, RuntimeError):
            return {}
        return {p: (None if r is None else int(round(r * 100))) for p, r in rates.items()}

    # 1. A single-field mutation (the ledger's reproduction: Free emails
    #    30_000 while the catalog says 3_000) must produce an error.
    single_field_errors: list[str] = []
    module = exec_mirror(read(MIRROR_PRICING), "tools/lib/pricing.py")
    if module is not None and isinstance(getattr(module, "PLANS", None), dict):
        rows = {
            plan: dict(row) if isinstance(row, dict) else row
            for plan, row in module.PLANS.items()
        }
        if "free" in rows and isinstance(rows["free"], dict):
            rows["free"]["emails"] = 30_000
            validate_mirror_rows(catalog, rows, rate_map(), single_field_errors)
            if not any("free.emails" in error for error in single_field_errors):
                failures.append("single-field Free emails=30_000 mutation was not detected")
        else:
            failures.append("mirror has no 'free' row to mutate")

    # 2. The whole historical (pre-2026-09-08) stale table must be rejected.
    stale_errors: list[str] = []
    validate_mirror_rows(catalog, STALE_MIRROR_ROWS, rate_map(), stale_errors)
    if len(stale_errors) < 6:
        failures.append(
            f"historical stale mirror produced only {len(stale_errors)} errors (expected >= 6)"
        )
    if verbose:
        print(
            "mirror self-test: Free emails=30_000 mutation detected by "
            f"{len(single_field_errors)} error(s); historical stale table detected by "
            f"{len(stale_errors)} per-field error(s)"
        )
    return failures


def _load_training_profiles() -> tuple[dict[str, Any] | None, list[str]]:
    """Parse EXTENDED_PROFILES out of the AI-training profile file."""
    errors: list[str] = []
    profiles = ROOT / "apps/ai/training/new_customer_profiles.py"
    if not profiles.exists():
        return None, ["apps/ai/training/new_customer_profiles.py is missing"]
    import ast

    source = read(profiles)
    try:
        tree = ast.parse(source)
    except SyntaxError as error:
        return None, [f"apps/ai/training/new_customer_profiles.py is not valid Python: {error}"]
    profiles_data = None
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            getattr(target, "id", None) == "EXTENDED_PROFILES" for target in node.targets
        ):
            try:
                profiles_data = ast.literal_eval(node.value)
            except ValueError as error:
                return None, [f"EXTENDED_PROFILES is not a literal: {error}"]
    if not isinstance(profiles_data, dict):
        return None, ["EXTENDED_PROFILES dict not found in the training profiles"]
    return profiles_data, errors


def _runtime_plan_for_profile(profile: dict[str, Any], catalog: dict[str, ParsedPlan]) -> ParsedPlan | None:
    plan_name = str(profile.get("plan_name", "")).lower()
    for plan_id, plan in catalog.items():
        if plan_name in (plan_id, plan.display_name.lower()):
            return plan
    return None


def _profile_expectations(runtime: ParsedPlan) -> dict[str, str]:
    """Canonical string form of every plan fact the profiles restate."""
    expected_price = str(runtime.monthly_cents // 100) if runtime.monthly_cents % 100 == 0 \
        else f"{runtime.monthly_cents / 100:.2f}"
    return {
        "email_limit": f"{runtime.email_limit:,}",
        "plan_price": expected_price,
        "api_call_limit": "Unlimited" if runtime.api_call_limit == -1 else f"{runtime.api_call_limit:,}",
        "team_limit": "Unlimited" if runtime.team_members == -1 else str(runtime.team_members),
    }


def training_profile_errors(
    profile_name: str, profile: dict[str, Any], runtime: ParsedPlan
) -> list[str]:
    """Per-field comparison of one profile against the parsed catalog row.

    Only fields the profile actually carries are compared, so a profile is
    free to omit a fact; a field it states must be canonical.
    """
    errors: list[str] = []
    for field, expected in _profile_expectations(runtime).items():
        if field not in profile:
            continue
        check(
            profile.get(field) == expected,
            f"training profile {profile_name} ({runtime.display_name}) {field} drift: "
            f"expected {expected!r}, got {profile.get(field)!r}",
            errors,
        )
    return errors


def validate_training_profiles(catalog: dict[str, ParsedPlan], errors: list[str]) -> None:
    """Every pricing/limit fact restated in the AI-training profiles vs the catalog.

    Runs in the DEFAULT gate (wired 2026-10-07 by the residual-fix wave): the
    file previously carried pre-2026-09-08 prices/limits (19 drifts) while an
    earlier validator *asserted* those stale values as canonical. The profiles
    are now canonical, and any future drift fails `validate_pricing_drift.py`
    — the same gate run by ci/stages/validate.sh and scripts/consistency-test.sh.
    `--check-training-profiles` is retained as a no-op compatibility flag.
    """
    profiles_data, load_errors = _load_training_profiles()
    errors.extend(load_errors)
    if profiles_data is None:
        return
    for profile_name, profile in profiles_data.items():
        if not isinstance(profile, dict):
            continue
        runtime = _runtime_plan_for_profile(profile, catalog)
        if runtime is None:
            continue
        errors.extend(training_profile_errors(profile_name, profile, runtime))


def training_profiles_self_test(catalog: dict[str, ParsedPlan], verbose: bool = False) -> list[str]:
    """Mutation proof for `validate_training_profiles`.

    For every profile and every canonical field it states, replace the value
    with a sentinel and require the comparison to report exactly that field.
    Run on every invocation so the profile gate is self-proving: if the
    comparison ever goes vacuous, the main gate turns red.
    """
    failures: list[str] = []
    profiles_data, load_errors = _load_training_profiles()
    if profiles_data is None:
        return [f"cannot load training profiles: {error}" for error in load_errors]
    checked = 0
    mutation_proofs = 0
    for profile_name, profile in profiles_data.items():
        if not isinstance(profile, dict):
            continue
        runtime = _runtime_plan_for_profile(profile, catalog)
        if runtime is None:
            continue
        checked += 1
        for field in _profile_expectations(runtime):
            mutated = dict(profile)
            mutated[field] = "\x00drift\x00"
            detected = training_profile_errors(profile_name, mutated, runtime)
            if not any(field in error for error in detected):
                failures.append(
                    f"training profile {profile_name}: mutated {field} was not detected"
                )
            else:
                mutation_proofs += 1
    if checked == 0:
        failures.append("no training profile matched a parsed catalog plan")
    if verbose and not failures:
        print(
            f"training-profile self-test: {mutation_proofs} field mutations across "
            f"{checked} profiles detected"
        )
    return failures


def validate_extended_artifacts(catalog: dict[str, ParsedPlan], errors: list[str]) -> None:
    """Cover the artifacts that historically drifted while this validator
    passed: the tools/ pricing mirror, the training corpus fixtures, and the
    marketing feature bullets (retention, limits) that the card checks never
    read."""
    validate_pricing_mirror(catalog, errors)

    payg_fix = ROOT / "tools/fix_payg_calculations.py"
    if payg_fix.exists():
        source = read(payg_fix)
        check("€" in source, "tools/fix_payg_calculations.py must quote EUR amounts", errors)
        check("$" not in source, "tools/fix_payg_calculations.py must not write USD amounts", errors)

    # NOTE 2026-10-07 (coverage audit U-2b adjacent, fixed by the residual
    # wave): the old block here ASSERTED the stale values in
    # apps/ai/training/new_customer_profiles.py ("email_limit": "30,000") as
    # canonical. That file had 19 pre-2026-09-08 prices/limits; it now carries
    # the canonical catalog facts and `validate_training_profiles` (run in the
    # DEFAULT gate, below) compares every field it states — plan_price,
    # email_limit, api_call_limit, team_limit — against the parsed catalog.
    # The `--check-training-profiles` flag is a retained no-op for callers.

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
    self_test_only = "--self-test" in sys.argv[1:]
    errors: list[str] = []
    catalog = validate_runtime_catalog(errors)

    if self_test_only:
        if not catalog:
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        failures = mirror_self_test(catalog, verbose=True)
        failures += training_profiles_self_test(catalog, verbose=True)
        for failure in failures:
            print(f"pricing-drift self-test FAIL: {failure}", file=sys.stderr)
        if failures:
            return 1
        print("pricing-drift self-test passed (mirror and training-profile mutations are detected)")
        return 0

    if catalog:
        validate_pricing_reference(catalog, errors)
        validate_marketing_data(catalog, errors)
        validate_marketing_source(catalog, errors)
    validate_canonical_artifacts(errors)
    if catalog:
        validate_extended_artifacts(catalog, errors)
        # The mirror comparison must be able to fail. Running the mutation
        # proof on every invocation keeps this gate self-proving: if the
        # structural check ever becomes vacuous, this gate turns red.
        for failure in mirror_self_test(catalog):
            errors.append(f"pricing-drift self-test failed: {failure}")
        # The AI-training profiles are canonical data, not prose: check them by
        # default (the residual-fix wave wired this; `--check-training-profiles`
        # is retained as a compatibility no-op) and prove the check can fail.
        validate_training_profiles(catalog, errors)
        for failure in training_profiles_self_test(catalog):
            errors.append(f"pricing-drift self-test failed: {failure}")
    validate_entitlement_boundaries(errors)
    validate_lifecycle_docs(errors)
    validate_sla_credit_docs(errors)
    validate_built_output(errors)
    if catalog and "--check-training-profiles" in sys.argv[1:]:
        validate_training_profiles(catalog, errors)

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print("pricing drift validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
