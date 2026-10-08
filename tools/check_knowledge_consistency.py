#!/usr/bin/env python3
"""Knowledge-consistency gate — one canonical catalog, every AI/sales surface derived.

The SalesCloser build plan (§9 CI plan; gap analysis §4.1 defect 1) requires
that the plan facts AI surfaces state are the facts billing charges. The
canonical source is `services/mail-server/crates/platform-catalog/src/lib.rs`;
the runtime billing seeds, the ai-service knowledge + verifier tables, the
sales knowledge base and `docs/pricing.md` all derive from or are pinned to
it.

This checker verifies the sources, not a build:
  1. platform-catalog rows  ==  billing `default_plans()` seeds (numeric
     fields) and `plan_overage_rate_millicents` (literal arms must agree with
     the catalog; the catalog delegation is checked to be the delegation);
  2. platform-catalog rows  ==  ai-service `verifier.rs` CANONICAL_PRICES /
     CANONICAL_EMAIL_LIMITS / CANONICAL_RATES (the verifier keeps its own
     copy on purpose — the checker proves the copy still agrees);
  3. platform-catalog rows  ==  the `docs/pricing.md` public table + PAYG
     rate table (converted through the same display rules);
  4. ai-service `knowledge.rs` and the sales KB derive their plan facts from
     `platform_catalog` and carry no hardcoded EUR plan prices (the exact
     defect class that shipped once: chat claiming Pro €65 while billing
     charged €89).

The same invariants are ALSO pinned by nextest (`verifier::knowledge_lockstep`,
`billing-service plans::catalog_drift_tests`) in the test stage. This gate
runs in the validate stage so drift fails before anything is compiled.

Self-test: `check_knowledge_consistency.py --self-test` copies the real
sources into a temp tree, applies each mutation class, and asserts the
checker fails on it.
"""

from __future__ import annotations

import ast
import re
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "services/mail-server/crates/platform-catalog/src/lib.rs"
BILLING_PLANS = ROOT / "services/mail-server/crates/billing-service/src/plans.rs"
AI_KNOWLEDGE = ROOT / "services/mail-server/crates/ai-service/src/knowledge.rs"
AI_VERIFIER = ROOT / "services/mail-server/crates/ai-service/src/verifier.rs"
# The sales KB implementation moved to the shared `sales-knowledge` crate
# (plan §5.5); sales-autopilot re-exports it. The derivation check follows the
# implementation; the re-export module is asserted separately below.
SALES_KB = ROOT / "services/mail-server/crates/sales-knowledge/src/lib.rs"
SALES_KB_REEXPORT = (
    ROOT / "services/mail-server/crates/sales-autopilot/src/knowledge.rs"
)
DOCS_PRICING = ROOT / "docs/pricing.md"
# These two contract/architecture docs restate the plan ladder and drifted
# silently (adversarial docs review 2026-10-06: stripe.md still carried the
# pre-2026-09-08 ladder, billing-lifecycle.md misstated every paid tier).
# Their plan tables are now parsed and pinned to the catalog.
STRIPE_CONTRACT = ROOT / "docs/tool-contracts/stripe.md"
BILLING_LIFECYCLE = ROOT / "docs/architecture/billing-lifecycle.md"
# The Python training/eval pipeline restates the catalog; it must agree with
# it (the inverted table here shipped wrong prices into AI training data —
# adversarial review 2026-10-06).
AI_TRAINING_PRICING = ROOT / "apps/ai/training/validate_pricing.py"

FAILURES: list[str] = []


def fail(message: str) -> None:
    FAILURES.append(message)


def _int(text: str) -> int:
    return int(text.replace("_", ""))


def _bool_field(block: str, field: str) -> bool:
    """A `field: true|false` literal; absent means the Rust default (false
    for the capability flags, so a seed that stops setting one still compares
    honestly against the catalog)."""
    match = re.search(rf"\b{re.escape(field)}:\s*(true|false)\b", block)
    return match.group(1) == "true" if match else False


def _int_field(block: str, field: str, default: int = 0) -> int:
    match = re.search(rf"\b{re.escape(field)}:\s*(-?[\d_]+)\s*,", block)
    return _int(match.group(1)) if match else default


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------


def parse_catalog(src: str) -> list[dict]:
    rows = []
    for block in re.findall(r"PlanRow \{(.*?)\n    \}", src, re.S):
        overage = re.search(
            r"overage_millicents_per_email: (?:Some\((-?[\d_]+)\)|None)", block
        )
        rows.append(
            {
                "name": re.search(r'name: "([^"]+)"', block).group(1),
                "display_name": re.search(r'display_name: "([^"]+)"', block).group(1),
                "monthly_cents": _int(
                    re.search(r"price_monthly_cents: (-?[\d_]+)", block).group(1)
                ),
                "yearly_cents": _int(
                    re.search(r"price_yearly_cents: (-?[\d_]+)", block).group(1)
                ),
                "email_limit": _int(
                    re.search(r"email_limit: (-?[\d_]+)", block).group(1)
                ),
                "api_call_limit": _int(
                    re.search(r"api_call_limit: (-?[\d_]+)", block).group(1)
                ),
                "retention_days": _int(
                    re.search(r"max_retention_days: (-?[\d_]+)", block).group(1)
                ),
                "team_members": _int(
                    re.search(r"max_team_members: (-?[\d_]+)", block).group(1)
                ),
                "overage_millicents": (
                    None if overage.group(1) is None else _int(overage.group(1))
                )
                if overage
                else None,
                # Feature gates sold in docs/pricing.md — pinned to the
                # billing seeds below so a flag can never be sold on one side
                # only (capability wave 1: audit_logs, template approval,
                # subaccounts/max_subaccounts).
                "audit_logs": _bool_field(block, "audit_logs"),
                "ab_testing": _bool_field(block, "ab_testing"),
                "time_travel_debugging": _bool_field(block, "time_travel_debugging"),
                "template_approval_workflow": _bool_field(block, "template_approval_workflow"),
                "subaccounts": _bool_field(block, "subaccounts"),
                "max_subaccounts": _int_field(block, "max_subaccounts"),
            }
        )
    assert rows, "platform-catalog parse produced no rows"
    return rows


def parse_catalog_payg_tiers(src: str) -> list[float]:
    block = re.search(
        r"PAYG_TIERS_EUR_PER_EMAIL: &\[\(i64, f64\)\] = &\[(.*?)\];", src, re.S
    ).group(1)
    return [float(rate) for _, rate in re.findall(r"\(([\d_]+|i64::MAX), ([\d.]+)\)", block)]


def parse_catalog_payg_uppers(src: str) -> list[int | None]:
    """Inclusive upper bounds per PAYG tier; i64::MAX means 'no bound'."""
    block = re.search(
        r"PAYG_TIERS_EUR_PER_EMAIL: &\[\(i64, f64\)\] = &\[(.*?)\];", src, re.S
    ).group(1)
    return [
        None if raw == "i64::MAX" else _int(raw)
        for raw, _ in re.findall(r"\(([\d_]+|i64::MAX), ([\d.]+)\)", block)
    ]


def parse_billing_seeds(src: str) -> dict[str, dict]:
    seeds = {}
    for block in re.split(r"PlanSeed \{", src)[1:]:
        tail = block.split("PlanFeatures")[0]
        name = re.search(r'name: "([^"]+)"', tail)
        if not name:
            continue
        seeds[name.group(1)] = {
            "display_name": re.search(r'display_name: "([^"]+)"', tail).group(1),
            "monthly_cents": _int(re.search(r"price_monthly: (-?[\d_]+)", tail).group(1)),
            "yearly_cents": _int(re.search(r"price_yearly: (-?[\d_]+)", tail).group(1)),
            "email_limit": _int(re.search(r"email_limit: (-?[\d_]+)", tail).group(1)),
            "api_call_limit": _int(
                re.search(r"api_call_limit: (-?[\d_]+)", tail).group(1)
            ),
        }
        features = re.search(
            r"max_retention_days: (-?[\d_]+),\s*max_team_members: (-?[\d_]+)", block
        )
        if features:
            seeds[name.group(1)]["retention_days"] = _int(features.group(1))
            seeds[name.group(1)]["team_members"] = _int(features.group(2))
        # Feature gates (absent = the PlanFeatures default false/0, so the
        # comparison stays honest when a seed stops setting one).
        seeds[name.group(1)]["audit_logs"] = _bool_field(block, "audit_logs")
        seeds[name.group(1)]["ab_testing"] = _bool_field(block, "ab_testing")
        seeds[name.group(1)]["time_travel_debugging"] = _bool_field(
            block, "time_travel_debugging"
        )
        seeds[name.group(1)]["template_approval_workflow"] = _bool_field(
            block, "template_approval_workflow"
        )
        seeds[name.group(1)]["subaccounts"] = _bool_field(block, "subaccounts")
        seeds[name.group(1)]["max_subaccounts"] = _int_field(block, "max_subaccounts")
    assert seeds, "billing seed parse produced no seeds"
    return seeds


def parse_billing_overage(src: str) -> dict[str, int]:
    """Literal overage arms, if any.

    Two shapes are legal: the historical literal-arm table, and the
    platform-catalog delegation (the canonical shape since the 2026-10-06
    refactor made `platform-catalog` the single source of plan facts —
    `parse_billing_overage` must not crash on it). A function that is neither
    is a failure, reported here as an actionable message instead of a bare
    AssertionError.
    """
    match = re.search(
        r"pub fn plan_overage_rate_millicents\(plan_name: &str\) -> Option<i64> \{(.*?)\n\}",
        src,
        re.S,
    )
    if match is None:
        fail(
            "billing-service/src/plans.rs has no plan_overage_rate_millicents(plan_name) — "
            "the overage contract moved or was renamed"
        )
        return {}
    body = match.group(1)
    out: dict[str, int] = {}
    for arm in re.finditer(r"((?:\s*\|?\s*\"[^\"]+\"\s*)+)=>\s*Some\((\d+)\)", body):
        for name in re.findall(r'"([^"]+)"', arm.group(1)):
            out[name] = int(arm.group(2))
    if not out and not (
        "platform_catalog::plan_by_name" in body
        and "overage_millicents_per_email" in body
    ):
        fail(
            "plan_overage_rate_millicents neither has literal arms nor delegates to "
            "platform_catalog::plan_by_name(...).overage_millicents_per_email — the overage "
            "rate must come from the canonical catalog (billing-service/src/plans.rs)"
        )
    return out


def parse_verifier_tables(src: str) -> dict[str, list]:
    def array(name: str) -> str:
        return re.search(rf"{name}: &\[[^\]]*\] = &\[(.*?)\];", src, re.S).group(1)

    def numbers(raw: str) -> list[float]:
        return [float(v.replace("_", "")) for v in re.findall(r"(-?[\d_]*\.?[\d_]+)", raw)]

    return {
        "prices": [int(v) for v in numbers(array("CANONICAL_PRICES"))],
        "limits": [int(v) for v in numbers(array("CANONICAL_EMAIL_LIMITS"))],
        "rates": numbers(array("CANONICAL_RATES")),
    }


def parse_docs_table(src: str) -> dict[str, dict]:
    rows = {}
    for line in src.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) != 10 or not cells[0].startswith("`"):
            continue
        plan_id = cells[0].strip("`")
        if plan_id in ("free", "starter", "pro", "growth", "scale", "enterprise"):
            rows[plan_id] = {
                "display_name": cells[1],
                "monthly_cents": _money_cents(cells[2]),
                "yearly_cents": _money_cents(cells[3]),
                "email_limit": _count(cells[4]),
                "api_call_limit": _count(cells[5]),
                "team_members": _count(cells[7]),
                "retention_days": _days(cells[8]),
            }
    assert rows, "docs/pricing.md table parse produced no rows"
    return rows


def parse_docs_payg(src: str) -> list[float]:
    section = re.search(
        r"PAYG pricing is metered independently(.*?)\n## ", src, re.S
    )
    assert section, "docs/pricing.md PAYG section not found"
    rates = [
        float(v)
        for v in re.findall(r"^\| [^|]+ \| €([\d.]+) \|$", section.group(1), re.M)
    ]
    assert rates, "docs/pricing.md PAYG tier table parse produced no rows"
    return rates


def _table_rows_after(src: str, heading: str) -> list[list[str]]:
    """Markdown table rows in the section that starts at `heading`."""
    section = src.split(heading, 1)[1]
    rows: list[list[str]] = []
    for line in section.splitlines():
        line = line.strip()
        if line.startswith("|"):
            cells = [c.strip() for c in line.strip("|").split("|")]
            if set("".join(cells)) <= set("-: "):
                continue  # separator row
            if cells and cells[0] == "Plan":
                continue  # header row
            rows.append(cells)
            continue
        if rows:
            break
    return rows


def parse_stripe_contract_plans(src: str) -> dict[str, dict]:
    """The `All prices are EUR` plan table in docs/tool-contracts/stripe.md."""
    rows = {}
    for cells in _table_rows_after(src, "All prices are EUR"):
        if len(cells) != 5:
            continue
        plan_id = cells[1].strip("`")
        monthly, annual = cells[2].lower(), cells[3].lower()
        rows[plan_id] = {
            "display_name": cells[0],
            "monthly_cents": None if "usage" in monthly else _money_cents(cells[2]),
            "yearly_cents": None if "usage" in annual else _money_cents(cells[3]),
        }
    assert rows, "docs/tool-contracts/stripe.md price table parse produced no rows"
    return rows


def _first_count(cell: str) -> int:
    """Leading number of a limits cell ('`3,000` + one-time …' -> 3000)."""
    if "unlimited" in cell.lower():
        return -1
    match = re.match(r"[^\d]*([\d,]+)", cell)
    return int(match.group(1).replace(",", "")) if match else -1


def _cents_cell(cell: str) -> int:
    """'`2,900` cents' -> 2900 (the lifecycle table states cents directly)."""
    value = cell.replace("`", "").replace("cents", "").replace(",", "").strip()
    return int(float(value))


def parse_billing_lifecycle_plans(src: str) -> dict[str, dict]:
    """The `## Plan Catalog` table in docs/architecture/billing-lifecycle.md."""
    rows = {}
    for cells in _table_rows_after(src, "## Plan Catalog"):
        if len(cells) != 7:
            continue
        plan_id = cells[1].strip("`")
        rows[plan_id] = {
            "display_name": cells[0],
            "monthly_cents": _cents_cell(cells[2]),
            "yearly_cents": _cents_cell(cells[3]),
            "email_limit": _first_count(cells[4]),
            "api_call_limit": _first_count(cells[5]),
            "rate_limit_tier": cells[6].strip("`"),
        }
    assert rows, "docs/architecture/billing-lifecycle.md plan table parse produced no rows"
    return rows


def _money_cents(cell: str) -> int:
    value = cell.replace("€", "").replace(",", "").replace("/year", "").strip()
    return round(float(value) * 100)


def _count(cell: str) -> int:
    value = cell.replace(",", "").strip()
    if value.lower() in ("unlimited", "—", "-"):
        return -1
    return int(value)


def _days(cell: str) -> int:
    value = re.sub(r"[^\d]", "", cell)
    return int(value) if value else -1


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


def check_billing_matches_catalog(
    catalog: list[dict], seeds: dict, overage_arms: dict[str, int]
) -> None:
    catalog_by_name = {row["name"]: row for row in catalog}
    for name, row in catalog_by_name.items():
        seed = seeds.get(name)
        if seed is None:
            fail(f"billing seed missing for catalog plan '{name}'")
            continue
        for field in ("display_name", "monthly_cents", "yearly_cents", "email_limit", "api_call_limit"):
            if seed[field] != row[field]:
                fail(
                    f"billing seed '{name}'.{field} = {seed[field]} but the canonical catalog "
                    f"says {row[field]} (billing-service/src/plans.rs vs platform-catalog)"
                )
        for field in ("retention_days", "team_members"):
            if field in seed and seed[field] != row[field]:
                fail(
                    f"billing seed '{name}'.{field} = {seed[field]} but the canonical catalog "
                    f"says {row[field]}"
                )
        # Feature gates sold in docs/pricing.md: the canonical catalog and the
        # billing runtime seeds must agree on every one, or the plan that is
        # sold is not the plan that is enforced.
        for field in (
            "audit_logs",
            "ab_testing",
            "time_travel_debugging",
            "template_approval_workflow",
            "subaccounts",
            "max_subaccounts",
        ):
            if seed.get(field) != row.get(field):
                fail(
                    f"billing seed '{name}'.{field} = {seed.get(field)} but the canonical "
                    f"catalog says {row.get(field)} (billing-service/src/plans.rs vs "
                    f"platform-catalog)"
                )
        expected_overage = row["overage_millicents"]
        if overage_arms:
            # Literal-arm shape: every arm must agree with the catalog row.
            actual_overage = overage_arms.get(name)
            if expected_overage != actual_overage:
                fail(
                    f"billing overage rate for '{name}' = {actual_overage} but the canonical "
                    f"catalog says {expected_overage} (millicents/email)"
                )
        # Delegation shape (no literal arms) is identity by construction when
        # `plan_overage_rate_millicents` calls platform_catalog::plan_by_name;
        # parse_billing_overage() has already failed the run if the function
        # neither carries arms nor delegates.


def check_verifier_matches_catalog(
    catalog: list[dict], payg_tiers: list[float], verifier: dict
) -> None:
    paid = [row for row in catalog if row["name"] != "payg"]
    expected_prices = [row["monthly_cents"] // 100 for row in paid]
    expected_limits = [row["email_limit"] for row in paid]
    expected_rates = list(payg_tiers) + [
        row["overage_millicents"] / 100.0
        for row in catalog
        if row["overage_millicents"] is not None
    ] + [0.10]

    if verifier["prices"] != expected_prices:
        fail(
            f"verifier CANONICAL_PRICES {verifier['prices']} drifted from the canonical "
            f"catalog {expected_prices} (ai-service/src/verifier.rs)"
        )
    if verifier["limits"] != expected_limits:
        fail(
            f"verifier CANONICAL_EMAIL_LIMITS {verifier['limits']} drifted from the canonical "
            f"catalog {expected_limits}"
        )
    if verifier["rates"] != expected_rates:
        fail(
            f"verifier CANONICAL_RATES {verifier['rates']} drifted from the canonical "
            f"catalog-derived rates {expected_rates}"
        )


def check_docs_matches_catalog(
    catalog: list[dict], payg_tiers: list[float], docs: dict, docs_payg: list[float]
) -> None:
    for row in catalog:
        if row["name"] == "payg":
            continue
        doc = docs.get(row["name"])
        if doc is None:
            fail(f"docs/pricing.md has no table row for plan '{row['name']}'")
            continue
        for field in (
            "display_name",
            "monthly_cents",
            "yearly_cents",
            "email_limit",
            "api_call_limit",
            "team_members",
            "retention_days",
        ):
            if doc[field] != row[field]:
                fail(
                    f"docs/pricing.md '{row['name']}'.{field} = {doc[field]} but the canonical "
                    f"catalog says {row[field]}"
                )
    if docs_payg != payg_tiers:
        fail(f"docs/pricing.md PAYG tiers {docs_payg} != canonical {payg_tiers}")


def check_doc_plan_tables_match_catalog(
    catalog: list[dict],
    stripe_rows: dict[str, dict],
    lifecycle_rows: dict[str, dict],
) -> None:
    """The stripe contract and billing-lifecycle plan tables restate the
    catalog; pin every row so the retired ladder cannot reappear."""
    for row in catalog:
        name = row["name"]
        for label, rows in (
            ("docs/tool-contracts/stripe.md", stripe_rows),
            ("docs/architecture/billing-lifecycle.md", lifecycle_rows),
        ):
            doc = rows.get(name)
            if doc is None:
                fail(f"{label} has no plan row for '{name}'")
                continue
            if doc["display_name"] != row["display_name"]:
                fail(
                    f"{label} '{name}'.display_name = {doc['display_name']!r} but the "
                    f"canonical catalog says {row['display_name']!r}"
                )
        stripe = stripe_rows.get(name)
        if stripe is not None and name != "payg":
            for field in ("monthly_cents", "yearly_cents"):
                if stripe[field] != row[field]:
                    fail(
                        f"docs/tool-contracts/stripe.md '{name}'.{field} = {stripe[field]} "
                        f"but the canonical catalog says {row[field]}"
                    )
        lifecycle = lifecycle_rows.get(name)
        if lifecycle is not None:
            for field in ("monthly_cents", "yearly_cents", "email_limit", "api_call_limit"):
                if lifecycle[field] != row[field]:
                    fail(
                        f"docs/architecture/billing-lifecycle.md '{name}'.{field} = "
                        f"{lifecycle[field]} but the canonical catalog says {row[field]}"
                    )


def production_only(src: str) -> str:
    """The source before its first test module — literal checks are about
    code that ships, not fixture text that deliberately quotes stale numbers."""
    for marker in ("\n#[cfg(test)]", "\nmod tests"):
        idx = src.find(marker)
        if idx != -1:
            src = src[:idx]
    return src


def check_ai_knowledge_derives_from_catalog(src: str) -> None:
    if "platform_catalog::PLANS" not in src:
        fail("ai-service/src/knowledge.rs does not derive its plan facts from platform_catalog")
    if "platform_catalog::PAYG_TIERS_EUR_PER_EMAIL" not in src:
        fail("ai-service/src/knowledge.rs does not derive PAYG tiers from platform_catalog")
    literal = re.search(r"price_eur:\s*\d", src)
    if literal:
        fail(
            "ai-service/src/knowledge.rs hardcodes a plan price "
            f"({literal.group(0)!r}) — plan facts must derive from platform_catalog"
        )


def check_sales_kb_derives_from_catalog(src: str) -> None:
    if "platform_catalog::plan_by_name" not in src:
        fail("sales KB plan facts do not derive from platform_catalog")
    hardcoded = re.search(r"plan is EUR \d", src) or re.search(r"starts from EUR \d", src)
    if hardcoded:
        fail(
            "sales-autopilot/src/knowledge.rs hardcodes a plan price "
            f"({hardcoded.group(0)!r}) — the KB plan facts must derive from platform_catalog"
        )


def check_ai_training_matches_catalog(
    catalog: list[dict],
    payg_tiers: list[float],
    payg_uppers: list[int | None],
    src: str,
) -> None:
    """The apps/ai training canon must equal the platform catalog exactly.

    The canon is parsed as a Python literal: any non-literal edit fails the
    gate loudly instead of silently skipping rows (the inverted-table defect
    class that shipped once).
    """
    match = re.search(r"CANONICAL_PRICING = (\{.*?\n\})", src, re.DOTALL)
    if not match:
        fail("apps/ai/training/validate_pricing.py has no CANONICAL_PRICING table")
        return
    try:
        table = ast.literal_eval(match.group(1))
    except (SyntaxError, ValueError) as error:
        fail(f"apps/ai/training CANONICAL_PRICING is not a literal table: {error}")
        return
    if not isinstance(table, dict):
        fail("apps/ai/training CANONICAL_PRICING is not a dict")
        return
    rows = {row["name"]: row for row in table.get("plans", [])}
    for plan in catalog:
        if plan["name"] == "payg":
            payg = table.get("payg") or {}
            base = f"€{plan['monthly_cents'] // 100:,}"
            if payg.get("base_price") != base:
                fail(
                    f"apps/ai training canon payg.base_price must be {base}: "
                    f"{payg.get('base_price')!r}"
                )
            tiers = payg.get("tiers") or []
            if len(tiers) != len(payg_tiers):
                fail(
                    f"apps/ai training canon has {len(tiers)} PAYG tiers but the catalog "
                    f"has {len(payg_tiers)}"
                )
                continue
            for index, (tier, upper) in enumerate(zip(tiers, payg_uppers)):
                minimum = 0 if index == 0 else (payg_uppers[index - 1] or 0) + 1
                expected = (minimum, upper, payg_tiers[index])
                actual = (tier.get("min"), tier.get("max"), tier.get("rate"))
                if actual != expected:
                    fail(
                        f"apps/ai training canon PAYG tier {index} is {actual!r} but the "
                        f"catalog says (min={minimum}, max={upper}, rate={payg_tiers[index]})"
                    )
            continue
        row = rows.get(plan["display_name"])
        if row is None:
            fail(
                f"apps/ai training canon is missing the canonical plan "
                f"{plan['display_name']!r}"
            )
            continue
        expectations = {
            "price": f"€{plan['monthly_cents'] // 100:,}",
            "annual": f"€{plan['yearly_cents'] // 100:,}",
            "emails": plan["email_limit"],
            "api_calls": plan["api_call_limit"],
        }
        for field, expected in expectations.items():
            if row.get(field) != expected:
                fail(
                    f"apps/ai training canon {plan['display_name']}.{field} must be "
                    f"{expected!r}: {row.get(field)!r}"
                )
    # The overage rate map feeds training answers about overage cost.
    overage = (table.get("overage") or {}).get("email_millicents_by_plan") or {}
    for plan in catalog:
        if plan["overage_millicents"] is None:
            continue
        key = plan["display_name"].lower()
        if overage.get(key) != plan["overage_millicents"]:
            fail(
                f"apps/ai training canon overage for {plan['display_name']} must be "
                f"{plan['overage_millicents']}: {overage.get(key)!r}"
            )
    extra = set(overage) - {
        plan["display_name"].lower()
        for plan in catalog
        if plan["overage_millicents"] is not None
    }
    if extra:
        fail(f"apps/ai training canon names unknown overage plans: {sorted(extra)}")


def run_checks(root: Path) -> list[str]:
    global FAILURES
    saved = FAILURES
    FAILURES = []
    try:
        catalog_src = (root / CATALOG.relative_to(ROOT)).read_text()
        billing_src = (root / BILLING_PLANS.relative_to(ROOT)).read_text()
        knowledge_src = (root / AI_KNOWLEDGE.relative_to(ROOT)).read_text()
        verifier_src = (root / AI_VERIFIER.relative_to(ROOT)).read_text()
        sales_src = (root / SALES_KB.relative_to(ROOT)).read_text()
        docs_src = (root / DOCS_PRICING.relative_to(ROOT)).read_text()
        stripe_src = (root / STRIPE_CONTRACT.relative_to(ROOT)).read_text()
        lifecycle_src = (root / BILLING_LIFECYCLE.relative_to(ROOT)).read_text()

        catalog = parse_catalog(catalog_src)
        payg_tiers = parse_catalog_payg_tiers(catalog_src)
        check_billing_matches_catalog(
            catalog, parse_billing_seeds(billing_src), parse_billing_overage(billing_src)
        )
        check_verifier_matches_catalog(
            catalog, payg_tiers, parse_verifier_tables(verifier_src)
        )
        check_docs_matches_catalog(
            catalog,
            payg_tiers,
            parse_docs_table(docs_src),
            parse_docs_payg(docs_src),
        )
        check_doc_plan_tables_match_catalog(
            catalog,
            parse_stripe_contract_plans(stripe_src),
            parse_billing_lifecycle_plans(lifecycle_src),
        )
        check_ai_knowledge_derives_from_catalog(production_only(knowledge_src))
        check_sales_kb_derives_from_catalog(production_only(sales_src))
        check_ai_training_matches_catalog(
            catalog,
            payg_tiers,
            parse_catalog_payg_uppers(catalog_src),
            (root / AI_TRAINING_PRICING.relative_to(ROOT)).read_text(),
        )
        reexport_src = (root / SALES_KB_REEXPORT.relative_to(ROOT)).read_text()
        if "pub use sales_knowledge::*;" not in reexport_src:
            fail(
                "sales-autopilot/src/knowledge.rs must re-export the shared "
                "sales-knowledge crate (pub use sales_knowledge::*;)"
            )
        return sorted(set(FAILURES))
    finally:
        FAILURES = saved


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

_SOURCES = (
    CATALOG,
    BILLING_PLANS,
    AI_KNOWLEDGE,
    AI_VERIFIER,
    SALES_KB,
    SALES_KB_REEXPORT,
    DOCS_PRICING,
    STRIPE_CONTRACT,
    BILLING_LIFECYCLE,
    AI_TRAINING_PRICING,
)


def _self_test() -> int:
    ok = True

    def expect_failure(label: str, path: Path, old: str, new: str, expect: str) -> None:
        nonlocal ok
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for source in _SOURCES:
                target = root / source.relative_to(ROOT)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
            victim = root / path.relative_to(ROOT)
            text = victim.read_text()
            if old not in text:
                print(f"self-test FAIL [{label}]: mutation anchor not found")
                ok = False
                return
            victim.write_text(text.replace(old, new, 1))
            problems = run_checks(root)
            matched = [p for p in problems if expect in p]
            if matched:
                print(f"self-test PASS [{label}]: {matched[0][:110]}")
            else:
                print(f"self-test FAIL [{label}]: expected a problem about {expect!r}, got {problems[:2]}")
                ok = False

    expect_failure(
        "catalog price change reaches docs",
        DOCS_PRICING,
        "| `pro` | Pro | €89 |",
        "| `pro` | Pro | €95 |",
        "'pro'.monthly_cents",
    )
    expect_failure(
        "billing seed drift vs catalog",
        BILLING_PLANS,
        "price_monthly: 2_900,",
        "price_monthly: 3_900,",
        "billing seed 'starter'.monthly_cents",
    )
    expect_failure(
        "seed flag removed vs catalog",
        BILLING_PLANS,
        "                // Growth+ sells customer audit read/export, A/B experiment\n"
        "                // execution, time-travel debugging, a custom tracking domain\n"
        "                // and custom retention (docs/pricing.md).\n"
        "                audit_logs: true,\n",
        "",
        "'growth'.audit_logs",
    )
    expect_failure(
        "seed ab_testing flag removed vs catalog",
        BILLING_PLANS,
        "                ab_testing: true,\n                time_travel_debugging: true,\n",
        "                time_travel_debugging: true,\n",
        "'growth'.ab_testing",
    )
    expect_failure(
        "seed subaccount cap drifts vs catalog",
        BILLING_PLANS,
        "                subaccounts: true,\n                max_subaccounts: 10,\n",
        "                subaccounts: true,\n                max_subaccounts: 25,\n",
        "'scale'.max_subaccounts",
    )
    expect_failure(
        "reintroduced literal overage arm drifts vs catalog",
        BILLING_PLANS,
        "platform_catalog::plan_by_name(plan_name)\n"
        "        .and_then(|catalog_row| catalog_row.overage_millicents_per_email)",
        'match plan_name {\n        "pro" => Some(99),\n        _ => None,\n    }',
        "billing overage rate for 'pro'",
    )
    expect_failure(
        "verifier table drift vs catalog",
        AI_VERIFIER,
        "const CANONICAL_PRICES: &[i64] = &[0, 29, 89, 229, 699, 1750];",
        "const CANONICAL_PRICES: &[i64] = &[0, 25, 65, 150, 350, 3000];",
        "CANONICAL_PRICES",
    )
    expect_failure(
        "hardcoded price in ai knowledge",
        AI_KNOWLEDGE,
        "price_eur: row.price_monthly_cents / 100,",
        "price_eur: 65,",
        "hardcodes a plan price",
    )
    expect_failure(
        "hardcoded price in the sales KB",
        SALES_KB,
        '                "Enterprise Cloud starts from EUR {} per month on an annual contract',
        '                "Enterprise Cloud starts from EUR 3000 per month on an annual contract',
        "hardcodes a plan price",
    )
    expect_failure(
        "docs retention drift vs catalog",
        DOCS_PRICING,
        "| 60 days | Add-on eligible |",
        "| 90 days | Add-on eligible |",
        "'pro'.retention_days",
    )
    expect_failure(
        "docs PAYG tier drift",
        DOCS_PRICING,
        "| Over 1,000,000 | €0.0003 |",
        "| Over 1,000,000 | €0.0004 |",
        "PAYG tiers",
    )
    expect_failure(
        "stripe contract table drift vs catalog",
        STRIPE_CONTRACT,
        "| Pro | `pro` | €89 | €890/year | Yes |",
        "| Pro | `pro` | €65 | €650/year | Yes |",
        "docs/tool-contracts/stripe.md 'pro'.monthly_cents",
    )
    expect_failure(
        "billing lifecycle table drift vs catalog",
        BILLING_LIFECYCLE,
        "| Developer | `starter` | `2,900` cents | `29,000` cents | `50,000` | `500,000` | `Standard` |",
        "| Developer | `starter` | `2,500` cents | `25,000` cents | `50,000` | `500,000` | `Standard` |",
        "docs/architecture/billing-lifecycle.md 'starter'.monthly_cents",
    )
    expect_failure(
        "ai training canon price drift vs catalog",
        AI_TRAINING_PRICING,
        '"price": "€89",    "annual": "€890",',
        '"price": "€95",    "annual": "€890",',
        "training canon Pro.price",
    )
    expect_failure(
        "ai training canon PAYG tier drift vs catalog",
        AI_TRAINING_PRICING,
        '{"min": 10_001,   "max": 100_000,    "rate": 0.0008},',
        '{"min": 10_001,   "max": 100_000,    "rate": 0.0009},',
        "PAYG tier 1",
    )
    if not run_checks(ROOT):
        print("self-test PASS [pristine tree]")
    else:
        print("self-test FAIL [pristine tree]: checker fails on the real sources")
        ok = False
    print(f"knowledge-consistency self-test: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


def main() -> int:
    problems = run_checks(ROOT)
    if problems:
        for problem in problems:
            print(f"FAIL knowledge-consistency: {problem}")
        print(f"knowledge-consistency: FAIL ({len(problems)} problem(s))")
        return 1
    print("PASS knowledge-consistency: catalog, billing, ai knowledge/verifier, sales KB and docs agree")
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv[1:]:
        sys.exit(_self_test())
    sys.exit(main())
