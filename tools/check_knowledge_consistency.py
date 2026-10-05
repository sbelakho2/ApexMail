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
     fields) and `plan_overage_rate_millicents` arms;
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
SALES_KB = ROOT / "services/mail-server/crates/sales-autopilot/src/knowledge.rs"
DOCS_PRICING = ROOT / "docs/pricing.md"

FAILURES: list[str] = []


def fail(message: str) -> None:
    FAILURES.append(message)


def _int(text: str) -> int:
    return int(text.replace("_", ""))


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
            }
        )
    assert rows, "platform-catalog parse produced no rows"
    return rows


def parse_catalog_payg_tiers(src: str) -> list[float]:
    block = re.search(
        r"PAYG_TIERS_EUR_PER_EMAIL: &\[\(i64, f64\)\] = &\[(.*?)\];", src, re.S
    ).group(1)
    return [float(rate) for _, rate in re.findall(r"\(([\d_]+|i64::MAX), ([\d.]+)\)", block)]


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
    assert seeds, "billing seed parse produced no seeds"
    return seeds


def parse_billing_overage(src: str) -> dict[str, int]:
    body = re.search(
        r"pub fn plan_overage_rate_millicents\(plan_name: &str\) -> Option<i64> \{(.*?)\n\}",
        src,
        re.S,
    ).group(1)
    out: dict[str, int] = {}
    for arm in re.finditer(r"((?:\s*\|?\s*\"[^\"]+\"\s*)+)=>\s*Some\((\d+)\)", body):
        for name in re.findall(r'"([^"]+)"', arm.group(1)):
            out[name] = int(arm.group(2))
    assert out, "billing overage parse produced no arms"
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


def check_billing_matches_catalog(catalog: list[dict], seeds: dict, rates: dict) -> None:
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
        expected_overage = row["overage_millicents"]
        actual_overage = rates.get(name)
        if expected_overage != actual_overage:
            fail(
                f"billing overage rate for '{name}' = {actual_overage} but the canonical "
                f"catalog says {expected_overage} (millicents/email)"
            )


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

        catalog = parse_catalog(catalog_src)
        check_billing_matches_catalog(
            catalog, parse_billing_seeds(billing_src), parse_billing_overage(billing_src)
        )
        check_verifier_matches_catalog(
            catalog, parse_catalog_payg_tiers(catalog_src), parse_verifier_tables(verifier_src)
        )
        check_docs_matches_catalog(
            catalog,
            parse_catalog_payg_tiers(catalog_src),
            parse_docs_table(docs_src),
            parse_docs_payg(docs_src),
        )
        check_ai_knowledge_derives_from_catalog(production_only(knowledge_src))
        check_sales_kb_derives_from_catalog(production_only(sales_src))
        return sorted(set(FAILURES))
    finally:
        FAILURES = saved


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

_SOURCES = (CATALOG, BILLING_PLANS, AI_KNOWLEDGE, AI_VERIFIER, SALES_KB, DOCS_PRICING)


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
