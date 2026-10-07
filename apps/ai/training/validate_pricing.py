#!/usr/bin/env python3
"""
validate_pricing.py — Structured pricing validator for ApexMail training data.

THE single source of truth for the Python training pipeline is this module's
CANONICAL_PRICING, which restates services/mail-server/crates/platform-catalog
(consumed by billing-service's runtime seed, the ai-service knowledge base and
the marketing/docs generation). tools/check_knowledge_consistency.py pins the
equality. Every generator, augmenter, validator and test fixture in
``apps/ai/training`` must import its plan prices, limits and rates from here —
never re-hardcode a number.

The table this module used to carry (Free 30,000 / €25 / €65 / €150 / €350 /
€3,000) was inverted against the catalog while claiming to match it, so the
pipeline would "fix" correct prices into wrong ones (adversarial review
2026-10-06). All published prices are EUR.

Usage:
    python validate_pricing.py                          # validate the corpus
    python validate_pricing.py --file data/train.jsonl # single file
    python validate_pricing.py --fix                     # rewrite legacy prices
    python validate_pricing.py --json                    # machine-readable output
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

# ── Canonical pricing table (source of truth) ──────────────────────────
# One row per shipped plan. Mirrors platform-catalog PLANS exactly:
# prices EUR, limits per month, -1 = unlimited. Free also carries the one-time
# 30,000-email launch allowance (a promo, NOT the monthly limit).
CANONICAL_PRICING = {
    "plans": [
        {"name": "Free",             "price": "€0",     "annual": "€0",      "emails": 3_000,    "api_calls": 30_000,     "team": 1,    "domains": 1},
        {"name": "Developer",        "price": "€29",    "annual": "€290",    "emails": 50_000,   "api_calls": 500_000,    "team": 5,    "domains": 5},
        {"name": "Pro",              "price": "€89",    "annual": "€890",    "emails": 150_000,  "api_calls": 2_000_000,  "team": 10,   "domains": 25},
        {"name": "Growth",           "price": "€229",   "annual": "€2,290",  "emails": 500_000,  "api_calls": 5_000_000,  "team": 25,   "domains": 100},
        {"name": "Business",         "price": "€699",   "annual": "€6,990",  "emails": 2_000_000,"api_calls": 20_000_000, "team": 50,   "domains": -1},   # -1 = unlimited
        {"name": "Enterprise Cloud", "price": "€1,750", "annual": "€17,500", "emails": 5_000_000,"api_calls": -1,         "team": -1,   "domains": -1},
    ],
    "payg": {
        "tiers": [
            {"min": 0,        "max": 10_000,     "rate": 0.001},
            {"min": 10_001,   "max": 100_000,    "rate": 0.0008},
            {"min": 100_001,  "max": 1_000_000,  "rate": 0.0005},
            {"min": 1_000_001,"max": None,       "rate": 0.0003},
        ],
        "base_price": "€0",
    },
    "overage": {
        # platform-catalog overage_millicents_per_email (review 2026-09-08 §9):
        # Developer 80, Pro 60, Growth/Business/Enterprise Cloud 35. EUR per
        # 1,000 emails = millicents (0.80 / 0.60 / 0.35). The flat 0.40 was a
        # legacy value no plan has.
        "email_millicents_by_plan": {"developer": 80, "pro": 60, "growth": 35,
                                     "business": 35, "enterprise cloud": 35},
        "api_free_tier": 30_000,
        "api_rate": 0.10,      # per 1,000 API calls above free tier (PAYG)
    },
    "addons": {
        "dedicated_ip": "€49/mo first, €69/mo each additional",
    },
    "free_launch_allowance_emails": 30_000,  # one-time, first 30 days — a promo
}

# ── Derived lookups (import these, never a literal) ─────────────────────
PLAN_BY_NAME = {p["name"].lower(): p for p in CANONICAL_PRICING["plans"]}
# Convenience row aliases for producers (use these instead of literals).
FREE = PLAN_BY_NAME["free"]
DEVELOPER = PLAN_BY_NAME["developer"]
PRO = PLAN_BY_NAME["pro"]
GROWTH = PLAN_BY_NAME["growth"]
BUSINESS = PLAN_BY_NAME["business"]
ENTERPRISE_CLOUD = PLAN_BY_NAME["enterprise cloud"]
PRICE_BY_PLAN = {p["name"].lower(): p["price"] for p in CANONICAL_PRICING["plans"]}
ANNUAL_PRICE_BY_PLAN = {p["name"].lower(): p["annual"] for p in CANONICAL_PRICING["plans"]}
EMAIL_LIMIT_BY_PLAN = {p["name"].lower(): p["emails"] for p in CANONICAL_PRICING["plans"]}
API_LIMIT_BY_PLAN = {p["name"].lower(): p["api_calls"] for p in CANONICAL_PRICING["plans"]}
TEAM_LIMIT_BY_PLAN = {p["name"].lower(): p["team"] for p in CANONICAL_PRICING["plans"]}
DOMAIN_LIMIT_BY_PLAN = {p["name"].lower(): p["domains"] for p in CANONICAL_PRICING["plans"]}
OVERAGE_MILLICENTS_BY_PLAN = CANONICAL_PRICING["overage"]["email_millicents_by_plan"]
# millicents/email → EUR per 1,000 emails: 80 → €0.80, 60 → €0.60, 35 → €0.35.
OVERAGE_RATE_BY_PLAN = {k: v / 100 for k, v in OVERAGE_MILLICENTS_BY_PLAN.items()}
PAYG_TIERS = CANONICAL_PRICING["payg"]["tiers"]
API_FREE_TIER = CANONICAL_PRICING["overage"]["api_free_tier"]
API_RATE_PER_1K = CANONICAL_PRICING["overage"]["api_rate"]
DEDICATED_IP_ADDON = CANONICAL_PRICING["addons"]["dedicated_ip"]
FREE_LAUNCH_ALLOWANCE_EMAILS = CANONICAL_PRICING["free_launch_allowance_emails"]

VALID_PRICES = set(p["price"] for p in CANONICAL_PRICING["plans"])
VALID_PRICES.update({"€49", "€69"})  # Dedicated IP add-on: first / additional
# Numeric canonical price values (validated regardless of currency symbol)
CANONICAL_PRICE_NUMBERS = {0, 29, 89, 229, 699, 1750, 49, 69}

# Legacy display names still found in pre-2026-09-08 corpora map onto the
# shipped plans (platform-catalog keeps "starter"/"scale"/"enterprise" as
# internal billing ids, but the customer-facing names changed).
PLAN_ALIASES: dict[str, str] = {
    "starter": "developer",
    "scale": "business",
    "enterprise": "enterprise cloud",
}
# Every alias that must be rewritten inside prose (display names).
LEGACY_DISPLAY_NAMES = {"Starter": "Developer", "Scale": "Business",
                        "Enterprise": "Enterprise Cloud"}


# Pre-review plan prices; a price-bearing assertion must never REQUIRE one.
LEGACY_PLAN_PRICE_NUMBERS = frozenset({25, 65, 150, 350, 3000})


def legacy_price_tokens(text: str) -> list[str]:
    """Legacy plan-price tokens (e.g. €25, €350) found in a string."""
    found = []
    for m in re.finditer(r"[€$]\s?(\d[\d,]*)", text or ""):
        try:
            value = int(m.group(1).replace(",", ""))
        except ValueError:
            continue
        if value in LEGACY_PLAN_PRICE_NUMBERS:
            found.append(m.group(0))
    return found


def canonical_key(name: str) -> str | None:
    """Map a plan name (canonical or legacy, any case) to its canonical key."""
    lowered = name.lower()
    if lowered in PLAN_BY_NAME:
        return lowered
    return PLAN_ALIASES.get(lowered)


def price_number(plan: str) -> int:
    """Numeric monthly price for a canonical or legacy plan name."""
    key = canonical_key(plan)
    if key is None:
        raise KeyError(f"unknown plan {plan!r}")
    return int(PRICE_BY_PLAN[key].replace("€", "").replace(",", ""))


def format_limit(value: int) -> str:
    """Render a plan limit; -1 means unlimited in platform-catalog."""
    return "Unlimited" if value < 0 else f"{value:,}"


def overage_rate_for(plan: str | None) -> float:
    """EUR-per-1,000 overage rate; falls back to the cheapest (Growth+) rate."""
    key = canonical_key(plan) if plan else None
    if key and key in OVERAGE_RATE_BY_PLAN:
        return OVERAGE_RATE_BY_PLAN[key]
    return 0.35


def render_pricing_table() -> str:
    """Markdown pricing table rendered from CANONICAL_PRICING."""
    lines = [
        "| Plan             | Price    | Emails/mo   | API calls/mo | Team      | Domains    |",
        "|------------------|----------|-------------|--------------|-----------|------------|",
    ]
    for p in CANONICAL_PRICING["plans"]:
        lines.append(
            f"| {p['name']:<16} | {p['price']:<8} | {format(p['emails'], ','):<11} "
            f"| {format_limit(p['api_calls']):<12} | {format_limit(p['team']):<9} "
            f"| {format_limit(p['domains']):<10} |"
        )
    lines.append("")
    lines.append(
        "Free also includes a one-time **30,000-email launch allowance** "
        "during the first 30 days (a promo, not the monthly limit)."
    )
    return "\n".join(lines)


def render_payg_info() -> str:
    """PAYG / overage paragraph rendered from CANONICAL_PRICING."""
    tiers = CANONICAL_PRICING["payg"]["tiers"]
    bands = ["0-10K", "10K-100K", "100K-1M", "1M+"]
    tier_bits = ", ".join(f"€{t['rate']:g} ({b})" for t, b in zip(tiers, bands))
    overage_bits = ", ".join(
        f"{PLAN_BY_NAME[k]['name']} €{v:.2f}"
        for k, v in OVERAGE_RATE_BY_PLAN.items()
    )
    return (
        f"Pay-as-you-go (PAYG): €0 base. Email tiers: {tier_bits}. "
        f"Plan overages per 1,000 extra emails: {overage_bits}. "
        f"API: first {API_FREE_TIER:,} calls free, then €{API_RATE_PER_1K:.2f}/1,000."
    )


# ── Validation ─────────────────────────────────────────────────────────

# Plan price references: "Developer (€29/month)", "Pro plan at €89/mo",
# "Developer costs €29/month", "Growth €229/month". A bounded amount of
# connecting text ("costs", "is", "at", ...) may sit between the plan name
# and the price. Both € and $ symbols are accepted — the NUMBERS are
# validated against the canonical table, and a '$' is itself reported as a
# violation because all published prices are EUR. Legacy names (Starter /
# Scale / Enterprise) resolve to their shipped plans, so "Starter €25" is
# reported as Developer quoted below €29.
PLAN_PRICE_PATTERN = re.compile(
    r"(?P<plan>Free|Starter|Developer|Pro|Growth|Scale|Business|Enterprise(?:\s+Cloud)?)"
    r"(?:\s+plan)?[^\n$€0-9]{0,24}?[$€]\s?(?P<price>[\d,]+(?:\.\d+)?)\s*(?:/mo|/month|\)?)?",
    re.IGNORECASE,
)

# Legacy Free-tier quotas: the old table granted 30,000 emails / 300,000 API
# calls per month. The canonical Free plan grants 3,000 / 30,000; 30,000 is
# only the one-time launch allowance.
FREE_MONTHLY_EMAIL_QUOTA_PATTERN = re.compile(
    r"\b30,000\b(?=[^\n]{0,30}?(?:emails?|e-mails?)[^\n]{0,20}?(?:/\s?mo|/month|per\s+month|a\s+month))",
    re.IGNORECASE,
)
FREE_MONTHLY_API_QUOTA_PATTERN = re.compile(
    r"\b300,000\b(?=[^\n]{0,30}?(?:API\s+calls?|calls?)(?!/\s?1)|APIs?)",
    re.IGNORECASE,
)
API_FREE_TIER_PATTERN = re.compile(
    r"(?:first\s+)?100,?000\s+(?:free\s+)?API\s+calls?", re.IGNORECASE)

# Legacy overage: no plan ever had a flat €0.40 per 1,000.
LEGACY_OVERAGE_PATTERN = re.compile(
    r"€\s?0\.40\s*(?:/1K|/1k\b|per\s+1,000|/1,000)", re.IGNORECASE)

# Competitor/3rd-party price patterns to ignore
COMPETITOR_PATTERNS = [
    re.compile(r"Mailchimp", re.IGNORECASE),
    re.compile(r"SendGrid", re.IGNORECASE),
    re.compile(r"competitor", re.IGNORECASE),
]


def is_competitor_text(text: str) -> bool:
    """Check if text segment references competitor pricing (skip these)."""
    return any(p.search(text) for p in COMPETITOR_PATTERNS)


def _plan_key(match_plan: str) -> str | None:
    return canonical_key(match_plan.replace(" ", "") if " " in match_plan else match_plan)


def validate_pricing_in_text(
    text: str,
    source: str = "unknown",
    fix: bool = False,
) -> list[dict[str, Any]]:
    """Validate all pricing references in text against the canonical table.

    Returns list of findings (warnings/errors). With ``fix=True`` the text is
    not modified here (validate_file rewrites files via canonize_text); the
    findings are still reported.
    """
    findings = []

    if is_competitor_text(text):
        return findings

    # Check plan+price pairs
    for match in PLAN_PRICE_PATTERN.finditer(text):
        matched_plan = re.sub(r"\s+", " ", match.group("plan")).strip()
        plan_key = canonical_key(matched_plan)
        if plan_key is None:
            continue

        # Not a plan-price quote: computed differences/savings phrased as
        # "costs €N/mo more (than ...)" or "saves €N".
        after = text[match.end():match.end() + 18].lower()
        connector = match.group(0)[len(match.group("plan")):].lower()
        if any(w in after for w in ("more", "less", "cheaper", "savings")):
            continue
        if any(w in connector for w in ("save", "saving")):
            continue

        price_str = match.group("price").replace(",", "")
        expected_price = PRICE_BY_PLAN[plan_key]
        expected_number = int(expected_price.replace("€", "").replace(",", ""))

        # A connector that crosses another plan name means table columns or
        # a sentence boundary, not this plan's price.
        connector = match.group(0)[len(match.group("plan")):].lower()
        if re.search(r"\b(?:free|starter|developer|pro|growth|scale|business|enterprise)\b", connector):
            continue
        # Per-unit rates and computed cents amounts (e.g. "Developer €0.80")
        # are not whole-euro plan prices.
        if "." in price_str:
            continue
        try:
            found_number = int(price_str)
        except ValueError:
            continue

        # The NUMBERS must match platform-catalog; a '$' symbol is also a
        # violation because every published ApexMail price is EUR.
        if found_number != expected_number:
            findings.append({
                "type": "error",
                "source": source,
                "message": (
                    f"{PLAN_BY_NAME[plan_key]['name']} plan price should be "
                    f"€{expected_number:,}/mo, not {match.group()}"
                ),
                "span": match.span(),
                "matched": match.group(),
                "expected": expected_price,
            })
        elif "$" in match.group():
            findings.append({
                "type": "error",
                "source": source,
                "message": (
                    f"{PLAN_BY_NAME[plan_key]['name']} price must be stated in EUR "
                    f"({expected_price}), not dollars: {match.group()}"
                ),
                "span": match.span(),
                "matched": match.group(),
                "expected": expected_price,
            })

    # Free monthly quotas must not be the legacy 30,000 / 300,000.
    for m in FREE_MONTHLY_EMAIL_QUOTA_PATTERN.finditer(text):
        window = text[max(0, m.start() - 120):m.end() + 30].lower()
        if any(w in window for w in ("launch allowance", "first 30 days", "promo")):
            continue
        findings.append({
            "type": "error",
            "source": source,
            "message": "Free plan email quota should be 3,000/mo (30,000 is only the launch allowance), not 30,000/mo",
            "span": m.span(),
            "matched": m.group(),
        })
    for m in FREE_MONTHLY_API_QUOTA_PATTERN.finditer(text):
        window = text[max(0, m.start() - 120):m.end() + 30].lower()
        if any(w in window for w in ("launch allowance", "first 30 days", "promo")):
            continue
        findings.append({
            "type": "error",
            "source": source,
            "message": "Free plan API quota should be 30,000/mo, not 300,000/mo",
            "span": m.span(),
            "matched": m.group(),
        })
    for m in API_FREE_TIER_PATTERN.finditer(text):
        findings.append({
            "type": "error",
            "source": source,
            "message": "API free tier is 30,000 calls, not 100,000",
            "span": m.span(),
            "matched": m.group(),
        })
    for m in LEGACY_OVERAGE_PATTERN.finditer(text):
        findings.append({
            "type": "error",
            "source": source,
            "message": (
                "no plan has €0.40/1,000 overage; platform-catalog pins "
                + ", ".join(f"{PLAN_BY_NAME[k]['name']} €{v:.2f}"
                            for k, v in OVERAGE_RATE_BY_PLAN.items())
                + " per 1,000"
            ),
            "span": m.span(),
            "matched": m.group(),
        })

    return findings


# ── One-shot correction path ───────────────────────────────────────────
# canonize_text() rewrites legacy prices/quotas/rates/plan names to the
# canonical table. It is used by `validate_pricing.py --fix` and by the
# one-shot sweep_currency_to_eur.py migration; keeping the rules here means
# there is exactly one correction implementation.

_PLAN_PRICE_FIX_RE = re.compile(
    r"(?P<plan>Free|Starter|Developer|Pro|Growth|Scale|Business|Enterprise(?:\s+Cloud)?)"
    # No backslash: raw source lines carry literal "\n" escapes and a match
    # must never cross from one embedded message into the next.
    r"(?P<mid>(?:\s+plan)?[^\n\\$€0-9]{0,24}?)"
    r"(?P<cur>[$€])\s?(?P<num>\d[\d,]*(?:\.\d+)?)"
    r"(?P<suffix>\s*(?:/mo|/month)?)",
    re.IGNORECASE,
)
_SKIP_CONNECTORS = ("save", "saving", "overage", "total", "difference", "less",
                    "more", "credit", "proration", "vs", "versus", "than",
                    "approx", "~", "≈", "off")
_ANNUAL_FIXES = {"€250": "€290", "€650": "€890", "€1,500": "€2,290",
                 "€3,500": "€6,990", "€30,000": "€17,500"}


def _near_competitor(text: str, start: int, end: int, window: int = 120) -> bool:
    """True when a competitor brand is named near the span (leave it alone)."""
    return is_competitor_text(text[max(0, start - window):end + window])


def _fix_plan_price(match: re.Match, counters: dict[str, int]) -> str:
    matched_plan = re.sub(r"\s+", " ", match.group("plan")).strip()
    key = canonical_key(matched_plan)
    if key is None:
        return match.group(0)
    mid = match.group("mid")
    if any(w in mid.lower() for w in _SKIP_CONNECTORS):
        return match.group(0)
    # A connector that crosses another plan name means a table column or a
    # sentence boundary, not this plan's price.
    if re.search(r"\b(?:free|starter|developer|pro|growth|scale|business|enterprise)\b",
                 mid, re.IGNORECASE):
        return match.group(0)
    if _near_competitor(match.string, match.start(), match.end()):
        return match.group(0)
    # "costs €60/mo more" is a computed difference, not a plan price.
    after = match.string[match.end():match.end() + 18].lower()
    if any(w in after for w in ("more", "less", "cheaper", "savings")):
        return match.group(0)
    canonical_name = PLAN_BY_NAME[key]["name"]
    canonical_price = PRICE_BY_PLAN[key]
    num = match.group("num")
    # Sub-euro amounts are per-unit rates (e.g. €0.40/1,000), never a plan price.
    if float(num.replace(",", "")) < 1:
        return match.group(0)
    if "." in num:
        decimals = len(num.split(".")[1])
        value = f"{int(canonical_price.replace('€', '').replace(',', '')):,.{decimals}f}"
    else:
        value = canonical_price.replace("€", "")
        value = f"{int(value.replace(',', '')):,}"
    out = f"{canonical_name}{mid}{match.group('cur')}{value}{match.group('suffix')}"
    if out != match.group(0):
        counters["plan prices"] = counters.get("plan prices", 0) + 1
    return out


def _fix_plan_names(match: re.Match, counters: dict[str, int]) -> str:
    word = match.group(0)
    replacement = LEGACY_DISPLAY_NAMES[word]
    counters["plan names"] = counters.get("plan names", 0) + 1
    return replacement


def _in_free_context(text: str, start: int, end: int) -> bool:
    """True when the match sits in Free-plan wording (and is not the launch
    allowance, which legitimately mentions 30,000 emails)."""
    window = text[max(0, start - 140):end + 40].lower()
    if "free" not in window:
        return False
    if any(w in window for w in ("launch allowance", "first 30 days", "promo")):
        return False
    if _near_competitor(text, start, end):
        return False
    return True


def _fix_free_quota(match: re.Match, counters: dict[str, int]) -> str:
    if not _in_free_context(match.string, match.start(), match.end()):
        return match.group(0)
    text = match.group(0)
    replacement = text.replace("30,000", "3,000").replace("300,000", "30,000")
    counters["Free quotas"] = counters.get("Free quotas", 0) + 1
    return replacement


def _fix_usage_pair(match: re.Match, counters: dict[str, int]) -> str:
    if not _in_free_context(match.string, match.start(), match.end()):
        return match.group(0)
    used = match.group("used")
    used_num = int(used.replace(",", ""))
    if abs(used_num) < 100:  # already rescaled
        return match.group(0)
    counters["Free usage pairs"] = counters.get("Free usage pairs", 0) + 1
    return f"{used_num // 10:,}/{match.group('limit')}"


def _fix_free_usage_pair(match: re.Match, counters: dict[str, int]) -> str:
    return _fix_usage_pair(match, counters)


def _fix_free_api_usage_pair(match: re.Match, counters: dict[str, int]) -> str:
    return _fix_usage_pair(match, counters)


def _fix_overage_rate(match: re.Match, counters: dict[str, int]) -> str:
    """Rewrite the flat legacy €0.40/1,000 with the plan's canonical rate."""
    if _near_competitor(match.string, match.start(), match.end()):
        return match.group(0)
    before = match.string[max(0, match.start() - 220):match.start()]
    plan = None
    for name in ("Enterprise Cloud", "Business", "Growth", "Pro", "Developer",
                 "Starter", "Scale", "Enterprise"):
        if re.search(rf"\b{name}\b", before, re.IGNORECASE):
            plan = name
            break
    if plan:
        rate = overage_rate_for(plan)
        counters["overage rates"] = counters.get("overage rates", 0) + 1
        return f"€{rate:.2f} per 1,000"
    counters["overage rates"] = counters.get("overage rates", 0) + 1
    return "€0.80 (Developer) / €0.60 (Pro) / €0.35 (Growth+) per 1,000"


def _fix_api_free_tier(match: re.Match, counters: dict[str, int]) -> str:
    text = match.group(0)
    text = re.sub(r"100,?000", "30,000", text)
    counters["API free tier"] = counters.get("API free tier", 0) + 1
    return text


def _fix_api_free_phrase(match: re.Match, counters: dict[str, int]) -> str:
    text = match.group(0)
    text = re.sub(r"100k", "30k", text).replace("100,000", "30,000")
    counters["API free tier"] = counters.get("API free tier", 0) + 1
    return text


def canonize_text(text: str, counters: dict[str, int] | None = None) -> tuple[str, int]:
    """Rewrite legacy pricing to the canonical table. Returns (new_text, n)."""
    if counters is None:
        counters = {}

    # 1. Plan-adjacent prices (canonical + legacy plan names).
    text = _PLAN_PRICE_FIX_RE.sub(lambda m: _fix_plan_price(m, counters), text)

    # 2. Legacy annual prices — ONLY in annual/yearly context, so a computed
    #    total that happens to equal a legacy annual figure (e.g. the sum of a
    #    base price and an overage) is never repriced.
    def _fix_annual(match: re.Match) -> str:
        window = match.string[max(0, match.start() - 90):match.start()].lower()
        after = match.string[match.end():match.end() + 20].lower()
        if ("annual" in window or "/year" in window or "per year" in window
                or "/year" in after or "per year" in after):
            counters["annual prices"] = counters.get("annual prices", 0) + 1
            return _ANNUAL_FIXES[match.group(0)]
        return match.group(0)

    text = re.sub("|".join(re.escape(k) for k in _ANNUAL_FIXES),
                  _fix_annual, text)

    # 3. Free-tier quotas: legacy 30,000/mo emails, 300,000/mo API calls.
    text = FREE_MONTHLY_EMAIL_QUOTA_PATTERN.sub(
        lambda m: _fix_free_quota(m, counters), text)
    text = FREE_MONTHLY_API_QUOTA_PATTERN.sub(
        lambda m: _fix_free_quota(m, counters), text)

    # 4. Free usage pairs (e.g. "29,800/30,000", "293,400/300,000").
    text = re.sub(r"\b(?P<used>[\d,]{4,})/(?P<limit>30,000)\b",
                  lambda m: _fix_free_usage_pair(m, counters), text)
    text = re.sub(r"\b(?P<used>[\d,]{4,})/(?P<limit>300,000)\b",
                  lambda m: _fix_free_api_usage_pair(m, counters), text)

    # 5. API free tier (30,000 now, was 100,000).
    text = API_FREE_TIER_PATTERN.sub(lambda m: _fix_api_free_tier(m, counters), text)
    text = re.sub(r"first\s+100k\s+free", lambda m: _fix_api_free_phrase(m, counters),
                  text, flags=re.IGNORECASE)

    # 6. Legacy overage rate → plan-canonical rate.
    text = LEGACY_OVERAGE_PATTERN.sub(lambda m: _fix_overage_rate(m, counters), text)

    # 7. Legacy plan display names (Starter → Developer, Scale → Business,
    #    Enterprise → Enterprise Cloud) when used as a product tier.
    text = re.sub(r"\bStarter\b", lambda m: _fix_plan_names(m, counters), text)
    text = re.sub(r"\bstarter\b", "developer", text)
    text = re.sub(r"\bScale\b(?=\s*(?:\(|/|,|\.|\bplan\b|\btier\b|\baccount\b|"
                  r"\bcustomer\b|\bincludes\b|\bsupports\b|\bis\b|[-–—]))",
                  lambda m: _fix_plan_names(m, counters), text)
    text = re.sub(r"\bEnterprise\b(?!\s+Cloud)(?=\s*(?:\(|/|,|\.|\bplan\b|\btier\b|"
                  r"\baccount\b|\bcustomer\b|\bcustomers\b|\bincludes\b|\bsupports\b|"
                  r"\bis\b|\bonly\b|\bSLA\b|\bdata\b|\bcompliance\b|\bteam\b|"
                  r"\bwhite-label\b|\bBAA\b|\bfeatures?\b|\bhas\b|\bgets\b|\badds\b|"
                  r"\bfrom\b|\bupgrade\b|[-–—]))",
                  lambda m: _fix_plan_names(m, counters), text)

    return text, sum(counters.values())


# ── File validation / fixing ───────────────────────────────────────────

def _iter_strings_with_path(node: Any):
    if isinstance(node, dict):
        for value in node.values():
            yield from _iter_strings_with_path(value)
    elif isinstance(node, list):
        for value in node:
            yield from _iter_strings_with_path(value)
    elif isinstance(node, str):
        yield None, node


def validate_file(
    filepath: str | Path,
    fix: bool = False,
    verbose: bool = False,
) -> list[dict[str, Any]]:
    """Validate all pricing references in a JSONL file (or JSON document)."""
    path = Path(filepath)
    if not path.exists():
        return [{"type": "error", "source": str(path), "message": "File not found"}]

    findings = []
    try:
        raw_lines = path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError:
        return [{"type": "error", "source": str(path), "message": "Not valid UTF-8"}]

    is_json_doc = path.suffix == ".json"
    if is_json_doc:
        try:
            document = json.loads("\n".join(raw_lines))
        except json.JSONDecodeError:
            return [{"type": "error", "source": str(path), "message": "Invalid JSON"}]
        entries = _json_strings(document)
    else:
        entries = []
        for line_no, line in enumerate(raw_lines, 1):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                findings.append({
                    "type": "error",
                    "source": f"{path}:{line_no}",
                    "message": "Invalid JSON",
                })
                continue
            entries.extend((line_no, text) for text in _iter_entry_strings(entry))

    fixed_lines: dict[int, str] = {}
    for line_no, content in entries:
        source = f"{path}:{line_no}"
        findings.extend(validate_pricing_in_text(content, source=source, fix=fix))

    if fix and not is_json_doc:
        new_lines = []
        changed = 0
        for line_no, line in enumerate(raw_lines, 1):
            stripped = line.strip()
            if not stripped:
                new_lines.append(line)
                continue
            try:
                entry = json.loads(stripped)
            except json.JSONDecodeError:
                new_lines.append(line)
                continue
            fixed_entry, n = _canonize_entry(entry)
            changed += n
            new_lines.append(json.dumps(fixed_entry, ensure_ascii=False)
                             if n else line)
        if changed:
            path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
            if verbose:
                print(f"  fixed {changed} pricing reference(s) in {path}")
        # Re-validate after fixing so callers see the true remaining findings.
        return validate_file(path, fix=False, verbose=verbose)

    return findings


def _json_strings(document: Any):
    yielded: list[tuple[None, str]] = []

    def walk(node):
        if isinstance(node, dict):
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)
        elif isinstance(node, str):
            yielded.append((None, node))

    walk(document)
    return yielded


def _iter_entry_strings(entry: Any):
    if isinstance(entry, dict):
        for key, value in entry.items():
            if isinstance(value, str):
                yield value
            else:
                for _, sub in _iter_strings_with_path(value):
                    yield sub
    else:
        for _, sub in _iter_strings_with_path(entry):
            yield sub


def _canonize_entry(entry: Any, counters: dict[str, int] | None = None) -> tuple[Any, int]:
    counters = counters if counters is not None else {}

    def rec(node):
        if isinstance(node, dict):
            return {k: rec(v) for k, v in node.items()}
        if isinstance(node, list):
            return [rec(v) for v in node]
        if isinstance(node, str):
            new, _ = canonize_text(node, counters)
            return new
        return node

    return rec(entry), sum(counters.values())


def default_corpus_files() -> list[Path]:
    """The tracked training corpus this pipeline owns.

    Root /data is a retired, gitignored scratch directory (see data/README.md)
    and is not validated here.
    """
    data_dir = Path(__file__).resolve().parent / "data"
    return sorted(data_dir.glob("*.jsonl"))


# ── Self-test (regression guard for the canon itself) ──────────────────
# The table INVERTED once (the validator claimed to match platform-catalog
# while listing Starter 50,000/€25 … Enterprise €3,000 and Free 30,000/mo),
# and the pipeline would then "fix" correct corpus text into wrong prices.
# This self-test fails if either half of that defect returns: the table
# drifts from the shipped platform-catalog values, or the legacy-price
# detector stops flagging the numbers the sweep exists to catch.
SELF_TEST_EXPECTED = {
    "free": ("€0", 3_000),
    "developer": ("€29", 50_000),
    "pro": ("€89", 150_000),
    "growth": ("€229", 500_000),
    "business": ("€699", 2_000_000),
    "enterprise cloud": ("€1,750", 5_000_000),
}


def self_test() -> int:
    """Prove the canonical table and the detector agree. Returns an exit code."""
    failures: list[str] = []

    for key, (price, emails) in SELF_TEST_EXPECTED.items():
        row = PLAN_BY_NAME.get(key)
        if row is None:
            failures.append(f"canonical table is missing plan {key!r}")
            continue
        if row["price"] != price:
            failures.append(
                f"{row['name']} price is {row['price']}, must be {price} "
                f"(platform-catalog)"
            )
        if row["emails"] != emails:
            failures.append(
                f"{row['name']} email limit is {row['emails']}, must be {emails} "
                f"(platform-catalog)"
            )

    # Canonical sentences must validate clean (the state the corpus is now in).
    for key, (price, emails) in SELF_TEST_EXPECTED.items():
        sentence = f"{PLAN_BY_NAME[key]['name']} is {price}/mo with {format(emails, ',')} emails."
        findings = validate_pricing_in_text(sentence, source="self-test")
        if findings:
            failures.append(
                f"canonical sentence flagged as invalid: {sentence!r} -> "
                f"{findings[0]['message']}"
            )

    # Every legacy plan price must still be detected. Tokens are built from
    # the numeric set so this file carries no live legacy price literal.
    if not LEGACY_PLAN_PRICE_NUMBERS:
        failures.append("the legacy-price detector was disabled (empty set)")
    for value in sorted(LEGACY_PLAN_PRICE_NUMBERS):
        text = f"Pro costs €{value}/month."
        if not legacy_price_tokens(text):
            failures.append(f"legacy price €{value} is no longer detected")

    # A wrong price attached to a plan name is a finding, not silence.
    probe = min(LEGACY_PLAN_PRICE_NUMBERS) if LEGACY_PLAN_PRICE_NUMBERS else 150
    wrong = f"Developer is €{probe}/mo."
    if not validate_pricing_in_text(wrong, source="self-test"):
        failures.append(f"wrong plan price not flagged: {wrong!r}")

    if failures:
        print("❌ SELF-TEST FAILED — the pricing canon regressed:")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("✅ Self-test passed: canonical table and legacy-price detector agree.")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Validate pricing references in ApexMail training data"
    )
    parser.add_argument(
        "--file", "-f",
        help="Single file to validate (default: all corpus data files)",
    )
    parser.add_argument(
        "--data-dir",
        help="Directory of JSONL corpus files (default: ./data next to this script)",
    )
    parser.add_argument(
        "--fix", action="store_true",
        help="Auto-fix discovered pricing issues (rewrites the JSONL corpus)",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output in JSON format (machine-readable)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Show detailed findings",
    )
    parser.add_argument(
        "--self-test", action="store_true",
        help="Prove the canonical table matches platform-catalog and the "
             "legacy-price detector still flags the old numbers",
    )
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    # Determine files to validate
    if args.file:
        files = [Path(args.file)]
    elif args.data_dir:
        files = sorted(Path(args.data_dir).glob("*.jsonl"))
    else:
        files = default_corpus_files()

    all_findings = []
    for f in files:
        if f.exists():
            findings = validate_file(f, fix=args.fix, verbose=args.verbose)
            all_findings.extend(findings)
            if args.verbose:
                for finding in findings:
                    print(f"  {finding['type'].upper()}: {finding['message']}")

    # Report
    errors = [f for f in all_findings if f["type"] == "error"]
    warnings = [f for f in all_findings if f["type"] == "warning"]

    if args.json:
        print(json.dumps({
            "status": "fail" if errors else "pass",
            "total": len(all_findings),
            "errors": len(errors),
            "warnings": len(warnings),
            "findings": all_findings,
        }, indent=2))
        return 1 if errors else 0

    print(f"\nPricing validation complete:")
    print(f"  Files checked: {len(files)}")
    print(f"  Total findings: {len(all_findings)}")
    print(f"  Errors: {len(errors)}")
    print(f"  Warnings: {len(warnings)}")

    if errors:
        print(f"\n❌ FAILED: {len(errors)} pricing error(s) found")
        for e in errors[:10]:
            print(f"  - {e['source']}: {e['message']}")
        return 1
    else:
        print(f"\n✅ PASSED: All pricing references match canonical rates")
        return 0


if __name__ == "__main__":
    sys.exit(main())
