"""
Canonical pricing constants for ApexMail (Python tooling mirror).

AUTHORITY
=========
The single source of truth for plan facts is the Rust catalog
`services/mail-server/crates/platform-catalog/src/lib.rs` (`pub const PLANS`),
which billing-service, ai-service and the knowledge base all consume. The
runtime billing seeds (`billing-service/src/plans.rs`) delegate their plan
facts to it, and `knowledge-consistency` pins that equality. This module is a
Python mirror of that catalog for the tools/ scripts; the drift validator
(`tools/validate_pricing_drift.py`) parses this file STRUCTURALLY (per plan,
per field) and fails if any value here disagrees with the catalog. Domain
caps are the one field the canonical catalog does not carry, so they are
mirrored from the runtime seeds' `PlanFeatures.max_sending_domains` — the
validator pins them against the parsed seed values too.

Values are:
  * `price_cents` / `price_yearly_cents` — euro CENTS (billing storage unit)
  * `emails` / `api_calls` / `domains` / `team` — monthly limits; -1 unlimited
  * `overage_millicents_per_email` — millicents per email beyond the included
    volume (None = no automatic overage; the public per-1,000 rate is this
    value / 100 in EUR).
  * `domains` — max sending domains (-1 unlimited)

All monetary values are EUR. Money math uses integer cents / millicents —
never floats. Update this file ONLY together with the catalog; the gate is
`python3 tools/validate_pricing_drift.py`.
"""

from typing import Dict, Optional, Tuple

# ── Plan Facts (canonical catalog mirror) ────────────────────────────────
PLANS: Dict[str, Dict] = {
    "free": {
        "display_name": "Free",
        "price_cents": 0,
        "price_yearly_cents": 0,
        "emails": 3_000,
        "api_calls": 30_000,
        "domains": 1,
        "team": 1,
        "retention_days": 7,
        "overage_millicents_per_email": None,
    },
    "starter": {
        "display_name": "Developer",
        "price_cents": 2_900,
        "price_yearly_cents": 29_000,
        "emails": 50_000,
        "api_calls": 500_000,
        "domains": 5,
        "team": 5,
        "retention_days": 30,
        "overage_millicents_per_email": 80,
    },
    "pro": {
        "display_name": "Pro",
        "price_cents": 8_900,
        "price_yearly_cents": 89_000,
        "emails": 150_000,
        "api_calls": 2_000_000,
        "domains": 25,
        "team": 10,
        "retention_days": 60,
        "overage_millicents_per_email": 60,
    },
    "growth": {
        "display_name": "Growth",
        "price_cents": 22_900,
        "price_yearly_cents": 229_000,
        "emails": 500_000,
        "api_calls": 5_000_000,
        "domains": 100,
        "team": 25,
        "retention_days": 90,
        "overage_millicents_per_email": 35,
    },
    "scale": {
        "display_name": "Business",
        "price_cents": 69_900,
        "price_yearly_cents": 699_000,
        "emails": 2_000_000,
        "api_calls": 20_000_000,
        "domains": -1,
        "team": 50,
        "retention_days": 365,
        "overage_millicents_per_email": 35,
    },
    "enterprise": {
        "display_name": "Enterprise Cloud",
        "price_cents": 175_000,
        "price_yearly_cents": 1_750_000,
        "emails": 5_000_000,
        "api_calls": -1,
        "domains": -1,
        "team": -1,
        "retention_days": 730,
        "overage_millicents_per_email": 35,
    },
    "payg": {
        "display_name": "Pay As You Go",
        "price_cents": 0,
        "price_yearly_cents": 0,
        "emails": -1,
        "api_calls": -1,
        "domains": 5,
        "team": 5,
        "retention_days": 30,
        "overage_millicents_per_email": None,
    },
}

# ── PAYG Tiers ───────────────────────────────────────────────────────────
# (upper_bound_inclusive_tier_start, per_email_rate_millicents)
# runtime source: platform-catalog/src/lib.rs PAYG_TIERS_EUR_PER_EMAIL
# (0.0010 / 0.0008 / 0.0005 / 0.0003 EUR per email).
PAYG_TIERS_MILLICENTS: Tuple[Tuple[int, int], ...] = (
    (10_000,    100),   # Tier 1: €1.00/1K
    (100_000,   80),    # Tier 2: €0.80/1K
    (1_000_000, 50),    # Tier 3: €0.50/1K
    (float("inf"), 30), # Tier 4: €0.30/1K (1M+)  # type: ignore[index]
)

# ── Add-on Pricing ───────────────────────────────────────────────────────
# Runtime dedicated-IP ladder: api-server/src/routes/explorer.rs computes
# `4_900 + (f.dedicated_ips - 1) * 6_900` (EUR 49 first / 69 each additional),
# parsed and pinned by the drift validator.
DEDICATED_IP_FIRST_CENTS = 4_900      # €49/month for the first dedicated IP
DEDICATED_IP_ADDITIONAL_CENTS = 6_900  # €69/month per additional dedicated IP

# ── Per-plan overage (cents per 1,000 emails) ────────────────────────────
# 1 millicent = 1/1000 cent, so 80 millicents/email = 0.08 cents/email =
# 80 cents per 1,000 emails (€0.80). The canonical field IS the cents-per-1K
# number. Plans absent here (free, payg) have no automatic overage.
OVERAGE_RATE_PER_1K_CENTS: Dict[str, int] = {
    plan_id: row["overage_millicents_per_email"]
    for plan_id, row in PLANS.items()
    if row["overage_millicents_per_email"] is not None
}

# ── Scale & Enterprise: unlimited mark for domains/team/contacts ─────────
UNLIMITED = -1


def plan_for(name: str) -> Optional[Dict]:
    """Plan row by billing id (`pro`) or display name (`Pro`/`Developer`)."""
    if name in PLANS:
        return PLANS[name]
    lowered = name.strip().lower()
    for plan_id, row in PLANS.items():
        if plan_id == lowered or row["display_name"].lower() == lowered:
            return row
    return None


def calculate_payg_millicents(emails: int) -> int:
    """Exact PAYG cost in millicents (integer, half-up per email tier)."""
    total = 0
    remaining = emails
    tier_start = 0

    for upper, rate in PAYG_TIERS_MILLICENTS:
        if remaining <= 0:
            break
        batch = min(remaining, int(upper) - tier_start)
        total += batch * rate
        remaining -= batch
        tier_start = int(upper)

    return total


def calculate_payg_cents(emails: int) -> int:
    """PAYG cost in whole cents, rounded half-up (matches the runtime)."""
    return (calculate_payg_millicents(emails) + 500) // 1000


def calculate_payg(emails: int) -> int:
    """PAYG cost in whole cents — kept for older callers.

    Returns cents (integer), not a float euro amount. Format for display
    with f"€{cents / 100:.2f}" at the edge.
    """
    return calculate_payg_cents(emails)
