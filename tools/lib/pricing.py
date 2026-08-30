"""
Canonical pricing constants for ApexMail.

Mirrors the Rust runtime catalog (billing-service/src/plans.rs plan seeds).
The runtime seeds are the source of truth; if the two disagree the drift
validator (tools/validate_pricing_drift.py) fails. Import this instead of
hardcoding values in fix/audit scripts.

All monetary values are EUR. Money math uses integer cents / millicents —
never floats.
"""

from typing import Dict, Tuple

# ── Plan Pricing (Monthly, EUR cents) ────────────────────────────────────
# Limits: emails/month, API calls/month. -1 means unlimited.
# runtime source: crates/billing-service/src/plans.rs (plan seeds)
PLANS: Dict[str, Dict] = {
    "Free":       {"price_cents": 0,      "emails": 30_000,    "api_calls": 300_000,   "domains": 1,  "team": 1,   "retention_days": 7},
    "Starter":    {"price_cents": 2_500,  "emails": 50_000,    "api_calls": 500_000,   "domains": 5,  "team": 5,   "retention_days": 30},
    "Pro":        {"price_cents": 6_500,  "emails": 150_000,   "api_calls": 2_000_000, "domains": 25, "team": 10,  "retention_days": 60},
    "Growth":     {"price_cents": 15_000, "emails": 500_000,   "api_calls": 5_000_000, "domains": 100, "team": 25, "retention_days": 90},
    "Scale":      {"price_cents": 35_000, "emails": 2_000_000, "api_calls": 20_000_000, "domains": -1, "team": 50, "retention_days": 365},
    "Enterprise": {"price_cents": 300_000, "emails": 5_000_000, "api_calls": -1,       "domains": -1, "team": -1, "retention_days": 730},
}

# ── PAYG Tiers ───────────────────────────────────────────────────────────
# (upper_bound_inclusive_tier_start, per_email_rate_millicents)
# runtime source: PaygPricing::default() (billing-service/src/config.rs)
PAYG_TIERS_MILLICENTS: Tuple[Tuple[int, int], ...] = (
    (10_000,    100),   # Tier 1: €1.00/1K
    (100_000,   80),    # Tier 2: €0.80/1K
    (1_000_000, 50),    # Tier 3: €0.50/1K
    (float("inf"), 30), # Tier 4: €0.30/1K (1M+)  # type: ignore[index]
)

# ── Add-on Pricing ───────────────────────────────────────────────────────
DEDICATED_IP_PRICE_CENTS = 3_000  # €30 per dedicated IP per month
OVERAGE_RATE_PER_1K_CENTS = 40    # €0.40 per 1,000 over-limit emails
FREE_API_CALLS_PER_MONTH = 100_000
PRICE_PER_1K_API_CALLS_CENTS = 10  # €0.10 / 1,000 API calls

# ── Scale & Enterprise: unlimited mark for domains/team/contacts ─────────
UNLIMITED = -1


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
