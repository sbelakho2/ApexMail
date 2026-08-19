"""
Canonical pricing constants for ApexMail.

Single source of truth for all plan prices, PAYG tiers, and limits.
Import this instead of hardcoding values in fix/audit scripts.
"""

from typing import Dict, Tuple

# ── Plan Pricing (Monthly) ───────────────────────────────────────────────
PLANS: Dict[str, Dict] = {
    "Free":      {"price": 0,    "emails": 3_000,   "api_calls": 50_000,   "domains": 1,    "team": 1,   "contacts": 1_000,    "retention_days": 7},
    "Starter":   {"price": 25,   "emails": 50_000,  "api_calls": 500_000,  "domains": 5,    "team": 5,   "contacts": 10_000,   "retention_days": 30},
    "Pro":       {"price": 65,   "emails": 150_000, "api_calls": 2_000_000, "domains": 25,  "team": 10,  "contacts": 50_000,   "retention_days": 60},
    "Growth":    {"price": 150,  "emails": 500_000, "api_calls": 5_000_000, "domains": 100, "team": 25,  "contacts": 200_000,  "retention_days": 90},
    "Scale":     {"price": 350,  "emails": 2_000_000, "api_calls": 20_000_000, "domains": 0,  "team": 0,  "contacts": 0,        "retention_days": 365},  # unlimited domains/team
    "Enterprise":{"price": 3000, "emails": 5_000_000, "api_calls": 50_000_000, "domains": 0,  "team": 0,  "contacts": 0,        "retention_days": 730},
}

# ── PAYG Tiers ───────────────────────────────────────────────────────────
# (upper_bound, per_email_rate)
PAYG_TIERS: Tuple[Tuple[int, float], ...] = (
    (10_000,    0.001),    # Tier 1: €1.00/1K
    (100_000,   0.0008),   # Tier 2: €0.80/1K
    (1_000_000, 0.0005),   # Tier 3: €0.50/1K
    (float('inf'), 0.0003),# Tier 4: €0.30/1K (1M+)
)

# ── Add-on Pricing ───────────────────────────────────────────────────────
DEDICATED_IP_PRICE = 30  # per additional dedicated IP per month
OVERAGE_RATE_PER_1K = 0.40  # per 1,000 over-limit emails

# ── Scale & Enterprise: unlimited mark for domains/team/contacts ─────────
UNLIMITED = -1


def calculate_payg(emails: int) -> float:
    """Calculate exact PAYG cost for a given number of emails."""
    total = 0.0
    remaining = emails
    tier_start = 0

    for upper, rate in PAYG_TIERS:
        if remaining <= 0:
            break
        batch = min(remaining, upper - tier_start)
        total += batch * rate
        remaining -= batch
        tier_start = upper

    return round(total, 2)
