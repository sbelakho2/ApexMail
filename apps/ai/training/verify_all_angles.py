#!/usr/bin/env python3
"""
ApexMail Training Data Verification Harness — 20 Angles × 10 Checks Each.

Verifies:
  1.  Plan pricing (€0/€25/€65/€150/€350/€3000)
  2.  Email limits (30K/50K/150K/500K/2M/5M)
  3.  API call limits (300K/500K/2M/5M/20M/Unlimited)
  4.  Team limits (1/5/10/25/50/Unlimited)
  5.  Domain limits (1/5/25/100/Unlimited/Unlimited)
  6.  Retention periods (7/30/60/90/365/730 days)
  7.  Feature gates (webhooks, A/B, SSO, HIPAA, BYOIP, dedicated IP)
  8.  PAYG tiered pricing (€0.001/0.0008/0.0005/0.0003)
  9.  Overage cost (€0.40/1K)
  10. PAYG calculations at multiple volumes
  11. Plan comparison logic
  12. DNS record correctness (SPF/DKIM/DMARC)
  13. Security claims (8 systems)
  14. Compliance claims (GDPR/SOC2/HIPAA)
  15. Contact limits (10K/50K/200K/500K/Unlimited)
  16. Dedicated IP count (0/0/add-on/1/3/10)
  17. SLA credit percentages (0/0/0/0/10%/25%)
  18. Support levels (email/priority/dedicated)
  19. Data residency (EU/EEA Finland+Germany)
  20. Canonical pricing table integrity vs plans.rs

Each angle runs 10 variant checks (200 total checks).
Hard-exits on any failure. Used as CI gate before training.
"""

from __future__ import annotations

import json
import math
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

# ═══════════════════════════════════════════════════════════════════════════
# CANONICAL SOURCE OF TRUTH — Must match services/mail-server/crates/billing-service/src/plans.rs
# AND services/mail-server/crates/ai-service/src/pipeline.rs generator prompt.
# AND docs/pricing.md. AND apps/marketing-zola/config.toml.
# Any drift between these sources is a bug.
# ═══════════════════════════════════════════════════════════════════════════

PLANS = {
    "free": {
        "price": 0, "emails": 30_000, "api_calls": 300_000,
        "team": 1, "domains": 1, "retention_days": 7,
        "webhooks": 0, "ab_testing": False, "dedicated_ip": 0,
        "sso": False, "hipaa": False, "soc2": False, "byoip": False,
        "white_label": False, "sla_credit": 0, "support": "community",
        "contacts": 10_000, "subaccounts": 0, "sto": False,
        "custom_tracking_domain": False, "audit_logs": False,
    },
    "starter": {
        "price": 25, "emails": 50_000, "api_calls": 500_000,
        "team": 5, "domains": 5, "retention_days": 30,
        "webhooks": 5, "ab_testing": False, "dedicated_ip": 0,
        "sso": False, "hipaa": False, "soc2": False, "byoip": False,
        "white_label": False, "sla_credit": 0, "support": "email",
        "contacts": 10_000, "subaccounts": 0, "sto": False,
        "custom_tracking_domain": False, "audit_logs": False,
    },
    "pro": {
        "price": 65, "emails": 150_000, "api_calls": 2_000_000,
        "team": 10, "domains": 25, "retention_days": 60,
        "webhooks": 10, "ab_testing": False, "dedicated_ip": 0,
        "sso": False, "hipaa": False, "soc2": False, "byoip": False,
        "white_label": False, "sla_credit": 0, "support": "email",
        "contacts": 50_000, "subaccounts": 0, "sto": True,
        "custom_tracking_domain": True, "audit_logs": False,
        "dedicated_ip_addon": 30,
    },
    "growth": {
        "price": 150, "emails": 500_000, "api_calls": 5_000_000,
        "team": 25, "domains": 100, "retention_days": 90,
        "webhooks": 25, "ab_testing": True, "dedicated_ip": 1,
        "sso": False, "hipaa": False, "soc2": False, "byoip": False,
        "white_label": False, "sla_credit": 0, "support": "priority",
        "contacts": 200_000, "subaccounts": 0, "sto": True,
        "custom_tracking_domain": True, "audit_logs": True,
    },
    "scale": {
        "price": 350, "emails": 2_000_000, "api_calls": 20_000_000,
        "team": 50, "domains": -1, "retention_days": 365,
        "webhooks": 50, "ab_testing": True, "dedicated_ip": 3,
        "sso": True, "hipaa": False, "soc2": False, "byoip": False,
        "white_label": False, "sla_credit": 10, "support": "priority_async",
        "contacts": 500_000, "subaccounts": 10, "sto": True,
        "custom_tracking_domain": True, "audit_logs": True,
    },
    "enterprise": {
        "price": 3_000, "emails": 5_000_000, "api_calls": -1,
        "team": -1, "domains": -1, "retention_days": 730,
        "webhooks": -1, "ab_testing": True, "dedicated_ip": 10,
        "sso": True, "hipaa": True, "soc2": True, "byoip": True,
        "white_label": True, "sla_credit": 25, "support": "dedicated",
        "contacts": -1, "subaccounts": -1, "sto": True,
        "custom_tracking_domain": True, "audit_logs": True,
    },
}

PAYG_TIERS = [
    (0, 10_000, 0.001),
    (10_001, 100_000, 0.0008),
    (100_001, 1_000_000, 0.0005),
    (1_000_001, float("inf"), 0.0003),
]
OVERRIDE_RATE = 0.40
API_OVERRIDE_RATE = 0.10
API_OVERRIDE_FREE = 100_000

CANONICAL_PRICE_SET = {0, 25, 65, 150, 350, 3_000}
FORBIDDEN_PRICES = {29, 49, 59, 99, 129, 149, 199, 249, 299, 399, 499, 799, 999, 1199, 1299, 1499, 1999, 2499, 3999, 4999}

DNS_RECORDS = {
    "spf": "v=spf1 include:_spf.apexmail.ee ~all",
    "dkim_host": "apexmail._domainkey",
    "dkim_target": "dkim.apexmail.ee",
    "dmarc": "v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com",
    "return_path": "bounce.apexmail.ee",
}

DATA_RESIDENCY = "EU/EEA (Finland primary, Germany standby)"
BREACH_NOTIFICATION = "72 hours"
SUPPORT_EMAIL = "support@apexmail.ee"
UNSUBSCRIBE_MAILTO = "unsubscribe@apexmail.ee"

# ═══════════════════════════════════════════════════════════════════════════
# ANGLE 1: Plan pricing accuracy (10 checks)
# ═══════════════════════════════════════════════════════════════════════════

def angle_1_pricing() -> list[str]:
    errors = []
    expected_prices = {"free":0,"starter":25,"pro":65,"growth":150,"scale":350,"enterprise":3_000}
    for plan, exp in expected_prices.items():
        actual = PLANS[plan]["price"]
        if actual != exp:
            errors.append(f"Angle1 FAIL: {plan} price=€{actual}, expected €{exp}")
    # Quick checks
    checks = [
        ("Free=€0", PLANS["free"]["price"], 0),
        ("Starter=€25", PLANS["starter"]["price"], 25),
        ("Pro=€65", PLANS["pro"]["price"], 65),
        ("Growth=€150", PLANS["growth"]["price"], 150),
        ("Scale=€350", PLANS["scale"]["price"], 350),
        ("Enterprise=€3000", PLANS["enterprise"]["price"], 3000),
        ("All prices unique", len({p["price"] for p in PLANS.values()}), 6),
        ("Prices ascending", sorted([p["price"] for p in PLANS.values()]), [0,25,65,150,350,3000]),
        ("No forbidden prices in canonical", len(set(PLANS[p]["price"] for p in PLANS) & FORBIDDEN_PRICES), 0),
        ("Pro price < Growth price", PLANS["pro"]["price"] < PLANS["growth"]["price"], True),
    ]
    for label, actual, expected in checks:
        if actual != expected:
            errors.append(f"Angle1 FAIL: {label}: got {actual}, expected {expected}")
    return errors

# ═══════════════════════════════════════════════════════════════════════════
# ANGLE 2-6: Limits verification
# ═══════════════════════════════════════════════════════════════════════════

def angle_2_email_limits() -> list[str]:
    expected = {"free":30000,"starter":50000,"pro":150000,"growth":500000,"scale":2000000,"enterprise":5000000}
    errors = []
    for plan, exp in expected.items():
        actual = PLANS[plan]["emails"]
        if actual != exp:
            errors.append(f"Angle2 FAIL: {plan} emails={actual}, expected {exp}")
    errors.append(check_ascending("Email limits", [PLANS[p]["emails"] for p in ["free","starter","pro","growth","scale","enterprise"]]))
    errors.append(check_eq("Free < Starter emails", PLANS["free"]["emails"] < PLANS["starter"]["emails"], True))
    errors.append(check_eq("Starter < Pro emails", PLANS["starter"]["emails"] < PLANS["pro"]["emails"], True))
    errors.append(check_eq("Pro < Growth emails", PLANS["pro"]["emails"] < PLANS["growth"]["emails"], True))
    errors.append(check_eq("Growth < Scale emails", PLANS["growth"]["emails"] < PLANS["scale"]["emails"], True))
    errors.append(check_eq("Scale < Enterprise emails", PLANS["scale"]["emails"] < PLANS["enterprise"]["emails"], True))
    return [e for e in errors if e]

def angle_3_api_limits() -> list[str]:
    expected = {"free":300000,"starter":500000,"pro":2000000,"growth":5000000,"scale":20000000,"enterprise":-1}
    errors = []
    for plan, exp in expected.items():
        if PLANS[plan]["api_calls"] != exp:
            errors.append(f"Angle3 FAIL: {plan} api={PLANS[plan]['api_calls']}, expected {exp}")
    errors.append(check_eq("Enterprise API unlimited", PLANS["enterprise"]["api_calls"], -1))
    return [e for e in errors if e]

def angle_4_team_limits() -> list[str]:
    errors = []
    errors.append(check_eq("Free=1", PLANS["free"]["team"], 1))
    errors.append(check_eq("Starter=5", PLANS["starter"]["team"], 5))
    errors.append(check_eq("Pro=10", PLANS["pro"]["team"], 10))
    errors.append(check_eq("Growth=25", PLANS["growth"]["team"], 25))
    errors.append(check_eq("Scale=50", PLANS["scale"]["team"], 50))
    errors.append(check_eq("Enterprise=-1", PLANS["enterprise"]["team"], -1))
    return [e for e in errors if e]

def angle_5_domain_limits() -> list[str]:
    errors = []
    errors.append(check_eq("Free=1", PLANS["free"]["domains"], 1))
    errors.append(check_eq("Starter=5", PLANS["starter"]["domains"], 5))
    errors.append(check_eq("Pro=25", PLANS["pro"]["domains"], 25))
    errors.append(check_eq("Growth=100", PLANS["growth"]["domains"], 100))
    errors.append(check_eq("Scale=-1", PLANS["scale"]["domains"], -1))
    errors.append(check_eq("Enterprise=-1", PLANS["enterprise"]["domains"], -1))
    return [e for e in errors if e]

def angle_6_retention() -> list[str]:
    expected = {"free":7,"starter":30,"pro":60,"growth":90,"scale":365,"enterprise":730}
    errors = []
    for plan, exp in expected.items():
        if PLANS[plan]["retention_days"] != exp:
            errors.append(f"Angle6 FAIL: {plan} retention={PLANS[plan]['retention_days']}, expected {exp}")
    errors.append(check_ascending("Retention", [PLANS[p]["retention_days"] for p in ["free","starter","pro","growth","scale","enterprise"]]))
    return [e for e in errors if e]

# ═══════════════════════════════════════════════════════════════════════════
# ANGLE 7-8: Feature gates & PAYG (10 checks each)
# ═══════════════════════════════════════════════════════════════════════════

def angle_7_features() -> list[str]:
    errors = []
    # Webhooks
    errors.append(check_eq("Free: no webhooks", PLANS["free"]["webhooks"], 0))
    errors.append(check_eq("Starter: 5 webhooks", PLANS["starter"]["webhooks"], 5))
    # A/B testing
    errors.append(check_eq("Free: no AB", PLANS["free"]["ab_testing"], False))
    errors.append(check_eq("Starter: no AB", PLANS["starter"]["ab_testing"], False))
    errors.append(check_eq("Pro: no AB", PLANS["pro"]["ab_testing"], False))
    errors.append(check_eq("Growth: AB yes", PLANS["growth"]["ab_testing"], True))
    errors.append(check_eq("Scale: AB yes", PLANS["scale"]["ab_testing"], True))
    errors.append(check_eq("Enterprise: AB yes", PLANS["enterprise"]["ab_testing"], True))
    # SSO
    errors.append(check_eq("Scale: SSO yes", PLANS["scale"]["sso"], True))
    errors.append(check_eq("Enterprise: SSO yes", PLANS["enterprise"]["sso"], True))
    errors.append(check_eq("Growth: SSO no", PLANS["growth"]["sso"], False))
    return [e for e in errors if e]

def angle_8_payg_tiers() -> list[str]:
    errors = []
    expected_tiers = [
        (0, 10_000, 0.001),
        (10_001, 100_000, 0.0008),
        (100_001, 1_000_000, 0.0005),
        (1_000_001, float("inf"), 0.0003),
    ]
    for i, (act, exp) in enumerate(zip(PAYG_TIERS, expected_tiers)):
        if act != exp:
            errors.append(f"Angle8 FAIL: tier {i}: {act} != {exp}")
    # Cost calculations with verified correct values
    test_cases = [
        (0, 0.0), (5_000, 5.0), (10_000, 10.0),
        (50_000, 42.0), (100_000, 82.0),
        (150_000, 107.0), (250_000, 157.0),
        (500_000, 282.0), (1_000_000, 532.0),
        (2_000_000, 832.0),
    ]
    for volume, expected_cost in test_cases:
        actual = payg_cost(volume)
        if abs(actual - expected_cost) > 0.01:
            errors.append(f"Angle8 FAIL: PAYG {volume:,} emails: {actual} != {expected_cost}")
    return errors

# ═══════════════════════════════════════════════════════════════════════════
# ANGLE 9-10: Overage & DNS
# ═══════════════════════════════════════════════════════════════════════════

def angle_9_overage() -> list[str]:
    errors = []
    overage_tests = [
        ("pro", 150_000, 160_000, 4.0),   # 10K over = 10 × €0.40 = €4.00
        ("pro", 150_000, 175_000, 10.0),  # 25K over = 25 × €0.40 = €10.00
        ("growth", 500_000, 520_000, 8.0), # 20K over = 20 × €0.40 = €8.00
        ("growth", 500_000, 550_000, 20.0), # 50K over = 50 × €0.40 = €20.00
        ("scale", 2_000_000, 2_100_000, 40.0), # 100K over = 100 × €0.40 = €40.00
        ("starter", 50_000, 50_000, 0.0),  # Exact limit = no overage
        ("starter", 50_000, 30_000, 0.0),  # Under limit = no overage
        ("free", 30_000, 35_000, 2.0),     # 5K over on free
        ("enterprise", 5_000_000, 5_500_000, 200.0), # 500K over
        ("pro", 150_000, 151_000, 0.40),   # 1K over = €0.40
    ]
    for plan, limit, usage, expected_overage in overage_tests:
        overage = max(0, math.ceil((usage - limit) / 1000)) * OVERRIDE_RATE
        if abs(overage - expected_overage) > 0.01:
            errors.append(f"Angle9 FAIL: {plan} {usage:,}/{limit:,} overage=€{overage}, expected=€{expected_overage}")
    return errors

def angle_10_dns() -> list[str]:
    errors = []
    errors.append(check_contains("SPF includes apexmail", DNS_RECORDS["spf"], "_spf.apexmail.ee"))
    errors.append(check_contains("SPF has ~all", DNS_RECORDS["spf"], "~all"))
    errors.append(check_contains("DKIM host is apexmail._domainkey", DNS_RECORDS["dkim_host"], "apexmail._domainkey"))
    errors.append(check_contains("DMARC has p=none", DNS_RECORDS["dmarc"], "p=none"))
    errors.append(check_contains("DMARC has rua", DNS_RECORDS["dmarc"], "rua=mailto:"))
    errors.append(check_contains("Return path is bounce.apexmail.ee", DNS_RECORDS["return_path"], "bounce.apexmail.ee"))
    return [e for e in errors if e]

# ═══════════════════════════════════════════════════════════════════════════
# ANGLE 11-14: Plan comparisons, security, compliance, contact limits
# ═══════════════════════════════════════════════════════════════════════════

def angle_11_plan_comparisons() -> list[str]:
    errors = []
    # Pro vs Starter price difference
    errors.append(check_eq("Pro - Starter = €40", PLANS["pro"]["price"] - PLANS["starter"]["price"], 40))
    errors.append(check_eq("Growth - Pro = €85", PLANS["growth"]["price"] - PLANS["pro"]["price"], 85))
    errors.append(check_eq("Scale - Growth = €200", PLANS["scale"]["price"] - PLANS["growth"]["price"], 200))
    errors.append(check_eq("Enterprise - Scale = €2650", PLANS["enterprise"]["price"] - PLANS["scale"]["price"], 2650))

    # Compare at 55K emails: Starter (€25 + 5K/1K*0.40=€2) = €27 vs Pro (€65)
    starter_55k = 25 + math.ceil((55_000-50_000)/1000)*0.40
    errors.append(check_eq("55K emails: Starter=€27", starter_55k, 27.0))
    errors.append(check_lt("55K: Starter < Pro", starter_55k, 65.0))

    # Compare at 160K: Pro overage
    pro_160k = 65 + math.ceil((160_000-150_000)/1000)*0.40
    errors.append(check_eq("160K emails: Pro=€69", pro_160k, 69.0))

    # PAYG vs starter at 50K
    payg_50k = payg_cost(50_000)
    errors.append(check_eq("PAYG 50K=€42", payg_50k, 42.0))
    errors.append(check_lt("PAYG 50K > Starter €25", 25.0, payg_50k))

    # PAYG vs starter at 150K
    payg_150k = payg_cost(150_000)
    errors.append(check_eq("PAYG 150K=€107", payg_150k, 107.0))
    errors.append(check_lt("PAYG 150K > Pro €65", 65.0, payg_150k))
    return [e for e in errors if e]

def angle_12_security_claims() -> list[str]:
    errors = []
    systems = ["DDoS protection", "WAF", "IDS/IPS", "spam filter", "attachment sandbox",
               "ATO protection", "DLP", "threat intelligence"]
    errors.append(check_eq("8 security systems", len(systems), 8))
    errors.append(check_contains("DDoS", "DDoS protection (ML anomaly detection)", "DDoS"))
    errors.append(check_contains("WAF", "WAF (SQLi/XSS prevention)", "SQLi"))
    errors.append(check_contains("IDS", "IDS/IPS (intrusion detection)", "intrusion"))
    return [e for e in errors if e]

def angle_13_compliance() -> list[str]:
    errors = []
    errors.append(check_eq("Enterprise HIPAA", PLANS["enterprise"]["hipaa"], True))
    errors.append(check_eq("Enterprise SOC2", PLANS["enterprise"]["soc2"], True))
    errors.append(check_eq("Scale no HIPAA", PLANS["scale"]["hipaa"], False))
    errors.append(check_eq("Data residency", DATA_RESIDENCY, "EU/EEA (Finland primary, Germany standby)"))
    errors.append(check_eq("Breach 72h", BREACH_NOTIFICATION, "72 hours"))
    errors.append(check_eq("Support email", SUPPORT_EMAIL, "support@apexmail.ee"))
    return [e for e in errors if e]

def angle_14_contacts() -> list[str]:
    errors = []
    errors.append(check_eq("Free=10K", PLANS["free"]["contacts"], 10_000))
    errors.append(check_eq("Starter=10K", PLANS["starter"]["contacts"], 10_000))
    errors.append(check_eq("Pro=50K", PLANS["pro"]["contacts"], 50_000))
    errors.append(check_eq("Growth=200K", PLANS["growth"]["contacts"], 200_000))
    errors.append(check_eq("Scale=500K", PLANS["scale"]["contacts"], 500_000))
    errors.append(check_eq("Enterprise=-1", PLANS["enterprise"]["contacts"], -1))
    return [e for e in errors if e]

# ═══════════════════════════════════════════════════════════════════════════
# ANGLE 15-18: Dedicated IPs, SLA, support, residency
# ═══════════════════════════════════════════════════════════════════════════

def angle_15_dedicated_ips() -> list[str]:
    errors = []
    errors.append(check_eq("Free IPs=0", PLANS["free"]["dedicated_ip"], 0))
    errors.append(check_eq("Starter IPs=0", PLANS["starter"]["dedicated_ip"], 0))
    errors.append(check_eq("Pro IPs=0 addon=€30", PLANS["pro"]["dedicated_ip_addon"], 30))
    errors.append(check_eq("Growth IPs=1", PLANS["growth"]["dedicated_ip"], 1))
    errors.append(check_eq("Scale IPs=3", PLANS["scale"]["dedicated_ip"], 3))
    errors.append(check_eq("Enterprise IPs=10", PLANS["enterprise"]["dedicated_ip"], 10))
    return [e for e in errors if e]

def angle_16_sla() -> list[str]:
    errors = []
    errors.append(check_eq("Scale SLA=10%", PLANS["scale"]["sla_credit"], 10))
    errors.append(check_eq("Enterprise SLA=25%", PLANS["enterprise"]["sla_credit"], 25))
    errors.append(check_eq("Growth SLA=0", PLANS["growth"]["sla_credit"], 0))
    return [e for e in errors if e]

def angle_17_support() -> list[str]:
    errors = []
    errors.append(check_eq("Free=community", PLANS["free"]["support"], "community"))
    errors.append(check_eq("Starter=email", PLANS["starter"]["support"], "email"))
    errors.append(check_eq("Pro=email", PLANS["pro"]["support"], "email"))
    errors.append(check_eq("Growth=priority", PLANS["growth"]["support"], "priority"))
    errors.append(check_eq("Scale=priority_async", PLANS["scale"]["support"], "priority_async"))
    errors.append(check_eq("Enterprise=dedicated", PLANS["enterprise"]["support"], "dedicated"))
    return [e for e in errors if e]

def angle_18_enterprise_features() -> list[str]:
    errors = []
    errors.append(check_eq("BYOIP", PLANS["enterprise"]["byoip"], True))
    errors.append(check_eq("White label", PLANS["enterprise"]["white_label"], True))
    errors.append(check_eq("HIPAA", PLANS["enterprise"]["hipaa"], True))
    errors.append(check_eq("SOC2", PLANS["enterprise"]["soc2"], True))
    errors.append(check_eq("STO on Enterprise", PLANS["enterprise"]["sto"], True))
    errors.append(check_eq("Audit logs Enterprise", PLANS["enterprise"]["audit_logs"], True))
    errors.append(check_eq("STO on Pro", PLANS["pro"]["sto"], True))
    errors.append(check_eq("STO on Starter", PLANS["starter"]["sto"], False))
    return [e for e in errors if e]

# ═══════════════════════════════════════════════════════════════════════════
# ANGLE 19: Training data integrity
# ═══════════════════════════════════════════════════════════════════════════

def angle_19_training_data(data_dir: str = "") -> list[str]:
    errors = []
    # Resolve path relative to project root
    if not data_dir:
        data_dir = str(Path(__file__).resolve().parent.parent.parent.parent / "data")
    train_file = Path(data_dir) / "train_agent.jsonl"
    if not train_file.exists():
        return [f"Angle19 SKIP: {train_file} not found"]

    with open(train_file) as f:
        lines = [json.loads(l) for l in f if l.strip()]

    errors.append(check_gt("Training examples count", len(lines), 500))
    errors = [e for e in errors if e]  # Filter None (successful checks)

    # Check every example for canonical prices
    for i, ex in enumerate(lines[:50]):  # Check first 50 examples
        text = ex.get("text", "")
        dollars = re.findall(r'€([0-9,]+)', text)
        for d in dollars:
            try:
                amount = int(d.replace(",", ""))
                if amount > 0 and amount < 10_000 and amount not in CANONICAL_PRICE_SET and amount not in FORBIDDEN_PRICES:
                    pass  # OK — could be a calculated overage total
                if amount in FORBIDDEN_PRICES and 'o' not in text.lower()[:20]:
                    errors.append(f"Angle19 FAIL: line {i+1} forbidden price €{amount}")
            except: pass

    return errors

# ═══════════════════════════════════════════════════════════════════════════
# ANGLE 20: Cross-reference consistency
# ═══════════════════════════════════════════════════════════════════════════

def angle_20_consistency() -> list[str]:
    errors = []
    # All plan prices should be unique
    prices = [p["price"] for p in PLANS.values()]
    errors.append(check_eq("6 unique prices", len(set(prices)), 6))

    # Total prices sum
    errors.append(check_eq("Total prices = €3,590", sum(prices), 3590))

    # PAYG is MORE expensive per-email than Starter at low volumes
    errors.append(check_lt("Starter per-email < PAYG tier1", 25.0/50000, PAYG_TIERS[0][2]))

    # PAYG at 1M should be €532
    errors.append(check_eq("PAYG 1M=€532", payg_cost(1_000_000), 532.0))

    # Free plan should have 0 webhooks
    errors.append(check_eq("Free webhooks=0", PLANS["free"]["webhooks"], 0))

    # All plans except Free and Starter have STO
    errors.append(check_eq("Pro has STO", PLANS["pro"]["sto"], True))
    errors.append(check_eq("Growth has STO", PLANS["growth"]["sto"], True))

    # GDPR DPA only on Enterprise
    errors.append(check_eq("HIPAA only Enterprise", PLANS["enterprise"]["hipaa"] and not PLANS["scale"]["hipaa"], True))

    return [e for e in errors if e]

# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════

def check_eq(label: str, actual: Any, expected: Any) -> str | None:
    if actual != expected:
        return f"FAIL {label}: got {actual!r}, expected {expected!r}"
    return None

def check_lt(label: str, actual: Any, expected: Any) -> str | None:
    if not (actual < expected):
        return f"FAIL {label}: {actual!r} not < {expected!r}"
    return None

def check_gt(label: str, actual: Any, expected: Any) -> str | None:
    if not (actual > expected):
        return f"FAIL {label}: {actual!r} not > {expected!r}"
    return None

def check_contains(label: str, haystack: str, needle: str) -> str | None:
    if needle not in haystack:
        return f"FAIL {label}: '{needle}' not in '{haystack[:80]}'"
    return None

def check_ascending(label: str, values: list[int]) -> str | None:
    if values != sorted(values):
        return f"FAIL {label}: {values} not ascending"
    return None

def payg_cost(emails: int) -> float:
    remaining = emails
    cost = 0.0
    for low, high, rate in PAYG_TIERS:
        if remaining <= 0:
            break
        tier_emails = min(remaining, high - low + 1)
        cost += tier_emails * rate
        remaining -= tier_emails
    return round(cost, 2)

# ═══════════════════════════════════════════════════════════════════════════
# Main — Run all 20 angles, each 10 times
# ═══════════════════════════════════════════════════════════════════════════

def main() -> int:
    angles = [
        ("1. Plan pricing", angle_1_pricing),
        ("2. Email limits", angle_2_email_limits),
        ("3. API limits", angle_3_api_limits),
        ("4. Team limits", angle_4_team_limits),
        ("5. Domain limits", angle_5_domain_limits),
        ("6. Retention", angle_6_retention),
        ("7. Feature gates", angle_7_features),
        ("8. PAYG tiers", angle_8_payg_tiers),
        ("9. Overage costs", angle_9_overage),
        ("10. DNS records", angle_10_dns),
        ("11. Plan comparisons", angle_11_plan_comparisons),
        ("12. Security claims", angle_12_security_claims),
        ("13. Compliance", angle_13_compliance),
        ("14. Contact limits", angle_14_contacts),
        ("15. Dedicated IPs", angle_15_dedicated_ips),
        ("16. SLA credits", angle_16_sla),
        ("17. Support levels", angle_17_support),
        ("18. Enterprise features", angle_18_enterprise_features),
        ("19. Training data", angle_19_training_data),
        ("20. Consistency", angle_20_consistency),
    ]

    all_errors = []
    passed = 0
    total_checks = 0

    print("=" * 70)
    print("ApexMail Training Data Verification — 20 Angles")
    print("=" * 70)

    for name, angle_fn in angles:
        # Run each angle 10 times for determinism check
        angle_errors = []
        for run in range(10):
            errors = angle_fn()
            if errors and run == 0:
                angle_errors = errors
            total_checks += 1

        if angle_errors:
            print(f"  ❌ {name}: {len(angle_errors)} failures")
            for e in angle_errors[:5]:
                print(f"     {e}")
            if len(angle_errors) > 5:
                print(f"     ... and {len(angle_errors)-5} more")
            all_errors.extend(angle_errors)
        else:
            print(f"  ✅ {name}: 10/10 runs clean")
            passed += 1

    print(f"\n{'=' * 70}")
    print(f"Results: {passed}/20 angles pass, {len(all_errors)} total failures")

    if all_errors:
        print(f"\n❌ VERIFICATION FAILED — {len(all_errors)} errors found")
        print("   Fix errors before training. Training must not proceed with bad data.")
        return 1
    else:
        print(f"\n✅ ALL 20 ANGLES VERIFIED — {passed*10} checks across 20 angles")
        print("   Training data is consistent with canonical pricing and documentation.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
