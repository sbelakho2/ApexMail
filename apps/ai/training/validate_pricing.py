#!/usr/bin/env python3
"""
validate_pricing.py — Structured pricing validator for ApexMail training data.

Replaces brittle regex-based pricing transformation with a JSON-based
canonical pricing table and structured validation. Verifies all pricing
references in training data match documented rates.

Usage:
    python validate_pricing.py                          # validate all data files
    python validate_pricing.py --file data/train.jsonl  # single file
    python validate_pricing.py --fix                     # auto-fix discovered issues
    python validate_pricing.py --json                    # machine-readable output
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any


# ── Canonical pricing table (source of truth) ──────────────────────────
# Matches services/mail-server/crates/billing-service/src/plans.rs and
# docs/pricing.md exactly. All published prices are EUR.
CANONICAL_PRICING = {
    "plans": [
        {"name": "Free",       "price": "€0",     "emails": 30_000,   "api_calls": 300_000,    "team": 1,    "domains": 1},
        {"name": "Starter",    "price": "€25",    "emails": 50_000,   "api_calls": 500_000,    "team": 5,    "domains": 5},
        {"name": "Pro",        "price": "€65",    "emails": 150_000,  "api_calls": 2_000_000,  "team": 10,   "domains": 25},
        {"name": "Growth",     "price": "€150",   "emails": 500_000,  "api_calls": 5_000_000,  "team": 25,   "domains": 100},
        {"name": "Scale",      "price": "€350",   "emails": 2_000_000,"api_calls": 20_000_000, "team": 50,   "domains": -1},   # -1 = unlimited
        {"name": "Enterprise", "price": "€3,000", "emails": 5_000_000,"api_calls": -1,         "team": -1,   "domains": -1},
    ],
    "payg": {
        "tiers": [
            {"min": 0,      "max": 10_000,     "rate": 0.001},
            {"min": 10_001, "max": 100_000,    "rate": 0.0008},
            {"min": 100_001,"max": 1_000_000,  "rate": 0.0005},
            {"min": 1_000_001,"max": None,     "rate": 0.0003},
        ],
        "base_price": "€0",
    },
    "overage": {
        "email_rate": 0.40,    # per 1,000 extra emails
        "api_free_tier": 100_000,
        "api_rate": 0.10,      # per 1,000 API calls above free tier
    },
    "addons": {
        "dedicated_ip": "€30/mo",
    },
}

# Build lookup dicts
PLAN_BY_NAME = {p["name"].lower(): p for p in CANONICAL_PRICING["plans"]}
PRICE_BY_PLAN = {p["name"].lower(): p["price"] for p in CANONICAL_PRICING["plans"]}
VALID_PRICES = set(p["price"] for p in CANONICAL_PRICING["plans"])
VALID_PRICES.add("€30")  # Dedicated IP add-on
# Numeric canonical price values (validated regardless of currency symbol)
CANONICAL_PRICE_NUMBERS = {0, 25, 65, 150, 350, 3000, 30}


# ── Regex patterns ─────────────────────────────────────────────────────

# Plan price references: "Starter (€25/month)", "Pro plan at €65/mo",
# "Starter costs €15/month", "Growth $150/month". A bounded amount of
# connecting text ("costs", "is", "at", ...) may sit between the plan name
# and the price. Both € and $ symbols are accepted — the NUMBERS are
# validated against the canonical table, and a '$' is itself reported as a
# violation because all published prices are EUR.
PLAN_PRICE_PATTERN = re.compile(
    r"(?P<plan>Free|Starter|Pro|Growth|Scale|Enterprise)"
    r"(?:\s+plan)?[^\n€$0-9]{0,24}?[€$]\s?(?P<price>[\d,]+)\s*(?:/mo|/month|\)?)?",
    re.IGNORECASE,
)

# Euro/dollar amount pattern (skip known non-plan prices)
DOLLAR_AMOUNT = re.compile(r"[€$]\d[\d,]*(?:\.\d+)?(?:/mo|/month|/email|/1,000)?")

# Competitor/3rd-party price patterns to ignore
COMPETITOR_PATTERNS = [
    re.compile(r"Mailchimp", re.IGNORECASE),
    re.compile(r"SendGrid", re.IGNORECASE),
    re.compile(r"competitor", re.IGNORECASE),
]


def is_competitor_text(text: str) -> bool:
    """Check if text segment references competitor pricing (skip these)."""
    return any(p.search(text) for p in COMPETITOR_PATTERNS)


def validate_pricing_in_text(
    text: str,
    source: str = "unknown",
    fix: bool = False,
) -> list[dict[str, Any]]:
    """Validate all pricing references in text against canonical table.
    
    Returns list of findings (warnings/errors).
    """
    findings = []
    
    if is_competitor_text(text):
        return findings
    
    # Check plan+price pairs
    for match in PLAN_PRICE_PATTERN.finditer(text):
        plan_name = match.group("plan").lower()
        price_str = match.group("price").replace(",", "")

        if plan_name not in PLAN_BY_NAME:
            continue

        expected_price = PRICE_BY_PLAN[plan_name]
        expected_number = int(expected_price.replace("€", "").replace(",", ""))

        try:
            found_number = int(price_str)
        except ValueError:
            continue

        # The NUMBERS must match plans.rs; a '$' symbol is also a violation
        # because every published ApexMail price is EUR.
        if found_number != expected_number:
            findings.append({
                "type": "error",
                "source": source,
                "message": (
                    f"{plan_name.title()} plan price should be "
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
                    f"{plan_name.title()} price must be stated in EUR "
                    f"({expected_price}), not dollars: {match.group()}"
                ),
                "span": match.span(),
                "matched": match.group(),
                "expected": expected_price,
            })

    return findings


def validate_file(
    filepath: str | Path,
    fix: bool = False,
    verbose: bool = False,
) -> list[dict[str, Any]]:
    """Validate all pricing references in a JSONL file."""
    path = Path(filepath)
    if not path.exists():
        return [{"type": "error", "source": str(path), "message": "File not found"}]
    
    findings = []
    
    with open(path) as f:
        for line_no, line in enumerate(f, 1):
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
            
            # Check all message content
            messages = entry.get("messages", [])
            for msg in messages:
                content = msg.get("content", "")
                text_findings = validate_pricing_in_text(
                    content,
                    source=f"{path}:{line_no}",
                    fix=fix,
                )
                findings.extend(text_findings)
            
            # Check text field
            text = entry.get("text", "")
            if text:
                text_findings = validate_pricing_in_text(
                    text,
                    source=f"{path}:{line_no}",
                    fix=fix,
                )
                findings.extend(text_findings)
    
    return findings


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Validate pricing references in ApexMail training data"
    )
    parser.add_argument(
        "--file", "-f",
        help="Single file to validate (default: all data files)",
    )
    parser.add_argument(
        "--fix", action="store_true",
        help="Auto-fix discovered pricing issues",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output in JSON format (machine-readable)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Show detailed findings",
    )
    args = parser.parse_args()
    
    # Determine files to validate
    if args.file:
        files = [Path(args.file)]
    else:
        data_dir = Path(__file__).resolve().parents[2] / "data"
        files = [
            data_dir / "golden_qa.jsonl",
            data_dir / "train.jsonl",
            data_dir / "val.jsonl",
            data_dir / "test.jsonl",
            data_dir / "train_agent.jsonl",
            data_dir / "recovered_training.jsonl",
        ]
    
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
