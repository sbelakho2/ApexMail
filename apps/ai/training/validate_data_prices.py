#!/usr/bin/env python3
"""
validate_data_prices.py — Adversarial price/currency/volume validator for the
committed training corpus (data/*.jsonl + data/system_prompts.json).

Asserts, per the canonical catalog in
services/mail-server/crates/billing-service/src/plans.rs (docs/pricing.md):

  1. Every plan-adjacent price token matches the canonical table
     (Free €0, Starter €25, Pro €65, Growth €150, Scale €350,
     Enterprise €3,000; dedicated-IP add-on €30).
  2. Every quoted per-email PAYG rate is one of €0.001/€0.0008/€0.0005/€0.0003
     and every per-1,000 rate is one of €0.40 (overage) / €0.50 / €0.80 /
     €1.00 / €0.30 / €0.10 (API).
  3. No '$'-denominated prices remain anywhere in the corpus.
  4. No negative volumes in tier/breakdown rows.
  5. No double-encoded UTF-8 (mojibake) sequences.

Exit code 0 = clean, 1 = violations found.
Usage: python3 validate_data_prices.py [--file PATH]...
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parents[3] / "data"

CANONICAL_PLAN_PRICES = {0: "free", 25: "starter", 65: "pro", 150: "growth",
                         350: "scale", 3000: "enterprise"}
ADDON_PRICES = {30}  # dedicated IP / month
CANONICAL_PER_EMAIL_RATES = {"0.001", "0.0008", "0.0005", "0.0003"}
CANONICAL_PER_1K_RATES = {"0.40", "0.50", "0.80", "1.00", "0.30", "0.10"}
# plans.rs email limits per plan (-1 = unlimited).
CANONICAL_EMAIL_LIMITS = {
    "free": 30_000, "starter": 50_000, "pro": 150_000, "growth": 500_000,
    "scale": 2_000_000, "enterprise": 5_000_000,
}
# The old fictional Free limit (3,000) still surfaces in recovered corpus
# rows; it is the single most common wrong-limit hallucination.
FREE_PLAN_WRONG_LIMIT_RE = re.compile(
    r"\bFree\b[^\n€$0-9]{0,60}?\b3,000\b[^\n]{0,20}?(?:emails|email\b)?",
    re.IGNORECASE,
)

# A plan-adjacent price. Word boundaries keep "Pro" from matching inside
# "Approximately". The bounded connector may not contain digits or arithmetic.
PLAN_PRICE_RE = re.compile(
    r"\b(?P<plan>Free|Starter|Pro|Growth|Scale|Enterprise)\b"
    r"(?:\s+plan)?(?P<connector>[^\n€$0-9]{0,24}?)[€$]\s?"
    r"(?P<price>\d[\d,]*(?:\.\d{1,4})?)\s*(?P<suffix>/mo|/month|\)?)?",
    re.IGNORECASE,
)
# Contexts in which a plan-adjacent amount is NOT a plan-price quote:
# savings/overage/difference phrasing, table headers crossing columns, or
# approximate computed costs.
CONNECTOR_SKIP_WORDS = ("save", "overage", "total", "current", "credit", "proration", "~", "≈")
AFTER_SKIP_WORDS = ("more", "less", "per 1,000", "/1k", "per 1k", "per thousand")
PLAN_WORDS = ("free", "starter", "pro", "growth", "scale", "enterprise")
PER_EMAIL_RATE_RE = re.compile(r"[€$](\d+\.\d{1,4})\s*(?:/email|per email|each)", re.IGNORECASE)
PER_1K_RATE_RE = re.compile(r"[€$](\d+\.\d{1,2})\s*(?:/1K|/1k\b|per 1,000|/1,000)", re.IGNORECASE)
DOLLAR_PRICE_RE = re.compile(r"\$\s?\d")
NEGATIVE_VOLUME_RE = re.compile(r"[|\s]\s?-\d{1,3}(?:,\d{3})+")
# Double-encoded UTF-8 tells: "Ã¢" (â re-encoded), cp1252-mangled euro/arrow
# fragments, and stray C1 control bytes from multi-byte sequences.
MOJIBAKE_RE = re.compile("Ã¢|Ã‚|â\x82¬|â\x86|â¬|€\x86")


def iter_strings(node):
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for value in node.values():
            yield from iter_strings(value)
    elif isinstance(node, list):
        for value in node:
            yield from iter_strings(value)


def check_text(text: str, source: str) -> list[str]:
    problems = []

    for m in PLAN_PRICE_RE.finditer(text):
        plan = m.group("plan").lower()
        connector = (m.group("connector") or "").lower()
        after = text[m.end():m.end() + 14].lower()
        raw = m.group("price").replace(",", "")
        try:
            value = float(raw)
        except ValueError:
            continue
        expected = next((p for p, name in CANONICAL_PLAN_PRICES.items() if name == plan), None)
        if expected is None:
            continue

        # Not a plan-price quote: per-unit rates, computed cents-precision
        # amounts, savings/overage/difference phrasing, or a connector that
        # crosses another plan name (table columns).
        if value < 1 or value != int(value):
            continue
        if any(word in connector for word in CONNECTOR_SKIP_WORDS):
            continue
        if any(word in connector for word in PLAN_WORDS):
            continue
        if any(word in after for word in AFTER_SKIP_WORDS):
            continue

        # A plan-adjacent €N is either the plan's own price, or (Pro/Growth+)
        # the €30 dedicated-IP add-on. Anything else is a wrong price.
        if "$" in m.group():
            problems.append(f"{source}: dollar price for {plan}: {m.group()!r}")
        elif int(value) != expected and not (int(value) in ADDON_PRICES and "ip" in text.lower()):
            problems.append(
                f"{source}: {plan} quoted at {m.group().strip()!r} but plans.rs says €{expected:,}"
            )

    for m in PER_EMAIL_RATE_RE.finditer(text):
        rate = m.group(1)
        if rate not in CANONICAL_PER_EMAIL_RATES:
            problems.append(f"{source}: non-canonical per-email rate €{rate}")

    for m in PER_1K_RATE_RE.finditer(text):
        rate = m.group(1)
        if rate not in CANONICAL_PER_1K_RATES:
            problems.append(f"{source}: non-canonical per-1,000 rate €{rate}")

    if DOLLAR_PRICE_RE.search(text):
        for m in DOLLAR_PRICE_RE.finditer(text):
            problems.append(f"{source}: '$' price remains: {m.group()!r}")

    if NEGATIVE_VOLUME_RE.search(text):
        for m in NEGATIVE_VOLUME_RE.finditer(text):
            problems.append(f"{source}: negative volume {m.group().strip()!r}")

    if MOJIBAKE_RE.search(text):
        problems.append(f"{source}: double-encoded UTF-8 (mojibake) sequence")

    for m in FREE_PLAN_WRONG_LIMIT_RE.finditer(text):
        problems.append(
            f"{source}: Free plan limit quoted as 3,000; plans.rs grants 30,000 ({m.group().strip()!r})"
        )

    return problems


def validate_file(path: Path) -> list[str]:
    problems: list[str] = []
    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return [f"{path}: unreadable ({exc})"]

    if path.suffix == ".jsonl":
        for line_no, line in enumerate(content.splitlines(), 1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                problems.append(f"{path}:{line_no}: invalid JSON ({exc})")
                continue
            for text in iter_strings(entry):
                problems.extend(check_text(text, f"{path.name}:{line_no}"))
    else:
        try:
            entry = json.loads(content)
        except json.JSONDecodeError as exc:
            return [f"{path}: invalid JSON ({exc})"]
        for text in iter_strings(entry):
            problems.extend(check_text(text, path.name))
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", action="append", help="Specific file to validate (repeatable)")
    args = parser.parse_args()

    if args.file:
        paths = [Path(f) for f in args.file]
    else:
        paths = sorted(DATA_DIR.glob("*.jsonl")) + [DATA_DIR / "system_prompts.json"]

    all_problems: list[str] = []
    checked = 0
    for path in paths:
        if not path.exists():
            all_problems.append(f"{path}: missing")
            continue
        checked += 1
        all_problems.extend(validate_file(path))

    print(f"Validated {checked} corpus files against the canonical EUR price book.")
    if all_problems:
        print(f"FAILED: {len(all_problems)} violation(s)")
        for problem in all_problems[:40]:
            print(f"  - {problem}")
        if len(all_problems) > 40:
            print(f"  ... and {len(all_problems) - 40} more")
        return 1
    print("PASS: plan prices, PAYG/overage rates, currency symbols, volumes, and "
          "encoding all match plans.rs.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
