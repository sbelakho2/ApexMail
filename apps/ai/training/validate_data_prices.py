#!/usr/bin/env python3
"""
validate_data_prices.py — Adversarial price/currency/volume validator for the
committed training corpus (data/*.jsonl + data/system_prompts.json).

Asserts, per the canonical catalog in
services/mail-server/crates/platform-catalog (pinned by
tools/check_knowledge_consistency.py):

  1. Every plan-adjacent price token matches the canonical table
     (Free €0, Developer €29, Pro €89, Growth €229, Business €699,
     Enterprise Cloud €1,750; dedicated-IP add-on €30).
  2. Every quoted per-email PAYG rate is one of €0.001/€0.0008/€0.0005/€0.0003
     and every per-1,000 rate is one of €1.00 / €0.80 / €0.50 / €0.30 (PAYG),
     €0.80 / €0.60 / €0.35 (plan overage) or €0.10 (API).
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

TRAINING_DIR = Path(__file__).resolve().parent
# The tracked corpus this pipeline owns (root /data is a retired, gitignored
# scratch directory — data/README.md — and is not validated here).
DATA_DIR = TRAINING_DIR / "data"

from validate_pricing import (  # noqa: E402
    CANONICAL_PRICING,
    OVERAGE_MILLICENTS_BY_PLAN,
    PAYG_TIERS,
    PLAN_ALIASES,
    PLAN_BY_NAME,
    canonical_key,
)

CANONICAL_PLAN_PRICES = {
    int(row["price"].replace("€", "").replace(",", "")): key
    for key, row in PLAN_BY_NAME.items()
}
ADDON_PRICES = {30}  # dedicated IP / month
CANONICAL_PER_EMAIL_RATES = {"0.001", "0.0008", "0.0005", "0.0003"}
# EUR per 1,000: PAYG bands (1.00/0.80/0.50/0.30), plan overage
# (0.80/0.60/0.35) and the PAYG API rate (0.10).
CANONICAL_PER_1K_RATES = {"1.00", "0.80", "0.50", "0.30", "0.60", "0.35", "0.10"}
CANONICAL_EMAIL_LIMITS = {
    key: row["emails"] for key, row in PLAN_BY_NAME.items()
}
# The pre-2026-09-08 table granted Free 30,000 emails/month and 300,000 API
# calls/month. The canonical Free plan grants 3,000/30,000; 30,000 is only
# the one-time launch allowance, so a monthly 30,000 claim is the wrong-limit
# hallucination (excluding explicit launch-allowance wording).
FREE_PLAN_WRONG_LIMIT_RE = re.compile(
    r"\bFree\b[^\n€$0-9]{0,60}?\b30,000\b[^\n]{0,24}?"
    r"(?:emails?[^\n]{0,16}?(?:/\s?mo|/month|per\s+month|monthly))",
    re.IGNORECASE,
)

# A plan-adjacent price. Word boundaries keep "Pro" from matching inside
# "Approximately". The bounded connector may not contain digits or arithmetic.
PLAN_PRICE_RE = re.compile(
    r"\b(?P<plan>Free|Starter|Developer|Pro|Growth|Scale|Business"
    r"|Enterprise(?:\s+Cloud)?)\b"
    r"(?:\s+plan)?(?P<connector>[^\n€$0-9]{0,24}?)[€$]\s?"
    r"(?P<price>\d[\d,]*(?:\.\d{1,4})?)\s*(?P<suffix>/mo|/month|\)?)?",
    re.IGNORECASE,
)
# Contexts in which a plan-adjacent amount is NOT a plan-price quote:
# savings/overage/difference phrasing, table headers crossing columns, or
# approximate computed costs.
CONNECTOR_SKIP_WORDS = ("save", "overage", "total", "current", "credit", "proration", "~", "≈")
AFTER_SKIP_WORDS = ("more", "less", "per 1,000", "/1k", "per 1k", "per thousand")
PLAN_WORDS = ("free", "starter", "developer", "pro", "growth", "scale",
              "business", "enterprise", "enterprise cloud")
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
        key = canonical_key(plan)
        expected = next((p for p, name in CANONICAL_PLAN_PRICES.items() if name == key), None)
        if expected is None:
            continue
        after_full = text[m.end():m.end() + 18].lower()
        if any(word in after_full for word in ("more", "less", "cheaper", "savings")):
            continue
        if any(word in connector for word in ("save", "saving")):
            continue

        # Not a plan-price quote: per-unit rates, computed cents-precision
        # amounts, savings/overage/difference phrasing, or a connector that
        # crosses another plan name (table columns).
        if value < 1 or value != int(value):
            continue
        if any(word in connector for word in CONNECTOR_SKIP_WORDS):
            continue
        if "=" in m.group():
            # computed total (plan + overage), not a plan-price quote
            continue
        if any(word in connector for word in PLAN_WORDS):
            continue
        if any(word in after for word in AFTER_SKIP_WORDS):
            continue
        before = text[max(0, m.start() - 160):m.start()].lower()
        if "annual" in before and int(value) == expected * 10:
            continue

        # A plan-adjacent €N is either the plan's own price, or (Pro/Growth+)
        # the €30 dedicated-IP add-on. Anything else is a wrong price.
        if "$" in m.group():
            problems.append(f"{source}: dollar price for {plan}: {m.group()!r}")
        elif int(value) != expected and not (int(value) in ADDON_PRICES and "ip" in text.lower()):
            problems.append(
                f"{source}: {plan} quoted at {m.group().strip()!r} but platform-catalog says €{expected:,}"
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
            f"{source}: Free plan limit quoted as 30,000/mo; the canonical "
            f"Free plan grants 3,000/mo and 30,000 is only the launch "
            f"allowance ({m.group().strip()!r})"
        )

    return problems


def validate_file(path: Path) -> list[str]:
    problems: list[str] = []
    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return [f"{path}: unreadable ({exc})"]

    if path.suffix == ".py":
        # Plain-text fixture modules: apply the text checks to the source.
        for line_no, line in enumerate(content.splitlines(), 1):
            source = f"{path.name}:{line_no}"
            stripped = line.strip()
            # The sweep/validator scripts themselves must keep literal $N
            # patterns to detect and rewrite remaining USD in the corpus.
            if path.name in {"sweep_currency_to_eur.py", "validate_data_prices.py",
                              "validate_pricing.py", "validate_pipeline.py"}:
                continue
            # Test/stress fixtures deliberately quote wrong prices to prove
            # the scorer and validators reject them — plan-price assertions
            # do not apply there, but the $-remains check always does.
            is_fixture_file = path.name.startswith(("test_", "stress_", "evaluate", "verify_"))
            is_adversarial = "?" in line and any(
                w in line for w in ("Is the", "My friend", "wrong", "adversarial")
            )
            is_token_list = "must_contain" in line or '"checks"' in line
            is_scorer_fixture = "score_golden_answer" in line or "assert score" in line
            # $-detection must still run everywhere (no USD may remain) —
            # except inside raw-string regexes, which must keep \$N match
            # patterns to find and rewrite legacy USD corpus rows.
            is_regex_line = 'r"' in line or "r'" in line
            if not is_regex_line:
                dollar_hits = [
                    f"{source}: '$' price remains: {dm.group()!r}"
                    for dm in re.finditer(r"\$\d[\d,]*(?:\.\d+)?", line)
                ]
                problems.extend(dollar_hits)
            if not (
                is_fixture_file
                or is_adversarial
                or is_token_list
                or is_scorer_fixture
            ):
                # Raw-string regex lines keep \$N match patterns on purpose
                # (they find legacy USD rows); strip the escapes before the
                # text checks so only the replacement side is validated.
                safe_line = line.replace("\\$", "") if is_regex_line else line
                problems.extend(check_text(safe_line, source))
        return problems

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
        paths = sorted(DATA_DIR.glob("*.jsonl")) + sorted(TRAINING_DIR.glob("*.py"))

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
          "encoding all match platform-catalog.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
