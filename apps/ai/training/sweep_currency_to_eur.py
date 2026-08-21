#!/usr/bin/env python3
"""
sweep_currency_to_eur.py — One-shot, auditable currency/price sweep.

Rewrites the committed training data and prompt builder so that every
ApexMail price matches the canonical EUR table from
services/mail-server/crates/billing-service/src/plans.rs (mirrored in
docs/pricing.md):

    Free €0/30K, Starter €25/50K, Pro €65/150K, Growth €150/500K,
    Scale €350/2M, Enterprise €3,000/5M,
    PAYG €0.001/€0.0008/€0.0005/€0.0003, overage €0.40 per 1,000,
    dedicated IP add-on €30/mo.

Rules applied (in order, each counted):
  1. Targeted golden_qa.jsonl answer rewrites (A/B testing gate, HIPAA/SOC 2
     claims, Enterprise pricing, annual billing).
  2. Wrong plan-price numbers in plan-named contexts: $15→€25 (Starter),
     $79→€65 (Pro). Legit computed totals with the same digits (e.g. the
     PAYG API "$15" = 150K × $0.10/1K) keep their number.
  3. PAYG tier-3 per-1K rate bug: $0.40/1K (and "Beyond 100K: $0.40 per
     1,000") → €0.50 — 0.0005 × 1,000 = €0.50, not €0.40.
  4. Enterprise "custom pricing" price claims → €3,000/month.
  5. Third-party USD facts (bug bounties, VMC certificates, CAN-SPAM fines)
     reworded to "USD N" so they are not ApexMail EUR prices.
  6. Remaining "$" price symbols → "€".
  7. prompts_v2.py / generate_gap_training.py: apexmail.com → apexmail.ee.

The script is idempotent and prints a per-file replacement count table.
Run:  python3 apps/ai/training/sweep_currency_to_eur.py [--dry-run]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
DATA_DIR = REPO_ROOT / "data"
TRAINING_DIR = REPO_ROOT / "apps" / "ai" / "training"

SWEEP_FILES = [
    DATA_DIR / "golden_qa.jsonl",
    DATA_DIR / "train.jsonl",
    DATA_DIR / "val.jsonl",
    DATA_DIR / "test.jsonl",
    DATA_DIR / "train_agent.jsonl",
    DATA_DIR / "recovered_training.jsonl",
    DATA_DIR / "system_prompts.json",
]

SCRIPT_FILES = [
    TRAINING_DIR / "prompts_v2.py",
    TRAINING_DIR / "generate_gap_training.py",
]

# ── Rule 1: targeted golden_qa rewrites ───────────────────────────────────

GOLDEN_REWRITES: dict[str, str] = {
    # Line 12: plans.rs grants ab_testing from growth, not pro.
    "A/B testing is available starting from the **Pro plan** ($79/month) and above. The Free and Starter plans do not include A/B testing. With A/B testing on Pro, you can test different subject lines, content, and send times to optimize your campaigns.":
        "A/B testing is available starting from the **Growth plan** (€150/month) and above (Growth, Scale, Enterprise). The Free, Starter, and Pro plans do not include A/B testing. With A/B testing on Growth, you can test different subject lines, content, and send times to optimize your campaigns.",
    # Line 15: plans.rs sets hipaa_compliance/soc2_compliance to false.
    "ApexMail's **Enterprise plan** includes **HIPAA** and **SOC 2** compliance certifications. The Enterprise plan also offers white-label capabilities, BYOIP, a dedicated Customer Success Manager, and a 99.9% SLA with 25% credit for violations. If your organization requires HIPAA or SOC 2 compliance, Enterprise is the plan you need.":
        "ApexMail is **not currently certified** for HIPAA and does not offer SOC 2 certification on any plan, including Enterprise. Enterprise does offer white-label capabilities, BYOIP, a dedicated Customer Success Manager, and a 99.9% SLA with 25% credit for violations. If you need to process regulated workloads, contact support@apexmail.ee so we can discuss requirements and required agreements in writing.",
    # Line 51: annual billing is defined (10x monthly = two months free).
    "I don't have specific information about annual billing discounts in our current pricing documentation. Our standard published pricing is monthly:":
        "Yes — annual billing is 10x the monthly price, effectively giving you two months free (about a 17% discount). Our published monthly prices are:",
    # Line 48: arithmetic consistency (Starter base is €25, so €25 + €2.40).
    "Your total bill: €15 + €2.40 = **€27.40**":
        "Your total bill: €25 + €2.40 = **€27.40**",
    "- Enterprise: custom pricing":
        "- Enterprise: €3,000/mo (annual €30,000/year; annual-contract sales flow)",
}

# ── Rules 2-4: exact-string price corrections ─────────────────────────────

def _plan_context_correction(wrong: str, canonical: str, plan_word: str):
    """Replace `wrong` with `canonical` only when `plan_word` appears within
    ±150 characters, so computed totals that happen to share digits (e.g. the
    PAYG API overage "$15" = 150K × $0.10/1K) are left to the plain symbol
    swap instead of being re-priced."""

    pattern = re.compile(wrong)
    plan_re = re.compile(plan_word, re.IGNORECASE)
    window = 150

    def _fix(text: str, counters: dict[str, int]) -> str:
        out = []
        last = 0
        replaced = 0
        for m in pattern.finditer(text):
            ctx_start = max(0, m.start() - window)
            ctx_end = min(len(text), m.end() + window)
            if plan_re.search(text[ctx_start:ctx_end]):
                out.append(text[last:m.start()])
                out.append(canonical)
                last = m.end()
                replaced += 1
        out.append(text[last:])
        if replaced:
            counters[wrong] = counters.get(wrong, 0) + replaced
        return "".join(out)

    return _fix


# Rule 2 — wrong plan prices, only in plan-named contexts. Both the '$'
# originals and any '€' leftovers from a previous partial sweep are covered.
FIX_STARTER_PRICE = _plan_context_correction(r"[$€]15\b", "€25", r"\bstarter\b")
FIX_PRO_PRICE = _plan_context_correction(r"[$€]79\b", "€65", r"\bpro\b")

CORRECTIONS: list[tuple[re.Pattern, str]] = [
    # Rule 3 — PAYG tier-3 per-1K rate: 0.0005 × 1,000 = €0.50.
    (re.compile(r"\$0\.40/1K"), "€0.50/1K"),
    (re.compile(r"Beyond 100K: \$0\.40 per 1,000"), "Beyond 100K: €0.50 per 1,000"),
    (re.compile(r"beyond 100K, and \$0\.40/1K"), "beyond 100K, and €0.50/1K"),
    # Rule 4 — Enterprise is €3,000/month in plans.rs, not "custom".
    (re.compile(r"\*\*custom pricing\*\* and includes"), "€3,000/month and includes"),
    (re.compile(r"\(custom pricing, 10 IPs\)"), "(€3,000/month, 10 IPs)"),
    (re.compile(r"Enterprise \(custom pricing\)"), "Enterprise (€3,000/month)"),
    (re.compile(r"custom pricing \(5,000,000 emails\)"), "€3,000/month (5,000,000 emails)"),
    # Rule 5 — genuinely-USD third-party facts (not ApexMail prices).
    (re.compile(r"up to \*\*\$51,744 per email\*\*"), "up to **USD 51,744 per email**"),
    (re.compile(r"~\$1,000-1,500/year"), "~USD 1,000-1,500/year"),
    (re.compile(r"~\$1,000–\$1,500/year"), "~USD 1,000–1,500/year"),
    (re.compile(r"\(\$1,000–\$1,500/year\)"), "(USD 1,000–1,500/year)"),
    (re.compile(r"Critical: \$500–\$5,000"), "Critical: USD 500–5,000"),
    (re.compile(r"High: \$200–\$1,000"), "High: USD 200–1,000"),
    (re.compile(r"Medium: \$50–\$200"), "Medium: USD 50–200"),
]

SYMBOL_SWAP = re.compile(r"\$")


def sweep_text(text: str, counters: dict[str, int]) -> str:
    counters.setdefault("golden_rewrites", 0)
    for old, new in GOLDEN_REWRITES.items():
        if old in text:
            text = text.replace(old, new)
            counters["golden_rewrites"] += 1
    text = FIX_STARTER_PRICE(text, counters)
    text = FIX_PRO_PRICE(text, counters)
    for pattern, replacement in CORRECTIONS:
        text, n = pattern.subn(replacement, text)
        if n:
            counters[pattern.pattern] = counters.get(pattern.pattern, 0) + n
    text, n = SYMBOL_SWAP.subn("€", text)
    counters["$→€ symbol swap"] = counters.get("$→€ symbol swap", 0) + n
    return text


def sweep_domain_refs(text: str, counters: dict[str, int]) -> str:
    # Rewrites "apexmail.com" and any "sub.apexmail.com" to apexmail.ee.
    pattern = re.compile(r"(?<![\w.-])(?:([a-z0-9-]+(?:\.[a-z0-9-]+)*)\.)?apexmail\.com\b")
    def _fix(m: re.Match) -> str:
        prefix = f"{m.group(1)}." if m.group(1) else ""
        return f"{prefix}apexmail.ee"
    text, n = pattern.subn(_fix, text)
    if n:
        counters["apexmail.com → apexmail.ee"] = counters.get("apexmail.com → apexmail.ee", 0) + n
    return text


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="Report counts without writing")
    args = parser.parse_args()

    grand_total = 0
    for path in SWEEP_FILES + SCRIPT_FILES:
        if not path.exists():
            print(f"SKIP (missing): {path}")
            continue
        original = path.read_text(encoding="utf-8")
        counters: dict[str, int] = {}
        swept = sweep_text(original, counters)
        if path.suffix == ".py":
            swept = sweep_domain_refs(swept, counters)
        total = sum(counters.values())
        grand_total += total
        if total:
            print(f"{path.relative_to(REPO_ROOT)}: {total} replacement(s)")
            for rule, n in sorted(counters.items(), key=lambda kv: -kv[1]):
                print(f"    {n:5d}  {rule}")
        else:
            print(f"{path.relative_to(REPO_ROOT)}: clean")
        if not args.dry_run and swept != original:
            path.write_text(swept, encoding="utf-8")

    # Refresh the integrity checksum for system_prompts.json when changed.
    prompts_json = DATA_DIR / "system_prompts.json"
    prompts_sha = DATA_DIR / "system_prompts.json.sha256"
    if not args.dry_run and prompts_json.exists() and prompts_sha.exists():
        digest = hashlib.sha256(prompts_json.read_bytes()).hexdigest()
        expected = prompts_sha.read_text(encoding="utf-8", errors="replace").split()[0]
        if digest != expected:
            prompts_sha.write_text(
                f"{digest}  system_prompts.json\\n", encoding="utf-8"
            )
            print(f"refreshed {prompts_sha.relative_to(REPO_ROOT)}")

    print(f"\nTotal replacements: {grand_total}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
