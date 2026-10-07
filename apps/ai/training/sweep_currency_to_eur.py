#!/usr/bin/env python3
"""
sweep_currency_to_eur.py — One-shot, auditable currency/price sweep.

Rewrites legacy training data and prompt builders so that every ApexMail
price matches the canonical catalog in
services/mail-server/crates/platform-catalog (pinned by
tools/check_knowledge_consistency.py):

    Free €0 / 3,000 emails / 30,000 API (plus a one-time 30,000-email launch
    allowance in the first 30 days), Developer €29 / 50,000 / 500,000,
    Pro €89 / 150,000 / 2,000,000, Growth €229 / 500,000 / 5,000,000,
    Business €699 / 2,000,000 / 20,000,000,
    Enterprise Cloud €1,750 / 5,000,000 / unlimited API,
    PAYG €0.001/€0.0008/€0.0005/€0.0003,
    overage €0.80 (Developer) / €0.60 (Pro) / €0.35 (Growth+) per 1,000,
    dedicated IP add-on €30/mo, annual = 10× monthly.

The pre-2026-09-08 table (Free 30,000 / Starter €25 / Pro €65 / Growth
€150 / Scale €350 / Enterprise €3,000) is what this script migrates FROM.
Rules applied (in order, each counted):
  1. Targeted golden_qa answer rewrites (A/B testing gate, HIPAA/SOC 2
     claims, Enterprise Cloud pricing, annual billing).
  2. Plan-adjacent legacy prices and quotas via
     validate_pricing.canonize_text() — ONE shared implementation, derived
     from CANONICAL_PRICING.
  3. PAYG tier-3 per-1K rate bug: $0.40/1K (and "Beyond 100K: $0.40 per
     1,000") → €0.50 — 0.0005 × 1,000 = €0.50, not €0.40.
  4. Enterprise "custom pricing" price claims → the canonical Enterprise
     Cloud price.
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
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from validate_pricing import (  # noqa: E402
    ENTERPRISE_CLOUD,
    PRICE_BY_PLAN,
    canonize_text,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
TRAINING_DIR = REPO_ROOT / "apps" / "ai" / "training"
DATA_DIR = TRAINING_DIR / "data"

# The tracked corpus this pipeline owns. Root /data is a retired, gitignored
# scratch directory (data/README.md) and is not swept.
SWEEP_FILES = sorted(DATA_DIR.glob("*.jsonl"))

# Every training-corpus generator/fixture script: the corpus is what the
# model trains on, so scripts that still emit USD prices reintroduce the
# drift on every regeneration.
SCRIPT_FILES = [
    TRAINING_DIR / "prompts_v2.py",
    TRAINING_DIR / "generate_gap_training.py",
    TRAINING_DIR / "new_customer_profiles.py",
    TRAINING_DIR / "extract_full_recovered.py",
    TRAINING_DIR / "extract_all_recovered.py",
    TRAINING_DIR / "generate_dataset.py",
    TRAINING_DIR / "generate_recovered_training.py",
    TRAINING_DIR / "integrate_recovered.py",
    TRAINING_DIR / "training_data.py",
    TRAINING_DIR / "augment_training_data.py",
    TRAINING_DIR / "merge_and_export.py",
    TRAINING_DIR / "validate_pricing.py",
    TRAINING_DIR / "run_test_agent.py",
    TRAINING_DIR / "test_agent.py",
    TRAINING_DIR / "test_fixes.py",
    TRAINING_DIR / "test_aggressively.py",
    TRAINING_DIR / "test_1000_adversarial.py",
    TRAINING_DIR / "stress_test_agent.py",
    TRAINING_DIR / "stress_test_recovered.py",
    TRAINING_DIR / "stress_test.py",
    TRAINING_DIR / "verify_all_angles.py",
    TRAINING_DIR / "evaluate.py",
    TRAINING_DIR / "evaluate_granular.py",
]

# ── Rule 1: targeted golden_qa rewrites ───────────────────────────────────

GOLDEN_REWRITES: dict[str, str] = {
    # A/B testing starts at Growth, not Pro.
    "A/B testing is available starting from the **Pro plan** ($79/month) and above. The Free and Starter plans do not include A/B testing. With A/B testing on Pro, you can test different subject lines, content, and send times to optimize your campaigns.":
        "A/B testing is available starting from the **Growth plan** (€229/month) and above (Growth, Business, Enterprise Cloud). The Free, Developer, and Pro plans do not include A/B testing. With A/B testing on Growth, you can test different subject lines, content, and send times to optimize your campaigns.",
    # platform-catalog sets hipaa_compliance/soc2_compliance to false.
    "ApexMail's **Enterprise plan** includes **HIPAA** and **SOC 2** compliance certifications. The Enterprise plan also offers white-label capabilities, BYOIP, a dedicated Customer Success Manager, and a 99.9% SLA with 25% credit for violations. If your organization requires HIPAA or SOC 2 compliance, Enterprise is the plan you need.":
        "ApexMail is **not currently certified** for HIPAA and does not offer SOC 2 certification on any plan, including Enterprise Cloud. Enterprise Cloud does offer white-label capabilities, BYOIP, a dedicated Customer Success Manager, and a 99.9% SLA with 25% credit for violations. If you need to process regulated workloads, contact support@apexmail.ee so we can discuss requirements and required agreements in writing.",
    # Annual billing is 10x monthly = two months free.
    "I don't have specific information about annual billing discounts in our current pricing documentation. Our standard published pricing is monthly:":
        "Yes — annual billing is 10x the monthly price, effectively giving you two months free (about a 17% discount). Our published monthly prices are:",
    # Enterprise is priced in the catalog, never "custom".
    "- Enterprise: custom pricing":
        f"- Enterprise Cloud: {ENTERPRISE_CLOUD['price']}/mo (annual {ENTERPRISE_CLOUD['annual']}/year; annual-contract sales flow)",
}

# ── Rules 2-6: canonical corrections ─────────────────────────────────────

CORRECTIONS: list[tuple[re.Pattern, str]] = [
    # Rule 3 — PAYG tier-3 per-1K rate: 0.0005 × 1,000 = €0.50.
    (re.compile(r"\$0\.40/1K"), "€0.50/1K"),
    (re.compile(r"Beyond 100K: \$0\.40 per 1,000"), "Beyond 100K: €0.50 per 1,000"),
    (re.compile(r"beyond 100K, and \$0\.40/1K"), "beyond 100K, and €0.50/1K"),
    # Rule 4 — Enterprise Cloud is priced in platform-catalog, not "custom".
    (re.compile(r"\*\*custom pricing\*\* and includes"),
     f"{ENTERPRISE_CLOUD['price']}/month and includes"),
    (re.compile(r"\(custom pricing, 10 IPs\)"),
     f"({ENTERPRISE_CLOUD['price']}/month, 10 IPs)"),
    (re.compile(r"Enterprise \(custom pricing\)"),
     f"Enterprise Cloud ({ENTERPRISE_CLOUD['price']}/month)"),
    (re.compile(r"custom pricing \(5,000,000 emails\)"),
     f"{ENTERPRISE_CLOUD['price']}/month (5,000,000 emails)"),
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
    # Rule 2 — plan-adjacent legacy prices, quotas, names and overage rates.
    # ONE shared implementation derived from CANONICAL_PRICING.
    text, _ = canonize_text(text, counters)
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
    parser.add_argument(
        "--include-scripts", action="store_true",
        help="Also sweep the historical source fixtures (one-shot migration; "
             "never run this against already-canonical sources)",
    )
    args = parser.parse_args()

    grand_total = 0
    # Default: the tracked JSONL corpus only. The source fixtures were swept
    # once during the migration; re-sweeping canonical .py sources can corrupt
    # migration patterns and computed examples, so it is opt-in.
    paths = list(SWEEP_FILES)
    if args.include_scripts:
        paths += [p for p in SCRIPT_FILES
                  if p.name not in {"sweep_currency_to_eur.py", "validate_pricing.py"}]
    for path in paths:
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
    prompts_json = REPO_ROOT / "data" / "system_prompts.json"
    prompts_sha = REPO_ROOT / "data" / "system_prompts.json.sha256"
    if not args.dry_run and prompts_json.exists() and prompts_sha.exists():
        digest = hashlib.sha256(prompts_json.read_bytes()).hexdigest()
        expected = prompts_sha.read_text(encoding="utf-8", errors="replace").split()[0]
        if digest != expected:
            prompts_sha.write_text(
                f"{digest}  system_prompts.json\n", encoding="utf-8"
            )
            print(f"refreshed {prompts_sha.relative_to(REPO_ROOT)}")

    print(f"\nTotal replacements: {grand_total}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
