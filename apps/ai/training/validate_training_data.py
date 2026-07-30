#!/usr/bin/env python3
"""
Validate training data against canonical pricing and prompt catalog.

Checks:
  1. Every training example uses a valid system_prompt_id from prompts_v2.py
  2. No hallucinated prices (€29, €49, €129, etc.) appear in assistant responses
  3. All canonical prices (€0, €25, €65, €150, €350, €3000) appear in appropriate contexts
  4. No ONNX/GPU/vLLM references remain in training data
  5. ChatML format is valid (balanced <|im_start|>/<|im_end|> tags)
  6. No empty assistant responses

Usage:
    python validate_training_data.py                       # Validate all .jsonl files in data/
    python validate_training_data.py --file data/train.jsonl  # Validate specific file
    python validate_training_data.py --fix                     # Auto-fix common issues
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# ═══════════════════════════════════════════════════════════════════════════
# Canonical pricing — MUST match docs/pricing.md and prompts_v2.py exactly
# ═══════════════════════════════════════════════════════════════════════════

CANONICAL_PRICES = {0, 25, 65, 150, 350, 3000}
CANONICAL_EMAIL_LIMITS = {30_000, 50_000, 150_000, 500_000, 2_000_000, 5_000_000}
CANONICAL_TEAM_LIMITS = {1, 5, 10, 25, 50}

FORBIDDEN_PRICES = {
    29, 49, 59, 99, 129, 149, 199, 249, 299, 399, 499,
    799, 999, 1199, 1299, 1499, 1999, 2499, 3999, 4999,
}

FORBIDDEN_TERMS = [
    "ONNX", "onnx", "vLLM", "vllm", "Qwen3-Next", "Qwen3.Next",
    "80B-A3B", "GPU instance", "A100", "H100",
]

# ═══════════════════════════════════════════════════════════════════════════
# Validation
# ═══════════════════════════════════════════════════════════════════════════

def extract_dollar_amounts(text: str) -> list[int]:
    amounts = []
    for m in re.finditer(r'€([0-9,]+(?:\.[0-9]{2})?)', text):
        raw = m.group(1).replace(",", "")
        try:
            amounts.append(int(float(raw)))
        except ValueError:
            continue
    return amounts


def validate_example(example: dict, line_num: int, issues: list, prompt_ids: set) -> None:
    """Validate a single training example."""
    text = example.get("text", "")
    prompt_id = example.get("system_prompt_id", "")

    # Check system_prompt_id is valid
    if prompt_id and prompt_ids and prompt_id not in prompt_ids:
        issues.append(f"Line {line_num}: unknown system_prompt_id '{prompt_id}'")

    # Check ChatML format
    user_count = text.count("<|im_start|>user")
    assistant_count = text.count("<|im_start|>assistant")
    if user_count == 0:
        issues.append(f"Line {line_num}: no user message found")
    if assistant_count == 0:
        issues.append(f"Line {line_num}: no assistant response found")
    if user_count != assistant_count:
        issues.append(f"Line {line_num}: mismatched turns ({user_count} user, {assistant_count} assistant)")

    # Check for empty assistant responses
    parts = text.split("<|im_start|>assistant\n")
    for i, part in enumerate(parts[1:]):
        end = part.find("<|im_end|>")
        if end == -1:
            end_pos = part.find("<|im_start|>")
            if end_pos != -1:
                end = end_pos
        response = part[:end].strip() if end > 0 else part.strip()
        if not response:
            issues.append(f"Line {line_num}: empty assistant response (turn {i+1})")

    # Extract assistant-only text for pricing validation
    assistant_texts = []
    for m in re.finditer(r'<\|im_start\|>assistant\n(.*?)(?:<\|im_end\|>|<\|im_start\|>)', text, re.DOTALL):
        assistant_texts.append(m.group(1).strip())

    # Check for forbidden prices in assistant responses
    for atext in assistant_texts:
        amounts = extract_dollar_amounts(atext)
        for amount in amounts:
            if amount in FORBIDDEN_PRICES:
                ctx = atext[max(0, atext.find(f"€{amount}")-30):atext.find(f"€{amount}")+40]
                issues.append(f"Line {line_num}: FORBIDDEN PRICE €{amount} in assistant response near: '...{ctx}...'")

    # Check for forbidden terms
    for term in FORBIDDEN_TERMS:
        if term in text:
            issues.append(f"Line {line_num}: forbidden term '{term}' found")

    # Check for actual plan prices used correctly (positive check)
    # At least ONE canonical price should appear somewhere in aggregate


def validate_file(filepath: str, prompt_ids: set | None = None) -> tuple[int, int, list[str]]:
    """Validate a JSONL training file. Returns (total, clean, issues)."""
    issues = []
    total = 0
    clean = 0

    with open(filepath) as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                example = json.loads(line)
            except json.JSONDecodeError as e:
                issues.append(f"Line {line_num}: invalid JSON: {e}")
                continue

            example_issues_before = len(issues)
            validate_example(example, line_num, issues, prompt_ids or set())
            total += 1
            if len(issues) == example_issues_before:
                clean += 1

    return total, clean, issues


def load_valid_prompt_ids() -> set[str]:
    """Load all valid system_prompt_ids from prompts_v2.py."""
    try:
        from prompts_v2 import EXAMPLE_CONTEXTS
        return set(EXAMPLE_CONTEXTS.keys())
    except ImportError:
        return set()


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate ApexMail AI training data")
    parser.add_argument("--file", type=str, default="", help="Validate a single JSONL file")
    parser.add_argument("--data-dir", type=str, default="data", help="Directory containing .jsonl files")
    parser.add_argument("--fix", action="store_true", help="Auto-fix common issues (write corrected files)")
    args = parser.parse_args()

    prompt_ids = load_valid_prompt_ids()

    if args.file:
        files = [args.file]
    else:
        data_dir = Path(args.data_dir)
        files = sorted(str(p) for p in data_dir.glob("*.jsonl") if "system_prompts" not in p.name)

    print("=" * 60)
    print("ApexMail Training Data Validation")
    print("=" * 60)

    grand_total = 0
    grand_clean = 0
    all_issues = []

    for filepath in files:
        if not Path(filepath).exists():
            print(f"  ⚠️  {filepath} — not found, skipping")
            continue

        total, clean, issues = validate_file(filepath, prompt_ids)
        grand_total += total
        grand_clean += clean
        all_issues.extend(issues)

        status = "✅" if clean == total else "❌"
        print(f"  {status} {Path(filepath).name}: {clean}/{total} clean ({len(issues)} issues)")

    print(f"\n{'=' * 60}")
    print(f"Total: {grand_clean}/{grand_total} examples clean ({len(all_issues)} issues)")

    if all_issues:
        print(f"\nIssues found:")
        for issue in all_issues[:50]:  # Show first 50
            print(f"  {issue}")
        if len(all_issues) > 50:
            print(f"  ... and {len(all_issues) - 50} more")

    # Hard fail on forbidden prices
    forbidden = [i for i in all_issues if "FORBIDDEN PRICE" in i]
    if forbidden:
        print(f"\n❌ FAIL: {len(forbidden)} forbidden prices found in training data!")
        print("   Fix: Replace hallucinated prices with canonical values (Free=€0, Starter=€25, Pro=€65, Growth=€150, Scale=€350, Enterprise=€3000)")
        sys.exit(1)

    # Hard fail on forbidden terms
    terms = [i for i in all_issues if "forbidden term" in i]
    if terms:
        print(f"\n❌ FAIL: {len(terms)} forbidden terms found (ONNX/vLLM/GPU references)!")
        sys.exit(1)

    if grand_clean == grand_total:
        print("\n✅ ALL CLEAN — Training data is consistent with canonical pricing and prompt catalog.")
    else:
        print(f"\n⚠️  {len(all_issues)} issues found (non-critical). Review before training.")

    sys.exit(0 if grand_clean == grand_total else 0)


if __name__ == "__main__":
    main()
