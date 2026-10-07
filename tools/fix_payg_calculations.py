#!/usr/bin/env python3
"""
Fix incorrect PAYG calculations in training data.

Uses shared pricing from lib/pricing.py as the single source of truth
(pinned against the Rust platform catalog by validate_pricing_drift.py).
The platform bills exclusively in EUR.

Safety (coverage audit U-2b): the corpus is written through
lib.fix_utils.write_lines, which refuses to overwrite an existing file
without a `.bak` backup; `--dry-run` reports the fixes and writes nothing.
This script previously wrote the tracked corpus in place with no backup.
"""

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common_paths import DATA_DIR
from lib.fix_utils import write_lines
from lib.pricing import calculate_payg_cents

CORPUS = DATA_DIR / "train_agent.jsonl"


class CorpusMissing(RuntimeError):
    """The historical corpus this one-off rewriter targets is absent."""


def fix_payg_calculations(dry_run: bool = False) -> int:
    filepath = CORPUS
    if not filepath.exists():
        raise CorpusMissing(
            f"corpus not found: {filepath}\n"
            "The historical train_agent.jsonl corpus no longer exists "
            "(apps/ai/training/data/ holds only augmented_*.jsonl); nothing to rewrite."
        )

    with open(filepath, 'r') as f:
        lines = f.readlines()

    fixed_count = 0
    fixed_lines = []

    total_cents = calculate_payg_cents(50_000)
    tier1_cents = calculate_payg_cents(10_000)
    tier2_cents = total_cents - tier1_cents

    for i, line in enumerate(lines, 1):
        modified = line

        try:
            data = json.loads(line)
            text = data.get('text', '')

            # Fix the specific 50,000 email PAYG calculation error
            # User asks about 50,000 but response calculates 10,000
            if '50,000 emails' in text and 'All 10,000 fall' in text:
                # Correct calculation for 50,000 emails (EUR, integer cents):
                # - First 10,000 at €0.001 = €10.00
                # - Next 40,000 at €0.0008 = €32.00
                # - Total = €42.00
                correct_response = (
                    "For exactly **50,000 emails** on Pay-As-You-Go:\\n\\n"
                    "| Tier | Emails | Rate | Cost |\\n"
                    "|------|--------|------|------|\\n"
                    f"| 0–10k | 10,000 | €0.001 | €{tier1_cents / 100:.2f} |\\n"
                    f"| 10k–100k | 40,000 | €0.0008 | €{tier2_cents / 100:.2f} |\\n"
                    f"\\n**Total: €{total_cents / 100:.2f}**\\n\\n"
                    "No base fee — you only pay for what you send. PAYG is great for variable or infrequent sending."
                )

                # Replace the incorrect assistant response
                old_response_pattern = r"For exactly \*\*50,000 emails\*\*.*?no base fee\. PAYG is great for low or variable volume\."
                modified = re.sub(old_response_pattern, correct_response, text, flags=re.DOTALL)

                if modified != text:
                    data['text'] = modified
                    modified = json.dumps(data, ensure_ascii=False) + '\n'
                    fixed_count += 1
                    print(f"Line {i}: Fixed 50,000 emails PAYG calculation")

        except json.JSONDecodeError:
            pass

        fixed_lines.append(modified)

    if dry_run:
        print(f"[dry-run] would fix {fixed_count} lines with incorrect PAYG calculations; no file written")
        return fixed_count

    # Guarded write: existing corpus is backed up to train_agent.jsonl.bak.
    write_lines(filepath, fixed_lines, backup=True)
    print(f"\nTotal fixed: {fixed_count} lines with incorrect PAYG calculations (backup: {filepath}.bak)")
    return fixed_count


if __name__ == '__main__':
    dry = "--dry-run" in sys.argv[1:]
    try:
        fix_payg_calculations(dry_run=dry)
    except CorpusMissing as error:
        print(error, file=sys.stderr)
        sys.exit(2)
    sys.exit(0)
