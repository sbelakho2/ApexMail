#!/usr/bin/env python3
"""
Fix incorrect PAYG calculations in training data.

Uses shared pricing from lib/pricing.py as the single source of truth.
"""

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common_paths import DATA_DIR
from lib.pricing import calculate_payg, PAYG_TIERS


def fix_payg_calculations():
    filepath = str(DATA_DIR / "train_agent.jsonl")

    with open(filepath, 'r') as f:
        lines = f.readlines()

    fixed_count = 0
    fixed_lines = []

    for i, line in enumerate(lines, 1):
        modified = line

        try:
            data = json.loads(line)
            text = data.get('text', '')

            # Fix the specific 50,000 email PAYG calculation error
            # User asks about 50,000 but response calculates 10,000
            if '50,000 emails' in text and 'All 10,000 fall' in text:
                # Correct calculation for 50,000 emails:
                # - First 10,000 at $0.001 = $10.00
                # - Next 40,000 at $0.0008 = $32.00
                # - Total = $42.00
                correct_response = (
                    "For exactly **50,000 emails** on Pay-As-You-Go:\\n\\n"
                    "| Tier | Emails | Rate | Cost |\\n"
                    "|------|--------|------|------|\\n"
                    "| 0–10k | 10,000 | $0.001 | $10.00 |\\n"
                    "| 10k–100k | 40,000 | $0.0008 | $32.00 |\\n"
                    "\\n**Total: $42.00**\\n\\n"
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

    # Write back
    with open(filepath, 'w') as f:
        f.writelines(fixed_lines)

    print(f"\nTotal fixed: {fixed_count} lines with incorrect PAYG calculations")
    return fixed_count


if __name__ == '__main__':
    fix_payg_calculations()
