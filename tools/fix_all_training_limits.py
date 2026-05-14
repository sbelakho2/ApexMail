#!/usr/bin/env python3
"""
Fix all pricing inconsistencies in AI training data.
Corrects plan limits to match canonical pricing from lib/pricing.py
"""

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common_paths import DATA_DIR
from lib.pricing import PLANS, UNLIMITED


def _plan_limits(plan_name: str) -> dict:
    """Get email/api/team limits for a plan, compatible with fix logic."""
    p = PLANS.get(plan_name, {})
    return {
        'email': p.get('emails', 0),
        'api': p.get('api_calls', 0),
        'team': p.get('team', 0),
    }


def fix_training_data():
    filepath = str(DATA_DIR / "train_agent.jsonl")

    with open(filepath, 'r') as f:
        lines = f.readlines()

    fixed_count = 0
    fixed_lines = []

    for i, line in enumerate(lines, 1):
        original = line
        modified = line

        try:
            data = json.loads(line)
            text = data.get('text', '')

            # Find which plan this line is about
            plan_match = re.search(r'Plan: (\w+) \(\$\d+/mo\)', text)
            if plan_match:
                plan = plan_match.group(1)
                if plan in PLANS:
                    canon = _plan_limits(plan)

                    # Fix email limits in customer context
                    if canon['email'] != UNLIMITED:
                        def fix_email_limit(match):
                            usage = match.group(1)
                            return f"Email usage this month: {usage}/{canon['email']:,}"
                        modified = re.sub(
                            r'Email usage this month: ([\d,]+)/[\d,]+',
                            fix_email_limit,
                            modified
                        )

                    # Fix API limits in customer context
                    if canon['api'] != UNLIMITED:
                        def fix_api_limit(match):
                            usage = match.group(1)
                            return f"API calls this month: {usage}/{canon['api']:,}"
                        modified = re.sub(
                            r'API calls this month: ([\d,]+)/[\d,]+',
                            fix_api_limit,
                            modified
                        )

                    # Fix team limits in customer context
                    if canon['team'] != UNLIMITED:
                        def fix_team_limit(match):
                            usage = match.group(1)
                            return f"Team members: {usage}/{canon['team']}"
                        modified = re.sub(
                            r'Team members: (\d+)/\d+',
                            fix_team_limit,
                            modified
                        )

                    # Also fix assistant responses that reference limits
                    if canon['email'] != UNLIMITED:
                        if 'Plan: ' + plan in modified and '|' not in modified[-500:]:
                            modified = re.sub(
                                r'Emails: ([\d,]+)\s*/\s*[\d,]+',
                                lambda m: f"Emails: {m.group(1)} / {canon['email']:,}",
                                modified
                            )

                    if canon['api'] != UNLIMITED:
                        if 'Plan: ' + plan in modified and '|' not in modified[-500:]:
                            modified = re.sub(
                                r'API calls: ([\d,]+)\s*/\s*[\d,]+',
                                lambda m: f"API calls: {m.group(1)} / {canon['api']:,}",
                                modified
                            )

        except json.JSONDecodeError:
            pass  # Skip invalid JSON

        if modified != original:
            fixed_count += 1
        fixed_lines.append(modified)

    # Write back
    with open(filepath, 'w') as f:
        f.writelines(fixed_lines)

    print(f"Fixed {fixed_count} lines with incorrect plan limits")
    return fixed_count


if __name__ == '__main__':
    fix_training_data()
