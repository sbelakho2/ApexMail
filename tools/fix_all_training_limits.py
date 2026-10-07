#!/usr/bin/env python3
"""
Fix plan-limit inconsistencies in AI training data.

Corrects plan limits to the canonical values from lib/pricing.py (which is
pinned field-by-field against the Rust platform catalog by
tools/validate_pricing_drift.py).

Safety (coverage audit U-2b): the corpus is written through
lib.fix_utils.write_jsonl, which refuses to overwrite an existing file
without first creating a `<file>.bak`; `--dry-run` reports the fixes and
writes nothing. This script previously wrote the tracked corpus in place
with no backup.
"""

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common_paths import DATA_DIR
from lib.fix_utils import write_jsonl
from lib.pricing import UNLIMITED, plan_for

CORPUS = DATA_DIR / "train_agent.jsonl"


def _plan_limits(plan_name: str) -> dict:
    """Canonical email/api/team limits for a plan id or display name."""
    plan = plan_for(plan_name) or {}
    return {
        'email': plan.get('emails', 0),
        'api': plan.get('api_calls', 0),
        'team': plan.get('team', 0),
    }


class CorpusMissing(RuntimeError):
    """The historical corpus this one-off rewriter targets is absent."""


def fix_training_data(dry_run: bool = False) -> int:
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

    for i, line in enumerate(lines, 1):
        original = line
        modified = line

        try:
            data = json.loads(line)
            text = data.get('text', '')

            # Find which plan this line is about
            plan_match = re.search(r'Plan: (\w+) \(\$\d+/mo\)', text)
            if plan_match:
                plan_name = plan_match.group(1)
                plan = plan_for(plan_name)
                if plan is not None:
                    canon = _plan_limits(plan_name)

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
                        if 'Plan: ' + plan_name in modified and '|' not in modified[-500:]:
                            modified = re.sub(
                                r'Emails: ([\d,]+)\s*/\s*[\d,]+',
                                lambda m: f"Emails: {m.group(1)} / {canon['email']:,}",
                                modified
                            )

                    if canon['api'] != UNLIMITED:
                        if 'Plan: ' + plan_name in modified and '|' not in modified[-500:]:
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

    if dry_run:
        print(f"[dry-run] would fix {fixed_count} lines with incorrect plan limits; no file written")
        return fixed_count

    # Backed-up write (write_jsonl creates <file>.bak before overwriting).
    records = [json.loads(line) for line in fixed_lines if line.strip()]
    write_jsonl(filepath, records, backup=True)
    print(f"Fixed {fixed_count} lines with incorrect plan limits (backup: {filepath}.bak)")
    return fixed_count


if __name__ == '__main__':
    dry = "--dry-run" in sys.argv[1:]
    try:
        fix_training_data(dry_run=dry)
    except CorpusMissing as error:
        print(error, file=sys.stderr)
        sys.exit(2)
    sys.exit(0)
