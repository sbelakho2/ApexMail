#!/usr/bin/env python3
"""
Fix all pricing inconsistencies in AI training data.
Corrects plan limits to match canonical pricing from plans.ts
"""

import json
import re

# Canonical limits from plans.ts
CANONICAL = {
    'Free': {'email': 3000, 'api': 50000, 'team': 1},
    'Starter': {'email': 50000, 'api': 500000, 'team': 5},
    'Pro': {'email': 150000, 'api': 2000000, 'team': 10},
    'Growth': {'email': 500000, 'api': 5000000, 'team': 25},
    'Scale': {'email': 2000000, 'api': 20000000, 'team': 50},
    'Enterprise': {'email': 5000000, 'api': -1, 'team': -1},  # -1 = Unlimited
}

def fix_training_data():
    filepath = '/Users/sabelakhoua/IdeaProjects/ApexMail/data/train_agent.jsonl'
    
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
                if plan in CANONICAL:
                    canon = CANONICAL[plan]
                    
                    # Fix email limits in customer context
                    # Pattern: "Email usage this month: X/Y"
                    if canon['email'] != -1:  # Not unlimited
                        def fix_email_limit(match):
                            usage = match.group(1)
                            return f"Email usage this month: {usage}/{canon['email']:,}"
                        modified = re.sub(
                            r'Email usage this month: ([\d,]+)/[\d,]+',
                            fix_email_limit,
                            modified
                        )
                    
                    # Fix API limits in customer context
                    # Pattern: "API calls this month: X/Y"
                    if canon['api'] != -1:  # Not unlimited
                        def fix_api_limit(match):
                            usage = match.group(1)
                            return f"API calls this month: {usage}/{canon['api']:,}"
                        modified = re.sub(
                            r'API calls this month: ([\d,]+)/[\d,]+',
                            fix_api_limit,
                            modified
                        )
                    
                    # Fix team limits in customer context
                    # Pattern: "Team members: X/Y"
                    if canon['team'] != -1:  # Not unlimited
                        def fix_team_limit(match):
                            usage = match.group(1)
                            return f"Team members: {usage}/{canon['team']}"
                        modified = re.sub(
                            r'Team members: (\d+)/\d+',
                            fix_team_limit,
                            modified
                        )
                    
                    # Also fix assistant responses that reference limits
                    # Fix wrong email limits in responses like "Emails: X / Y (Z%)"
                    if canon['email'] != -1:
                        # Match patterns like "67,500 / 100,000" in responses
                        def fix_response_email(match):
                            usage = match.group(1).strip()
                            return f"{usage} / {canon['email']:,}"
                        # Only fix if NOT in a pricing table context
                        if 'Plan: ' + plan in modified and '|' not in modified[-500:]:
                            modified = re.sub(
                                r'Emails: ([\d,]+)\s*/\s*[\d,]+',
                                lambda m: f"Emails: {m.group(1)} / {canon['email']:,}",
                                modified
                            )
                    
                    if canon['api'] != -1:
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
