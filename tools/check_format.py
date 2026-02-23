#!/usr/bin/env python3
"""Check chat format structure of training data."""
import json

issues = []
with open('data/train_agent.jsonl', 'r') as f:
    for i, line in enumerate(f, 1):
        obj = json.loads(line)
        text = obj['text']
        sys_count = text.count('<|im_start|>system')
        user_count = text.count('<|im_start|>user')
        asst_count = text.count('<|im_start|>assistant')
        end_count = text.count('<|im_end|>')
        expected_ends = sys_count + user_count + asst_count
        if sys_count != 1:
            issues.append((i, f'sys_count={sys_count}'))
        if user_count < 1:
            issues.append((i, f'user_count={user_count}'))
        if asst_count < 1:
            issues.append((i, f'asst_count={asst_count}'))
        if end_count != expected_ends:
            issues.append((i, f'end_mismatch: {end_count} vs {expected_ends}'))

if issues:
    print(f'Found {len(issues)} marker issues:')
    for line, issue in issues[:10]:
        print(f'  Line {line}: {issue}')
else:
    print('All 1193 examples have proper chat marker structure')
