#!/usr/bin/env python3
"""Check chat format structure of training data."""
import json
import re

START_RE = re.compile(r"<\|im_start\|>(system|user|assistant|tool)")
END_RE = re.compile(r"<\|im_end\|>")

issues = []
with open('data/train_agent.jsonl', 'r') as f:
    for i, line in enumerate(f, 1):
        obj = json.loads(line)
        text = obj['text']
        starts = START_RE.findall(text)
        sys_count = sum(1 for role in starts if role == 'system')
        user_count = sum(1 for role in starts if role == 'user')
        asst_count = sum(1 for role in starts if role == 'assistant')
        tool_count = sum(1 for role in starts if role == 'tool')
        end_count = len(END_RE.findall(text))
        expected_ends = sys_count + user_count + asst_count + tool_count
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
    print('All examples have proper chat marker structure')
