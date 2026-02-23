#!/usr/bin/env python3
"""Check plan context for lines with complex math errors."""
import json, re

filepath = 'data/train_agent.jsonl'
target_lines = [533, 596, 783, 964, 115, 226, 419, 612, 763]

with open(filepath) as f:
    lines = f.readlines()

for ln in target_lines:
    data = json.loads(lines[ln-1])
    text = data['text']
    plan = re.search(r'Plan: (\w+) \(\$(\d+)/mo\)', text)
    user = re.findall(r'<\|im_start\|>user\n(.*?)(?:<\|im_end\|>)', text, re.DOTALL)
    assist = re.findall(r'<\|im_start\|>assistant\n(.*?)(?:<\|im_end\|>|$)', text, re.DOTALL)
    print(f"L{ln}:")
    print(f"  Plan: {plan.group(1) if plan else 'Unauth'} ({plan.group(2) if plan else '?'})")
    print(f"  User: {user[0].strip()[:120] if user else 'N/A'}")
    # Show just the problematic sections
    for p in assist:
        for m in re.finditer(r'.{0,30}(?:overage|50,000|100,000|150,000|25,000|Pro|Starter|included|limit).{0,80}', p, re.I):
            snippet = m.group(0).strip().replace('\n', ' ')
            if snippet:
                print(f"  > {snippet[:150]}")
    print()
