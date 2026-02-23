#!/usr/bin/env python3
"""Extract COMPLETE assistant responses for lines with math errors."""
import json
import re

filepath = 'data/train_agent.jsonl'
target_lines = [42, 104, 310, 341, 603, 689, 851, 1044]

with open(filepath) as f:
    lines = f.readlines()

for target in target_lines:
    data = json.loads(lines[target - 1])
    text = data['text']
    
    print(f"\n{'#'*70}")
    print(f"# LINE {target}")
    print(f"{'#'*70}")
    
    # Plan context
    plan_match = re.search(r'Plan: (\w+) \(\$(\d+)/mo\)', text)
    if plan_match:
        print(f"Plan: {plan_match.group(1)} (${plan_match.group(2)}/mo)")
    else:
        print("Plan: Unknown/Unauthenticated")
    
    # Email usage
    usage = re.search(r'Email usage this month: ([\w/,]+)', text)
    if usage:
        print(f"Email usage: {usage.group(1)}")
    
    # User question (first)
    user_parts = re.findall(r'<\|im_start\|>user\n(.*?)(?:<\|im_end\|>)', text, re.DOTALL)
    if user_parts:
        print(f"\nUSER: {user_parts[0].strip()}")
    
    # ALL assistant responses
    assist_parts = re.findall(r'<\|im_start\|>assistant\n(.*?)(?:<\|im_end\|>|$)', text, re.DOTALL)
    for j, part in enumerate(assist_parts):
        print(f"\nASSISTANT [{j+1}]:")
        print(part.strip())
