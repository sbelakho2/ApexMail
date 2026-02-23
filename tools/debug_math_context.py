#!/usr/bin/env python3
"""Extract full context around flagged math issues."""
import json
import re

filepath = 'data/train_agent.jsonl'
target_lines = [42, 104, 310, 341, 349, 603, 659, 689, 851, 1044]

with open(filepath) as f:
    lines = f.readlines()

for target in target_lines:
    data = json.loads(lines[target - 1])
    text = data['text']
    parts = re.findall(r'<\|im_start\|>assistant\n(.*?)(?:<\|im_end\|>|$)', text, re.DOTALL)
    assistant = '\n'.join(parts)
    
    print(f"\n{'='*70}")
    print(f"LINE {target}")
    print(f"{'='*70}")
    
    # Show plan context
    plan_match = re.search(r'Plan: (\w+) \(\$(\d+)/mo\)', text)
    if plan_match:
        print(f"Plan: {plan_match.group(1)} (${plan_match.group(2)}/mo)")
    else:
        print("Plan: Unauthenticated")
    
    # Show user question
    user_parts = re.findall(r'<\|im_start\|>user\n(.*?)(?:<\|im_end\|>|$)', text, re.DOTALL)
    if user_parts:
        print(f"User: {user_parts[0][:200]}...")
    
    # Show relevant section of assistant response (around the math)
    patterns_of_interest = [
        r'[\d,]+ extra.*?\$[\d.]+',
        r'\$[\d.]+ \+ \$[\d.]+ = \$[\d.]+',
        r'[\d,]+ [×x] \$[\d.]+ = \$[\d.]+',
        r'overage',
        r'total.*?\$[\d.]+',
    ]
    
    for line_text in assistant.split('\n'):
        for pat in patterns_of_interest:
            if re.search(pat, line_text, re.I):
                print(f"  > {line_text.strip()}")
                break
