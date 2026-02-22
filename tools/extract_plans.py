#!/usr/bin/env python3
"""Extract the exact plan features text from JSONL for targeted replacement."""
import json, re

for path in ['data/train_agent.jsonl', 'apps/ai/training/data/train.jsonl']:
    print(f"\n=== {path} ===")
    with open(path) as f:
        line = f.readline()
    obj = json.loads(line)
    text = obj['text']
    
    # Find each plan feature line
    for plan in ['Free', 'Starter', 'Pro', 'Growth', 'Scale', 'Enterprise']:
        # Search for **PlanName ($price)**: or **PlanName ($price):**
        pat = rf'\*\*{plan}[^*]*\*\*[:\s]*[^\n]+'
        matches = re.findall(pat, text)
        for m in matches:
            if any(c in m for c in ['29', '59', '129', '399', '1,299']):
                print(f"  OLD: {m}")
            elif any(c in m for c in ['25', '65', '150', '350', '800']):
                pass  # already updated
