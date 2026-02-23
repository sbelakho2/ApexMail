#!/usr/bin/env python3
"""Show context around arithmetic errors on L349 and L659."""
import json, re

filepath = 'data/train_agent.jsonl'
with open(filepath) as f:
    lines = f.readlines()

for ln in [349, 659]:
    data = json.loads(lines[ln - 1])
    text = data['text']
    assist_parts = re.findall(r'<\|im_start\|>assistant\n(.*?)(?:<\|im_end\|>|$)', text, re.DOTALL)
    assistant = '\n'.join(assist_parts)
    
    # Find the $72 + $450 = $532 pattern
    m = re.search(r'\$(72[\d.]*)\s*\+\s*\$(450[\d.]*)\s*=\s*\*?\*?\$?([\d.]+)', assistant)
    if m:
        start = max(0, m.start() - 200)
        end = min(len(assistant), m.end() + 200)
        print(f"\n{'='*60}")
        print(f"L{ln}: Context around ${m.group(1)} + ${m.group(2)} = ${m.group(3)}")
        print(f"{'='*60}")
        print(assistant[start:end])
