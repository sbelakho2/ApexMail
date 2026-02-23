#!/usr/bin/env python3
"""Show full assistant responses for remaining 4 lines."""
import json, re

filepath = 'data/train_agent.jsonl'
with open(filepath) as f:
    lines = f.readlines()

for ln in [310, 334, 814, 1044]:
    data = json.loads(lines[ln - 1])
    text = data['text']
    assists = re.findall(r'<\|im_start\|>assistant\n(.*?)(?:<\|im_end\|>|$)', text, re.DOTALL)
    for idx, a in enumerate(assists):
        print(f"\n{'='*60}")
        print(f"L{ln} assistant[{idx}] ({len(a)} chars):")
        print(f"{'='*60}")
        print(a[:2000])
        if len(a) > 2000:
            print(f"... ({len(a) - 2000} more chars)")
