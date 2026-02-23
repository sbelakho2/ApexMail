#!/usr/bin/env python3
"""Fix last 2 arithmetic errors: L132/558 overage math, L450/1019 Starter total."""
import json, re

filepath = 'data/train_agent.jsonl'
with open(filepath) as f:
    lines = f.readlines()

fixes = 0

# Show and fix L132/558: "350K over (~$175 in overages" → "~$140"
for ln in [132, 558]:
    data = json.loads(lines[ln - 1])
    text = data['text']
    if '~$175' in text and '350' in text.lower():
        text = text.replace('~$175', '~$140')
        data['text'] = text
        lines[ln - 1] = json.dumps(data, ensure_ascii=False) + '\n'
        fixes += 1
        print(f"  L{ln}: Fixed $175→$140 (350K × $0.40/1K)")
    else:
        print(f"  L{ln}: Pattern not found, searching...")
        assists = re.findall(r'<\|im_start\|>assistant\n(.*?)(?:<\|im_end\|>|$)', text, re.DOTALL)
        for a in assists:
            if '175' in a or '350' in a.lower():
                idx = a.find('175')
                if idx > 0:
                    print(f"    ...{a[max(0,idx-60):idx+30]}...")

# Show and fix L450/1019: "$53.60" → "$34.68" for Starter calculation
for ln in [450, 1019]:
    data = json.loads(lines[ln - 1])
    text = data['text']
    if '$53.60' in text:
        # Replace $53.60 with $34.68 in the context of Starter cost
        text = text.replace('$53.60', '$34.68')
        data['text'] = text
        lines[ln - 1] = json.dumps(data, ensure_ascii=False) + '\n'
        fixes += 1
        print(f"  L{ln}: Fixed $53.60→$34.68 (Starter $25 + 24.2K × $0.40/1K = $9.68)")
    else:
        print(f"  L{ln}: '$53.60' not found, checking...")
        assists = re.findall(r'<\|im_start\|>assistant\n(.*?)(?:<\|im_end\|>|$)', text, re.DOTALL)
        for a in assists:
            if 'starter' in a.lower() and ('53' in a or '74' in a):
                for line in a.split('\n'):
                    if 'starter' in line.lower() or '53' in line or '74' in line:
                        print(f"    {line[:120]}")

with open(filepath, 'w') as f:
    f.writelines(lines)
print(f"\nFixed {fixes} lines")
