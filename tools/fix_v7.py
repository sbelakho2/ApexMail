#!/usr/bin/env python3
"""Fix v7: Fix the 4 remaining real errors."""
import json

from common_paths import data_path

FILEPATH = str(data_path("train_agent.jsonl"))

with open(FILEPATH) as f:
    lines = f.readlines()

fixes = 0

def fix(ln, old, new, desc):
    global fixes
    idx = ln - 1
    data = json.loads(lines[idx])
    text = data['text']
    if old in text:
        text = text.replace(old, new)
        data['text'] = text
        lines[idx] = json.dumps(data, ensure_ascii=False) + '\n'
        fixes += 1
        print(f"  L{ln}: {desc}")
    else:
        print(f"  L{ln}: NOT FOUND — {desc}")

# 1. L224/L444: Enterprise "20,000,000 API calls" (no /mo suffix)
for ln in [224, 444]:
    fix(ln,
        'Enterprise includes 5,000,000 emails/month, 20,000,000 API calls,',
        'Enterprise includes 5,000,000 emails/month, unlimited API calls,',
        'Enterprise API 20M→Unlimited')

# 2. L620/L905: Growth cascading bug - 20M → 5M
for ln in [620, 905]:
    fix(ln,
        'Growth plan ($150/month) includes **20,000,000 API calls/month**',
        'Growth plan ($150/month) includes **5,000,000 API calls/month**',
        'Growth API cascading fix 20M→5M')

# Also fix the "not 2 million" part which no longer makes sense
for ln in [620, 905]:
    fix(ln,
        '**5,000,000 API calls/month** — not 2 million',
        '**5,000,000 API calls/month**',
        'Removed stale "not 2 million" correction')

with open(FILEPATH, 'w') as f:
    f.writelines(lines)

print(f"\nTotal fixes: {fixes}")
