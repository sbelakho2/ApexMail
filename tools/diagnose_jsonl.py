#!/usr/bin/env python3
"""Diagnose remaining old prices in JSONL files."""
import json, re

for path in ['data/train_agent.jsonl', 'apps/ai/training/data/train.jsonl']:
    print(f"\n=== {path} ===")
    with open(path) as f:
        line = f.readline()
    obj = json.loads(line)
    text = obj['text']
    
    # Find old pricing
    old_patterns = [
        r'Starter \(\$29\)',
        r'Pro \(\$59\)',
        r'Growth \(\$129\)',
        r'Scale \(\$399\)',
        r'Enterprise \(\$1,299\)',
        r'\$0\.50 per 1',
        r'\$0\.50/1',
        r'\$49/mo',
        r'\$30/month',
        r'\| \$29\s',
        r'\| \$59\s',
        r'\| \$129\s',
        r'\| \$399\s',
        r'\| \$1,299\s',
    ]
    
    for pat in old_patterns:
        matches = list(re.finditer(pat, text))
        if matches:
            m = matches[0]
            start = max(0, m.start() - 40)
            end = min(len(text), m.end() + 60)
            ctx = text[start:end].replace('\n', '\\n')
            print(f"  FOUND ({len(matches)}x) {pat}: ...{ctx}...")

    # Verify new prices exist
    new_patterns = ['$25', '$65', '$150', '$350', '$800']
    for p in new_patterns:
        count = text.count(p)
        if count > 0:
            print(f"  NEW OK: {p} found {count}x")
