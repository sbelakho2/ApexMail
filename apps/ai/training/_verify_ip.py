#!/usr/bin/env python3
"""Verify dedicated IP pricing in train_agent.jsonl."""

with open("/Users/sabelakhoua/IdeaProjects/ApexMail/data/train_agent.jsonl", "r") as f:
    content = f.read()

# Check all forms of $50 near "dedicated"
import re
for pattern in [r'\$50', r'\\$50', r'\\\$50', r'dedicated.{0,30}50']:
    matches = list(re.finditer(pattern, content))
    print(f"Pattern '{pattern}': {len(matches)} matches")
    for m in matches:
        s = max(0, m.start() - 30)
        e = min(len(content), m.end() + 30)
        print(f"  ...{content[s:e]}...")

print()

# Also check for $49 near dedicated
for pattern in [r'\$49', r'dedicated.{0,30}49']:
    matches = list(re.finditer(pattern, content))
    print(f"Pattern '{pattern}': {len(matches)} matches")
    for m in matches[:5]:
        s = max(0, m.start() - 30)
        e = min(len(content), m.end() + 30)
        print(f"  ...{content[s:e]}...")
