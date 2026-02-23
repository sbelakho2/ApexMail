#!/usr/bin/env python3
"""Spot-check subagent findings on specific lines."""
import json, re

filepath = 'data/train_agent.jsonl'
with open(filepath) as f:
    lines = f.readlines()

checks = {
    # Enterprise old email limit 2M
    270: "Enterprise.*?2[,.]?000[,.]?000",
    349: "Enterprise.*?2[,.]?000[,.]?000|2[,.]?000[,.]?000.*?Enterprise",
    # Scale old email limit 500K  
    299: "Scale.*?500[,.]?000|500[,.]?000.*?Scale",
    312: "Scale.*?500[,.]?000|500[,.]?000.*?Scale",
    # Growth old email limit 100K
    96: "Growth.*?100[,.]?000|100[,.]?000.*?Growth",
    # Growth old team count 10
    72: "Growth.*?\\b10\\b.*?team|team.*?\\b10\\b.*?Growth",
    126: "Growth.*?\\b10\\b.*?team|Pro.*?\\b5\\b.*?team",
    # Starter wrong domain 25
    334: "Starter.*?25.*?domain",
    # Overage math
    69: r"\$2\.50|2\.50",
}

for ln, pattern in checks.items():
    data = json.loads(lines[ln - 1])
    text = data['text']
    assists = re.findall(r'<\|im_start\|>assistant\n(.*?)(?:<\|im_end\|>|$)', text, re.DOTALL)
    assistant = '\n'.join(assists)
    
    m = re.search(pattern, assistant, re.IGNORECASE | re.DOTALL)
    if m:
        start = max(0, m.start() - 40)
        end = min(len(assistant), m.end() + 40)
        snippet = assistant[start:end].replace('\n', '↵')
        print(f"L{ln}: CONFIRMED — ...{snippet}...")
    else:
        print(f"L{ln}: NOT FOUND with pattern '{pattern}'")
        # Show first 300 chars of assistant
        print(f"  Preview: {assistant[:300].replace(chr(10), '↵')}")
